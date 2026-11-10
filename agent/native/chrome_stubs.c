/*
 * chrome_stubs.c — Stub implementations when stealer.c/chrome_v20.c
 * are excluded from build. Allows stager to link cleanly.
 * These functions return 0 (no data) — stealer.c overrides them when included.
 *
 * Usage: include in STAGER_SRC when NOT including stealer.c
 */
#include "ares_agent.h"

#pragma weak Ares_StealChromeCreds
int Ares_StealChromeCreds(DECRYPTED_CRED* creds, int max_creds)
{
    (void)creds; (void)max_creds;
    return 0;
}

#pragma weak Ares_StealChromeCookies
int Ares_StealChromeCookies(STOLEN_COOKIE* cookies, int max_cookies)
{
    (void)cookies; (void)max_cookies;
    return 0;
}

#pragma weak Ares_StealChromelevator
int Ares_StealChromelevator(DECRYPTED_CRED* creds, int max_creds,
    STOLEN_COOKIE* cookies, int max_cookies)
{
    (void)creds; (void)max_creds;
    (void)cookies; (void)max_cookies;
    return 0;
}
