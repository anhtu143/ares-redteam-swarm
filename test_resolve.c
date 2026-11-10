#include <windows.h>
#include <stdio.h>
#include "ares_resolve.h"
int main() {
    printf("Resolving APIs...\n");
    if (Ares_ResolveAPIs()) {
        printf("OK! p_WinHttpOpen=%p p_CryptUnprotectData=%p p_CoCreateInstance=%p\n",
            (void*)p_WinHttpOpen, (void*)p_CryptUnprotectData, (void*)p_CoCreateInstance);
        printf("p_WinHttpWebSocketSend=%p\n", (void*)p_WinHttpWebSocketSend);
    } else {
        printf("FAILED\n");
        printf("  winhttp=%p crypt32=%p bcrypt=%p ole32=%p\n",
            (void*)g_mod_winhttp, (void*)g_mod_crypt32, (void*)g_mod_bcrypt, (void*)g_mod_ole32);
    }
    return 0;
}
