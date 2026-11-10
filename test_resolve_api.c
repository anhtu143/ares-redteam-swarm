#include <windows.h>
#include <stdio.h>
#include "agent/native/ares_resolve.h"

int main() {
    printf("[*] Testing Ares_ResolveAPIs()...\n");
    
    // Test individual resolvers
    printf("[*] Testing winhttp...\n");
    BOOL wh = _resolve_winhttp();
    printf("  winhttp: %s\n", wh ? "OK" : "FAIL");
    
    printf("[*] Testing crypt32...\n");
    BOOL c32 = _resolve_crypt32();
    printf("  crypt32: %s\n", c32 ? "OK" : "FAIL");

    printf("[*] Testing bcrypt...\n");
    BOOL bc = _resolve_bcrypt();
    printf("  bcrypt: %s\n", bc ? "OK" : "FAIL");

    printf("[*] Testing shell32...\n");
    BOOL sh = _resolve_shell32();
    printf("  shell32: %s\n", sh ? "OK" : "FAIL");

    printf("[*] Testing ole32...\n");
    BOOL ole = _resolve_ole32();
    printf("  ole32: %s\n", ole ? "OK" : "FAIL");

    printf("[*] Testing kernel32 sensitive...\n");
    BOOL k32 = _resolve_kernel32_sensitive();
    printf("  kernel32: %s\n", k32 ? "OK" : "FAIL");
    printf("  CreateProcessA: %p\n", (void*)p_CreateProcessA);
    printf("  CreateProcessW: %p\n", (void*)p_CreateProcessW);
    printf("  ReadProcessMemory: %p\n", (void*)p_ReadProcessMemory);
    printf("  WriteProcessMemory: %p\n", (void*)p_WriteProcessMemory);
    printf("  VirtualProtect: %p\n", (void*)p_VirtualProtect);

    printf("\n[*] Full Ares_ResolveAPIs()...\n");
    BOOL all = Ares_ResolveAPIs();
    printf("  Result: %s\n", all ? "ALL OK" : "FAIL");
    
    return all ? 0 : 1;
}
