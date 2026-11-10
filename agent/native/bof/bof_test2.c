#include <windows.h>
#include <stdio.h>

void BeaconOutput(int type, const char* data, int len);
void BeaconPrintf(int type, const char* fmt, ...);

/* Cobalt Strike BOF beacon API forward decls - resolved by loader */
#define DECLSPEC_IMPORT __declspec(dllimport)

/* Use CobaltStrike-style beacon_t approach: inline functions */
void go(char* args, int alen) {
    char buf[128];
    DWORD pid = GetCurrentProcessId();
    snprintf(buf, sizeof(buf), "BOF_TEST_OK pid=%lu", (unsigned long)pid);
    BeaconOutput(0, buf, (int)strlen(buf));
}
