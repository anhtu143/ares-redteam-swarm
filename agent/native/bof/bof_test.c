#include <windows.h>

typedef void (*BeaconOutput_t)(int, const char*, int);
extern BeaconOutput_t __imp_BeaconOutput;
#define BeaconOutput(type,data,len) __imp_BeaconOutput(type,data,len)

void go(char* args, int alen) {
    char buf[64] = "BOF_OK: hello from bof_test";
    BeaconOutput(0, buf, (int)strlen(buf));
}
