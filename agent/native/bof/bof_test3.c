/*
 * bof_test3.c — test wcsstr with BOF rdata wchar string
 */
#include <windows.h>
void BeaconOutput(int type, const char* data, int len);
#define CALLBACK_OUTPUT 0

void go(char* args, int alen)
{
    /* Test 1: wcsstr with literal */
    const wchar_t* hay = L"MsMpEng.exe";
    const wchar_t* ndl = L"MsMpEng";
    const wchar_t* res = wcsstr(hay, ndl);

    /* Test 2: static array of wchar_t* */
    const wchar_t* avNames[] = {
        L"MsMpEng.exe",
        L"SentinelAgent",
        NULL
    };

    char buf[256];
    int n = 0;
    n += (int)(res ? 1 : 0);  /* 1 if wcsstr found */

    /* Check avNames pointers are valid */
    for (int i = 0; avNames[i]; i++) {
        const wchar_t* p = wcsstr(L"MsMpEng.exe running", avNames[i]);
        n += (p ? 1 : 0);
    }

    buf[0] = '0' + (char)n;
    buf[1] = 0;
    BeaconOutput(CALLBACK_OUTPUT, buf, 1);
}
