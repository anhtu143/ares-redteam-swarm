#!/usr/bin/env python3
"""
gen_xor_key.py — Generate a random per-build XOR key and print as a GCC -D flag.

Usage (from Makefile):
    XOR_KEY_FLAG := $(shell python3 tools/gen_xor_key.py)
    CFLAGS += $(XOR_KEY_FLAG)

Then re-encrypt all strings:
    python3 tools/gen_full_strings.py --key <byte>

Output format:  -DCFG_XOR_KEY=0xNN
"""
import secrets
import sys

# Avoid trivially weak keys (0x00 = no-op, 0xFF = all-ones)
# Also avoid keys that produce printable ASCII output for common strings
BAD_KEYS = {0x00, 0xFF, 0x5A}  # 0x5A = old default, explicitly exclude

while True:
    key = secrets.randbelow(256)
    if key not in BAD_KEYS:
        break

print(f"-DCFG_XOR_KEY=0x{key:02X}")
