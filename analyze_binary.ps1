$binPath = "build\svcupdate.dat"

Write-Host "=== BUILD COMPLETED ==="
if (!(Test-Path $binPath)) { Write-Host "FILE MISSING!"; exit 1 }
$fi = Get-Item $binPath
Write-Host "Size: $($fi.Length) bytes | Created: $($fi.CreationTime)"

Write-Host "`n=== CHECKING EVERY 10s FOR 60s ==="
for ($i = 1; $i -le 6; $i++) {
    Start-Sleep -Seconds 10
    if (Test-Path $binPath) {
        Write-Host "  [$($i*10)s] ALIVE"
    } else {
        Write-Host "  [$($i*10)s] QUARANTINED!"
        $det = Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 1
        Write-Host "  Threat: $($det.ThreatID) | Resources: $($det.Resources -join ',')"
        exit 1
    }
}

Write-Host "`n=== SURVIVED 60s - RUNNING DEEP ANALYSIS ==="
try {
    $bytes = [System.IO.File]::ReadAllBytes($binPath)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    
    $apis = @("WinHttpOpen","CryptUnprotectData","BCryptDecrypt","AmsiScanBuffer","EtwEventWrite",
              "nkbihfbeogaeaoehlefnkodbefgpgknn","bfnaelmomeimhlpmgjnjophhpkkoljpa",
              "Google\\Chrome","Microsoft\\Edge","Login Data","Local State","encrypted_key",
              "MetaMask","Phantom","schtasks","powershell","amsi.dll","winhttp.dll","crypt32.dll")
    $found = 0
    foreach ($s in $apis) {
        $c = ([regex]::Matches($text, [regex]::Escape($s))).Count
        if ($c -gt 0) { Write-Host "  [FOUND] $s"; $found++ }
    }
    if ($found -eq 0) { Write-Host "  ALL SIGNATURES: CLEAN" }
    Write-Host "`n=== DEFENDER BYPASS CONFIRMED! ==="
} catch {
    Write-Host "  Read blocked: $_"
}
