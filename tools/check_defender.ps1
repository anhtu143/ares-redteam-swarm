$threats = Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-10) }
if ($threats) {
    Write-Host "=== DEFENDER DETECTIONS (last 10 min) ==="
    $threats | ForEach-Object {
        Write-Host "  Threat: $($_.ThreatName)"
        Write-Host "  Time:   $($_.InitialDetectionTime)"
        Write-Host "  Action: $($_.ActionSuccess)"
        Write-Host ""
    }
} else {
    Write-Host "[+] NO Defender detections in last 10 minutes"
}

# Check if test_full.exe still exists
if (Test-Path "build\test_full.exe") {
    $size = (Get-Item "build\test_full.exe").Length
    Write-Host "[+] test_full.exe still alive: $size bytes"
} else {
    Write-Host "[!] test_full.exe was QUARANTINED"
}

# Check quarantine
$quarantine = Get-MpThreat
if ($quarantine) {
    Write-Host ""
    Write-Host "=== Quarantine History ==="
    $quarantine | Select-Object ThreatName, IsActive | Format-Table
}
