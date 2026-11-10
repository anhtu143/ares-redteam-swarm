Start-MpScan -ScanPath 'C:\Users\Admin\.openclaw\workspace\Ares_Framework\build\runtimebroker.exe' -ScanType CustomScan
Start-Sleep 10
$d = Get-MpThreatDetection -ErrorAction SilentlyContinue | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddMinutes(-2) }
if ($d) { 
    $d | Format-List ThreatName,ActionSuccess
} else { 
    Write-Host '[+] ON-DEMAND SCAN PASSED - 0 detections' -ForegroundColor Green 
}
$f = Get-Item 'C:\Users\Admin\.openclaw\workspace\Ares_Framework\build\runtimebroker.exe' -ErrorAction SilentlyContinue
if ($f) {
    Write-Host "[+] Binary ALIVE: $($f.Length) bytes" -ForegroundColor Green
} else {
    Write-Host '[-] Binary QUARANTINED!' -ForegroundColor Red
}
