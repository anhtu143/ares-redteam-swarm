taskkill /f /im chrome.exe 2>&1 | Out-Null
Start-Sleep 2

$lockFile = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\SingletonLock"
Remove-Item -Force $lockFile -ErrorAction SilentlyContinue

$p = Start-Process "C:\Program Files\Google\Chrome\Application\chrome.exe" `
    -ArgumentList "--headless=new --remote-debugging-port=19333 --no-first-run --disable-gpu" `
    -PassThru -WindowStyle Hidden

Start-Sleep 5
Write-Host "PID: $($p.Id) HasExited: $($p.HasExited)"

try {
    $ver = (Invoke-WebRequest "http://127.0.0.1:19333/json/version" -UseBasicParsing).Content
    Write-Host "VERSION: $ver"
} catch {
    Write-Host "VERSION ERROR: $($_.Exception.Message)"
}

try {
    $list = (Invoke-WebRequest "http://127.0.0.1:19333/json" -UseBasicParsing).Content
    Write-Host "LIST: $list"
} catch {
    Write-Host "LIST ERROR: $($_.Exception.Message)"
}

Stop-Process $p -Force -ErrorAction SilentlyContinue
