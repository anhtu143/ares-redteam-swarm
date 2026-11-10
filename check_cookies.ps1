# Kill chrome, copy DB, check, relaunch
taskkill /f /im chrome.exe 2>&1 | Out-Null
Start-Sleep 2

$db = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\Default\Network\Cookies"
$dbCopy = Join-Path $env:TEMP "cookies_check.db"
Copy-Item $db $dbCopy -Force

$sz = (Get-Item $dbCopy).Length
Write-Host "Cookie DB: $sz bytes"

# Read binary and find domain patterns
$bytes = [System.IO.File]::ReadAllBytes($dbCopy)
$content = [System.Text.Encoding]::ASCII.GetString($bytes)

# Find all domain-like strings (host_key field)
$domainPattern = '\.[a-z0-9-]+\.(com|org|net|io|co|dev|me)'
$matches = [regex]::Matches($content, $domainPattern)
$uniqueDomains = $matches | ForEach-Object { $_.Value } | Sort-Object -Unique
Write-Host "`nFound $($uniqueDomains.Count) unique domains in cookie DB:"
foreach ($d in $uniqueDomains) {
    $c = ($matches | Where-Object { $_.Value -eq $d }).Count
    Write-Host "  $d : $c cookie entries"
}

# Count total cookies by finding common cookie fields
$nameCount = ([regex]::Matches($content, 'encrypted_value')).Count
Write-Host "`nEstimated cookie entries: ~$nameCount"

Remove-Item $dbCopy -Force

# Relaunch chrome
Start-Process "C:\Program Files\Google\Chrome\Application\chrome.exe"
Write-Host "`nChrome relaunched"
