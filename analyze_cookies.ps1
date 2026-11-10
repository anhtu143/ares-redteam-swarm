$c = Get-Content "build\extracted_cookies.json" -Raw -ErrorAction SilentlyContinue
if (-not $c) { Write-Host "No file"; exit }
Write-Host "File: $($c.Length) bytes"

$names = [regex]::Matches($c, '"name":"([^"]+)"')
$domains = [regex]::Matches($c, '"domain":"([^"]+)"')
Write-Host "Total cookies: $($names.Count)"

$uDom = $domains | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
Write-Host "`nDomains ($($uDom.Count)):"
foreach ($d in $uDom) {
    $cnt = ($domains | Where-Object { $_.Groups[1].Value -eq $d }).Count
    Write-Host "  $d : $cnt cookies"
}

# Show high-value cookies
Write-Host "`nHigh-Value Cookies:"
$hvNames = @("session","sid","auth","token","jwt","PHPSESSID","JSESSIONID","oauth","login","NID","SID","APISID","SSID","HSID","SAPISID")
foreach ($n in $names) {
    $nv = $n.Groups[1].Value
    foreach ($hv in $hvNames) {
        if ($nv -match $hv) {
            Write-Host "  [HV] $nv"
            break
        }
    }
}
