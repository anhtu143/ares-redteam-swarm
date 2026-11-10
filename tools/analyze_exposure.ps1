$b = [IO.File]::ReadAllBytes("build\runtimebroker.dat")
$t = [Text.Encoding]::ASCII.GetString($b)

# Extract Win32 API names from binary
$pattern = '[A-Z][a-z]+[A-Z][a-zA-Z0-9]+'
$matches = [regex]::Matches($t, $pattern)
$apis = @{}
foreach ($m in $matches) {
    $v = $m.Value
    if ($v.Length -ge 8 -and $v.Length -le 40) {
        $apis[$v] = $true
    }
}

Write-Host "=== IAT/STRING API EXPOSURE ==="
Write-Host "Total unique API-like strings: $($apis.Count)"
Write-Host ""

# Categorize
$sensitive = @("WinHttp","Crypt","BCrypt","Reg","CoCreate","AddVectored",
    "GetThread","SetThread","NtQuery","NtAllocate","NtWrite","NtProtect",
    "NtCreate","CreateRemoteThread","VirtualAlloc","WriteProcessMemory",
    "OpenProcess","TerminateProcess","CreateToolhelp","SHGetFolder",
    "Shell","CreateProcess","WinExec","LoadLibrary","GetProcAddress")

Write-Host "--- SENSITIVE APIs ---"
foreach ($api in ($apis.Keys | Sort-Object)) {
    foreach ($s in $sensitive) {
        if ($api -like "*$s*") {
            Write-Host "  [!] $api"
            break
        }
    }
}

Write-Host ""
Write-Host "--- ALL PLAINTEXT STRINGS (>= 10 chars) ---"
$strings = [regex]::Matches($t, '[\x20-\x7E]{10,120}')
$seen = @{}
foreach ($m in $strings) {
    $v = $m.Value.Trim()
    if (-not $seen.ContainsKey($v) -and $v -notmatch '^\s*$') {
        $seen[$v] = $true
    }
}
$keywords = @("chrome","edge","brave","opera","vivaldi","discord","telegram",
    "Login Data","Cookies","Local State","User Data","headless","debug",
    "schtask","EdgeUpdate","msedge","pipe","DPAPI","v20","blocked",
    "exe","dll","NtQuery","Sentinel","CrowdStrike","Defender","MsMpEng",
    "password","wallet","MetaMask","extension","profile","Default","Network")
    
foreach ($str in ($seen.Keys | Sort-Object)) {
    foreach ($kw in $keywords) {
        if ($str -like "*$kw*") {
            Write-Host "  $str"
            break
        }
    }
}
