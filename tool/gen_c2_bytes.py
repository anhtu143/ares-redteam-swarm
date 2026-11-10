host = '127.0.0.1'
key = 0x5A
enc = [b ^ key for b in host.encode()]
c_arr = ', '.join(f'0x{b:02X}' for b in enc)
print(f'// "{host}" XOR 0x5A:')
print(f'static const BYTE CFG_C2_0[] = {{{c_arr}}};')
print(f'#define CFG_C2_0_LEN {len(enc)}')
print(f'#define CFG_C2_PORT 443')
