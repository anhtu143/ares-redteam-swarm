"""Disassemble RetrieveAppBoundKey at 0x285EE10"""
import struct
from capstone import *

with open(r'C:\Program Files\Google\Chrome\Application\148.0.7778.168\chrome.dll', 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
num_secs = struct.unpack_from('<H', data, e_lfanew + 6)[0]
opt_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
sec_off = e_lfanew + 24 + opt_size

for i in range(num_secs):
    s = sec_off + i * 40
    name = data[s:s+8].rstrip(b'\x00').decode()
    rva = struct.unpack_from('<I', data, s + 12)[0]
    vsize = struct.unpack_from('<I', data, s + 8)[0]
    rawoff = struct.unpack_from('<I', data, s + 20)[0]
    if name == '.text':
        text_rva, text_vsize, text_rawoff = rva, vsize, rawoff
        break

target_rva = 0x285EE10
file_off = text_rawoff + (target_rva - text_rva)
chunk = data[file_off:file_off+300]

md = Cs(CS_ARCH_X86, CS_MODE_64)
for insn in md.disasm(chunk, target_rva):
    print(f'  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}')
    if insn.mnemonic == 'ret' or insn.address > target_rva + 250:
        break
