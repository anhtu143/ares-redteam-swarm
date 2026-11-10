"""
Disassemble the code around the LEA breakpoint to understand where the key is.
Use capstone for disassembly.
"""
import os, sys
try:
    from capstone import *
except ImportError:
    os.system(f'{sys.executable} -m pip install capstone -q')
    from capstone import *

# Read chrome.dll from disk and parse the section at the LEA offset
chrome_dll = r"C:\Program Files\Google\Chrome\Application\148.0.7778.168\chrome.dll"
with open(chrome_dll, "rb") as f:
    data = f.read()

print(f"[*] chrome.dll: {len(data)} bytes")

# Find the rdata string "OSCrypt.AppBoundProvider.KeyRetrieval.Status"
marker = b"OSCrypt.AppBoundProvider.KeyRetrieval.Status"
pos = data.find(marker)
print(f"[*] Marker at file offset: 0x{pos:X}")

# Parse PE sections
import struct
dos_e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
pe = dos_e_lfanew
num_sections = struct.unpack_from("<H", data, pe + 6)[0]
opt_size = struct.unpack_from("<H", data, pe + 20)[0]
sections_off = pe + 24 + opt_size
image_base = struct.unpack_from("<Q", data, pe + 24 + 24)[0]  # OptionalHeader.ImageBase

sections = []
for i in range(num_sections):
    s = sections_off + i * 40
    name = data[s:s+8].rstrip(b'\x00').decode()
    vsize = struct.unpack_from("<I", data, s + 8)[0]
    rva = struct.unpack_from("<I", data, s + 12)[0]
    rawsize = struct.unpack_from("<I", data, s + 16)[0]
    rawoff = struct.unpack_from("<I", data, s + 20)[0]
    sections.append((name, rva, vsize, rawoff, rawsize))
    if name in ('.text', '.rdata'):
        print(f"  {name}: RVA=0x{rva:X}, VSize=0x{vsize:X}, RawOff=0x{rawoff:X}")

# Get marker RVA
marker_rva = None
for name, rva, vsize, rawoff, rawsize in sections:
    if rawoff <= pos < rawoff + rawsize:
        marker_rva = rva + (pos - rawoff)
        print(f"[*] Marker RVA: 0x{marker_rva:X}")
        break

# Find LEA instruction referencing this RVA in .text section
text_sec = [s for s in sections if s[0] == '.text'][0]
text_rva, text_vsize, text_rawoff, text_rawsize = text_sec[1:]
text_data = data[text_rawoff:text_rawoff + text_rawsize]

print(f"[*] Scanning .text ({len(text_data)} bytes) for LEA -> RVA 0x{marker_rva:X}...")
lea_offset = None
for i in range(len(text_data) - 7):
    if text_data[i] == 0x48 and text_data[i+1] == 0x8D:
        modrm = text_data[i+2]
        if (modrm & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", text_data, i + 3)[0]
            cur_rva = text_rva + i + 7
            target_rva = cur_rva + disp
            if target_rva == marker_rva:
                lea_offset = text_rawoff + i
                lea_rva = text_rva + i
                print(f"[+] LEA at file offset 0x{lea_offset:X}, RVA 0x{lea_rva:X}")
                break

if lea_offset:
    # Disassemble function around the LEA (go back ~100 bytes, show ~200 bytes)
    start = max(0, lea_offset - 200)
    end = min(len(data), lea_offset + 200)
    chunk = data[start:end]
    base_rva = lea_rva - (lea_offset - start)
    
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    print(f"\n[*] Disassembly around LEA (RVA 0x{lea_rva:X}):\n")
    for insn in md.disasm(chunk, base_rva):
        marker_str = ""
        if insn.address == lea_rva:
            marker_str = "  <--- BREAKPOINT HERE"
        print(f"  0x{insn.address:X}: {insn.mnemonic:8s} {insn.op_str}{marker_str}")
        if insn.address > lea_rva + 100:
            break
