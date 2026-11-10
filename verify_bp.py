import ctypes as ct
import ctypes.wintypes as wt

pid = 41356

kernel32 = ct.windll.kernel32
psapi = ct.windll.psapi

# Use PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
hProc = kernel32.OpenProcess(0x0410, False, pid)
print(f'Handle: {hProc}')

# Enumerate modules using EnumProcessModulesEx
hMods = (ct.c_uint64 * 1024)()
cbNeeded = wt.DWORD()
psapi.EnumProcessModulesEx(hProc, ct.byref(hMods), ct.sizeof(hMods), ct.byref(cbNeeded), 3)

chrome_dll_base = None
nMods = cbNeeded.value // 8
print(f'Found {nMods} modules')
for i in range(nMods):
    name = ct.create_string_buffer(260)
    psapi.GetModuleFileNameExA(hProc, ct.c_void_p(hMods[i]), name, 260)
    if b'chrome.dll' in name.value.lower():
        chrome_dll_base = hMods[i]
        print(f'chrome.dll: 0x{chrome_dll_base:X}')
        break

if chrome_dll_base:
    # Expected at RVA 0x861BDFD: mov ebx, eax = 89 C3
    target = chrome_dll_base + 0x861BDFD
    buf = ct.create_string_buffer(32)
    got = ct.c_size_t()
    res = kernel32.ReadProcessMemory(hProc, ct.c_uint64(target), buf, 32, ct.byref(got))
    print(f'Read at 0x{target:X}: res={res}, got={got.value}')
    raw = buf.raw[:got.value]
    print(f'Hex: {raw[:16].hex(" ")}')
    # Expected: 89 C3 48 8D 0D ...
    if raw[0:2] == bytes([0x89, 0xC3]):
        print('MATCH! mov ebx, eax confirmed')
    else:
        print(f'MISMATCH: expected 89 C3, got {raw[0]:02X} {raw[1]:02X}')
    
    # Also check CALL at 0x861BDF8
    target2 = chrome_dll_base + 0x861BDF8
    kernel32.ReadProcessMemory(hProc, ct.c_uint64(target2), buf, 8, ct.byref(got))
    print(f'CALL at 0x{target2:X}: {buf.raw[:5].hex(" ")}')
    # Expected: E8 xx xx xx xx (relative call)
    if buf.raw[0] == 0xE8:
        print('CALL instruction confirmed')

kernel32.CloseHandle(hProc)
