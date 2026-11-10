import urllib.request, json

BOT = "dbc6137cabc0a85d"
req = urllib.request.Request(
    f"http://127.0.0.1:8443/api/panel/data/{BOT}",
    headers={"Authorization": "Bearer ares2026prod"})
raw = urllib.request.urlopen(req).read()
data = json.loads(raw.decode('utf-8', errors='replace'))

for item in data:
    tp = item.get("type", "?")
    entries = item.get("data", item.get("entries", []))
    if isinstance(entries, list):
        print(f"\n=== {tp.upper()} ({len(entries)} entries) ===")
        for e in entries[:5]:
            url = e.get("url", "?")[:40]
            user = e.get("user", e.get("username", "?"))[:20]
            pw = e.get("pass", e.get("password", ""))[:15]
            status = e.get("status", "")
            if "url" in e:
                print(f"  {url:40s} | {user:20s} | {pw:15s} | {status}")
            elif "host" in e or "name" in e:
                host = e.get("host", "?")[:25]
                name = e.get("name", "?")[:20]
                val = e.get("value", "?")[:20]
                print(f"  {host:25s} | {name:20s} | {val}")
    elif isinstance(entries, dict):
        print(f"\n=== {tp.upper()} (dict) ===")
        for k, v in list(entries.items())[:5]:
            print(f"  {k}: {str(v)[:60]}")
