import json

with open(r'C:\Users\Admin\AppData\Local\Temp\ares_cookies.json', 'r') as f:
    cookies = json.load(f)

# Count by domain
domains = {}
for c in cookies:
    d = c.get('domain', 'unknown')
    domains[d] = domains.get(d, 0) + 1

print('=== Cookie Summary ===')
for d, count in sorted(domains.items(), key=lambda x: -x[1]):
    print(f'  {count:3d} cookies | {d}')
print(f'\nTotal: {len(cookies)} cookies across {len(domains)} domains')

# Show all session/auth cookies
print('\n=== Session/Auth Cookies ===')
for c in cookies:
    n = c.get('name', '').lower()
    if any(k in n for k in ['session', 'token', 'auth', 'sid', 'login', 'jwt', 'access']):
        dom = c.get('domain', '')
        name = c.get('name', '')
        val = c.get('value', '')[:60]
        print(f'  {dom:30s} | {name:30s} | {val}')

# Show httpOnly secure cookies
print('\n=== Secure HttpOnly Cookies ===')
for c in cookies:
    if c.get('httpOnly') and c.get('secure'):
        dom = c.get('domain', '')
        name = c.get('name', '')
        val = c.get('value', '')[:60]
        print(f'  {dom:30s} | {name:30s} | {val}')
