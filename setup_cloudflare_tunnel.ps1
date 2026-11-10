<#
.SYNOPSIS
    ARES C2 — Cloudflare Tunnel Setup (thay thế ngrok)

.DESCRIPTION
    Script tự động:
      1. Download + install cloudflared (nếu chưa có)
      2. Login vào Cloudflare account
      3. Tạo named tunnel "ares-c2" (URL cố định vĩnh viễn)
      4. Generate config file
      5. Hướng dẫn deploy CF Worker relay

.PARAMETER TunnelName
    Tên tunnel (mặc định: ares-c2)

.PARAMETER C2Port
    Port C2 server local (mặc định: 8443)

.PARAMETER C2Proto
    Protocol C2 (http hoặc https, mặc định: http)

.EXAMPLE
    .\setup_cloudflare_tunnel.ps1
    .\setup_cloudflare_tunnel.ps1 -TunnelName "my-tunnel" -C2Port 443 -C2Proto "https"
#>
param(
    [string]$TunnelName = "ares-c2",
    [int]$C2Port = 8443,
    [string]$C2Proto = "http"
)

$ErrorActionPreference = "Stop"

# ── Banner ──
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "  ║  ☁  ARES C2 — Cloudflare Tunnel Setup  ☁     ║" -ForegroundColor Red
Write-Host "  ║     Thay thế ngrok = tunnel cố định           ║" -ForegroundColor DarkRed
Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

# ── Step 1: Check/Install cloudflared ──
Write-Host "[1/5] Kiểm tra cloudflared..." -ForegroundColor Cyan

$cloudflared = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cloudflared) {
    Write-Host "  [!] cloudflared chưa được cài. Đang download..." -ForegroundColor Yellow

    $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
    $cfUrl = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-$arch.exe"
    $cfPath = "$env:LOCALAPPDATA\cloudflared\cloudflared.exe"

    # Tạo thư mục
    $cfDir = Split-Path $cfPath
    if (-not (Test-Path $cfDir)) { New-Item -ItemType Directory -Path $cfDir -Force | Out-Null }

    Write-Host "  [*] Downloading: $cfUrl" -ForegroundColor Gray
    Invoke-WebRequest -Uri $cfUrl -OutFile $cfPath -UseBasicParsing

    # Thêm vào PATH (session)
    $env:PATH = "$cfDir;$env:PATH"

    # Thêm vào PATH (persistent user)
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($userPath -notlike "*$cfDir*") {
        [Environment]::SetEnvironmentVariable("PATH", "$cfDir;$userPath", "User")
        Write-Host "  [+] Đã thêm cloudflared vào PATH" -ForegroundColor Green
    }

    Write-Host "  [+] cloudflared đã được cài: $cfPath" -ForegroundColor Green
} else {
    Write-Host "  [+] cloudflared đã có: $($cloudflared.Source)" -ForegroundColor Green
}

# Verify
$cfVersion = & cloudflared --version 2>&1
Write-Host "  [*] Version: $cfVersion" -ForegroundColor Gray

# ── Step 2: Login vào Cloudflare ──
Write-Host ""
Write-Host "[2/5] Login vào Cloudflare account..." -ForegroundColor Cyan
Write-Host "  [*] Trình duyệt sẽ mở để authenticate." -ForegroundColor Gray
Write-Host "  [*] Login bằng tài khoản: degead826@gmail.com" -ForegroundColor Yellow

$credFile = "$env:USERPROFILE\.cloudflared\cert.pem"
if (Test-Path $credFile) {
    Write-Host "  [+] Đã login trước đó (cert.pem exists). Skip." -ForegroundColor Green
} else {
    Write-Host "  [*] Đang mở trình duyệt..." -ForegroundColor Gray
    & cloudflared tunnel login
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] Login thất bại. Thử lại." -ForegroundColor Red
        exit 1
    }
    Write-Host "  [+] Login thành công!" -ForegroundColor Green
}

# ── Step 3: Tạo Named Tunnel ──
Write-Host ""
Write-Host "[3/5] Tạo Named Tunnel: $TunnelName ..." -ForegroundColor Cyan

# Check if tunnel already exists
$existingTunnels = & cloudflared tunnel list --output json 2>&1 | ConvertFrom-Json -ErrorAction SilentlyContinue
$existingTunnel = $existingTunnels | Where-Object { $_.name -eq $TunnelName }

if ($existingTunnel) {
    $tunnelID = $existingTunnel.id
    Write-Host "  [+] Tunnel '$TunnelName' đã tồn tại: $tunnelID" -ForegroundColor Green
} else {
    $createOutput = & cloudflared tunnel create $TunnelName 2>&1
    Write-Host "  $createOutput" -ForegroundColor Gray

    # Re-fetch tunnel ID
    $existingTunnels = & cloudflared tunnel list --output json 2>&1 | ConvertFrom-Json
    $existingTunnel = $existingTunnels | Where-Object { $_.name -eq $TunnelName }
    $tunnelID = $existingTunnel.id

    if (-not $tunnelID) {
        Write-Host "  [!] Không thể lấy Tunnel ID. Output:" -ForegroundColor Red
        Write-Host "  $createOutput" -ForegroundColor Red
        exit 1
    }
    Write-Host "  [+] Tunnel tạo thành công: $tunnelID" -ForegroundColor Green
}

# ── Step 4: Tạo Config File ──
Write-Host ""
Write-Host "[4/5] Tạo config file..." -ForegroundColor Cyan

$cfConfigDir = "$env:USERPROFILE\.cloudflared"
$configFile = "$cfConfigDir\config.yml"

# Find credentials file
$credFiles = Get-ChildItem "$cfConfigDir\*.json" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "^[a-f0-9\-]+\.json$" }
$credFile = $credFiles | Select-Object -First 1

$configContent = @"
# ═══════════════════════════════════════════════════
#  ARES C2 — Cloudflare Tunnel Configuration
#  Tunnel: $TunnelName ($tunnelID)
#  Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# ═══════════════════════════════════════════════════

tunnel: $tunnelID
credentials-file: $($credFile.FullName -replace '\\','/')

# Ingress rules — route traffic to local C2 server
ingress:
  # Main C2 endpoint — all HTTP(S) traffic
  - service: ${C2Proto}://localhost:$C2Port
    originRequest:
      noTLSVerify: true          # C2 dùng self-signed cert
      connectTimeout: 30s
      keepAliveTimeout: 90s
      keepAliveConnections: 100

  # Catch-all (required by cloudflared)
  - service: http_status:404
"@

# Backup old config if exists
if (Test-Path $configFile) {
    $backupName = "$configFile.bak.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $configFile $backupName
    Write-Host "  [*] Backup config cũ: $backupName" -ForegroundColor Gray
}

Set-Content -Path $configFile -Value $configContent -Encoding UTF8
Write-Host "  [+] Config saved: $configFile" -ForegroundColor Green

# ── Step 5: Summary & Instructions ──
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  ✓ Cloudflare Tunnel Setup Complete!                     ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Tunnel ID:    $tunnelID" -ForegroundColor White
Write-Host "  Tunnel Name:  $TunnelName" -ForegroundColor White
Write-Host "  Config:       $configFile" -ForegroundColor White
Write-Host "  C2 Target:    ${C2Proto}://localhost:$C2Port" -ForegroundColor White
Write-Host ""
Write-Host "  ── Cách dùng ──" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1. Chạy tunnel:" -ForegroundColor Cyan
Write-Host "     cloudflared tunnel run $TunnelName" -ForegroundColor White
Write-Host ""
Write-Host "  2. (Optional) Route DNS nếu có domain trên Cloudflare:" -ForegroundColor Cyan
Write-Host "     cloudflared tunnel route dns $TunnelName c2.your-domain.com" -ForegroundColor White
Write-Host ""
Write-Host "  3. Quick URL (không cần domain):" -ForegroundColor Cyan
Write-Host "     cloudflared tunnel --url ${C2Proto}://localhost:$C2Port" -ForegroundColor White
Write-Host ""
Write-Host "  4. Dùng script tự động:" -ForegroundColor Cyan
Write-Host "     .\start_c2_cloudflare.ps1" -ForegroundColor White
Write-Host ""

# ── Save tunnel info for other scripts ──
$infoFile = Join-Path (Split-Path $MyInvocation.MyCommand.Path) ".cloudflare_tunnel_info"
@"
TUNNEL_ID=$tunnelID
TUNNEL_NAME=$TunnelName
C2_PORT=$C2Port
C2_PROTO=$C2Proto
"@ | Set-Content $infoFile -Encoding UTF8

Write-Host "  [*] Tunnel info saved to: $infoFile" -ForegroundColor Gray
Write-Host ""
