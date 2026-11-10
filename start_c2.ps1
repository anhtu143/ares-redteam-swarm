# Ares C2 — Quick Start Script (v4.2)
#
# LOCAL TESTING ONLY — for production use start_c2_cloudflare.ps1
#
# Usage: powershell -ExecutionPolicy Bypass -File start_c2.ps1 [-Token "mytoken"] [-Port 8443]
#
# For production deployment (Cloudflare Tunnel):
#   .\start_c2_cloudflare.ps1
#   .\start_c2_cloudflare.ps1 -QuickTunnel    # No login needed
param(
    [string]$Token = "admin",
    [int]$Port = 8443
)

$c2dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$c2dir = Join-Path $c2dir "c2server"

Write-Host ""
Write-Host "  ╔══════════════════════════════════════╗" -ForegroundColor Red
Write-Host "  ║   ☠  ARES C2 — Quick Start  ☠        ║" -ForegroundColor Red
Write-Host "  ╚══════════════════════════════════════╝" -ForegroundColor Red
Write-Host ""
Write-Host "  ⚠ LOCAL TEST MODE — not exposed to internet" -ForegroundColor Yellow
Write-Host "  ⚠ For production: .\start_c2_cloudflare.ps1" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Panel URL : http://127.0.0.1:$Port/" -ForegroundColor Cyan
Write-Host "  Auth Token: $Token" -ForegroundColor Yellow
Write-Host "  C2 Port   : $Port" -ForegroundColor White
Write-Host ""
Write-Host "  Ctrl+C to stop" -ForegroundColor Gray
Write-Host ""

Set-Location $c2dir
go run ./cmd --port $Port --no-tls --token $Token
