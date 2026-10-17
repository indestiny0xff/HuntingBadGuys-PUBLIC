-- Hunting Bad Guys: PostgreSQL schema.
-- Applied automatically at startup (idempotent). Manual use:
--   psql "$HUNTER_DB_DSN" -f data/schema.sql

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    is_deleted      BOOLEAN DEFAULT FALSE,
    email           TEXT,
    auth_provider   TEXT NOT NULL DEFAULT 'local',
    sso_subject     TEXT,
    is_admin        BOOLEAN NOT NULL DEFAULT FALSE
);
-- Upgrades from 0.x: add the SSO columns to an existing users table.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email         TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_subject   TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin      BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ALTER COLUMN hashed_password SET DEFAULT '';
CREATE INDEX IF NOT EXISTS users_sso_subject_idx ON users(sso_subject);

CREATE TABLE IF NOT EXISTS api_keys (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_keys_user_id_idx ON api_keys(user_id);

CREATE TABLE IF NOT EXISTS results (
    id             TEXT PRIMARY KEY,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target         TEXT NOT NULL,
    is_private     BOOLEAN DEFAULT FALSE,
    has_screenshot BOOLEAN DEFAULT FALSE,
    scanned_at     TIMESTAMPTZ,
    kind           TEXT,
    data           JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS results_user_id_idx  ON results(user_id);
CREATE INDEX IF NOT EXISTS results_private_idx  ON results(is_private);
CREATE INDEX IF NOT EXISTS results_scanned_idx  ON results(scanned_at DESC);

CREATE TABLE IF NOT EXISTS screenshots (
    result_id TEXT PRIMARY KEY REFERENCES results(id) ON DELETE CASCADE,
    b64       TEXT NOT NULL,
    phash     TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS cases (
    id      TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data    JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS cases_user_id_idx ON cases(user_id);

CREATE TABLE IF NOT EXISTS folders (
    id      TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data    JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS folders_user_id_idx ON folders(user_id);

CREATE TABLE IF NOT EXISTS alert_rules (
    id      TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data    JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS alert_rules_user_id_idx ON alert_rules(user_id);

CREATE TABLE IF NOT EXISTS notifications (
    id      TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data    JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS notifications_user_id_idx ON notifications(user_id);

CREATE TABLE IF NOT EXISTS blog_posts (
    id            TEXT        PRIMARY KEY,
    slug          TEXT        NOT NULL UNIQUE,
    is_published  BOOLEAN     NOT NULL DEFAULT TRUE,
    published_at  TIMESTAMPTZ DEFAULT NOW(),
    data          JSONB       NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS blog_posts_pub ON blog_posts (is_published, published_at DESC);
