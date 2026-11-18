import sqlite3
from flask import g, current_app

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    email           TEXT    NOT NULL UNIQUE,
    phone           TEXT,
    password_hash   TEXT    NOT NULL,
    email_verified  INTEGER NOT NULL DEFAULT 0,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL,
    last_login_at   INTEGER
);

CREATE TABLE IF NOT EXISTS otps (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     TEXT    NOT NULL,
    code_hash   TEXT    NOT NULL,
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0,
    ip           TEXT,
    user_agent   TEXT
);

CREATE TABLE IF NOT EXISTS credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    doc_type      TEXT    NOT NULL,
    holder_name   TEXT    NOT NULL,
    number_hash   TEXT    NOT NULL UNIQUE,
    number_last4  TEXT    NOT NULL,
    name_matches  INTEGER NOT NULL DEFAULT 0,
    status        TEXT    NOT NULL DEFAULT 'verified',
    created_at    INTEGER NOT NULL,
    UNIQUE (user_id, doc_type)
);

CREATE TABLE IF NOT EXISTS settings (
    user_id          INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    privacy_switches TEXT NOT NULL,
    thresholds       TEXT NOT NULL,
    ai_model         TEXT NOT NULL,
    privacy_controls TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS qr_tokens (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked     INTEGER NOT NULL DEFAULT 0,
    scans       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS identity_accounts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id              INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service_name         TEXT    NOT NULL,
    service_type         TEXT    NOT NULL DEFAULT 'online', -- 'email', 'phone', 'online'
    domain               TEXT,
    identifier           TEXT    NOT NULL, -- email or phone used
    password_strength    INTEGER NOT NULL DEFAULT 60, -- 0-100 score
    password_reused      INTEGER NOT NULL DEFAULT 0, -- 0 or 1
    password_fingerprint TEXT,                      -- salted hash fingerprint (never plaintext)
    two_factor_enabled   INTEGER NOT NULL DEFAULT 0, -- 0 or 1
    breach_status        TEXT    NOT NULL DEFAULT 'safe', -- 'safe', 'review', 'breached'
    breach_count         INTEGER NOT NULL DEFAULT 0,
    last_breach_name     TEXT,
    last_checked_at      INTEGER NOT NULL,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_activity (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action_type TEXT    NOT NULL, -- 'add', 'fix', 'breach_found', 'recheck', 'delete'
    account_id  INTEGER,
    description TEXT    NOT NULL,
    created_at  INTEGER NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()
