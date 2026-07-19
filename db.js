const Database = require('better-sqlite3');
const path = require('path');

const DB_PATH = process.env.DB_PATH || './kp-auth.db';
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─── Schema ──────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    name        TEXT NOT NULL,
    avatar_url  TEXT,
    verified    INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS email_verifications (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used        INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS oauth_clients (
    id            TEXT PRIMARY KEY,
    client_id     TEXT UNIQUE NOT NULL,
    client_secret TEXT NOT NULL,
    name          TEXT NOT NULL,
    description   TEXT,
    redirect_uris TEXT NOT NULL,
    scopes        TEXT DEFAULT 'openid email profile',
    logo_url      TEXT,
    created_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS auth_codes (
    code          TEXT PRIMARY KEY,
    client_id     TEXT NOT NULL,
    user_id       TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    code_challenge      TEXT,
    code_challenge_method TEXT,
    expires_at    TEXT NOT NULL,
    used          INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    scopes      TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked     INTEGER DEFAULT 0,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// ─── Helpers ─────────────────────────────────────────────────────────────────

const User = {
  create: db.prepare(`
    INSERT INTO users (id, email, password, name) VALUES (?, ?, ?, ?)
  `),
  findByEmail: db.prepare(`SELECT * FROM users WHERE email = ?`),
  findById: db.prepare(`SELECT * FROM users WHERE id = ?`),
  verify: db.prepare(`UPDATE users SET verified = 1, updated_at = datetime('now') WHERE id = ?`),
  update: db.prepare(`UPDATE users SET name = ?, updated_at = datetime('now') WHERE id = ?`),
};

const EmailVerification = {
  create: db.prepare(`
    INSERT INTO email_verifications (token, user_id, expires_at) VALUES (?, ?, ?)
  `),
  findByToken: db.prepare(`SELECT * FROM email_verifications WHERE token = ? AND used = 0`),
  markUsed: db.prepare(`UPDATE email_verifications SET used = 1 WHERE token = ?`),
  deleteExpired: db.prepare(`DELETE FROM email_verifications WHERE expires_at < datetime('now')`),
};

const OAuthClient = {
  create: db.prepare(`
    INSERT INTO oauth_clients (id, client_id, client_secret, name, description, redirect_uris, scopes, logo_url)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `),
  findByClientId: db.prepare(`SELECT * FROM oauth_clients WHERE client_id = ?`),
  findAll: db.prepare(`SELECT id, client_id, name, description, redirect_uris, scopes, logo_url, created_at FROM oauth_clients`),
  delete: db.prepare(`DELETE FROM oauth_clients WHERE client_id = ?`),
};

const AuthCode = {
  create: db.prepare(`
    INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `),
  findByCode: db.prepare(`SELECT * FROM auth_codes WHERE code = ? AND used = 0`),
  markUsed: db.prepare(`UPDATE auth_codes SET used = 1 WHERE code = ?`),
  deleteExpired: db.prepare(`DELETE FROM auth_codes WHERE expires_at < datetime('now')`),
};

const RefreshToken = {
  create: db.prepare(`
    INSERT INTO refresh_tokens (token, user_id, client_id, scopes, expires_at)
    VALUES (?, ?, ?, ?, ?)
  `),
  find: db.prepare(`SELECT * FROM refresh_tokens WHERE token = ? AND revoked = 0`),
  revoke: db.prepare(`UPDATE refresh_tokens SET revoked = 1 WHERE token = ?`),
  revokeAllForUser: db.prepare(`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND client_id = ?`),
  deleteExpired: db.prepare(`DELETE FROM refresh_tokens WHERE expires_at < datetime('now')`),
};

const Session = {
  create: db.prepare(`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`),
  find: db.prepare(`SELECT * FROM sessions WHERE id = ? AND expires_at > datetime('now')`),
  delete: db.prepare(`DELETE FROM sessions WHERE id = ?`),
  deleteExpired: db.prepare(`DELETE FROM sessions WHERE expires_at < datetime('now')`),
};

// Cleanup job — runs every hour
setInterval(() => {
  try {
    AuthCode.deleteExpired.run();
    RefreshToken.deleteExpired.run();
    Session.deleteExpired.run();
    EmailVerification.deleteExpired.run();
  } catch (e) {
    console.error('[DB Cleanup]', e.message);
  }
}, 60 * 60 * 1000);

module.exports = { db, User, EmailVerification, OAuthClient, AuthCode, RefreshToken, Session };
