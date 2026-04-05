-- Auth service schema.

-- ACL policy config (JSON, loaded into Casbin on startup)
CREATE TABLE IF NOT EXISTS acl_config (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  config_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Per-user credentials
CREATE TABLE IF NOT EXISTS user_credentials (
  email TEXT NOT NULL,
  service TEXT NOT NULL,
  credentials_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (email, service)
);

-- Service-level credentials (admin-managed)
CREATE TABLE IF NOT EXISTS service_credentials (
  service TEXT PRIMARY KEY,
  credentials_json TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- OAuth identity cache (WorkOS sub → email)
CREATE TABLE IF NOT EXISTS oauth_users (
  sub TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  resolved_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- MCP key runtime data (written by portal, read for /keys/validate)
CREATE TABLE IF NOT EXISTS mcp_keys (
  key_id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  name TEXT NOT NULL,
  created_by TEXT NOT NULL,
  project_id TEXT NOT NULL,
  credentials_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
