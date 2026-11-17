/**
 * Portal login: Google OIDC users, TOTP, bootstrap sessions, and the
 * platform-logins cutover that retires MCP_FLOW_ADMIN_TOKEN.
 * workspaces.disabled_at is added in after(), only when that table exists
 * (Store creates it; a migrations-only database does not).
 */
import type { DatabaseSync } from "node:sqlite";
import { idCheck, idCheckNullable } from "./sql-helpers.js";

export const MIGRATION_0025 = `
CREATE TABLE portal_google (
  id TEXT PRIMARY KEY CHECK (id = 'google'),
  client_id TEXT NOT NULL CHECK (length(client_id) BETWEEN 1 AND 256),
  client_secret_enc TEXT NOT NULL,
  hosted_domain TEXT CHECK (hosted_domain IS NULL OR length(hosted_domain) BETWEEN 1 AND 253),
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE portal_user (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "pu_")}),
  email TEXT NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254),
  google_sub TEXT UNIQUE CHECK (google_sub IS NULL OR length(google_sub) BETWEEN 1 AND 255),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
  platform_admin INTEGER NOT NULL DEFAULT 0 CHECK (platform_admin IN (0, 1)),
  mfa_completed_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE portal_membership (
  user_id TEXT NOT NULL REFERENCES portal_user(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin' CHECK (role = 'admin'),
  PRIMARY KEY (user_id, workspace_id)
) STRICT;

CREATE TABLE portal_session (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "ps_")}),
  token_hash TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('bootstrap', 'user')),
  workspace_id TEXT,
  user_id TEXT REFERENCES portal_user(id) ON DELETE CASCADE,
  agent_id TEXT CHECK (${idCheckNullable("agent_id", "agt_")}),
  mfa_ok INTEGER NOT NULL DEFAULT 0 CHECK (mfa_ok IN (0, 1)),
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL,
  CHECK (kind = 'bootstrap' OR user_id IS NOT NULL)
) STRICT;

CREATE INDEX idx_portal_session_user ON portal_session(user_id);

CREATE TABLE portal_login_mfa (
  user_id TEXT PRIMARY KEY REFERENCES portal_user(id) ON DELETE CASCADE,
  secret_enc TEXT NOT NULL,
  enrolled_at TEXT,
  updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE portal_platform (
  id TEXT PRIMARY KEY CHECK (id = 'platform'),
  enabled_at TEXT
) STRICT;

CREATE TABLE portal_oauth_state (
  state_hash TEXT PRIMARY KEY,
  nonce_hash TEXT NOT NULL,
  pkce_verifier_enc TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
) STRICT;
`;

export function applyWorkspaceDisabledAt(db: DatabaseSync): void {
  const table = db
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'workspaces'`)
    .get() as { name: string } | undefined;
  if (!table) return;
  const cols = db.prepare(`PRAGMA table_info(workspaces)`).all() as Array<{ name: string }>;
  if (cols.some((c) => c.name === "disabled_at")) return;
  db.exec(`ALTER TABLE workspaces ADD COLUMN disabled_at TEXT`);
}
