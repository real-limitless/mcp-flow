/**
 * 0022_project_secret_scope (issue #74).
 * Opt-in per-key flag secrets_project_write (default off), registered env targets,
 * single-use upload tickets (token hash only, never a secret value), and
 * PRODUCTION bind approvals (refs only).
 * DOWN refuses while a target, ticket, approval, or granted flag remains.
 */
import { idCheck, idCheckNullable, NOW } from "./sql-helpers.js";

export const MIGRATION_0022 = `
ALTER TABLE mcpflow_api_key ADD COLUMN secrets_project_write INTEGER NOT NULL DEFAULT 0
  CHECK (secrets_project_write IN (0,1));

CREATE TABLE mcpflow_project_env_target (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "etg_")}),
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  project_id TEXT NOT NULL CHECK (
    length(project_id) BETWEEN 1 AND 128 AND project_id NOT GLOB '*[^a-z0-9_-]*'
  ),
  backend_slug TEXT NOT NULL CHECK (length(backend_slug) BETWEEN 1 AND 64),
  compose_id TEXT NOT NULL CHECK (length(compose_id) BETWEEN 1 AND 128),
  tier TEXT NOT NULL CHECK (tier IN ('DEVELOPMENT','PRODUCTION')),
  created_by_key TEXT CHECK (${idCheckNullable("created_by_key", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL DEFAULT (${NOW}),
  revoked_at TEXT,
  UNIQUE (workspace_id, project_id, backend_slug, compose_id)
) STRICT;

CREATE TABLE mcpflow_secret_upload (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "upl_")}),
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  project_id TEXT NOT NULL CHECK (
    length(project_id) BETWEEN 1 AND 128 AND project_id NOT GLOB '*[^a-z0-9_-]*'
  ),
  name TEXT NOT NULL CHECK (name NOT GLOB '*[^a-z0-9_-]*' AND length(name) BETWEEN 1 AND 128),
  description TEXT CHECK (description IS NULL OR length(description) <= 512),
  token_hash TEXT NOT NULL CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
  created_by_key TEXT NOT NULL CHECK (${idCheck("created_by_key", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  created_by_agent TEXT NOT NULL CHECK (${idCheck("created_by_agent", "agt_")})
    REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL DEFAULT (${NOW}),
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  secret_id TEXT CHECK (${idCheckNullable("secret_id", "sec_")})
) STRICT;

CREATE INDEX mcpflow_secret_upload_pending
  ON mcpflow_secret_upload (workspace_id, project_id)
  WHERE consumed_at IS NULL;

CREATE TABLE mcpflow_project_secret_approval (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "psa_")}),
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  project_id TEXT NOT NULL CHECK (
    length(project_id) BETWEEN 1 AND 128 AND project_id NOT GLOB '*[^a-z0-9_-]*'
  ),
  key_id TEXT NOT NULL CHECK (${idCheck("key_id", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  agent_id TEXT NOT NULL CHECK (${idCheck("agent_id", "agt_")})
    REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  backend_slug TEXT NOT NULL CHECK (length(backend_slug) BETWEEN 1 AND 64),
  compose_id TEXT NOT NULL CHECK (length(compose_id) BETWEEN 1 AND 128),
  env_key TEXT NOT NULL CHECK (length(env_key) BETWEEN 1 AND 128),
  action TEXT NOT NULL CHECK (action IN ('set','unset','resync')),
  ref TEXT NOT NULL CHECK (
    (action = 'unset' AND ref = '')
    OR (action <> 'unset' AND length(ref) BETWEEN 10 AND 300 AND substr(ref, 1, 9) = 'secret://')
  ),
  version INTEGER NOT NULL CHECK (version >= 0),
  private INTEGER NOT NULL DEFAULT 0 CHECK (private IN (0,1)),
  state TEXT NOT NULL CHECK (state IN ('pending','approved','denied','expired')),
  created_at TEXT NOT NULL DEFAULT (${NOW}),
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by_key TEXT CHECK (${idCheckNullable("decided_by_key", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT
) STRICT;
`;

export const MIGRATION_0022_DOWN = `
CREATE TEMP TABLE mcpflow_0022_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0022_down_guard (n)
  SELECT
    (SELECT count(*) FROM mcpflow_project_env_target)
    + (SELECT count(*) FROM mcpflow_secret_upload)
    + (SELECT count(*) FROM mcpflow_project_secret_approval)
    + (SELECT count(*) FROM mcpflow_api_key WHERE secrets_project_write <> 0);
DROP TABLE mcpflow_project_secret_approval;
DROP TABLE mcpflow_secret_upload;
DROP TABLE mcpflow_project_env_target;
ALTER TABLE mcpflow_api_key DROP COLUMN secrets_project_write;
DROP TABLE mcpflow_0022_down_guard;
`;
