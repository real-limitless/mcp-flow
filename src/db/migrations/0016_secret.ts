/**
 * 0016_secret (Secrets B, §4 / §0.8).
 * mcpflow_secret and mcpflow_secret_version. STRICT, idCheck sec_, FKs ON DELETE RESTRICT.
 * DOWN refuses while either table holds a row (ciphertext or not).
 * Do not edit 0001–0015.
 */
import { idCheck, idCheckNullable, NOW } from "./sql-helpers.js";

export const MIGRATION_0016 = `
CREATE TABLE mcpflow_secret (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "sec_")}),
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  project_id TEXT NOT NULL CHECK (
    length(project_id) BETWEEN 1 AND 128 AND project_id NOT GLOB '*[^a-z0-9_-]*'
  ),
  name TEXT NOT NULL CHECK (name NOT GLOB '*[^a-z0-9_-]*' AND length(name) BETWEEN 1 AND 128),
  type TEXT NOT NULL CHECK (type IN ('token','password','uuid','keypair','import')),
  imported INTEGER NOT NULL DEFAULT 0 CHECK (imported IN (0,1)),
  generator_json TEXT NOT NULL CHECK (json_valid(generator_json) AND length(generator_json) <= 8192),
  current_version INTEGER NOT NULL CHECK (current_version >= 1),
  description TEXT CHECK (description IS NULL OR length(description) <= 512),
  created_by_key TEXT CHECK (${idCheckNullable("created_by_key", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  created_by_agent TEXT CHECK (${idCheckNullable("created_by_agent", "agt_")})
    REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL DEFAULT (${NOW}),
  deleted_at TEXT,
  UNIQUE (workspace_id, project_id, name)
) STRICT;

CREATE TABLE mcpflow_secret_version (
  secret_id TEXT NOT NULL REFERENCES mcpflow_secret(id) ON DELETE RESTRICT,
  version INTEGER NOT NULL CHECK (version >= 1),
  state TEXT NOT NULL CHECK (state IN ('active','previous','disabled','destroyed')),
  ciphertext BLOB,
  wrapped_dek BLOB,
  kek_id TEXT NOT NULL CHECK (length(kek_id) BETWEEN 1 AND 128),
  value_hmac TEXT NOT NULL CHECK (length(value_hmac) = 64 AND value_hmac NOT GLOB '*[^0-9a-f]*'),
  public_part TEXT,
  created_at TEXT NOT NULL DEFAULT (${NOW}),
  created_by_key TEXT CHECK (${idCheckNullable("created_by_key", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  disabled_at TEXT,
  destroyed_at TEXT,
  PRIMARY KEY (secret_id, version),
  CHECK (
    (state = 'destroyed' AND ciphertext IS NULL AND wrapped_dek IS NULL AND destroyed_at IS NOT NULL)
    OR (state <> 'destroyed' AND ciphertext IS NOT NULL AND wrapped_dek IS NOT NULL)
  )
) STRICT;

CREATE INDEX mcpflow_secret_version_state ON mcpflow_secret_version (secret_id, state);

CREATE TRIGGER mcpflow_secret_version_one_active BEFORE INSERT ON mcpflow_secret_version
WHEN NEW.state = 'active' AND EXISTS (
  SELECT 1 FROM mcpflow_secret_version WHERE secret_id = NEW.secret_id AND state = 'active'
)
BEGIN SELECT RAISE(ABORT, 'secret already has an active version'); END;

CREATE TRIGGER mcpflow_secret_version_one_active_upd BEFORE UPDATE OF state ON mcpflow_secret_version
WHEN NEW.state = 'active' AND OLD.state <> 'active' AND EXISTS (
  SELECT 1 FROM mcpflow_secret_version
   WHERE secret_id = NEW.secret_id AND state = 'active' AND version <> NEW.version
)
BEGIN SELECT RAISE(ABORT, 'secret already has an active version'); END;
`;

export const MIGRATION_0016_DOWN = `
CREATE TEMP TABLE mcpflow_0016_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0016_down_guard (n)
  SELECT (SELECT count(*) FROM mcpflow_secret) + (SELECT count(*) FROM mcpflow_secret_version);
DROP TABLE mcpflow_secret_version;
DROP TABLE mcpflow_secret;
DROP TABLE mcpflow_0016_down_guard;
`;
