/**
 * 0017_secret_sink_grant (Secrets B, §4).
 * Sink and grant tables for later substitution. B does not write them.
 * DOWN refuses while either table holds a row.
 */
import { idCheck, idCheckNullable, jsonArrayCheck, NOW } from "./sql-helpers.js";

export const MIGRATION_0017 = `
CREATE TABLE mcpflow_secret_sink (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "snk_")}),
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  backend_slug TEXT NOT NULL CHECK (length(backend_slug) BETWEEN 1 AND 64),
  tool TEXT NOT NULL CHECK (length(tool) BETWEEN 1 AND 128),
  field_path TEXT NOT NULL CHECK (length(field_path) BETWEEN 1 AND 256),
  target_field TEXT NOT NULL CHECK (length(target_field) BETWEEN 1 AND 128),
  targets_json TEXT NOT NULL CHECK (${jsonArrayCheck("targets_json")}),
  encoding TEXT NOT NULL CHECK (encoding IN ('env-text','env-text-quoted','json','header','raw')),
  created_by_key TEXT CHECK (${idCheckNullable("created_by_key", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL DEFAULT (${NOW})
) STRICT;

CREATE TABLE mcpflow_secret_grant (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "sgr_")}),
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  key_id TEXT CHECK (${idCheckNullable("key_id", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  agent_id TEXT CHECK (${idCheckNullable("agent_id", "agt_")})
    REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  ref_pattern TEXT NOT NULL CHECK (
    length(ref_pattern) BETWEEN 10 AND 300 AND substr(ref_pattern, 1, 9) = 'secret://'
  ),
  sink_id TEXT NOT NULL REFERENCES mcpflow_secret_sink(id) ON DELETE RESTRICT,
  require_approval INTEGER NOT NULL DEFAULT 0 CHECK (require_approval IN (0,1)),
  pin_version_at_approval INTEGER NOT NULL DEFAULT 1 CHECK (pin_version_at_approval IN (0,1)),
  created_by_key TEXT CHECK (${idCheckNullable("created_by_key", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL DEFAULT (${NOW}),
  revoked_at TEXT,
  CHECK ((key_id IS NULL) <> (agent_id IS NULL))
) STRICT;

CREATE INDEX mcpflow_secret_grant_sink ON mcpflow_secret_grant (sink_id);
`;

export const MIGRATION_0017_DOWN = `
CREATE TEMP TABLE mcpflow_0017_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0017_down_guard (n)
  SELECT (SELECT count(*) FROM mcpflow_secret_sink) + (SELECT count(*) FROM mcpflow_secret_grant);
DROP TABLE mcpflow_secret_grant;
DROP TABLE mcpflow_secret_sink;
DROP TABLE mcpflow_0017_down_guard;
`;
