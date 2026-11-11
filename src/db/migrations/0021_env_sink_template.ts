/**
 * 0021_env_sink_template (Secrets phase C).
 * Template rows storing ref form only (never values) for resync.
 * DOWN refuses while rows exist.
 */
import { idCheck, NOW } from "./sql-helpers.js";

export const MIGRATION_0021 = `
CREATE TABLE mcpflow_env_template (
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  backend_slug TEXT NOT NULL CHECK (length(backend_slug) BETWEEN 1 AND 64),
  compose_id TEXT NOT NULL CHECK (length(compose_id) BETWEEN 1 AND 128),
  env_key TEXT NOT NULL CHECK (length(env_key) BETWEEN 1 AND 128),
  ref TEXT NOT NULL CHECK (length(ref) BETWEEN 10 AND 300 AND substr(ref, 1, 9) = 'secret://'),
  version INTEGER NOT NULL CHECK (version >= 1),
  updated_at TEXT NOT NULL DEFAULT (${NOW}),
  PRIMARY KEY (workspace_id, backend_slug, compose_id, env_key)
) STRICT;
`;

export const MIGRATION_0021_DOWN = `
CREATE TEMP TABLE mcpflow_0021_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0021_down_guard (n)
  SELECT count(*) FROM mcpflow_env_template;
DROP TABLE mcpflow_env_template;
DROP TABLE mcpflow_0021_down_guard;
`;
