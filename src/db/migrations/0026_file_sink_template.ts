/**
 * 0026_file_sink_template (issue #90).
 * File-mount templates for the Dokploy compose file sink.
 * Authorization stays on mcpflow_secret_sink / mcpflow_secret_grant
 * (one grant per project, backend, and compose id). This table stores
 * the ref, path, mount id, and optional env key name. Never a value.
 * DOWN refuses while rows exist.
 */
import { idCheck, NOW } from "./sql-helpers.js";

export const MIGRATION_0026 = `
CREATE TABLE mcpflow_file_template (
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  backend_slug TEXT NOT NULL CHECK (length(backend_slug) BETWEEN 1 AND 64),
  compose_id TEXT NOT NULL CHECK (length(compose_id) BETWEEN 1 AND 128),
  mount_path TEXT NOT NULL CHECK (length(mount_path) BETWEEN 1 AND 256),
  mount_id TEXT NOT NULL CHECK (length(mount_id) BETWEEN 1 AND 128),
  ref TEXT NOT NULL CHECK (length(ref) BETWEEN 10 AND 300 AND substr(ref, 1, 9) = 'secret://'),
  version INTEGER NOT NULL CHECK (version >= 1),
  env_key TEXT CHECK (env_key IS NULL OR length(env_key) BETWEEN 1 AND 128),
  updated_at TEXT NOT NULL DEFAULT (${NOW}),
  PRIMARY KEY (workspace_id, backend_slug, compose_id, mount_path)
) STRICT;

CREATE INDEX mcpflow_file_template_ref
  ON mcpflow_file_template (workspace_id, ref);
`;

export const MIGRATION_0026_DOWN = `
CREATE TEMP TABLE mcpflow_0026_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0026_down_guard (n)
  SELECT count(*) FROM mcpflow_file_template;
DROP INDEX mcpflow_file_template_ref;
DROP TABLE mcpflow_file_template;
DROP TABLE mcpflow_0026_down_guard;
`;
