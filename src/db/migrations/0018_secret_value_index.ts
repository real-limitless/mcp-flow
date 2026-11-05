/**
 * 0018_secret_value_index (Secrets B, §4).
 * Cross-call echo index. B stores the table; dispatch does not read it.
 * DOWN refuses while any row exists.
 */
import { idCheck, NOW } from "./sql-helpers.js";

export const MIGRATION_0018 = `
CREATE TABLE mcpflow_secret_value_index (
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")}),
  target_key TEXT NOT NULL CHECK (length(target_key) BETWEEN 1 AND 256),
  form TEXT NOT NULL CHECK (form IN ('raw','json','b64','b64url','url')),
  value_hmac TEXT NOT NULL CHECK (length(value_hmac) = 64 AND value_hmac NOT GLOB '*[^0-9a-f]*'),
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  first_seen TEXT NOT NULL DEFAULT (${NOW}),
  PRIMARY KEY (workspace_id, target_key, form, value_hmac),
  FOREIGN KEY (secret_id, version) REFERENCES mcpflow_secret_version(secret_id, version) ON DELETE RESTRICT
) STRICT;
`;

export const MIGRATION_0018_DOWN = `
CREATE TEMP TABLE mcpflow_0018_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0018_down_guard (n) SELECT count(*) FROM mcpflow_secret_value_index;
DROP TABLE mcpflow_secret_value_index;
DROP TABLE mcpflow_0018_down_guard;
`;
