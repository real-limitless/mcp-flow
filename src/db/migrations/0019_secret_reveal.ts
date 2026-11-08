/**
 * 0019_secret_reveal (Secrets B, §4).
 * Append-only reveal log and human-only key flags. Reveal and import APIs are later.
 * The agent kind-change guard is not in this migration.
 * DOWN refuses while a reveal row exists, then drops the flag columns.
 */
import { idCheck, idCheckNullable, NOW } from "./sql-helpers.js";

export const MIGRATION_0019 = `
CREATE TABLE mcpflow_reveal_event (
  id TEXT PRIMARY KEY CHECK (${idCheck("id", "rev_")}),
  ts TEXT NOT NULL DEFAULT (${NOW}),
  workspace_id TEXT NOT NULL CHECK (${idCheck("workspace_id", "ws_")})
    REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  secret_id TEXT NOT NULL,
  version INTEGER NOT NULL,
  actor_key TEXT CHECK (${idCheckNullable("actor_key", "key_")})
    REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  actor_agent TEXT CHECK (${idCheckNullable("actor_agent", "agt_")})
    REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  actor_kind TEXT NOT NULL CHECK (actor_kind IN ('reveal_key','master','admin_ui')),
  channel TEXT NOT NULL CHECK (channel IN ('mcp','rest','admin_ui')),
  reason TEXT,
  approval_id TEXT,
  approver_human TEXT,
  ip TEXT,
  delivery TEXT CHECK (delivery IS NULL OR delivery IN ('in_call','single_use_token')),
  alert_sent_at TEXT,
  alert_channel TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('revealed','denied','error')),
  FOREIGN KEY (secret_id, version) REFERENCES mcpflow_secret_version(secret_id, version) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER mcpflow_reveal_event_no_update BEFORE UPDATE ON mcpflow_reveal_event
BEGIN SELECT RAISE(ABORT, 'reveal_event is append-only'); END;

CREATE TRIGGER mcpflow_reveal_event_no_delete BEFORE DELETE ON mcpflow_reveal_event
BEGIN SELECT RAISE(ABORT, 'reveal_event is append-only'); END;

ALTER TABLE mcpflow_api_key ADD COLUMN can_reveal_secrets INTEGER NOT NULL DEFAULT 0
  CHECK (can_reveal_secrets IN (0,1));
ALTER TABLE mcpflow_api_key ADD COLUMN can_import_secrets INTEGER NOT NULL DEFAULT 0
  CHECK (can_import_secrets IN (0,1));
ALTER TABLE mcpflow_api_key ADD COLUMN reveal_requires_approval INTEGER NOT NULL DEFAULT 1
  CHECK (reveal_requires_approval IN (0,1));

CREATE TRIGGER mcpflow_api_key_secret_flags_ins BEFORE INSERT ON mcpflow_api_key
WHEN (NEW.can_import_secrets = 1 OR NEW.reveal_requires_approval = 0)
 AND (SELECT kind FROM mcpflow_agent WHERE id = NEW.agent_id) IS NOT 'human'
BEGIN SELECT RAISE(ABORT, 'human-only secret flags'); END;

CREATE TRIGGER mcpflow_api_key_secret_flags_upd
BEFORE UPDATE OF can_import_secrets, reveal_requires_approval ON mcpflow_api_key
WHEN (NEW.can_import_secrets = 1 OR NEW.reveal_requires_approval = 0)
 AND (SELECT kind FROM mcpflow_agent WHERE id = NEW.agent_id) IS NOT 'human'
BEGIN SELECT RAISE(ABORT, 'human-only secret flags'); END;
`;

export const MIGRATION_0019_DOWN = `
CREATE TEMP TABLE mcpflow_0019_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0019_down_guard (n) SELECT count(*) FROM mcpflow_reveal_event;
DROP TRIGGER mcpflow_api_key_secret_flags_ins;
DROP TRIGGER mcpflow_api_key_secret_flags_upd;
ALTER TABLE mcpflow_api_key DROP COLUMN reveal_requires_approval;
ALTER TABLE mcpflow_api_key DROP COLUMN can_import_secrets;
ALTER TABLE mcpflow_api_key DROP COLUMN can_reveal_secrets;
DROP TABLE mcpflow_reveal_event;
DROP TABLE mcpflow_0019_down_guard;
`;
