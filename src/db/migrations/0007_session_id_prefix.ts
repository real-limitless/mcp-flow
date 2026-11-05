/**
 * 0007 (Security T2.5 Re-review 2):
 * - I-3: session ids get the prefix `sess_` so they can't be confused with `mf_sess_` bearer tokens.
 *   Existing `mf_sess_` ids stay valid (sessions are short-lived); new ids use `sess_`.
 *   SQLite can't alter a CHECK, so mcpflow_session is rebuilt (create new, copy, drop, rename),
 *   with its indexes, triggers, the resolvable view, and the triggers on other tables that touch it.
 * - Fix (never shipped, fixed in place): DROP TABLE on a table still referenced by
 *   mcpflow_pending_call.session_id leaves deferred FK violations that the later RENAME does not
 *   clear, so COMMIT failed whenever a pending_call row had session_id set. The references are
 *   detached first (snapshot trigger dropped for the duration, recreated verbatim from 0003),
 *   the table is swapped, and the references are restored.
 */
export const MIGRATION_0007 = `
PRAGMA defer_foreign_keys = ON;

-- detach pending_call.session_id refs (the 0003 snapshot trigger forbids touching session_id)
DROP TRIGGER mcpflow_pending_call_snapshot;
CREATE TEMP TABLE mcpflow_tmp_session_ref AS
  SELECT id, session_id FROM mcpflow_pending_call WHERE session_id IS NOT NULL;
UPDATE mcpflow_pending_call SET session_id = NULL WHERE session_id IS NOT NULL;

DROP VIEW mcpflow_resolvable_session;
DROP TRIGGER mcpflow_api_key_revoke_sessions;
DROP TRIGGER mcpflow_agent_revoke_sessions;

CREATE TABLE mcpflow_session_new (
  id          TEXT PRIMARY KEY CHECK (substr(id, 1, 5) = 'sess_' OR substr(id, 1, 8) = 'mf_sess_'),
  token_hash  TEXT NOT NULL UNIQUE,
  agent_id    TEXT NOT NULL REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  key_id      TEXT NOT NULL REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  project_id  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at  TEXT NOT NULL,
  revoked_at  TEXT,
  CHECK (expires_at > created_at)
) STRICT;
INSERT INTO mcpflow_session_new (id, token_hash, agent_id, key_id, project_id, created_at, expires_at, revoked_at)
  SELECT id, token_hash, agent_id, key_id, project_id, created_at, expires_at, revoked_at FROM mcpflow_session;
DROP TABLE mcpflow_session;
ALTER TABLE mcpflow_session_new RENAME TO mcpflow_session;

-- re-attach the refs, then restore the 0003 snapshot trigger verbatim
UPDATE mcpflow_pending_call
   SET session_id = (SELECT session_id FROM temp.mcpflow_tmp_session_ref r WHERE r.id = mcpflow_pending_call.id)
 WHERE id IN (SELECT id FROM temp.mcpflow_tmp_session_ref);
DROP TABLE temp.mcpflow_tmp_session_ref;

CREATE TRIGGER mcpflow_pending_call_snapshot BEFORE UPDATE ON mcpflow_pending_call
WHEN NEW.id IS NOT OLD.id OR NEW.call_id IS NOT OLD.call_id OR NEW.workspace_id IS NOT OLD.workspace_id
  OR NEW.agent_id IS NOT OLD.agent_id OR NEW.key_id IS NOT OLD.key_id
  OR NEW.session_id IS NOT OLD.session_id OR NEW.project_id IS NOT OLD.project_id
  OR NEW.backend_slug IS NOT OLD.backend_slug OR NEW.tool IS NOT OLD.tool
  OR NEW.qualified_tool IS NOT OLD.qualified_tool OR NEW.args_hash IS NOT OLD.args_hash
  OR NEW.args_redacted IS NOT OLD.args_redacted OR NEW.args_key_ref IS NOT OLD.args_key_ref
  OR NEW.matched_rules IS NOT OLD.matched_rules OR NEW.approvers IS NOT OLD.approvers
  OR NEW.created_at IS NOT OLD.created_at OR NEW.expires_at IS NOT OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'pending_call snapshot is immutable'); END;

CREATE INDEX mcpflow_session_key_live   ON mcpflow_session(key_id)   WHERE revoked_at IS NULL;
CREATE INDEX mcpflow_session_agent_live ON mcpflow_session(agent_id) WHERE revoked_at IS NULL;

CREATE TRIGGER mcpflow_session_ins_owner BEFORE INSERT ON mcpflow_session
WHEN (SELECT agent_id FROM mcpflow_api_key WHERE id = NEW.key_id) IS NOT NEW.agent_id
BEGIN SELECT RAISE(ABORT, 'session agent must own key'); END;

CREATE TRIGGER mcpflow_session_ins_clamp AFTER INSERT ON mcpflow_session
WHEN NEW.expires_at > (SELECT expires_at FROM mcpflow_api_key WHERE id = NEW.key_id)
BEGIN
  UPDATE mcpflow_session SET expires_at = (SELECT expires_at FROM mcpflow_api_key WHERE id = NEW.key_id)
   WHERE id = NEW.id;
END;

CREATE TRIGGER mcpflow_session_upd_guard BEFORE UPDATE ON mcpflow_session
WHEN NEW.id IS NOT OLD.id OR NEW.token_hash IS NOT OLD.token_hash
  OR NEW.agent_id IS NOT OLD.agent_id OR NEW.key_id IS NOT OLD.key_id
  OR NEW.project_id IS NOT OLD.project_id
  OR NEW.expires_at > OLD.expires_at
  OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN SELECT RAISE(ABORT, 'session identity immutable; expiry shorten-only; revoke terminal'); END;

CREATE TRIGGER mcpflow_epoch_session_upd AFTER UPDATE OF revoked_at ON mcpflow_session
BEGIN UPDATE mcpflow_identity_epoch SET epoch = epoch + 1 WHERE id = 1; END;

CREATE TRIGGER mcpflow_api_key_revoke_sessions AFTER UPDATE OF status ON mcpflow_api_key
WHEN NEW.status = 'revoked' AND OLD.status <> 'revoked'
BEGIN
  UPDATE mcpflow_session SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE key_id = NEW.id AND revoked_at IS NULL;
END;

CREATE TRIGGER mcpflow_agent_revoke_sessions AFTER UPDATE OF status ON mcpflow_agent
WHEN NEW.status IN ('revoked','suspended') AND OLD.status = 'active'
BEGIN
  UPDATE mcpflow_session SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE agent_id = NEW.id AND revoked_at IS NULL;
END;

CREATE VIEW mcpflow_resolvable_session AS
SELECT s.id AS session_id, s.token_hash, s.project_id, s.expires_at, s.agent_id, s.key_id
  FROM mcpflow_session s
  JOIN mcpflow_api_key k ON k.id = s.key_id
  JOIN mcpflow_agent a ON a.id = s.agent_id
 WHERE s.revoked_at IS NULL AND strftime('%Y-%m-%dT%H:%M:%fZ','now') < s.expires_at
   AND k.status IN ('active','rotating') AND strftime('%Y-%m-%dT%H:%M:%fZ','now') < k.expires_at AND a.status = 'active';
`;
