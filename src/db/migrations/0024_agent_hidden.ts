/**
 * 0024_agent_hidden.
 * A revoked bot can leave the portal: hidden_at plus a tombstone name frees the
 * display name. The agent row stays because sessions and calls reference it.
 * Session project_id may change so a project slug rename can retarget live sessions.
 * Other session columns stay immutable.
 */
export const MIGRATION_0024 = `
ALTER TABLE mcpflow_agent ADD COLUMN hidden_at TEXT;

DROP TRIGGER mcpflow_session_upd_guard;
CREATE TRIGGER mcpflow_session_upd_guard BEFORE UPDATE ON mcpflow_session
WHEN NEW.id IS NOT OLD.id OR NEW.token_hash IS NOT OLD.token_hash
  OR NEW.agent_id IS NOT OLD.agent_id OR NEW.key_id IS NOT OLD.key_id
  OR NEW.expires_at > OLD.expires_at
  OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN SELECT RAISE(ABORT, 'session identity immutable; expiry shorten-only; revoke terminal'); END;
`;

export const MIGRATION_0024_DOWN = `
CREATE TEMP TABLE mcpflow_0024_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0024_down_guard (n)
  SELECT count(*) FROM mcpflow_agent WHERE hidden_at IS NOT NULL;
DROP TRIGGER mcpflow_session_upd_guard;
CREATE TRIGGER mcpflow_session_upd_guard BEFORE UPDATE ON mcpflow_session
WHEN NEW.id IS NOT OLD.id OR NEW.token_hash IS NOT OLD.token_hash
  OR NEW.agent_id IS NOT OLD.agent_id OR NEW.key_id IS NOT OLD.key_id
  OR NEW.project_id IS NOT OLD.project_id
  OR NEW.expires_at > OLD.expires_at
  OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN SELECT RAISE(ABORT, 'session identity immutable; expiry shorten-only; revoke terminal'); END;
ALTER TABLE mcpflow_agent DROP COLUMN hidden_at;
DROP TABLE mcpflow_0024_down_guard;
`;
