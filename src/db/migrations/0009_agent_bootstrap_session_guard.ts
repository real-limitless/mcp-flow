/**
 * 0009 (Database db-t1.2 §9/§10, SQLite delta; Database update 2026-10-18):
 * - Bootstrap: created_by IS NULL only for the bootstrap human admin, at most one per workspace;
 *   created_by is immutable and the bootstrap agent cannot be demoted.
 * - Sessions can only be minted for an active agent with a live key.
 * - New session ids must be sess_<24 hex>. Legacy mf_sess_ rows (allowed by the 0007 table CHECK)
 *   stay valid until they expire; they are NOT revoked here. Key/agent revoke and agent suspend
 *   still end them at once (0007 cascade triggers match on key_id / agent_id, not on the id prefix).
 * - token_hash / secret_hash must be a hash (sha256-pepper$v1$<64 hex> or $argon2id$...), never a token.
 *   Rows whose token_hash looks like a plaintext token are revoked (counted in mcpflow_migration_note).
 * Deviation from Database's SQL: the bootstrap unique index is per workspace_id instead of global,
 * because the branch supports several workspaces in one DB (each has its own bootstrap admin).
 */
export const MIGRATION_0009 = `
CREATE UNIQUE INDEX mcpflow_agent_one_bootstrap ON mcpflow_agent (workspace_id) WHERE created_by IS NULL;

CREATE TRIGGER mcpflow_agent_bootstrap_ins BEFORE INSERT ON mcpflow_agent
WHEN NEW.created_by IS NULL AND NOT (NEW.kind = 'human' AND NEW.is_admin = 1)
BEGIN SELECT RAISE(ABORT, 'only the bootstrap human admin may have created_by NULL'); END;

CREATE TRIGGER mcpflow_agent_bootstrap_upd BEFORE UPDATE ON mcpflow_agent
WHEN NEW.created_by IS NOT OLD.created_by
  OR (NEW.created_by IS NULL AND NOT (NEW.kind = 'human' AND NEW.is_admin = 1))
BEGIN SELECT RAISE(ABORT, 'created_by is immutable; bootstrap agent cannot be demoted'); END;

CREATE TRIGGER mcpflow_session_ins_live BEFORE INSERT ON mcpflow_session
WHEN NOT EXISTS (SELECT 1 FROM mcpflow_agent WHERE id = NEW.agent_id AND status = 'active')
  OR NOT EXISTS (SELECT 1 FROM mcpflow_api_key WHERE id = NEW.key_id
                  AND status IN ('active','rotating')
                  AND strftime('%Y-%m-%dT%H:%M:%fZ','now') < expires_at)
BEGIN SELECT RAISE(ABORT, 'session requires an active agent and a live key'); END;

CREATE TRIGGER mcpflow_session_ins_id BEFORE INSERT ON mcpflow_session
WHEN NOT (length(NEW.id) = 29 AND substr(NEW.id, 1, 5) = 'sess_' AND substr(NEW.id, 6) NOT GLOB '*[^0-9a-f]*')
BEGIN SELECT RAISE(ABORT, 'session id must be sess_<24 hex>'); END;

CREATE TRIGGER mcpflow_session_ins_token_hash BEFORE INSERT ON mcpflow_session
WHEN instr(NEW.token_hash, 'mf_') > 0
  OR NOT (  (substr(NEW.token_hash, 1, 17) = 'sha256-pepper$v1$' AND length(NEW.token_hash) = 81
             AND substr(NEW.token_hash, 18) NOT GLOB '*[^0-9a-f]*')
         OR substr(NEW.token_hash, 1, 10) = '$argon2id$')
BEGIN SELECT RAISE(ABORT, 'token_hash must be a hash (sha256-pepper$v1$<64 hex> or $argon2id$...), never the token'); END;

CREATE TRIGGER mcpflow_api_key_ins_secret_hash BEFORE INSERT ON mcpflow_api_key
WHEN instr(NEW.secret_hash, 'mf_') > 0
  OR NOT (  (substr(NEW.secret_hash, 1, 17) = 'sha256-pepper$v1$' AND length(NEW.secret_hash) = 81
             AND substr(NEW.secret_hash, 18) NOT GLOB '*[^0-9a-f]*')
         OR substr(NEW.secret_hash, 1, 10) = '$argon2id$')
BEGIN SELECT RAISE(ABORT, 'secret_hash must be a hash, never the key'); END;

INSERT INTO mcpflow_migration_note (migration_id, note)
SELECT '0009_agent_bootstrap_session_guard', json_object('bootstrap_violations', count(*))
  FROM mcpflow_agent WHERE created_by IS NULL AND NOT (kind = 'human' AND is_admin = 1)
HAVING count(*) > 0;
INSERT INTO mcpflow_migration_note (migration_id, note)
SELECT '0009_agent_bootstrap_session_guard', json_object('non_hash_token_rows_revoked', count(*))
  FROM mcpflow_session WHERE instr(token_hash, 'mf_') > 0 AND revoked_at IS NULL
HAVING count(*) > 0;
UPDATE mcpflow_session SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
 WHERE revoked_at IS NULL AND instr(token_hash, 'mf_') > 0;
`;

/** Manual/dev rollback only (the runner has no down path). Revoked plaintext-hash sessions stay revoked. */
export const MIGRATION_0009_DOWN = `
DROP TRIGGER mcpflow_api_key_ins_secret_hash;
DROP TRIGGER mcpflow_session_ins_token_hash;
DROP TRIGGER mcpflow_session_ins_id;
DROP TRIGGER mcpflow_session_ins_live;
DROP TRIGGER mcpflow_agent_bootstrap_upd;
DROP TRIGGER mcpflow_agent_bootstrap_ins;
DROP INDEX mcpflow_agent_one_bootstrap;
`;
