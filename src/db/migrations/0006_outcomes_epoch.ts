/**
 * Migration 0006 (Security T2.5 re-review R-1, L-5).
 *
 * R-1  mcpflow_call_outcome: durable, minimal per-call outcome for approval_pending (async) calls and
 *      for any call sent with an idempotency key, so "ran" / "never ran" / "unknown" survive restarts
 *      and expiry. Results are stored encrypted, size-capped, read once, then purged.
 *      mcpflow_pending_call.abandoned_at: an approved hold whose waiter died (gateway restart) is
 *      closed out: it can never be dispatched afterwards and its args ciphertext can be purged.
 * L-5  mcpflow_identity_epoch: a DB-side counter bumped by every identity change, so resolver caches
 *      in other processes drop stale entries on their next lookup.
 */
const NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

const bump = (name: string, on: string) => `
CREATE TRIGGER mcpflow_epoch_${name} AFTER ${on}
BEGIN UPDATE mcpflow_identity_epoch SET epoch = epoch + 1 WHERE id = 1; END;`;

export const MIGRATION_0006 = `
CREATE TABLE mcpflow_call_outcome (
  call_id           TEXT PRIMARY KEY,
  pending_call_id   TEXT REFERENCES mcpflow_pending_call(id) DEFERRABLE INITIALLY DEFERRED,
  workspace_id      TEXT NOT NULL,
  agent_id          TEXT NOT NULL REFERENCES mcpflow_agent(id),
  key_id            TEXT NOT NULL REFERENCES mcpflow_api_key(id),
  idempotency_key   TEXT CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 128),
  qualified_tool    TEXT,
  args_hash         TEXT NOT NULL,
  async             INTEGER NOT NULL DEFAULT 0 CHECK (async IN (0,1)),
  state             TEXT NOT NULL DEFAULT 'pending'
                    CHECK (state IN ('pending','executed','not_executed','unknown')),
  final_outcome     TEXT,
  result_status     TEXT,
  created_at        TEXT NOT NULL DEFAULT (${NOW}),
  completed_at      TEXT,
  result_ciphertext BLOB,
  result_bytes      INTEGER CHECK (result_bytes IS NULL OR result_bytes >= 0),
  result_truncated  INTEGER NOT NULL DEFAULT 0 CHECK (result_truncated IN (0,1)),
  result_read_at    TEXT,
  result_purged_at  TEXT,
  UNIQUE (agent_id, key_id, idempotency_key),
  CHECK (state = 'pending' OR completed_at IS NOT NULL)
) STRICT;
CREATE INDEX mcpflow_call_outcome_open ON mcpflow_call_outcome (state) WHERE state = 'pending';
CREATE INDEX mcpflow_call_outcome_results ON mcpflow_call_outcome (completed_at) WHERE result_ciphertext IS NOT NULL;

CREATE TRIGGER mcpflow_call_outcome_terminal BEFORE UPDATE OF state ON mcpflow_call_outcome
WHEN OLD.state <> 'pending' AND NEW.state IS NOT OLD.state
BEGIN SELECT RAISE(ABORT, 'call outcome is terminal'); END;

CREATE TRIGGER mcpflow_call_outcome_identity BEFORE UPDATE ON mcpflow_call_outcome
WHEN NEW.call_id IS NOT OLD.call_id OR NEW.agent_id IS NOT OLD.agent_id OR NEW.key_id IS NOT OLD.key_id
  OR NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.args_hash IS NOT OLD.args_hash
  OR NEW.pending_call_id IS NOT OLD.pending_call_id AND OLD.pending_call_id IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'call outcome identity is immutable'); END;

CREATE TRIGGER mcpflow_call_outcome_no_delete BEFORE DELETE ON mcpflow_call_outcome
BEGIN SELECT RAISE(ABORT, 'call outcomes are never deleted (results are purged instead)'); END;

ALTER TABLE mcpflow_pending_call ADD COLUMN abandoned_at TEXT;

CREATE TRIGGER mcpflow_pending_call_abandon BEFORE UPDATE OF abandoned_at ON mcpflow_pending_call
WHEN NEW.abandoned_at IS NOT OLD.abandoned_at AND (OLD.abandoned_at IS NOT NULL
  OR NOT (OLD.status = 'approved' AND OLD.dispatched_at IS NULL))
BEGIN SELECT RAISE(ABORT, 'only an approved, undispatched hold can be abandoned, once'); END;

CREATE TRIGGER mcpflow_pending_call_no_dispatch_abandoned BEFORE UPDATE OF dispatched_at ON mcpflow_pending_call
WHEN OLD.abandoned_at IS NOT NULL OR NEW.abandoned_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'hold was abandoned; it can never be dispatched'); END;

DROP TRIGGER mcpflow_pending_call_ciphertext;
CREATE TRIGGER mcpflow_pending_call_ciphertext BEFORE UPDATE ON mcpflow_pending_call
WHEN NEW.args_ciphertext IS NOT OLD.args_ciphertext
  AND (NEW.args_ciphertext IS NOT NULL OR NEW.status = 'pending'
       OR (NEW.status = 'approved' AND NEW.dispatched_at IS NULL AND NEW.abandoned_at IS NULL))
BEGIN SELECT RAISE(ABORT, 'args_ciphertext can only be purged after resolution/dispatch/abandon'); END;

CREATE TABLE mcpflow_identity_epoch (
  id    INTEGER PRIMARY KEY CHECK (id = 1),
  epoch INTEGER NOT NULL
) STRICT;
INSERT INTO mcpflow_identity_epoch (id, epoch) VALUES (1, 0);
${bump("agent_upd", "UPDATE OF status, is_admin, kind, revoked_at ON mcpflow_agent")}
${bump("key_upd", "UPDATE OF status, expires_at, revoked_at, valid_from ON mcpflow_api_key")}
${bump("agent_proj_ins", "INSERT ON mcpflow_agent_project")}
${bump("agent_proj_del", "DELETE ON mcpflow_agent_project")}
${bump("key_proj_ins", "INSERT ON mcpflow_api_key_project")}
${bump("key_proj_del", "DELETE ON mcpflow_api_key_project")}
${bump("session_upd", "UPDATE OF revoked_at ON mcpflow_session")}
`;
