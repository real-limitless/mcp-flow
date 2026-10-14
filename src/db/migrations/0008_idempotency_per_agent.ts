/**
 * 0008 (Security T2.5 Re-review 2, R2-1): idempotency keys are unique per AGENT, not per API key,
 * so a re-send on a rotated key replays instead of running again. The old (agent, key, idem)
 * UNIQUE stays; this one is strictly narrower.
 *
 * R3-4: before 0008 the same agent could legitimately use one idempotency key on two API keys.
 * Those duplicates are resolved here instead of failing the upgrade: per (agent_id, idempotency_key)
 * the EARLIEST row (created_at, then call_id) keeps the key, which is also the row a replay would
 * have used; later rows keep their outcome but lose the key (set to NULL). The identity trigger
 * forbids that update, so it is dropped and recreated (verbatim from 0006) inside this migration.
 * The number of de-keyed rows is recorded in mcpflow_migration_note.
 */
export const MIGRATION_0008 = `
CREATE TABLE IF NOT EXISTS mcpflow_migration_note (
  migration_id TEXT NOT NULL,
  note         TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
) STRICT;

INSERT INTO mcpflow_migration_note (migration_id, note)
SELECT '0008_idempotency_per_agent', json_object('dekeyed_duplicates', count(*))
  FROM mcpflow_call_outcome o
 WHERE o.idempotency_key IS NOT NULL
   AND EXISTS (SELECT 1 FROM mcpflow_call_outcome k
                WHERE k.agent_id = o.agent_id AND k.idempotency_key = o.idempotency_key
                  AND (k.created_at < o.created_at OR (k.created_at = o.created_at AND k.call_id < o.call_id)))
HAVING count(*) > 0;

DROP TRIGGER mcpflow_call_outcome_identity;

UPDATE mcpflow_call_outcome AS o SET idempotency_key = NULL
 WHERE o.idempotency_key IS NOT NULL
   AND EXISTS (SELECT 1 FROM mcpflow_call_outcome k
                WHERE k.agent_id = o.agent_id AND k.idempotency_key = o.idempotency_key
                  AND (k.created_at < o.created_at OR (k.created_at = o.created_at AND k.call_id < o.call_id)));

CREATE TRIGGER mcpflow_call_outcome_identity BEFORE UPDATE ON mcpflow_call_outcome
WHEN NEW.call_id IS NOT OLD.call_id OR NEW.agent_id IS NOT OLD.agent_id OR NEW.key_id IS NOT OLD.key_id
  OR NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.args_hash IS NOT OLD.args_hash
  OR NEW.pending_call_id IS NOT OLD.pending_call_id AND OLD.pending_call_id IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'call outcome identity is immutable'); END;

CREATE UNIQUE INDEX mcpflow_call_outcome_idem_agent
  ON mcpflow_call_outcome(agent_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
`;
