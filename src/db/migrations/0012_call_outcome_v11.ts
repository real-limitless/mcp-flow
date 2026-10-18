/**
 * 0012_call_outcome_v11 (Database db-t2.1-pending-result.md; Architecture T2.1 §11/§12).
 * mcpflow_call_outcome is the single result store: write-once, re-readable until result_expires_at
 * (24 h from result_stored_at) by the calling agent or an active human admin, purge-only (reason
 * expired | quota | legacy_read_once), read-once removed. Every read is a call_audit 'result_read' row.
 * call_audit is rebuilt (rows, audit_ids and the sqlite_sequence high-water mark kept; indexes and
 * triggers recreated verbatim) to allow the new event types.
 * Deviation from Database's SQL (flagged): event_type 'result_purge' is added as well, because §12
 * requires a call_audit event for every purge and a purge has no agt_ actor (lifecycle needs one).
 * DOWN maps result_read and result_purge rows to lifecycle rows (lifecycle_action = the old type;
 * purge rows get actor = owner agent), so no audit row is lost.
 */
export const MIGRATION_0012 = `
-- 0012_call_outcome_v11 (T2.1 §11): call_outcome is the single result store; re-readable 24 h; reads audited

-- (1) call_audit gains event_type 'result_read' (SQLite can't alter a CHECK: rebuild, rows/ids/sequence preserved)
DROP TRIGGER mcpflow_call_audit_approver_human;
DROP TRIGGER mcpflow_call_audit_no_self_approval;
DROP TRIGGER mcpflow_call_audit_no_update;
DROP TRIGGER mcpflow_call_audit_no_delete;
CREATE TABLE mcpflow_call_audit_new (
  audit_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  event_type       TEXT NOT NULL CHECK (event_type IN ('decision','completion','lifecycle','result_read','result_purge')),
  call_id          TEXT NOT NULL,
  workspace_id     TEXT,
  agent_id         TEXT,
  agent_name       TEXT,
  key_id           TEXT,
  key_prefix       TEXT,
  project_id       TEXT,
  backend_slug     TEXT,
  tool             TEXT,
  qualified_tool   TEXT,
  placement        TEXT,
  device_id        TEXT,
  args_redacted    TEXT CHECK (args_redacted IS NULL OR json_valid(args_redacted)),
  args_hash        TEXT,
  policy_decision  TEXT CHECK (policy_decision IN ('allow','deny','require_approval')),
  final_outcome    TEXT CHECK (final_outcome IN
                     ('executed','denied','approval_denied','approval_expired','cancelled','error')),
  rule_id          TEXT,
  matched_rule_ids TEXT CHECK (matched_rule_ids IS NULL OR (json_valid(matched_rule_ids) AND json_type(matched_rule_ids) = 'array')),
  pending_call_id  TEXT,
  approver         TEXT CHECK (approver IS NULL OR (length(approver) = 28 AND substr(approver, 1, 4) = 'agt_' AND substr(approver, 5) NOT GLOB '*[^0-9a-f]*')),
  approver_note    TEXT,
  latency_ms       INTEGER CHECK (latency_ms >= 0),
  backend_latency_ms INTEGER CHECK (backend_latency_ms >= 0),
  result_status    TEXT CHECK (result_status IN ('ok','error','not_dispatched','timeout')),
  error_code       TEXT,
  lifecycle_action TEXT,
  actor            TEXT CHECK (actor IS NULL OR (length(actor) = 28 AND substr(actor, 1, 4) = 'agt_' AND substr(actor, 5) NOT GLOB '*[^0-9a-f]*')),
  rule_version     INTEGER,
  grant_id         TEXT CHECK (grant_id IS NULL OR (length(grant_id) = 28 AND substr(grant_id, 1, 4) = 'grt_' AND substr(grant_id, 5) NOT GLOB '*[^0-9a-f]*')),
  CHECK (event_type <> 'decision'   OR policy_decision IS NOT NULL OR error_code IS 'unauthenticated'),
  CHECK (event_type <> 'completion' OR (final_outcome IS NOT NULL AND result_status IS NOT NULL)),
  CHECK (event_type <> 'lifecycle'  OR (lifecycle_action IS NOT NULL AND actor IS NOT NULL)),
  CHECK (event_type <> 'result_read' OR (actor IS NOT NULL AND agent_id IS NOT NULL
         AND policy_decision IS NULL AND final_outcome IS NULL AND lifecycle_action IS NULL)),
  CHECK (event_type <> 'result_purge' OR (agent_id IS NOT NULL AND error_code IN ('purged:expired','purged:quota')
         AND policy_decision IS NULL AND final_outcome IS NULL AND lifecycle_action IS NULL)),
  CHECK (final_outcome IS NULL OR final_outcome NOT IN ('approval_denied') OR approver IS NOT NULL),
  CHECK (final_outcome IS NULL OR final_outcome = 'executed' OR final_outcome = 'error'
         OR result_status = 'not_dispatched')
) STRICT;
INSERT INTO mcpflow_call_audit_new (audit_id, ts, event_type, call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id, backend_slug, tool, qualified_tool, placement, device_id, args_redacted, args_hash, policy_decision, final_outcome, rule_id, matched_rule_ids, pending_call_id, approver, approver_note, latency_ms, backend_latency_ms, result_status, error_code, lifecycle_action, actor, rule_version, grant_id)
SELECT audit_id, ts, event_type, call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id, backend_slug, tool, qualified_tool, placement, device_id, args_redacted, args_hash, policy_decision, final_outcome, rule_id, matched_rule_ids, pending_call_id, approver, approver_note, latency_ms, backend_latency_ms, result_status, error_code, lifecycle_action, actor, rule_version, grant_id FROM mcpflow_call_audit ORDER BY audit_id;
-- keep the AUTOINCREMENT high-water mark (ids freed by retention are never reused)
DELETE FROM sqlite_sequence WHERE name = 'mcpflow_call_audit_new';
INSERT INTO sqlite_sequence (name, seq)
  SELECT 'mcpflow_call_audit_new', seq FROM sqlite_sequence WHERE name = 'mcpflow_call_audit';
DROP TABLE mcpflow_call_audit;          -- DROP TABLE fires no DELETE triggers; ours are already dropped
ALTER TABLE mcpflow_call_audit_new RENAME TO mcpflow_call_audit;
CREATE INDEX mcpflow_call_audit_ts         ON mcpflow_call_audit (ts);
CREATE INDEX mcpflow_call_audit_agent_ts   ON mcpflow_call_audit (agent_id, ts DESC);
CREATE INDEX mcpflow_call_audit_key_ts     ON mcpflow_call_audit (key_id, ts DESC);
CREATE INDEX mcpflow_call_audit_proj_tool  ON mcpflow_call_audit (project_id, backend_slug, tool, ts DESC);
CREATE INDEX mcpflow_call_audit_pending    ON mcpflow_call_audit (pending_call_id) WHERE pending_call_id IS NOT NULL;
CREATE INDEX mcpflow_call_audit_policy_ts  ON mcpflow_call_audit (policy_decision, ts DESC)
  WHERE policy_decision IN ('deny','require_approval');
CREATE INDEX mcpflow_call_audit_outcome_ts ON mcpflow_call_audit (final_outcome, ts DESC)
  WHERE final_outcome IS NOT NULL AND final_outcome <> 'executed';
CREATE INDEX mcpflow_call_audit_call_id    ON mcpflow_call_audit (call_id);
CREATE INDEX mcpflow_call_audit_rule  ON mcpflow_call_audit (rule_id, rule_version) WHERE rule_id IS NOT NULL;
CREATE INDEX mcpflow_call_audit_grant ON mcpflow_call_audit (grant_id) WHERE grant_id IS NOT NULL;
CREATE TRIGGER mcpflow_call_audit_approver_human BEFORE INSERT ON mcpflow_call_audit
WHEN NEW.approver IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM mcpflow_agent WHERE id = NEW.approver AND kind = 'human')
BEGIN SELECT RAISE(ABORT, 'approver is not a human agent'); END;

CREATE TRIGGER mcpflow_call_audit_no_self_approval BEFORE INSERT ON mcpflow_call_audit
WHEN NEW.approver IS NOT NULL AND NEW.approver = NEW.agent_id
BEGIN SELECT RAISE(ABORT, 'an agent cannot approve its own call'); END;

CREATE TRIGGER mcpflow_call_audit_no_update BEFORE UPDATE ON mcpflow_call_audit
BEGIN SELECT RAISE(ABORT, 'mcpflow_call_audit is append-only (UPDATE rejected)'); END;

CREATE TRIGGER mcpflow_call_audit_no_delete BEFORE DELETE ON mcpflow_call_audit
BEGIN SELECT RAISE(ABORT, 'mcpflow_call_audit is append-only (DELETE rejected)'); END;

-- (2) call_outcome: write-once result with its own 24 h expiry, purge-only, read-once removed
ALTER TABLE mcpflow_call_outcome ADD COLUMN result_stored_at TEXT;
ALTER TABLE mcpflow_call_outcome ADD COLUMN result_expires_at TEXT;
ALTER TABLE mcpflow_call_outcome ADD COLUMN result_purge_reason TEXT
  CHECK (result_purge_reason IS NULL OR result_purge_reason IN ('expired','quota','legacy_read_once'));

-- backfill rows written before v11 (TTL was 24 h from completed_at)
UPDATE mcpflow_call_outcome
   SET result_stored_at  = COALESCE(completed_at, created_at),
       result_expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', COALESCE(completed_at, created_at), '+24 hours')
 WHERE result_ciphertext IS NOT NULL;
UPDATE mcpflow_call_outcome
   SET result_purge_reason = CASE WHEN result_read_at IS NOT NULL THEN 'legacy_read_once' ELSE 'expired' END,
       result_purged_at = COALESCE(result_purged_at, result_read_at)
 WHERE result_ciphertext IS NULL AND (result_purged_at IS NOT NULL OR result_read_at IS NOT NULL);

CREATE INDEX mcpflow_call_outcome_result_expiry ON mcpflow_call_outcome (result_expires_at)
  WHERE result_ciphertext IS NOT NULL;

-- store: once, with a 24 h window, never after a purge
CREATE TRIGGER mcpflow_call_outcome_result_store BEFORE UPDATE OF result_ciphertext ON mcpflow_call_outcome
WHEN OLD.result_ciphertext IS NULL AND NEW.result_ciphertext IS NOT NULL AND (
     OLD.result_stored_at IS NOT NULL OR OLD.result_purged_at IS NOT NULL
  OR NEW.result_stored_at IS NULL OR NEW.result_expires_at IS NULL
  OR NEW.result_expires_at <= NEW.result_stored_at
  OR (julianday(NEW.result_expires_at) - julianday(NEW.result_stored_at)) * 86400.0 > 86400.001)
BEGIN SELECT RAISE(ABORT, 'result is write-once with result_stored_at and result_expires_at <= 24 h'); END;

-- write-once: stored result and its metadata never change; ciphertext only goes to NULL via purge
CREATE TRIGGER mcpflow_call_outcome_result_immutable BEFORE UPDATE ON mcpflow_call_outcome
WHEN (OLD.result_stored_at IS NOT NULL AND (
        NEW.result_stored_at IS NOT OLD.result_stored_at OR NEW.result_expires_at IS NOT OLD.result_expires_at
     OR NEW.result_bytes IS NOT OLD.result_bytes OR NEW.result_truncated IS NOT OLD.result_truncated
     OR (NEW.result_ciphertext IS NOT NULL AND NEW.result_ciphertext IS NOT OLD.result_ciphertext)))
  OR (OLD.result_purged_at IS NOT NULL AND (NEW.result_purged_at IS NOT OLD.result_purged_at
     OR NEW.result_purge_reason IS NOT OLD.result_purge_reason))
BEGIN SELECT RAISE(ABORT, 'stored result is write-once; purge is terminal'); END;

-- purge: only with a reason, and 'expired' only once the 24 h window has passed
CREATE TRIGGER mcpflow_call_outcome_result_purge BEFORE UPDATE OF result_ciphertext ON mcpflow_call_outcome
WHEN OLD.result_ciphertext IS NOT NULL AND NEW.result_ciphertext IS NULL AND (
     NEW.result_purged_at IS NULL OR NEW.result_purge_reason IS NULL
  OR NEW.result_purge_reason = 'legacy_read_once'
  OR (NEW.result_purge_reason = 'expired'
      AND strftime('%Y-%m-%dT%H:%M:%fZ','now') < OLD.result_expires_at))
BEGIN SELECT RAISE(ABORT, 'purge needs result_purged_at + reason; expired only after result_expires_at'); END;

-- read-once is gone: reads are recorded in call_audit (event_type result_read), not on this row
CREATE TRIGGER mcpflow_call_outcome_no_read_once BEFORE UPDATE OF result_read_at ON mcpflow_call_outcome
WHEN NEW.result_read_at IS NOT OLD.result_read_at
BEGIN SELECT RAISE(ABORT, 'read-once removed in v11: audit reads in mcpflow_call_audit instead'); END;
`;

/** Manual/dev rollback only. */
export const MIGRATION_0012_DOWN = `
-- 0012_call_outcome_v11 DOWN
DROP TRIGGER mcpflow_call_outcome_no_read_once;
DROP TRIGGER mcpflow_call_outcome_result_purge;
DROP TRIGGER mcpflow_call_outcome_result_immutable;
DROP TRIGGER mcpflow_call_outcome_result_store;
DROP INDEX mcpflow_call_outcome_result_expiry;
ALTER TABLE mcpflow_call_outcome DROP COLUMN result_purge_reason;
ALTER TABLE mcpflow_call_outcome DROP COLUMN result_expires_at;
ALTER TABLE mcpflow_call_outcome DROP COLUMN result_stored_at;

-- result_read rows survive as lifecycle rows (lifecycle_action='result_read', actor = reader): no audit row is lost
INSERT INTO mcpflow_migration_note (migration_id, note)
SELECT '0012_call_outcome_v11:down', json_object('result_read_rows_mapped_to_lifecycle', count(*))
  FROM mcpflow_call_audit WHERE event_type = 'result_read' HAVING count(*) > 0;
INSERT INTO mcpflow_migration_note (migration_id, note)
SELECT '0012_call_outcome_v11:down', json_object('result_purge_rows_mapped_to_lifecycle', count(*))
  FROM mcpflow_call_audit WHERE event_type = 'result_purge' HAVING count(*) > 0;
DROP TRIGGER mcpflow_call_audit_approver_human;
DROP TRIGGER mcpflow_call_audit_no_self_approval;
DROP TRIGGER mcpflow_call_audit_no_update;
DROP TRIGGER mcpflow_call_audit_no_delete;
-- exact pre-0012 definition (branch 0002 + 0003 ADD COLUMNs), so DOWN restores the schema text
CREATE TABLE mcpflow_call_audit_new (
  audit_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  event_type       TEXT NOT NULL CHECK (event_type IN ('decision','completion','lifecycle')),
  call_id          TEXT NOT NULL,
  workspace_id     TEXT,
  agent_id         TEXT,
  agent_name       TEXT,
  key_id           TEXT,
  key_prefix       TEXT,
  project_id       TEXT,
  backend_slug     TEXT,
  tool             TEXT,
  qualified_tool   TEXT,
  placement        TEXT,
  device_id        TEXT,
  args_redacted    TEXT CHECK (args_redacted IS NULL OR json_valid(args_redacted)),
  args_hash        TEXT,
  policy_decision  TEXT CHECK (policy_decision IN ('allow','deny','require_approval')),
  final_outcome    TEXT CHECK (final_outcome IN
                     ('executed','denied','approval_denied','approval_expired','cancelled','error')),
  rule_id          TEXT,
  matched_rule_ids TEXT CHECK (matched_rule_ids IS NULL OR (json_valid(matched_rule_ids) AND json_type(matched_rule_ids) = 'array')),
  pending_call_id  TEXT,
  approver         TEXT CHECK (approver IS NULL OR (length(approver) = 28 AND substr(approver, 1, 4) = 'agt_' AND substr(approver, 5) NOT GLOB '*[^0-9a-f]*')),
  approver_note    TEXT,
  latency_ms       INTEGER CHECK (latency_ms >= 0),
  backend_latency_ms INTEGER CHECK (backend_latency_ms >= 0),
  result_status    TEXT CHECK (result_status IN ('ok','error','not_dispatched','timeout')),
  error_code       TEXT,
  lifecycle_action TEXT,
  actor            TEXT CHECK (actor IS NULL OR (length(actor) = 28 AND substr(actor, 1, 4) = 'agt_' AND substr(actor, 5) NOT GLOB '*[^0-9a-f]*')), rule_version INTEGER, grant_id TEXT CHECK (grant_id IS NULL OR (length(grant_id) = 28 AND substr(grant_id, 1, 4) = 'grt_' AND substr(grant_id, 5) NOT GLOB '*[^0-9a-f]*')),
  -- reference uses error_code = 'unauthenticated'; IS makes a NULL error_code fail instead of passing (SQL NULL CHECK semantics)
  CHECK (event_type <> 'decision'   OR policy_decision IS NOT NULL OR error_code IS 'unauthenticated'),
  CHECK (event_type <> 'completion' OR (final_outcome IS NOT NULL AND result_status IS NOT NULL)),
  CHECK (event_type <> 'lifecycle'  OR (lifecycle_action IS NOT NULL AND actor IS NOT NULL)),
  CHECK (final_outcome IS NULL OR final_outcome NOT IN ('approval_denied') OR approver IS NOT NULL),
  CHECK (final_outcome IS NULL OR final_outcome = 'executed' OR final_outcome = 'error'
         OR result_status = 'not_dispatched')
) STRICT;
INSERT INTO mcpflow_call_audit_new (audit_id, ts, event_type, call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id, backend_slug, tool, qualified_tool, placement, device_id, args_redacted, args_hash, policy_decision, final_outcome, rule_id, matched_rule_ids, pending_call_id, approver, approver_note, latency_ms, backend_latency_ms, result_status, error_code, lifecycle_action, actor, rule_version, grant_id)
SELECT audit_id, ts, CASE WHEN event_type IN ('result_read','result_purge') THEN 'lifecycle' ELSE event_type END, call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id, backend_slug, tool, qualified_tool, placement, device_id, args_redacted, args_hash, policy_decision, final_outcome, rule_id, matched_rule_ids, pending_call_id, approver, approver_note, latency_ms, backend_latency_ms, result_status, error_code, CASE WHEN event_type IN ('result_read','result_purge') THEN event_type ELSE lifecycle_action END, CASE event_type WHEN 'result_purge' THEN COALESCE(actor, agent_id) ELSE actor END, rule_version, grant_id FROM mcpflow_call_audit ORDER BY audit_id;
-- keep the AUTOINCREMENT high-water mark (ids freed by retention are never reused)
DELETE FROM sqlite_sequence WHERE name = 'mcpflow_call_audit_new';
INSERT INTO sqlite_sequence (name, seq)
  SELECT 'mcpflow_call_audit_new', seq FROM sqlite_sequence WHERE name = 'mcpflow_call_audit';
DROP TABLE mcpflow_call_audit;          -- DROP TABLE fires no DELETE triggers; ours are already dropped
ALTER TABLE mcpflow_call_audit_new RENAME TO mcpflow_call_audit;
CREATE INDEX mcpflow_call_audit_ts         ON mcpflow_call_audit (ts);
CREATE INDEX mcpflow_call_audit_agent_ts   ON mcpflow_call_audit (agent_id, ts DESC);
CREATE INDEX mcpflow_call_audit_key_ts     ON mcpflow_call_audit (key_id, ts DESC);
CREATE INDEX mcpflow_call_audit_proj_tool  ON mcpflow_call_audit (project_id, backend_slug, tool, ts DESC);
CREATE INDEX mcpflow_call_audit_pending    ON mcpflow_call_audit (pending_call_id) WHERE pending_call_id IS NOT NULL;
CREATE INDEX mcpflow_call_audit_policy_ts  ON mcpflow_call_audit (policy_decision, ts DESC)
  WHERE policy_decision IN ('deny','require_approval');
CREATE INDEX mcpflow_call_audit_outcome_ts ON mcpflow_call_audit (final_outcome, ts DESC)
  WHERE final_outcome IS NOT NULL AND final_outcome <> 'executed';
CREATE INDEX mcpflow_call_audit_call_id    ON mcpflow_call_audit (call_id);
CREATE INDEX mcpflow_call_audit_rule  ON mcpflow_call_audit (rule_id, rule_version) WHERE rule_id IS NOT NULL;
CREATE INDEX mcpflow_call_audit_grant ON mcpflow_call_audit (grant_id) WHERE grant_id IS NOT NULL;
CREATE TRIGGER mcpflow_call_audit_approver_human BEFORE INSERT ON mcpflow_call_audit
WHEN NEW.approver IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM mcpflow_agent WHERE id = NEW.approver AND kind = 'human')
BEGIN SELECT RAISE(ABORT, 'approver is not a human agent'); END;

CREATE TRIGGER mcpflow_call_audit_no_self_approval BEFORE INSERT ON mcpflow_call_audit
WHEN NEW.approver IS NOT NULL AND NEW.approver = NEW.agent_id
BEGIN SELECT RAISE(ABORT, 'an agent cannot approve its own call'); END;

CREATE TRIGGER mcpflow_call_audit_no_update BEFORE UPDATE ON mcpflow_call_audit
BEGIN SELECT RAISE(ABORT, 'mcpflow_call_audit is append-only (UPDATE rejected)'); END;

CREATE TRIGGER mcpflow_call_audit_no_delete BEFORE DELETE ON mcpflow_call_audit
BEGIN SELECT RAISE(ABORT, 'mcpflow_call_audit is append-only (DELETE rejected)'); END;
`;
