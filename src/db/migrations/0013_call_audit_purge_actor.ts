/**
 * 0013_call_audit_purge_actor (Database review of 1a90e2bc, item 1). Purge audit rows get a defined
 * system actor that carries the purge reason: 'system:sweeper' with error_code 'purged:expired',
 * 'system:quota' with 'purged:quota'. 'system:*' actors are valid on result_purge rows only; every
 * other actor is still an agt_ id. This is a new migration rather than an edit of 0012, because DBs
 * that already ran 0012 from 1a90e2bc (QA) never re-run it.
 * call_audit is rebuilt again (rows, audit_ids and the sqlite_sequence high-water mark kept; indexes
 * and triggers recreated verbatim from 0012). Every existing purge row gets the system actor for its
 * error_code. What that changed is recorded in mcpflow_migration_note as
 * {null_backfilled, agt_actor_overwritten}: 1a90e2bc wrote NULL actors, but the 0012 CHECK also
 * allowed an agt_ actor on a purge row, and such an actor is replaced (counted, never silently).
 * DOWN restores the 0012 table and sets purge-row actors back to NULL (the reason stays in error_code).
 */
export const MIGRATION_0013 = `
-- 0013_call_audit_purge_actor: result_purge rows carry a system actor matching the purge reason
-- every purge row's actor is set from its reason; record what that changed (Database review of f9388505):
-- null_backfilled = actor was NULL (as 1a90e2bc wrote them), agt_actor_overwritten = an agt_ actor was replaced
INSERT INTO mcpflow_migration_note (migration_id, note)
SELECT '0013_call_audit_purge_actor',
       json_object('null_backfilled', sum(actor IS NULL),
                   'agt_actor_overwritten', sum(actor IS NOT NULL AND substr(actor, 1, 7) <> 'system:'))
  FROM mcpflow_call_audit WHERE event_type = 'result_purge'
HAVING sum(actor IS NULL OR substr(actor, 1, 7) <> 'system:') > 0;
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
  actor            TEXT CHECK (actor IS NULL OR actor IN ('system:sweeper','system:quota')
                     OR (length(actor) = 28 AND substr(actor, 1, 4) = 'agt_' AND substr(actor, 5) NOT GLOB '*[^0-9a-f]*')),
  rule_version     INTEGER,
  grant_id         TEXT CHECK (grant_id IS NULL OR (length(grant_id) = 28 AND substr(grant_id, 1, 4) = 'grt_' AND substr(grant_id, 5) NOT GLOB '*[^0-9a-f]*')),
  CHECK (event_type <> 'decision'   OR policy_decision IS NOT NULL OR error_code IS 'unauthenticated'),
  CHECK (event_type <> 'completion' OR (final_outcome IS NOT NULL AND result_status IS NOT NULL)),
  CHECK (event_type <> 'lifecycle'  OR (lifecycle_action IS NOT NULL AND actor IS NOT NULL)),
  CHECK (event_type <> 'result_read' OR (actor IS NOT NULL AND agent_id IS NOT NULL
         AND policy_decision IS NULL AND final_outcome IS NULL AND lifecycle_action IS NULL)),
  -- purge rows: system actor matching the reason (sweeper = expiry, quota = byte caps); owner in agent_id
  -- (IS, not =: a NULL actor must fail the CHECK, not slip through as NULL)
  CHECK (event_type <> 'result_purge' OR (agent_id IS NOT NULL
         AND ((actor IS 'system:sweeper' AND error_code IS 'purged:expired') OR (actor IS 'system:quota' AND error_code IS 'purged:quota'))
         AND policy_decision IS NULL AND final_outcome IS NULL AND lifecycle_action IS NULL)),
  -- system actors exist only on purge rows
  CHECK (actor IS NULL OR substr(actor, 1, 7) <> 'system:' OR event_type = 'result_purge'),
  CHECK (final_outcome IS NULL OR final_outcome NOT IN ('approval_denied') OR approver IS NOT NULL),
  CHECK (final_outcome IS NULL OR final_outcome = 'executed' OR final_outcome = 'error'
         OR result_status = 'not_dispatched')
) STRICT;
INSERT INTO mcpflow_call_audit_new (audit_id, ts, event_type, call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id, backend_slug, tool, qualified_tool, placement, device_id, args_redacted, args_hash, policy_decision, final_outcome, rule_id, matched_rule_ids, pending_call_id, approver, approver_note, latency_ms, backend_latency_ms, result_status, error_code, lifecycle_action, actor, rule_version, grant_id)
SELECT audit_id, ts, event_type, call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id, backend_slug, tool, qualified_tool, placement, device_id, args_redacted, args_hash, policy_decision, final_outcome, rule_id, matched_rule_ids, pending_call_id, approver, approver_note, latency_ms, backend_latency_ms, result_status, error_code, lifecycle_action, CASE WHEN event_type = 'result_purge' THEN CASE error_code WHEN 'purged:expired' THEN 'system:sweeper' WHEN 'purged:quota' THEN 'system:quota' END ELSE actor END, rule_version, grant_id FROM mcpflow_call_audit ORDER BY audit_id;
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

/** Manual/dev rollback only. */
export const MIGRATION_0013_DOWN = `
-- 0013_call_audit_purge_actor DOWN: back to the 0012 CHECKs; purge rows lose their system actor
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
SELECT audit_id, ts, event_type, call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id, backend_slug, tool, qualified_tool, placement, device_id, args_redacted, args_hash, policy_decision, final_outcome, rule_id, matched_rule_ids, pending_call_id, approver, approver_note, latency_ms, backend_latency_ms, result_status, error_code, lifecycle_action, CASE WHEN event_type = 'result_purge' THEN NULL ELSE actor END, rule_version, grant_id FROM mcpflow_call_audit ORDER BY audit_id;
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
