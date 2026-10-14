/**
 * Migration 0002 — append-only call audit (db-t3.1-call-audit.md).
 * SQLite variant: no partitions (ts indexed), JSON as TEXT, RAISE(ABORT) append-only triggers.
 * Q6 (Database, 2026-10-14): the completion CHECKs are kept exactly as written:
 *   - gateway failure before dispatch: final_outcome='error', result_status='not_dispatched'
 *   - gateway failure after dispatch:  final_outcome='error', result_status='error' (no 'unknown' in enum)
 *   - backend error/timeout:           final_outcome='executed', result_status='error'|'timeout'
 * Retention never deletes on the normal path; see the maintenance path (T3.1 retention, later).
 */
import { NOW, idCheckNullable, jsonArrayCheck } from "./sql-helpers.js";

export const MIGRATION_0002 = `
CREATE TABLE mcpflow_call_audit (
  audit_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts               TEXT NOT NULL DEFAULT (${NOW}),
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
  matched_rule_ids TEXT CHECK (matched_rule_ids IS NULL OR (${jsonArrayCheck("matched_rule_ids")})),
  pending_call_id  TEXT,
  approver         TEXT CHECK (${idCheckNullable("approver", "agt_")}),
  approver_note    TEXT,
  latency_ms       INTEGER CHECK (latency_ms >= 0),
  backend_latency_ms INTEGER CHECK (backend_latency_ms >= 0),
  result_status    TEXT CHECK (result_status IN ('ok','error','not_dispatched','timeout')),
  error_code       TEXT,
  lifecycle_action TEXT,
  actor            TEXT CHECK (${idCheckNullable("actor", "agt_")}),
  -- reference uses error_code = 'unauthenticated'; IS makes a NULL error_code fail instead of passing (SQL NULL CHECK semantics)
  CHECK (event_type <> 'decision'   OR policy_decision IS NOT NULL OR error_code IS 'unauthenticated'),
  CHECK (event_type <> 'completion' OR (final_outcome IS NOT NULL AND result_status IS NOT NULL)),
  CHECK (event_type <> 'lifecycle'  OR (lifecycle_action IS NOT NULL AND actor IS NOT NULL)),
  CHECK (final_outcome IS NULL OR final_outcome NOT IN ('approval_denied') OR approver IS NOT NULL),
  CHECK (final_outcome IS NULL OR final_outcome = 'executed' OR final_outcome = 'error'
         OR result_status = 'not_dispatched')
) STRICT;

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
