/**
 * Migration 0003 — policy rules (immutable versions), pending calls, approve-similar grants,
 * audit linkage (db-t2.1-policy-pending.md). SQLite variant; Database-confirmed defaults:
 * grants are a separate table, any one approver decides, match_agents holds agt_ ids,
 * mf_pending_status returns status only (no stored result table yet).
 * Seed/starter rules are NOT here: see src/db/seeds/policy-starter.sql (unapplied until Chen approves).
 */
import { NOW, idCheck, idCheckNullable, jsonArrayCheck } from "./sql-helpers.js";

const NONEMPTY = (c: string) => `${jsonArrayCheck(c)} AND json_array_length(${c}) > 0`;
const SECS = (a: string, b: string) => `((julianday(${a}) - julianday(${b})) * 86400.0)`;

export const MIGRATION_0003 = `
CREATE TABLE mcpflow_policy_rule (
  id              TEXT PRIMARY KEY CHECK (${idCheck("id", "rule_")}),
  workspace_id    TEXT NOT NULL REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  enabled         INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1)),
  current_version INTEGER,
  created_at      TEXT NOT NULL DEFAULT (${NOW}),
  created_by      TEXT NOT NULL REFERENCES mcpflow_agent(id),
  retired_at      TEXT,
  retired_by      TEXT REFERENCES mcpflow_agent(id),
  CHECK ((retired_at IS NULL) = (retired_by IS NULL)),
  FOREIGN KEY (id, current_version) REFERENCES mcpflow_policy_rule_version(rule_id, version)
    DEFERRABLE INITIALLY DEFERRED
) STRICT;

CREATE TABLE mcpflow_policy_rule_version (
  rule_id            TEXT NOT NULL REFERENCES mcpflow_policy_rule(id) ON DELETE RESTRICT,
  version            INTEGER NOT NULL CHECK (version >= 1),
  priority           INTEGER NOT NULL DEFAULT 100,
  description        TEXT NOT NULL,
  match_agents       TEXT NOT NULL DEFAULT '["*"]' CHECK (${jsonArrayCheck("match_agents")}),
  match_projects     TEXT NOT NULL DEFAULT '["*"]' CHECK (${jsonArrayCheck("match_projects")}),
  match_backends     TEXT NOT NULL DEFAULT '["*"]' CHECK (${jsonArrayCheck("match_backends")}),
  match_tools        TEXT NOT NULL DEFAULT '["*"]' CHECK (${jsonArrayCheck("match_tools")}),
  match_args         TEXT NOT NULL DEFAULT '[]'    CHECK (${jsonArrayCheck("match_args")}),
  effect             TEXT NOT NULL CHECK (effect IN ('allow','deny','require_approval')),
  approval_timeout_s INTEGER CHECK (approval_timeout_s BETWEEN 1 AND 3600),
  approvers          TEXT CHECK (approvers IS NULL OR (${jsonArrayCheck("approvers")})),
  reason_to_agent    TEXT,
  created_at         TEXT NOT NULL DEFAULT (${NOW}),
  created_by         TEXT NOT NULL REFERENCES mcpflow_agent(id),
  PRIMARY KEY (rule_id, version),
  CHECK (effect <> 'require_approval' OR (approvers IS NOT NULL AND json_array_length(approvers) > 0)),
  CHECK (effect = 'require_approval' OR (approvers IS NULL AND approval_timeout_s IS NULL))
) STRICT;

CREATE TRIGGER mcpflow_policy_rule_version_consecutive BEFORE INSERT ON mcpflow_policy_rule_version
WHEN NEW.version <> COALESCE((SELECT max(version) FROM mcpflow_policy_rule_version
                               WHERE rule_id = NEW.rule_id), 0) + 1
BEGIN SELECT RAISE(ABORT, 'versions must be consecutive'); END;

CREATE TRIGGER mcpflow_policy_rule_version_approvers BEFORE INSERT ON mcpflow_policy_rule_version
WHEN NEW.approvers IS NOT NULL AND EXISTS (
  SELECT 1 FROM json_each(NEW.approvers) j
   WHERE NOT EXISTS (SELECT 1 FROM mcpflow_agent a WHERE a.id = j.value AND a.kind = 'human'))
BEGIN SELECT RAISE(ABORT, 'approver is not a human agent'); END;

CREATE TRIGGER mcpflow_policy_rule_version_no_update BEFORE UPDATE ON mcpflow_policy_rule_version
BEGIN SELECT RAISE(ABORT, 'policy_rule_version is immutable; insert a new version'); END;

CREATE TRIGGER mcpflow_policy_rule_version_no_delete BEFORE DELETE ON mcpflow_policy_rule_version
BEGIN SELECT RAISE(ABORT, 'policy_rule_version is immutable; insert a new version'); END;

CREATE TRIGGER mcpflow_policy_rule_no_delete BEFORE DELETE ON mcpflow_policy_rule
BEGIN SELECT RAISE(ABORT, 'policy rules are retired, never deleted'); END;

CREATE TRIGGER mcpflow_policy_rule_upd_guard BEFORE UPDATE ON mcpflow_policy_rule
WHEN NEW.id IS NOT OLD.id OR NEW.workspace_id IS NOT OLD.workspace_id
  OR NEW.created_by IS NOT OLD.created_by OR NEW.created_at IS NOT OLD.created_at
  OR (OLD.retired_at IS NOT NULL AND (NEW.retired_at IS NOT OLD.retired_at OR NEW.enabled <> OLD.enabled
      OR NEW.current_version IS NOT OLD.current_version))
  OR (OLD.current_version IS NOT NULL AND NEW.current_version < OLD.current_version)
BEGIN SELECT RAISE(ABORT, 'policy_rule identity immutable; retire terminal; version forward-only'); END;

CREATE VIEW mcpflow_active_policy_rule AS
SELECT r.workspace_id, v.*
  FROM mcpflow_policy_rule r
  JOIN mcpflow_policy_rule_version v ON v.rule_id = r.id AND v.version = r.current_version
 WHERE r.enabled = 1 AND r.retired_at IS NULL;

CREATE TABLE mcpflow_pending_call (
  id               TEXT PRIMARY KEY CHECK (${idCheck("id", "pc_")}),
  call_id          TEXT NOT NULL UNIQUE,
  workspace_id     TEXT NOT NULL,
  agent_id         TEXT NOT NULL REFERENCES mcpflow_agent(id),
  key_id           TEXT NOT NULL REFERENCES mcpflow_api_key(id),
  session_id       TEXT REFERENCES mcpflow_session(id),
  project_id       TEXT NOT NULL,
  backend_slug     TEXT NOT NULL,
  tool             TEXT NOT NULL,
  qualified_tool   TEXT,
  placement        TEXT,
  device_id        TEXT,
  args_redacted    TEXT NOT NULL CHECK (json_valid(args_redacted)),
  args_ciphertext  BLOB,
  args_key_ref     TEXT,
  args_hash        TEXT NOT NULL,
  matched_rules    TEXT NOT NULL CHECK (${jsonArrayCheck("matched_rules")}),
  approvers        TEXT NOT NULL CHECK (${NONEMPTY("approvers")}),
  reason_to_agent  TEXT,
  created_at       TEXT NOT NULL DEFAULT (${NOW}),
  expires_at       TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','approved','denied','expired','cancelled')),
  decided_by       TEXT REFERENCES mcpflow_agent(id),
  decided_at       TEXT,
  note             TEXT,
  dispatched_at    TEXT,
  grant_id         TEXT REFERENCES mcpflow_approval_grant(id) DEFERRABLE INITIALLY DEFERRED,
  CHECK (expires_at > created_at AND ${SECS("expires_at", "created_at")} <= 3600.001),
  CHECK ((status IN ('approved','denied')) = (decided_by IS NOT NULL)),
  CHECK ((status = 'pending') = (decided_at IS NULL)),
  CHECK (dispatched_at IS NULL OR status = 'approved'),
  CHECK (status <> 'pending' OR args_ciphertext IS NOT NULL)
) STRICT;
CREATE INDEX mcpflow_pending_call_open  ON mcpflow_pending_call (expires_at) WHERE status = 'pending';
CREATE INDEX mcpflow_pending_call_agent ON mcpflow_pending_call (agent_id, created_at DESC);

CREATE TRIGGER mcpflow_pending_call_ins_approvers BEFORE INSERT ON mcpflow_pending_call
WHEN EXISTS (SELECT 1 FROM json_each(NEW.approvers) j
              WHERE NOT EXISTS (SELECT 1 FROM mcpflow_agent a WHERE a.id = j.value AND a.kind = 'human'))
BEGIN SELECT RAISE(ABORT, 'approver is not a human agent'); END;

CREATE TRIGGER mcpflow_pending_call_ins_state BEFORE INSERT ON mcpflow_pending_call
WHEN NEW.status <> 'pending' OR NEW.dispatched_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'pending_call must be inserted as pending'); END;

CREATE TRIGGER mcpflow_pending_call_no_delete BEFORE DELETE ON mcpflow_pending_call
BEGIN SELECT RAISE(ABORT, 'pending_call rows are never deleted'); END;

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

CREATE TRIGGER mcpflow_pending_call_ciphertext BEFORE UPDATE ON mcpflow_pending_call
WHEN NEW.args_ciphertext IS NOT OLD.args_ciphertext
  AND (NEW.args_ciphertext IS NOT NULL OR NEW.status = 'pending'
       OR (NEW.status = 'approved' AND NEW.dispatched_at IS NULL))
BEGIN SELECT RAISE(ABORT, 'args_ciphertext can only be purged after resolution/dispatch'); END;

CREATE TRIGGER mcpflow_pending_call_terminal BEFORE UPDATE OF status ON mcpflow_pending_call
WHEN NEW.status <> OLD.status AND OLD.status <> 'pending'
BEGIN SELECT RAISE(ABORT, 'pending_call already resolved (terminal)'); END;

CREATE TRIGGER mcpflow_pending_call_decision_after_expiry BEFORE UPDATE OF status ON mcpflow_pending_call
WHEN NEW.status <> OLD.status AND NEW.status IN ('approved','denied') AND ${NOW} >= OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'pending_call expired; timeout = deny'); END;

CREATE TRIGGER mcpflow_pending_call_no_self_approval BEFORE UPDATE OF status ON mcpflow_pending_call
WHEN NEW.status <> OLD.status AND NEW.status IN ('approved','denied') AND NEW.decided_by = OLD.agent_id
BEGIN SELECT RAISE(ABORT, 'no self-approval'); END;

CREATE TRIGGER mcpflow_pending_call_decider_human BEFORE UPDATE OF status ON mcpflow_pending_call
WHEN NEW.status <> OLD.status AND NEW.status IN ('approved','denied') AND NOT EXISTS (
  SELECT 1 FROM mcpflow_agent WHERE id = NEW.decided_by AND kind = 'human' AND status = 'active')
BEGIN SELECT RAISE(ABORT, 'decided_by must be an active human agent'); END;

CREATE TRIGGER mcpflow_pending_call_decider_listed BEFORE UPDATE OF status ON mcpflow_pending_call
WHEN NEW.status <> OLD.status AND NEW.status IN ('approved','denied') AND NOT EXISTS (
  SELECT 1 FROM json_each(OLD.approvers) j WHERE j.value = NEW.decided_by)
BEGIN SELECT RAISE(ABORT, 'decided_by is not an approver for this call'); END;

CREATE TRIGGER mcpflow_pending_call_early_expiry BEFORE UPDATE OF status ON mcpflow_pending_call
WHEN NEW.status <> OLD.status AND NEW.status = 'expired' AND ${NOW} < OLD.expires_at
BEGIN SELECT RAISE(ABORT, 'cannot expire before expires_at'); END;

CREATE TRIGGER mcpflow_pending_call_decision_frozen BEFORE UPDATE ON mcpflow_pending_call
WHEN OLD.status <> 'pending' AND (NEW.decided_by IS NOT OLD.decided_by
  OR NEW.decided_at IS NOT OLD.decided_at OR NEW.note IS NOT OLD.note)
BEGIN SELECT RAISE(ABORT, 'decision is immutable once resolved'); END;

CREATE TRIGGER mcpflow_pending_call_dispatch_once BEFORE UPDATE OF dispatched_at ON mcpflow_pending_call
WHEN OLD.dispatched_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'already dispatched'); END;

CREATE TRIGGER mcpflow_agent_cancel_pending AFTER UPDATE OF status ON mcpflow_agent
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
  UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = ${NOW},
         note = 'agent ' || NEW.status
   WHERE agent_id = NEW.id AND status = 'pending';
END;

CREATE TRIGGER mcpflow_api_key_cancel_pending AFTER UPDATE OF status ON mcpflow_api_key
WHEN NEW.status = 'revoked' AND OLD.status <> 'revoked'
BEGIN
  UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = ${NOW}, note = 'key revoked'
   WHERE key_id = NEW.id AND status = 'pending';
END;

CREATE TABLE mcpflow_approval_grant (
  id                     TEXT PRIMARY KEY CHECK (${idCheck("id", "grt_")}),
  source_pending_call_id TEXT NOT NULL REFERENCES mcpflow_pending_call(id),
  workspace_id           TEXT NOT NULL,
  agent_id               TEXT NOT NULL REFERENCES mcpflow_agent(id),
  project_id             TEXT NOT NULL,
  backend_slug           TEXT NOT NULL,
  tool                   TEXT NOT NULL,
  match_args             TEXT NOT NULL DEFAULT '[]' CHECK (${jsonArrayCheck("match_args")}),
  args_hash              TEXT,
  overrides_rule_ids     TEXT NOT NULL CHECK (${NONEMPTY("overrides_rule_ids")}),
  granted_by             TEXT NOT NULL REFERENCES mcpflow_agent(id),
  granted_at             TEXT NOT NULL DEFAULT (${NOW}),
  expires_at             TEXT NOT NULL,
  max_uses               INTEGER CHECK (max_uses >= 1),
  use_count              INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
  revoked_at             TEXT,
  revoked_by             TEXT REFERENCES mcpflow_agent(id),
  revoked_reason         TEXT,
  CHECK (expires_at > granted_at AND ${SECS("expires_at", "granted_at")} <= 3600.001),
  CHECK (max_uses IS NULL OR use_count <= max_uses),
  CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
) STRICT;
CREATE INDEX mcpflow_approval_grant_live ON mcpflow_approval_grant (agent_id, project_id, backend_slug, tool)
  WHERE revoked_at IS NULL;

CREATE TRIGGER mcpflow_approval_grant_ins_granter BEFORE INSERT ON mcpflow_approval_grant
WHEN NEW.granted_by = NEW.agent_id OR NOT EXISTS (
  SELECT 1 FROM mcpflow_agent WHERE id = NEW.granted_by AND kind = 'human' AND status = 'active')
BEGIN SELECT RAISE(ABORT, 'granted_by must be an active human agent other than the grantee'); END;

CREATE TRIGGER mcpflow_approval_grant_ins_source BEFORE INSERT ON mcpflow_approval_grant
WHEN NOT EXISTS (SELECT 1 FROM mcpflow_pending_call p
                  WHERE p.id = NEW.source_pending_call_id AND p.status = 'approved'
                    AND p.decided_by = NEW.granted_by AND p.agent_id = NEW.agent_id
                    AND p.backend_slug = NEW.backend_slug AND p.tool = NEW.tool
                    AND p.project_id = NEW.project_id)
BEGIN SELECT RAISE(ABORT, 'grant must derive from a call the same human approved, same scope'); END;

CREATE TRIGGER mcpflow_approval_grant_ins_fresh BEFORE INSERT ON mcpflow_approval_grant
WHEN NEW.use_count <> 0 OR NEW.revoked_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'grant must be inserted live with use_count 0'); END;

CREATE TRIGGER mcpflow_approval_grant_no_delete BEFORE DELETE ON mcpflow_approval_grant
BEGIN SELECT RAISE(ABORT, 'grants are revoked, never deleted'); END;

CREATE TRIGGER mcpflow_approval_grant_scope BEFORE UPDATE ON mcpflow_approval_grant
WHEN NEW.id IS NOT OLD.id OR NEW.source_pending_call_id IS NOT OLD.source_pending_call_id
  OR NEW.workspace_id IS NOT OLD.workspace_id
  OR NEW.agent_id IS NOT OLD.agent_id OR NEW.project_id IS NOT OLD.project_id
  OR NEW.backend_slug IS NOT OLD.backend_slug OR NEW.tool IS NOT OLD.tool
  OR NEW.match_args IS NOT OLD.match_args OR NEW.args_hash IS NOT OLD.args_hash
  OR NEW.overrides_rule_ids IS NOT OLD.overrides_rule_ids OR NEW.granted_by IS NOT OLD.granted_by
  OR NEW.granted_at IS NOT OLD.granted_at OR NEW.expires_at IS NOT OLD.expires_at
  OR NEW.max_uses IS NOT OLD.max_uses
BEGIN SELECT RAISE(ABORT, 'grant scope is immutable'); END;

CREATE TRIGGER mcpflow_approval_grant_revoke_terminal BEFORE UPDATE ON mcpflow_approval_grant
WHEN OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS NOT OLD.revoked_at
  OR NEW.revoked_by IS NOT OLD.revoked_by OR NEW.revoked_reason IS NOT OLD.revoked_reason)
BEGIN SELECT RAISE(ABORT, 'grant revocation is terminal'); END;

CREATE TRIGGER mcpflow_approval_grant_use_step BEFORE UPDATE OF use_count ON mcpflow_approval_grant
WHEN NEW.use_count NOT IN (OLD.use_count, OLD.use_count + 1)
BEGIN SELECT RAISE(ABORT, 'use_count only increments by 1'); END;

CREATE TRIGGER mcpflow_approval_grant_use_live BEFORE UPDATE OF use_count ON mcpflow_approval_grant
WHEN NEW.use_count > OLD.use_count AND (OLD.revoked_at IS NOT NULL OR ${NOW} >= OLD.expires_at)
BEGIN SELECT RAISE(ABORT, 'grant not live'); END;

ALTER TABLE mcpflow_call_audit ADD COLUMN rule_version INTEGER;
ALTER TABLE mcpflow_call_audit ADD COLUMN grant_id TEXT CHECK (${idCheckNullable("grant_id", "grt_")});
CREATE INDEX mcpflow_call_audit_rule  ON mcpflow_call_audit (rule_id, rule_version) WHERE rule_id IS NOT NULL;
CREATE INDEX mcpflow_call_audit_grant ON mcpflow_call_audit (grant_id) WHERE grant_id IS NOT NULL;
`;
