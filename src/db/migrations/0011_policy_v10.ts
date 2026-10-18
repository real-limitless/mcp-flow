/**
 * 0011_policy_v10 (Database db-t2.1 §10, SQLite delta; SQL verbatim):
 * - policy_rule_version.min_approvals INTEGER NOT NULL DEFAULT 1 (reserved; the admin API only accepts 1).
 * - match_agents on new versions must be ["*"] or agt_ ids of agents in the rule's workspace.
 *   Existing versions are immutable and are only counted in mcpflow_migration_note.
 * - pending_call.cancel_reason (set once, only on cancel); the 0003 cancel triggers now set it.
 * - A hold needs at least one active human approver at insert time (RAISE 'no_active_approver'), and a hold
 *   whose last active approver is suspended/revoked is cancelled with cancel_reason 'no_active_approver'.
 */
export const MIGRATION_0011 = `
-- 0011_policy_v10: min_approvals (reserved), agent matchers = agt_ ids or '*', no_active_approver
ALTER TABLE mcpflow_policy_rule_version
  ADD COLUMN min_approvals INTEGER NOT NULL DEFAULT 1 CHECK (min_approvals >= 1);  -- reserved, NOT enforced in v1

CREATE TRIGGER mcpflow_policy_rule_version_match_agents BEFORE INSERT ON mcpflow_policy_rule_version
WHEN EXISTS (SELECT 1 FROM json_each(NEW.match_agents) j
              WHERE j.type <> 'text'
                 OR (j.value <> '*' AND NOT (length(j.value) = 28 AND substr(j.value,1,4) = 'agt_'
                                             AND substr(j.value,5) NOT GLOB '*[^0-9a-f]*')))
  OR json_array_length(NEW.match_agents) = 0
  OR (json_array_length(NEW.match_agents) > 1
      AND EXISTS (SELECT 1 FROM json_each(NEW.match_agents) j WHERE j.value = '*'))
BEGIN SELECT RAISE(ABORT, 'match_agents must be ["*"] or a list of agt_ ids'); END;

CREATE TRIGGER mcpflow_policy_rule_version_match_agents_exist BEFORE INSERT ON mcpflow_policy_rule_version
WHEN EXISTS (SELECT 1 FROM json_each(NEW.match_agents) j
              WHERE j.value <> '*' AND NOT EXISTS (
                SELECT 1 FROM mcpflow_agent a JOIN mcpflow_policy_rule r ON r.id = NEW.rule_id
                 WHERE a.id = j.value AND a.workspace_id = r.workspace_id))
BEGIN SELECT RAISE(ABORT, 'match_agents references an unknown agent in this workspace'); END;

-- existing versions are immutable: report, don't rewrite
INSERT INTO mcpflow_migration_note (migration_id, note)
SELECT '0011_policy_v10', json_object('versions_with_non_id_agent_matchers', count(DISTINCT v.rule_id || ':' || v.version))
  FROM mcpflow_policy_rule_version v, json_each(v.match_agents) j
 WHERE j.value <> '*' AND NOT (length(j.value) = 28 AND substr(j.value,1,4) = 'agt_')
HAVING count(*) > 0;

-- structured cancel reason (note stays free text)
ALTER TABLE mcpflow_pending_call ADD COLUMN cancel_reason TEXT
  CHECK (cancel_reason IS NULL OR cancel_reason IN
         ('agent_suspended','agent_revoked','key_revoked','no_active_approver','client_disconnected','shutdown'));

CREATE TRIGGER mcpflow_pending_call_cancel_reason BEFORE UPDATE ON mcpflow_pending_call
WHEN (NEW.cancel_reason IS NOT OLD.cancel_reason AND (OLD.cancel_reason IS NOT NULL OR NEW.status <> 'cancelled'))
BEGIN SELECT RAISE(ABORT, 'cancel_reason is set once, only on cancel'); END;

-- fail closed at hold time: at least one approver must be an active human
CREATE TRIGGER mcpflow_pending_call_ins_active_approver BEFORE INSERT ON mcpflow_pending_call
WHEN NOT EXISTS (SELECT 1 FROM json_each(NEW.approvers) j JOIN mcpflow_agent a ON a.id = j.value
                  WHERE a.kind = 'human' AND a.status = 'active')
BEGIN SELECT RAISE(ABORT, 'no_active_approver'); END;

-- T2.1 §10.5: last active approver suspended/revoked -> cancel immediately
CREATE TRIGGER mcpflow_pending_call_no_active_approver AFTER UPDATE OF status ON mcpflow_agent
WHEN OLD.status = 'active' AND NEW.status <> 'active' AND NEW.kind = 'human'
BEGIN
  UPDATE mcpflow_pending_call
     SET status = 'cancelled', decided_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
         note = 'no_active_approver', cancel_reason = 'no_active_approver'
   WHERE status = 'pending'
     AND EXISTS (SELECT 1 FROM json_each(approvers) j WHERE j.value = NEW.id)
     AND NOT EXISTS (SELECT 1 FROM json_each(approvers) j JOIN mcpflow_agent a ON a.id = j.value
                      WHERE a.kind = 'human' AND a.status = 'active');
END;

-- existing cancel triggers (branch 0003) now also set cancel_reason
DROP TRIGGER mcpflow_agent_cancel_pending;
CREATE TRIGGER mcpflow_agent_cancel_pending AFTER UPDATE OF status ON mcpflow_agent
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
  UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
         note = 'agent ' || NEW.status,
         cancel_reason = CASE NEW.status WHEN 'revoked' THEN 'agent_revoked' ELSE 'agent_suspended' END
   WHERE agent_id = NEW.id AND status = 'pending';
END;
DROP TRIGGER mcpflow_api_key_cancel_pending;
CREATE TRIGGER mcpflow_api_key_cancel_pending AFTER UPDATE OF status ON mcpflow_api_key
WHEN NEW.status = 'revoked' AND OLD.status <> 'revoked'
BEGIN
  UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
         note = 'key revoked', cancel_reason = 'key_revoked'
   WHERE key_id = NEW.id AND status = 'pending';
END;
`;

/** Manual/dev rollback only. */
export const MIGRATION_0011_DOWN = `
DROP TRIGGER mcpflow_pending_call_no_active_approver;
DROP TRIGGER mcpflow_pending_call_ins_active_approver;
DROP TRIGGER mcpflow_pending_call_cancel_reason;
DROP TRIGGER mcpflow_policy_rule_version_match_agents;
DROP TRIGGER mcpflow_policy_rule_version_match_agents_exist;
DROP TRIGGER mcpflow_agent_cancel_pending;
CREATE TRIGGER mcpflow_agent_cancel_pending AFTER UPDATE OF status ON mcpflow_agent
WHEN OLD.status = 'active' AND NEW.status <> 'active'
BEGIN
  UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
         note = 'agent ' || NEW.status
   WHERE agent_id = NEW.id AND status = 'pending';
END;
DROP TRIGGER mcpflow_api_key_cancel_pending;
CREATE TRIGGER mcpflow_api_key_cancel_pending AFTER UPDATE OF status ON mcpflow_api_key
WHEN NEW.status = 'revoked' AND OLD.status <> 'revoked'
BEGIN
  UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
         note = 'key revoked'
   WHERE key_id = NEW.id AND status = 'pending';
END;
ALTER TABLE mcpflow_pending_call DROP COLUMN cancel_reason;
ALTER TABLE mcpflow_policy_rule_version DROP COLUMN min_approvals;
`;
