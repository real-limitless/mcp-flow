/**
 * Migration 0005 (Security T2.5 M-3): approve-similar grants die when what they relied on changes.
 *  - a rule they override gets a new current_version, is disabled, or is retired
 *  - the granting human is no longer active
 * Revocation is recorded (revoked_at/by/reason); grants are never deleted.
 */
const NOW = "strftime('%Y-%m-%dT%H:%M:%fZ','now')";

export const MIGRATION_0005 = `
CREATE TRIGGER mcpflow_grant_revoke_on_rule_change AFTER UPDATE ON mcpflow_policy_rule
WHEN NEW.current_version IS NOT OLD.current_version OR NEW.enabled IS NOT OLD.enabled
  OR NEW.retired_at IS NOT OLD.retired_at
BEGIN
  UPDATE mcpflow_approval_grant
     SET revoked_at = ${NOW},
         revoked_by = COALESCE(NEW.retired_by,
                        (SELECT created_by FROM mcpflow_policy_rule_version
                          WHERE rule_id = NEW.id AND version = NEW.current_version),
                        NEW.created_by),
         revoked_reason = 'rule changed: ' || NEW.id
   WHERE revoked_at IS NULL
     AND EXISTS (SELECT 1 FROM json_each(overrides_rule_ids) j WHERE j.value = NEW.id);
END;

CREATE TRIGGER mcpflow_grant_revoke_on_granter_inactive AFTER UPDATE OF status ON mcpflow_agent
WHEN NEW.status <> 'active' AND OLD.status = 'active'
BEGIN
  UPDATE mcpflow_approval_grant
     SET revoked_at = ${NOW}, revoked_by = NEW.id, revoked_reason = 'granter no longer active'
   WHERE revoked_at IS NULL AND granted_by = NEW.id;
END;
`;
