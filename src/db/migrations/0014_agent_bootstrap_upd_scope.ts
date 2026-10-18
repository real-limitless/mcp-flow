/**
 * 0014_agent_bootstrap_upd_scope (Security Re-review 5, R5-5). The 0009 update trigger fired on ANY
 * update of a row with created_by NULL that is not a human admin, so a pre-0009 violation row
 * (counted as bootstrap_violations by 0009) could not be suspended or revoked, and the revoke
 * cascades aborted with it. The trigger now fires only when created_by, kind or is_admin change.
 * The rule itself is unchanged: created_by is immutable, the bootstrap admin cannot be demoted, and
 * a non-admin row cannot gain created_by NULL. Status changes (suspend, revoke) are no longer blocked.
 */
export const MIGRATION_0014 = `
-- 0014_agent_bootstrap_upd_scope: scope the bootstrap update guard to the columns it protects
DROP TRIGGER mcpflow_agent_bootstrap_upd;
CREATE TRIGGER mcpflow_agent_bootstrap_upd BEFORE UPDATE OF created_by, kind, is_admin ON mcpflow_agent
WHEN NEW.created_by IS NOT OLD.created_by
  OR (NEW.created_by IS NULL AND NOT (NEW.kind = 'human' AND NEW.is_admin = 1))
BEGIN SELECT RAISE(ABORT, 'created_by is immutable; bootstrap agent cannot be demoted'); END;
`;

/** Manual/dev rollback only: the 0009 trigger text. */
export const MIGRATION_0014_DOWN = `
DROP TRIGGER mcpflow_agent_bootstrap_upd;
CREATE TRIGGER mcpflow_agent_bootstrap_upd BEFORE UPDATE ON mcpflow_agent
WHEN NEW.created_by IS NOT OLD.created_by
  OR (NEW.created_by IS NULL AND NOT (NEW.kind = 'human' AND NEW.is_admin = 1))
BEGIN SELECT RAISE(ABORT, 'created_by is immutable; bootstrap agent cannot be demoted'); END;
`;
