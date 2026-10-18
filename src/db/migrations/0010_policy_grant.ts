/**
 * 0010_policy_grant (Database db-t2.1 §10.1, SQLite delta): mcpflow_approval_grant -> mcpflow_policy_grant,
 * granted_at -> created_at, max_uses/use_count dropped (no use limit). The 0005 auto-revoke triggers are
 * recreated against the new table and mcpflow_live_policy_grant is what the evaluator reads.
 * Grants that had a use limit are counted in mcpflow_migration_note (the limit is dropped, not enforced).
 * pending_call.grant_id refs are detached around the swap (DROP TABLE would leave deferred FK violations).
 * SQL is Database's, verbatim.
 */
export const MIGRATION_0010 = `
-- 0010_policy_grant: approval_grant -> policy_grant (T2.1 §10.1); drop use limit; granted_at -> created_at
PRAGMA defer_foreign_keys = ON;

DROP TRIGGER mcpflow_approval_grant_ins_granter;
DROP TRIGGER mcpflow_approval_grant_ins_source;
DROP TRIGGER mcpflow_approval_grant_ins_fresh;
DROP TRIGGER mcpflow_approval_grant_no_delete;
DROP TRIGGER mcpflow_approval_grant_scope;
DROP TRIGGER mcpflow_approval_grant_revoke_terminal;
DROP TRIGGER mcpflow_approval_grant_use_step;
DROP TRIGGER mcpflow_approval_grant_use_live;
DROP TRIGGER mcpflow_grant_revoke_on_rule_change;
DROP TRIGGER mcpflow_grant_revoke_on_granter_inactive;
DROP INDEX mcpflow_approval_grant_live;

ALTER TABLE mcpflow_approval_grant RENAME TO mcpflow_policy_grant;   -- pending_call.grant_id FK follows (legacy_alter_table=OFF)

CREATE TABLE mcpflow_policy_grant_new (
  id                     TEXT PRIMARY KEY CHECK (length(id) = 28 AND substr(id,1,4) = 'grt_' AND substr(id,5) NOT GLOB '*[^0-9a-f]*'),
  source_pending_call_id TEXT NOT NULL REFERENCES mcpflow_pending_call(id),
  workspace_id           TEXT NOT NULL,
  -- match snapshot (frozen at grant time)
  agent_id               TEXT NOT NULL REFERENCES mcpflow_agent(id),
  project_id             TEXT NOT NULL,
  backend_slug           TEXT NOT NULL,
  tool                   TEXT NOT NULL,
  match_args             TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(match_args) AND json_type(match_args) = 'array'),
  args_hash              TEXT,
  overrides_rule_ids     TEXT NOT NULL CHECK (json_valid(overrides_rule_ids) AND json_type(overrides_rule_ids) = 'array' AND json_array_length(overrides_rule_ids) > 0),
  granted_by             TEXT NOT NULL REFERENCES mcpflow_agent(id),
  created_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at             TEXT NOT NULL,
  revoked_at             TEXT,
  revoked_by             TEXT REFERENCES mcpflow_agent(id),
  revoked_reason         TEXT,
  CHECK (expires_at > created_at AND (julianday(expires_at) - julianday(created_at)) * 86400.0 <= 3600.001),
  CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
) STRICT;

INSERT INTO mcpflow_policy_grant_new (id, source_pending_call_id, workspace_id, agent_id, project_id, backend_slug,
  tool, match_args, args_hash, overrides_rule_ids, granted_by, created_at, expires_at, revoked_at, revoked_by, revoked_reason)
SELECT id, source_pending_call_id, workspace_id, agent_id, project_id, backend_slug,
  tool, match_args, args_hash, overrides_rule_ids, granted_by, granted_at, expires_at, revoked_at, revoked_by, revoked_reason
  FROM mcpflow_policy_grant;
INSERT INTO mcpflow_migration_note (migration_id, note)
SELECT '0010_policy_grant', json_object('grants_with_use_limit_dropped', count(*))
  FROM mcpflow_policy_grant WHERE max_uses IS NOT NULL HAVING count(*) > 0;

-- DROP TABLE runs an implicit DELETE; with FKs on, rows still referenced by pending_call.grant_id
-- would leave deferred violations that a later RENAME does not clear. Detach, swap, re-attach.
CREATE TEMP TABLE mcpflow_tmp_grant_ref AS
  SELECT id, grant_id FROM mcpflow_pending_call WHERE grant_id IS NOT NULL;
UPDATE mcpflow_pending_call SET grant_id = NULL WHERE grant_id IS NOT NULL;
DROP TABLE mcpflow_policy_grant;
ALTER TABLE mcpflow_policy_grant_new RENAME TO mcpflow_policy_grant;
UPDATE mcpflow_pending_call
   SET grant_id = (SELECT grant_id FROM temp.mcpflow_tmp_grant_ref r WHERE r.id = mcpflow_pending_call.id)
 WHERE id IN (SELECT id FROM temp.mcpflow_tmp_grant_ref);
DROP TABLE temp.mcpflow_tmp_grant_ref;

CREATE INDEX mcpflow_policy_grant_live ON mcpflow_policy_grant (agent_id, project_id, backend_slug, tool)
  WHERE revoked_at IS NULL;

CREATE TRIGGER mcpflow_policy_grant_ins_granter BEFORE INSERT ON mcpflow_policy_grant
WHEN NEW.granted_by = NEW.agent_id OR NOT EXISTS (
  SELECT 1 FROM mcpflow_agent WHERE id = NEW.granted_by AND kind = 'human' AND status = 'active')
BEGIN SELECT RAISE(ABORT, 'granted_by must be an active human agent other than the grantee'); END;

CREATE TRIGGER mcpflow_policy_grant_ins_source BEFORE INSERT ON mcpflow_policy_grant
WHEN NOT EXISTS (SELECT 1 FROM mcpflow_pending_call p
                  WHERE p.id = NEW.source_pending_call_id AND p.status = 'approved'
                    AND p.decided_by = NEW.granted_by AND p.agent_id = NEW.agent_id
                    AND p.backend_slug = NEW.backend_slug AND p.tool = NEW.tool
                    AND p.project_id = NEW.project_id)
BEGIN SELECT RAISE(ABORT, 'grant must derive from a call the same human approved, same scope'); END;

CREATE TRIGGER mcpflow_policy_grant_ins_fresh BEFORE INSERT ON mcpflow_policy_grant
WHEN NEW.revoked_at IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'grant must be inserted live'); END;

CREATE TRIGGER mcpflow_policy_grant_no_delete BEFORE DELETE ON mcpflow_policy_grant
BEGIN SELECT RAISE(ABORT, 'grants are revoked, never deleted'); END;

-- only revoked_at/by/reason may change, once
CREATE TRIGGER mcpflow_policy_grant_immutable BEFORE UPDATE ON mcpflow_policy_grant
WHEN NEW.id IS NOT OLD.id OR NEW.source_pending_call_id IS NOT OLD.source_pending_call_id
  OR NEW.workspace_id IS NOT OLD.workspace_id OR NEW.agent_id IS NOT OLD.agent_id
  OR NEW.project_id IS NOT OLD.project_id OR NEW.backend_slug IS NOT OLD.backend_slug
  OR NEW.tool IS NOT OLD.tool OR NEW.match_args IS NOT OLD.match_args
  OR NEW.args_hash IS NOT OLD.args_hash OR NEW.overrides_rule_ids IS NOT OLD.overrides_rule_ids
  OR NEW.granted_by IS NOT OLD.granted_by OR NEW.created_at IS NOT OLD.created_at
  OR NEW.expires_at IS NOT OLD.expires_at
  OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS NOT OLD.revoked_at
      OR NEW.revoked_by IS NOT OLD.revoked_by OR NEW.revoked_reason IS NOT OLD.revoked_reason))
BEGIN SELECT RAISE(ABORT, 'grant snapshot immutable; revocation terminal'); END;

-- 0005 behaviour, recreated against the new table
CREATE TRIGGER mcpflow_grant_revoke_on_rule_change AFTER UPDATE ON mcpflow_policy_rule
WHEN NEW.current_version IS NOT OLD.current_version OR NEW.enabled IS NOT OLD.enabled
  OR NEW.retired_at IS NOT OLD.retired_at
BEGIN
  UPDATE mcpflow_policy_grant
     SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
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
  UPDATE mcpflow_policy_grant
     SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), revoked_by = NEW.id,
         revoked_reason = 'granter no longer active'
   WHERE revoked_at IS NULL AND granted_by = NEW.id;
END;

-- live grants as the evaluator sees them (a live grant counts as allow; never overrides deny)
CREATE VIEW mcpflow_live_policy_grant AS
SELECT * FROM mcpflow_policy_grant
 WHERE revoked_at IS NULL AND strftime('%Y-%m-%dT%H:%M:%fZ','now') < expires_at;
`;

/** Manual/dev rollback only. Restored grants get max_uses NULL, use_count 0. */
export const MIGRATION_0010_DOWN = `
PRAGMA defer_foreign_keys = ON;
DROP VIEW mcpflow_live_policy_grant;
DROP TRIGGER mcpflow_grant_revoke_on_rule_change;
DROP TRIGGER mcpflow_grant_revoke_on_granter_inactive;
DROP TRIGGER mcpflow_policy_grant_ins_granter;
DROP TRIGGER mcpflow_policy_grant_ins_source;
DROP TRIGGER mcpflow_policy_grant_ins_fresh;
DROP TRIGGER mcpflow_policy_grant_no_delete;
DROP TRIGGER mcpflow_policy_grant_immutable;
DROP INDEX mcpflow_policy_grant_live;
ALTER TABLE mcpflow_policy_grant RENAME TO mcpflow_approval_grant;  -- pending_call FK follows
CREATE TABLE mcpflow_approval_grant_new (
  id                     TEXT PRIMARY KEY CHECK (length(id) = 28 AND substr(id, 1, 4) = 'grt_' AND substr(id, 5) NOT GLOB '*[^0-9a-f]*'),
  source_pending_call_id TEXT NOT NULL REFERENCES mcpflow_pending_call(id),
  workspace_id           TEXT NOT NULL,
  agent_id               TEXT NOT NULL REFERENCES mcpflow_agent(id),
  project_id             TEXT NOT NULL,
  backend_slug           TEXT NOT NULL,
  tool                   TEXT NOT NULL,
  match_args             TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(match_args) AND json_type(match_args) = 'array'),
  args_hash              TEXT,
  overrides_rule_ids     TEXT NOT NULL CHECK (json_valid(overrides_rule_ids) AND json_type(overrides_rule_ids) = 'array' AND json_array_length(overrides_rule_ids) > 0),
  granted_by             TEXT NOT NULL REFERENCES mcpflow_agent(id),
  granted_at             TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  expires_at             TEXT NOT NULL,
  max_uses               INTEGER CHECK (max_uses >= 1),
  use_count              INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
  revoked_at             TEXT,
  revoked_by             TEXT REFERENCES mcpflow_agent(id),
  revoked_reason         TEXT,
  CHECK (expires_at > granted_at AND ((julianday(expires_at) - julianday(granted_at)) * 86400.0) <= 3600.001),
  CHECK (max_uses IS NULL OR use_count <= max_uses),
  CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
) STRICT;
INSERT INTO mcpflow_approval_grant_new (id, source_pending_call_id, workspace_id, agent_id, project_id, backend_slug,
  tool, match_args, args_hash, overrides_rule_ids, granted_by, granted_at, expires_at, max_uses, use_count,
  revoked_at, revoked_by, revoked_reason)
SELECT id, source_pending_call_id, workspace_id, agent_id, project_id, backend_slug,
  tool, match_args, args_hash, overrides_rule_ids, granted_by, created_at, expires_at, NULL, 0,
  revoked_at, revoked_by, revoked_reason
  FROM mcpflow_approval_grant;
CREATE TEMP TABLE mcpflow_tmp_grant_ref AS
  SELECT id, grant_id FROM mcpflow_pending_call WHERE grant_id IS NOT NULL;
UPDATE mcpflow_pending_call SET grant_id = NULL WHERE grant_id IS NOT NULL;
DROP TABLE mcpflow_approval_grant;
ALTER TABLE mcpflow_approval_grant_new RENAME TO mcpflow_approval_grant;
UPDATE mcpflow_pending_call
   SET grant_id = (SELECT grant_id FROM temp.mcpflow_tmp_grant_ref r WHERE r.id = mcpflow_pending_call.id)
 WHERE id IN (SELECT id FROM temp.mcpflow_tmp_grant_ref);
DROP TABLE temp.mcpflow_tmp_grant_ref;

-- branch 0003 grant index + triggers, verbatim
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
WHEN NEW.use_count > OLD.use_count AND (OLD.revoked_at IS NOT NULL OR strftime('%Y-%m-%dT%H:%M:%fZ','now') >= OLD.expires_at)
BEGIN SELECT RAISE(ABORT, 'grant not live'); END;


-- branch 0005 triggers, verbatim

CREATE TRIGGER mcpflow_grant_revoke_on_rule_change AFTER UPDATE ON mcpflow_policy_rule
WHEN NEW.current_version IS NOT OLD.current_version OR NEW.enabled IS NOT OLD.enabled
  OR NEW.retired_at IS NOT OLD.retired_at
BEGIN
  UPDATE mcpflow_approval_grant
     SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
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
     SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), revoked_by = NEW.id, revoked_reason = 'granter no longer active'
   WHERE revoked_at IS NULL AND granted_by = NEW.id;
END;
`;
