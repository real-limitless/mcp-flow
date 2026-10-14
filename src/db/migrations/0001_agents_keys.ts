/**
 * Migration 0001 — agents, keys, sessions (T1.1 §8, db-t1.2-agents-keys.md).
 * SQLite variant of the reference Postgres DDL: mcpflow_* STRICT tables,
 * ISO-8601 UTC TEXT timestamps, enum CHECKs, state rules as RAISE(ABORT) triggers.
 */
import { NOW, idCheck } from "./sql-helpers.js";

export const MIGRATION_0001 = `
CREATE TABLE mcpflow_workspace (
  id                 TEXT PRIMARY KEY CHECK (${idCheck("id", "ws_")}),
  owner_principal_id TEXT NOT NULL
                     REFERENCES mcpflow_agent(id) DEFERRABLE INITIALLY DEFERRED,
  created_at         TEXT NOT NULL DEFAULT (${NOW})
) STRICT;

CREATE TABLE mcpflow_agent (
  id             TEXT PRIMARY KEY CHECK (${idCheck("id", "agt_")}),
  workspace_id   TEXT NOT NULL REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT
                 DEFERRABLE INITIALLY DEFERRED,
  name           TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  owner          TEXT NOT NULL,
  kind           TEXT NOT NULL CHECK (kind IN ('grokbot','cloud_agent','human','service')),
  is_admin       INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0,1)),
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','revoked')),
  created_at     TEXT NOT NULL DEFAULT (${NOW}),
  updated_at     TEXT NOT NULL DEFAULT (${NOW}),
  revoked_at     TEXT,
  created_by     TEXT REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  revoked_by     TEXT REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  revoked_reason TEXT,
  UNIQUE (workspace_id, name),
  CHECK (NOT is_admin OR kind = 'human'),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CHECK (revoked_at IS NULL OR (revoked_by IS NOT NULL AND revoked_reason IS NOT NULL))
) STRICT;

CREATE TABLE mcpflow_agent_project (
  agent_id   TEXT NOT NULL REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  project_id TEXT NOT NULL,
  PRIMARY KEY (agent_id, project_id)
) STRICT;

CREATE TABLE mcpflow_api_key (
  id                 TEXT PRIMARY KEY CHECK (${idCheck("id", "key_")}),
  agent_id           TEXT NOT NULL REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  prefix             TEXT NOT NULL UNIQUE CHECK (length(prefix) = 12),
  secret_hash        TEXT NOT NULL UNIQUE,
  status             TEXT NOT NULL DEFAULT 'active'
                     CHECK (status IN ('active','rotating','revoked','expired')),
  predecessor_key_id TEXT REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  valid_from         TEXT NOT NULL DEFAULT (${NOW}),
  expires_at         TEXT NOT NULL,
  last_used_at       TEXT,
  last_used_ip       TEXT,
  created_at         TEXT NOT NULL DEFAULT (${NOW}),
  created_by         TEXT NOT NULL REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  revoked_at         TEXT,
  revoked_by         TEXT REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  revoked_reason     TEXT,
  CHECK (expires_at > valid_from),
  CHECK (julianday(expires_at) - julianday(created_at) <= 365.0001),
  CHECK (predecessor_key_id IS NULL OR predecessor_key_id <> id),
  CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
  CHECK (revoked_at IS NULL OR (revoked_by IS NOT NULL AND revoked_reason IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX mcpflow_api_key_one_successor ON mcpflow_api_key(predecessor_key_id)
  WHERE predecessor_key_id IS NOT NULL;
CREATE INDEX mcpflow_api_key_agent_live ON mcpflow_api_key(agent_id)
  WHERE status IN ('active','rotating');

CREATE TABLE mcpflow_api_key_project (
  key_id     TEXT NOT NULL REFERENCES mcpflow_api_key(id) ON DELETE CASCADE,
  agent_id   TEXT NOT NULL,
  project_id TEXT NOT NULL,
  PRIMARY KEY (key_id, project_id),
  FOREIGN KEY (agent_id, project_id)
    REFERENCES mcpflow_agent_project(agent_id, project_id) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER mcpflow_api_key_project_agent BEFORE INSERT ON mcpflow_api_key_project
WHEN (SELECT agent_id FROM mcpflow_api_key WHERE id = NEW.key_id) IS NOT NEW.agent_id
BEGIN SELECT RAISE(ABORT, 'api_key_project agent must own key'); END;

-- api_key: predecessor same agent; at most 2 live keys per agent
CREATE TRIGGER mcpflow_api_key_ins_pred BEFORE INSERT ON mcpflow_api_key
WHEN NEW.predecessor_key_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM mcpflow_api_key p WHERE p.id = NEW.predecessor_key_id AND p.agent_id = NEW.agent_id)
BEGIN SELECT RAISE(ABORT, 'predecessor key must belong to the same agent'); END;

CREATE TRIGGER mcpflow_api_key_ins_cap BEFORE INSERT ON mcpflow_api_key
WHEN NEW.status IN ('active','rotating') AND (
  SELECT count(*) FROM mcpflow_api_key
   WHERE agent_id = NEW.agent_id AND status IN ('active','rotating')) >= 2
BEGIN SELECT RAISE(ABORT, 'agent already has 2 live keys (T1.1 limit)'); END;

CREATE TRIGGER mcpflow_api_key_upd_identity BEFORE UPDATE ON mcpflow_api_key
WHEN NEW.secret_hash IS NOT OLD.secret_hash OR NEW.prefix IS NOT OLD.prefix
  OR NEW.agent_id IS NOT OLD.agent_id OR NEW.valid_from IS NOT OLD.valid_from
  OR NEW.id IS NOT OLD.id OR NEW.created_at IS NOT OLD.created_at
  OR NEW.created_by IS NOT OLD.created_by
  OR NEW.predecessor_key_id IS NOT OLD.predecessor_key_id
BEGIN SELECT RAISE(ABORT, 'api_key identity columns are immutable'); END;

CREATE TRIGGER mcpflow_api_key_upd_expiry BEFORE UPDATE ON mcpflow_api_key
WHEN NEW.expires_at > OLD.expires_at
  AND NOT (OLD.status = 'rotating' AND NEW.status = 'rotating')
BEGIN SELECT RAISE(ABORT, 'expires_at may only be extended on a rotating key'); END;

CREATE TRIGGER mcpflow_api_key_upd_revoked BEFORE UPDATE ON mcpflow_api_key
WHEN OLD.status = 'revoked' AND (NEW.status <> 'revoked'
  OR NEW.revoked_at IS NOT OLD.revoked_at OR NEW.revoked_by IS NOT OLD.revoked_by)
BEGIN SELECT RAISE(ABORT, 'revoked is terminal (T1.1 §8.1)'); END;

CREATE TRIGGER mcpflow_api_key_upd_cap BEFORE UPDATE OF status ON mcpflow_api_key
WHEN NEW.status IN ('active','rotating') AND OLD.status NOT IN ('active','rotating') AND (
  SELECT count(*) FROM mcpflow_api_key
   WHERE agent_id = NEW.agent_id AND status IN ('active','rotating') AND id <> NEW.id) >= 2
BEGIN SELECT RAISE(ABORT, 'agent already has 2 live keys (T1.1 limit)'); END;

CREATE TRIGGER mcpflow_api_key_no_delete BEFORE DELETE ON mcpflow_api_key
BEGIN SELECT RAISE(ABORT, 'api keys are revoked, never deleted'); END;

-- agent: revoked terminal; kind/workspace immutable; never deleted; admin only human
CREATE TRIGGER mcpflow_agent_upd_revoked BEFORE UPDATE ON mcpflow_agent
WHEN OLD.status = 'revoked' AND NEW.status <> 'revoked'
BEGIN SELECT RAISE(ABORT, 'revoked is terminal (T1.1 §8.1)'); END;

CREATE TRIGGER mcpflow_agent_upd_immutable BEFORE UPDATE ON mcpflow_agent
WHEN NEW.kind IS NOT OLD.kind OR NEW.workspace_id IS NOT OLD.workspace_id OR NEW.id IS NOT OLD.id
BEGIN SELECT RAISE(ABORT, 'agent kind/workspace are immutable'); END;

CREATE TRIGGER mcpflow_agent_touch AFTER UPDATE ON mcpflow_agent
WHEN NEW.updated_at IS OLD.updated_at
BEGIN UPDATE mcpflow_agent SET updated_at = ${NOW} WHERE id = NEW.id; END;

CREATE TRIGGER mcpflow_agent_no_delete BEFORE DELETE ON mcpflow_agent
BEGIN SELECT RAISE(ABORT, 'agents are revoked, never deleted'); END;

-- sessions (mf_sess_*), hash only
CREATE TABLE mcpflow_session (
  id          TEXT PRIMARY KEY CHECK (substr(id, 1, 8) = 'mf_sess_'),
  token_hash  TEXT NOT NULL UNIQUE,
  agent_id    TEXT NOT NULL REFERENCES mcpflow_agent(id) ON DELETE RESTRICT,
  key_id      TEXT NOT NULL REFERENCES mcpflow_api_key(id) ON DELETE RESTRICT,
  project_id  TEXT NOT NULL,
  created_at  TEXT NOT NULL DEFAULT (${NOW}),
  expires_at  TEXT NOT NULL,
  revoked_at  TEXT,
  CHECK (expires_at > created_at)
) STRICT;
CREATE INDEX mcpflow_session_key_live   ON mcpflow_session(key_id)   WHERE revoked_at IS NULL;
CREATE INDEX mcpflow_session_agent_live ON mcpflow_session(agent_id) WHERE revoked_at IS NULL;

CREATE TRIGGER mcpflow_session_ins_owner BEFORE INSERT ON mcpflow_session
WHEN (SELECT agent_id FROM mcpflow_api_key WHERE id = NEW.key_id) IS NOT NEW.agent_id
BEGIN SELECT RAISE(ABORT, 'session agent must own key'); END;

-- expiry = min(session ttl, key.expires_at); SQLite cannot assign NEW, so clamp after insert
CREATE TRIGGER mcpflow_session_ins_clamp AFTER INSERT ON mcpflow_session
WHEN NEW.expires_at > (SELECT expires_at FROM mcpflow_api_key WHERE id = NEW.key_id)
BEGIN
  UPDATE mcpflow_session SET expires_at = (SELECT expires_at FROM mcpflow_api_key WHERE id = NEW.key_id)
   WHERE id = NEW.id;
END;

CREATE TRIGGER mcpflow_session_upd_guard BEFORE UPDATE ON mcpflow_session
WHEN NEW.id IS NOT OLD.id OR NEW.token_hash IS NOT OLD.token_hash
  OR NEW.agent_id IS NOT OLD.agent_id OR NEW.key_id IS NOT OLD.key_id
  OR NEW.project_id IS NOT OLD.project_id
  OR NEW.expires_at > OLD.expires_at
  OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN SELECT RAISE(ABORT, 'session identity immutable; expiry shorten-only; revoke terminal'); END;

CREATE TRIGGER mcpflow_api_key_revoke_sessions AFTER UPDATE OF status ON mcpflow_api_key
WHEN NEW.status = 'revoked' AND OLD.status <> 'revoked'
BEGIN
  UPDATE mcpflow_session SET revoked_at = ${NOW} WHERE key_id = NEW.id AND revoked_at IS NULL;
END;

CREATE TRIGGER mcpflow_agent_revoke_sessions AFTER UPDATE OF status ON mcpflow_agent
WHEN NEW.status IN ('revoked','suspended') AND OLD.status = 'active'
BEGIN
  UPDATE mcpflow_session SET revoked_at = ${NOW} WHERE agent_id = NEW.id AND revoked_at IS NULL;
END;

-- resolution views (T1.3); "now" evaluated at query time
CREATE VIEW mcpflow_resolvable_key AS
SELECT k.id AS key_id, k.prefix, k.secret_hash, k.expires_at, k.status AS key_status,
       a.id AS agent_id, a.name AS agent_name, a.owner, a.workspace_id, a.kind, a.is_admin
  FROM mcpflow_api_key k JOIN mcpflow_agent a ON a.id = k.agent_id
 WHERE k.status IN ('active','rotating') AND a.status = 'active'
   AND ${NOW} >= k.valid_from AND ${NOW} < k.expires_at;

CREATE VIEW mcpflow_resolvable_session AS
SELECT s.id AS session_id, s.token_hash, s.project_id, s.expires_at, s.agent_id, s.key_id
  FROM mcpflow_session s
  JOIN mcpflow_api_key k ON k.id = s.key_id
  JOIN mcpflow_agent a ON a.id = s.agent_id
 WHERE s.revoked_at IS NULL AND ${NOW} < s.expires_at
   AND k.status IN ('active','rotating') AND ${NOW} < k.expires_at AND a.status = 'active';
`;
