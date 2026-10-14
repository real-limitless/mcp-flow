/**
 * Migration 0004 — link Web Push subscriptions to human approver agents (T2.4).
 * push_subscriptions is a legacy (pre-mcpflow_*) table; this only adds a nullable column.
 */
export const MIGRATION_0004 = `
-- same shape as the legacy SCHEMA definition; no-op when the gateway Store already created it
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  operator_key_id TEXT NOT NULL DEFAULT '',
  endpoint TEXT NOT NULL,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(endpoint)
);
ALTER TABLE push_subscriptions ADD COLUMN agent_id TEXT REFERENCES mcpflow_agent(id);
CREATE INDEX IF NOT EXISTS push_subscriptions_agent ON push_subscriptions(workspace_id, agent_id);

CREATE TRIGGER mcpflow_push_sub_agent_human_ins BEFORE INSERT ON push_subscriptions
WHEN NEW.agent_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM mcpflow_agent WHERE id = NEW.agent_id AND kind = 'human')
BEGIN SELECT RAISE(ABORT, 'push subscription agent must be a human agent'); END;

CREATE TRIGGER mcpflow_push_sub_agent_human_upd BEFORE UPDATE OF agent_id ON push_subscriptions
WHEN NEW.agent_id IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM mcpflow_agent WHERE id = NEW.agent_id AND kind = 'human')
BEGIN SELECT RAISE(ABORT, 'push subscription agent must be a human agent'); END;
`;
