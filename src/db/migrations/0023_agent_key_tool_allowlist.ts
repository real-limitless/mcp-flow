/**
 * 0023_agent_key_tool_allowlist (issue #76).
 * Optional tool-name prefixes on an agent key. Null means no extra prefix filter
 * (project membership still applies). The value is a JSON array of strings, never a secret.
 * DOWN refuses while any key still has a list set, then drops the column and its epoch trigger.
 */
export const MIGRATION_0023 = `
ALTER TABLE mcpflow_api_key ADD COLUMN tool_prefix_allowlist TEXT
  CHECK (
    tool_prefix_allowlist IS NULL
    OR (json_valid(tool_prefix_allowlist) AND json_type(tool_prefix_allowlist) = 'array')
  );

CREATE TRIGGER mcpflow_epoch_key_allowlist AFTER UPDATE OF tool_prefix_allowlist ON mcpflow_api_key
BEGIN UPDATE mcpflow_identity_epoch SET epoch = epoch + 1 WHERE id = 1; END;
`;

export const MIGRATION_0023_DOWN = `
CREATE TEMP TABLE mcpflow_0023_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0023_down_guard (n)
  SELECT count(*) FROM mcpflow_api_key WHERE tool_prefix_allowlist IS NOT NULL;
DROP TRIGGER mcpflow_epoch_key_allowlist;
ALTER TABLE mcpflow_api_key DROP COLUMN tool_prefix_allowlist;
DROP TABLE mcpflow_0023_down_guard;
`;
