/**
 * 0015_call_payload (Secrets A1, §0.6).
 * mcpflow_call_payload is insert-only ciphertext (call_id, phase). Hashes stay on call_audit.
 * Purge is the CLI maintenance path, which drops the no-delete trigger for that statement only.
 * DOWN refuses while any ciphertext row remains (it would drop the blob).
 * 0016–0019 stay reserved for later Secrets phases. Do not edit 0001–0014.
 */
import { NOW } from "./sql-helpers.js";

export const CALL_PAYLOAD_NO_DELETE_TRIGGER = `CREATE TRIGGER mcpflow_call_payload_no_delete BEFORE DELETE ON mcpflow_call_payload
BEGIN SELECT RAISE(ABORT, 'call_payload purge is maintenance-only'); END;`;

export const MIGRATION_0015 = `
-- 0015_call_payload: encrypted scrubbed ref-form, separate from append-only call_audit
ALTER TABLE mcpflow_call_audit ADD COLUMN request_payload_hash TEXT;
ALTER TABLE mcpflow_call_audit ADD COLUMN result_hash TEXT;
ALTER TABLE mcpflow_call_audit ADD COLUMN scrub_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mcpflow_call_audit ADD COLUMN redaction_flags TEXT;
ALTER TABLE mcpflow_call_audit ADD COLUMN payload_truncated INTEGER NOT NULL DEFAULT 0 CHECK (payload_truncated IN (0, 1));
ALTER TABLE mcpflow_call_audit ADD COLUMN secret_refs_json TEXT CHECK (secret_refs_json IS NULL OR json_valid(secret_refs_json));

CREATE TABLE mcpflow_call_payload (
  call_id              TEXT NOT NULL,
  phase                TEXT NOT NULL CHECK (phase IN ('request', 'result')),
  workspace_id         TEXT NOT NULL REFERENCES mcpflow_workspace(id) ON DELETE RESTRICT,
  created_at           TEXT NOT NULL DEFAULT (${NOW}),
  ciphertext           BLOB NOT NULL,
  key_ref              TEXT NOT NULL,
  truncated            INTEGER NOT NULL CHECK (truncated IN (0, 1)),
  plaintext_suspected  INTEGER NOT NULL CHECK (plaintext_suspected IN (0, 1)),
  byte_len             INTEGER NOT NULL CHECK (byte_len >= 0 AND byte_len <= 65536),
  PRIMARY KEY (call_id, phase)
) STRICT;

CREATE INDEX mcpflow_call_payload_created ON mcpflow_call_payload (created_at);
CREATE INDEX mcpflow_call_payload_workspace ON mcpflow_call_payload (workspace_id, created_at);

CREATE TRIGGER mcpflow_call_payload_needs_decision BEFORE INSERT ON mcpflow_call_payload
WHEN NOT EXISTS (
  SELECT 1 FROM mcpflow_call_audit WHERE call_id = NEW.call_id AND event_type = 'decision'
)
BEGIN SELECT RAISE(ABORT, 'call_payload requires a decision audit row'); END;

CREATE TRIGGER mcpflow_call_payload_no_update BEFORE UPDATE ON mcpflow_call_payload
BEGIN SELECT RAISE(ABORT, 'call_payload is insert-only'); END;

${CALL_PAYLOAD_NO_DELETE_TRIGGER}
`;

/**
 * Manual rollback. The guard aborts the statement when any ciphertext row exists,
 * so a down-migration cannot drop stored payloads.
 */
export const MIGRATION_0015_DOWN = `
CREATE TEMP TABLE mcpflow_0015_down_guard (n INTEGER CHECK (n = 0));
INSERT INTO mcpflow_0015_down_guard (n) SELECT count(*) FROM mcpflow_call_payload;
DROP TABLE mcpflow_call_payload;
ALTER TABLE mcpflow_call_audit DROP COLUMN secret_refs_json;
ALTER TABLE mcpflow_call_audit DROP COLUMN payload_truncated;
ALTER TABLE mcpflow_call_audit DROP COLUMN redaction_flags;
ALTER TABLE mcpflow_call_audit DROP COLUMN scrub_count;
ALTER TABLE mcpflow_call_audit DROP COLUMN result_hash;
ALTER TABLE mcpflow_call_audit DROP COLUMN request_payload_hash;
DROP TABLE mcpflow_0015_down_guard;
`;
