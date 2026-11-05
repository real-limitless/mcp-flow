/**
 * mcpflow_call_payload (Secrets §0.6 / A1).
 * Insert-only. The body is the scrubbed ref-form, encrypted under audit-enc with AAD
 * call_id + phase. Hashes stay on call_audit. Reveal results are not stored.
 * Reads and the 90-day purge are maintenance/admin paths; each read writes payload_read.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { PolicyKeys } from "../identity/dev-keys.js";
import { incrementalVacuum, type IncrementalVacuumResult } from "../db/maintenance.js";
import { auditActor } from "./call-audit-cols.js";
import { argsHash } from "../policy/crypto.js";
import { PAYLOAD_MAX_BYTES, redactBeforePersist, type PersistRedaction } from "./redact-persist.js";

export const PAYLOAD_RETENTION_DAYS = 90;
const IV = 12;
const TAG = 16;

export type PayloadPhase = "request" | "result";

export function isRevealTool(tool: string | null | undefined): boolean {
  if (!tool) return false;
  return tool === "mf_secret_reveal" || tool.endsWith("__mf_secret_reveal");
}

export function payloadAad(callId: string, phase: PayloadPhase): Buffer {
  return Buffer.from(`mcp-flow/audit-payload/v1|${callId}|${phase}`, "utf8");
}

export function encryptCallPayload(key: Buffer, callId: string, phase: PayloadPhase, json: string): Buffer {
  if (key.length !== 32) throw new Error("audit-enc key must be 32 bytes");
  const iv = randomBytes(IV);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(payloadAad(callId, phase));
  const ct = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

export function decryptCallPayload(key: Buffer, callId: string, phase: PayloadPhase, blob: Uint8Array): unknown {
  if (key.length !== 32) throw new Error("audit-enc key must be 32 bytes");
  const buf = Buffer.from(blob);
  const decipher = createDecipheriv("aes-256-gcm", key, buf.subarray(0, IV));
  decipher.setAAD(payloadAad(callId, phase));
  decipher.setAuthTag(buf.subarray(IV, IV + TAG));
  const pt = Buffer.concat([decipher.update(buf.subarray(IV + TAG)), decipher.final()]);
  return JSON.parse(pt.toString("utf8")) as unknown;
}

export interface PreparedPayload {
  skip: boolean;
  red: PersistRedaction;
  /** Columns for the call_audit row. Hashes stay here after the payload is purged. */
  fields: Record<string, unknown>;
}

/** Redact and describe the audit columns. Does not write. */
export function prepareCallPayload(keys: PolicyKeys, phase: PayloadPhase, body: unknown, tool?: string | null): PreparedPayload {
  if (phase === "result" && isRevealTool(tool)) {
    return { skip: true, red: redactBeforePersist({ withheld: "reveal" }), fields: {} };
  }
  const red = redactBeforePersist(body);
  const hash = argsHash(keys.argsHmac, red.value);
  const fields: Record<string, unknown> = {
    scrub_count: red.scrubCount,
    redaction_flags: JSON.stringify(red.flags),
    payload_truncated: red.truncated || red.withheld ? 1 : 0,
    secret_refs_json: JSON.stringify(red.secretRefs),
  };
  if (phase === "request") fields.request_payload_hash = hash;
  else fields.result_hash = hash;
  return { skip: false, red, fields };
}

export function insertCallPayload(
  db: DatabaseSync,
  keys: PolicyKeys,
  opts: { callId: string; phase: PayloadPhase; workspaceId: string; red: PersistRedaction; createdAt?: string },
): void {
  const json = JSON.stringify(opts.red.value);
  if (json == null) throw new Error("call payload did not serialize");
  const byteLen = Buffer.byteLength(json, "utf8");
  if (byteLen > PAYLOAD_MAX_BYTES) throw new Error("call payload exceeds 64KiB");
  const blob = encryptCallPayload(keys.auditEnc, opts.callId, opts.phase, json);
  db.prepare(
    `INSERT INTO mcpflow_call_payload (
       call_id, phase, workspace_id, created_at, ciphertext, key_ref, truncated, plaintext_suspected, byte_len
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    opts.callId,
    opts.phase,
    opts.workspaceId,
    opts.createdAt ?? new Date().toISOString(),
    blob,
    keys.keyRef,
    opts.red.truncated || opts.red.withheld ? 1 : 0,
    opts.red.plaintextSuspected || opts.red.withheld ? 1 : 0,
    byteLen,
  );
}

export interface StoredPayload {
  callId: string;
  phase: PayloadPhase;
  truncated: boolean;
  plaintextSuspected: boolean;
  body: unknown;
}

function assertHumanAdmin(db: DatabaseSync, workspaceId: string, actor: string): void {
  const id = auditActor(actor);
  const row = db
    .prepare(
      `SELECT 1 AS ok FROM mcpflow_agent
        WHERE id = ? AND workspace_id = ? AND kind = 'human' AND is_admin = 1 AND status = 'active'`,
    )
    .get(id, workspaceId) as { ok: number } | undefined;
  if (!row) throw new Error("call payload requires an active human admin");
}

export function readCallPayload(
  db: DatabaseSync,
  keys: PolicyKeys,
  opts: { workspaceId: string; callId: string; phase: PayloadPhase; actor: string },
): StoredPayload {
  assertHumanAdmin(db, opts.workspaceId, opts.actor);
  const row = db
    .prepare(
      `SELECT ciphertext, key_ref, truncated, plaintext_suspected
         FROM mcpflow_call_payload WHERE call_id = ? AND phase = ? AND workspace_id = ?`,
    )
    .get(opts.callId, opts.phase, opts.workspaceId) as
    | { ciphertext: Uint8Array; key_ref: string; truncated: number; plaintext_suspected: number }
    | undefined;
  if (!row) throw new Error("call payload not found");
  if (row.key_ref !== keys.keyRef) throw new Error("call payload key ref does not match the current audit key");
  const body = decryptCallPayload(keys.auditEnc, opts.callId, opts.phase, row.ciphertext);
  recordPayloadLifecycle(db, {
    workspaceId: opts.workspaceId,
    actor: opts.actor,
    action: "payload_read",
    callId: opts.callId,
    detail: { phase: opts.phase, call_id: opts.callId },
  });
  return {
    callId: opts.callId,
    phase: opts.phase,
    truncated: row.truncated === 1,
    plaintextSuspected: row.plaintext_suspected === 1,
    body,
  };
}

function recordPayloadLifecycle(
  db: DatabaseSync,
  opts: { workspaceId: string; actor: string; action: "payload_read" | "payload_purge"; callId: string; detail: Record<string, unknown> },
): void {
  db.prepare(
    `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, lifecycle_action, actor, args_redacted)
     VALUES ('lifecycle', ?, ?, ?, ?, ?)`,
  ).run(opts.callId, opts.workspaceId, opts.action, auditActor(opts.actor), JSON.stringify(opts.detail));
}

export function payloadRetentionCutoff(now: Date, days = PAYLOAD_RETENTION_DAYS): string {
  if (!Number.isInteger(days) || days < 1) throw new Error("payload retention days must be an integer ≥ 1");
  return new Date(now.getTime() - days * 86_400_000).toISOString();
}

export interface PayloadPurgeResult {
  dryRun: boolean;
  before: string;
  rows: number;
  vacuum?: IncrementalVacuumResult;
}

/**
 * Delete payload ciphertext older than `before`. Dry-run unless execute is set.
 * Writes one lifecycle row (date range, row count). Then checkpoint and incremental_vacuum.
 * call_audit rows are not deleted.
 */
export function purgeCallPayloads(
  db: DatabaseSync,
  opts: { workspaceId: string; before: string; actor: string; execute?: boolean },
): PayloadPurgeResult {
  assertHumanAdmin(db, opts.workspaceId, opts.actor);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.test(opts.before)) {
    throw new Error("before must be an ISO-8601 UTC timestamp");
  }
  const count = Number(
    (db.prepare(`SELECT count(*) AS n FROM mcpflow_call_payload WHERE workspace_id = ? AND created_at < ?`).get(opts.workspaceId, opts.before) as { n: number }).n,
  );
  if (opts.execute !== true) return { dryRun: true, before: opts.before, rows: count };
  const trig = db.prepare(`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'mcpflow_call_payload_no_delete'`).get() as { sql: string } | undefined;
  if (!trig) throw new Error("missing trigger mcpflow_call_payload_no_delete");
  db.exec("BEGIN IMMEDIATE;");
  let deleted = 0;
  try {
    db.exec("DROP TRIGGER mcpflow_call_payload_no_delete;");
    deleted = Number(
      db.prepare(`DELETE FROM mcpflow_call_payload WHERE workspace_id = ? AND created_at < ?`).run(opts.workspaceId, opts.before).changes,
    );
    db.exec(trig.sql.endsWith(";") ? trig.sql : `${trig.sql};`);
    recordPayloadLifecycle(db, {
      workspaceId: opts.workspaceId,
      actor: opts.actor,
      action: "payload_purge",
      callId: `lc_${randomBytes(12).toString("hex")}`,
      detail: { before: opts.before, rows: deleted, retention_days: PAYLOAD_RETENTION_DAYS },
    });
    db.exec("COMMIT;");
  } catch (err) {
    try {
      if (db.isTransaction) db.exec("ROLLBACK;");
    } catch {
      /* keep the original error */
    }
    throw err;
  }
  try {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  } catch {
    /* in-memory databases have no wal file to truncate */
  }
  const vacuum = incrementalVacuum(db);
  return { dryRun: false, before: opts.before, rows: deleted, vacuum };
}
