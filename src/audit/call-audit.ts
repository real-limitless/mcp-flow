/**
 * T3.1 / T3.3 — read side and retention for mcpflow_call_audit (db-t3.1).
 * The write path lives in the policy enforcer (decision + completion rows) and the
 * agent directory (lifecycle rows). Nothing here UPDATEs or DELETEs call_audit rows (T2.1 §12): call_audit
 * is never deleted, not even by retention.
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, renameSync, rmSync, writeSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { incrementalVacuum, type IncrementalVacuumResult } from "../db/maintenance.js";

export interface CallAuditFilter {
  from?: string;
  to?: string;
  agentId?: string;
  keyId?: string;
  projectId?: string;
  backendSlug?: string;
  tool?: string;
  eventType?: "decision" | "completion" | "lifecycle" | "result_read" | "result_purge";
  policyDecision?: "allow" | "deny" | "require_approval";
  finalOutcome?: string;
  callId?: string;
  pendingCallId?: string;
}

/** snake_case args/query params -> filter (shared by MCP tools and REST). */
export function callAuditFilterFrom(a: Record<string, unknown>): CallAuditFilter {
  const s = (k: string) => (typeof a[k] === "string" && a[k] ? String(a[k]) : undefined);
  return {
    from: s("from"), to: s("to"), agentId: s("agent_id"), keyId: s("key_id"), projectId: s("project_id"),
    backendSlug: s("backend_slug"), tool: s("tool"),
    eventType: s("event_type") as CallAuditFilter["eventType"],
    policyDecision: s("policy_decision") as CallAuditFilter["policyDecision"],
    finalOutcome: s("final_outcome"), callId: s("call_id"), pendingCallId: s("pending_call_id"),
  };
}

export const QUERY_MAX_LIMIT = 500;
export const EXPORT_MAX_ROWS = 10_000;

export const CALL_AUDIT_COLUMNS = [
  "audit_id", "ts", "event_type", "call_id", "workspace_id", "agent_id", "agent_name", "key_id", "key_prefix",
  "project_id", "backend_slug", "tool", "qualified_tool", "placement", "device_id", "args_redacted", "args_hash",
  "policy_decision", "final_outcome", "rule_id", "rule_version", "matched_rule_ids", "grant_id", "pending_call_id",
  "approver", "approver_note", "latency_ms", "backend_latency_ms", "result_status", "error_code",
  "lifecycle_action", "actor",
] as const;

const FILTER_COLS: Array<[keyof CallAuditFilter, string]> = [
  ["agentId", "agent_id"], ["keyId", "key_id"], ["projectId", "project_id"], ["backendSlug", "backend_slug"],
  ["tool", "tool"], ["eventType", "event_type"], ["policyDecision", "policy_decision"],
  ["finalOutcome", "final_outcome"], ["callId", "call_id"], ["pendingCallId", "pending_call_id"],
];

function where(workspaceId: string, f: CallAuditFilter, cursor?: number): { sql: string; params: Array<string | number> } {
  const parts = ["workspace_id = ?"];
  const params: Array<string | number> = [workspaceId];
  for (const [k, col] of FILTER_COLS) {
    const v = f[k];
    if (v != null && v !== "") {
      parts.push(`${col} = ?`);
      params.push(String(v));
    }
  }
  if (f.from) {
    parts.push("ts >= ?");
    params.push(f.from);
  }
  if (f.to) {
    parts.push("ts < ?");
    params.push(f.to);
  }
  if (cursor != null) {
    parts.push("audit_id < ?");
    params.push(cursor);
  }
  return { sql: parts.join(" AND "), params };
}

export type CallAuditRow = Record<(typeof CALL_AUDIT_COLUMNS)[number], unknown>;

function decode(r: Record<string, unknown>): CallAuditRow {
  const out = { ...r } as Record<string, unknown>;
  for (const k of ["args_redacted", "matched_rule_ids"]) {
    if (typeof out[k] === "string") {
      try {
        out[k] = JSON.parse(out[k] as string);
      } catch {
        /* keep text */
      }
    }
  }
  return out as CallAuditRow;
}

/** Newest first, cursor = audit_id of the last row returned. */
export function queryCallAudit(
  db: DatabaseSync,
  workspaceId: string,
  filter: CallAuditFilter = {},
  opts: { limit?: number; cursor?: number } = {},
): { rows: CallAuditRow[]; nextCursor: number | null } {
  const limit = Math.min(Math.max(Math.floor(opts.limit ?? 100), 1), QUERY_MAX_LIMIT);
  const w = where(workspaceId, filter, opts.cursor);
  const rows = db
    .prepare(`SELECT ${CALL_AUDIT_COLUMNS.join(", ")} FROM mcpflow_call_audit WHERE ${w.sql} ORDER BY audit_id DESC LIMIT ?`)
    .all(...w.params, limit + 1) as Record<string, unknown>[];
  const page = rows.slice(0, limit).map(decode);
  const nextCursor = rows.length > limit ? Number(page.at(-1)!.audit_id) : null;
  return { rows: page, nextCursor };
}

function csvCell(v: unknown): string {
  if (v == null) return "";
  let s = typeof v === "string" ? v : JSON.stringify(v);
  // spreadsheet formula injection guard (strings only; leading whitespace and fullwidth forms too)
  if (typeof v === "string" && /^[\s\u3000]*[=+\-@\uFF1D\uFF0B\uFF0D\uFF20\t\r\n]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** Export (oldest first) as CSV or JSON. Rows are already redacted at write time. */
export function exportCallAudit(
  db: DatabaseSync,
  workspaceId: string,
  filter: CallAuditFilter,
  format: "csv" | "json",
  maxRows = EXPORT_MAX_ROWS,
): { body: string; rows: number; truncated: boolean; contentType: string } {
  const cap = Math.min(Math.max(maxRows, 1), EXPORT_MAX_ROWS);
  const w = where(workspaceId, filter);
  const raw = db
    .prepare(`SELECT ${CALL_AUDIT_COLUMNS.join(", ")} FROM mcpflow_call_audit WHERE ${w.sql} ORDER BY audit_id ASC LIMIT ?`)
    .all(...w.params, cap + 1) as Record<string, unknown>[];
  const truncated = raw.length > cap;
  const rows = raw.slice(0, cap).map(decode);
  if (format === "json") {
    return { body: JSON.stringify({ rows, truncated }), rows: rows.length, truncated, contentType: "application/json" };
  }
  const lines = [CALL_AUDIT_COLUMNS.join(",")];
  for (const r of rows) lines.push(CALL_AUDIT_COLUMNS.map((c) => csvCell(r[c])).join(","));
  return { body: lines.join("\r\n") + "\r\n", rows: rows.length, truncated, contentType: "text/csv; charset=utf-8" };
}

export const DEFAULT_RETENTION_MONTHS = 12;

/** First instant (UTC) of the month `months` before `now`. */
export function retentionCutoff(now: Date, months: number): string {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - months, 1));
  return d.toISOString();
}

export interface RetentionResult {
  dryRun: boolean;
  files: string[];
  /** Security R2-6 / T2.1 §12: resolved call_outcome rows (no live result payload) older than `before` */
  state: { call_outcome: number };
  /** PM: incremental_vacuum after the delete (execute only; a no-op unless auto_vacuum = INCREMENTAL) */
  vacuum?: IncrementalVacuumResult;
}

/**
 * Retention maintenance path (separate from the gateway request path). Architecture T2.1 §12:
 * export-then-delete applies ONLY to mcpflow_call_outcome rows. mcpflow_call_audit rows (including
 * result_read / result_purge events) and mcpflow_pending_call rows are never deleted; the only
 * call_audit write is one appended lifecycle row ('state_retention') recording the run.
 * - dry run by default (counts only, nothing written or deleted); pass execute: true to act
 * - `before` must be a month boundary AND at least `minMonths` (default 12) in the past
 * - only resolved outcomes whose result payload is gone (purged / never stored) are eligible
 * - archive: <archiveDir>/call_outcome_<ws>_before-<YYYY-MM>.jsonl, mode 0600, fsynced, written to a
 *   temp name and renamed only after the delete commits; never overwrites; temp removed on failure
 * - delete: ONE BEGIN IMMEDIATE txn: drop the outcome no-delete trigger, delete exactly the exported
 *   rows, recreate the trigger, append the lifecycle row
 */
export function runAuditRetention(
  db: DatabaseSync,
  opts: {
    workspaceId: string;
    before: string;
    archiveDir: string;
    actor: string;
    execute?: boolean;
    minMonths?: number;
    now?: Date;
  },
): RetentionResult {
  const execute = opts.execute === true; // dry run unless explicitly executed
  if (!/^ws_[A-Za-z0-9_-]{1,64}$/.test(opts.workspaceId)) throw new Error("invalid workspace id");
  if (!/^\d{4}-\d{2}-01T00:00:00(\.000)?Z$/.test(opts.before)) {
    throw new Error("before must be the first instant of a month, e.g. 2026-09-01T00:00:00.000Z");
  }
  const minMonths = opts.minMonths ?? DEFAULT_RETENTION_MONTHS;
  // Security T2.5 R-4: the floor cannot be disabled or inverted
  if (!Number.isInteger(minMonths) || minMonths < 1) throw new Error("minMonths must be an integer ≥ 1");
  const cutoff = retentionCutoff(opts.now ?? new Date(), minMonths);
  if (new Date(opts.before).getTime() > new Date(cutoff).getTime()) {
    throw new Error(`before (${opts.before}) is newer than the retention floor ${cutoff} (${minMonths} months)`);
  }
  const file = outcomeArchiveName(opts.archiveDir, opts.workspaceId, opts.before);
  if (!execute) return { dryRun: true, files: [file], state: { call_outcome: countOutcomeRows(db, opts.workspaceId, opts.before) } };
  mkdirSync(opts.archiveDir, { recursive: true, mode: 0o700 });
  if (existsSync(file)) throw new Error(`EEXIST: archive already exists: ${file}`);
  const n = retainOutcomes(db, opts, file);
  // PM: give the deleted rows' pages back (no-op unless auto_vacuum = INCREMENTAL; see `mcp-flow db vacuum`)
  const vacuum = incrementalVacuum(db);
  return { dryRun: false, files: [file], state: { call_outcome: n }, vacuum };
}

// ---------- R2-6 / §12: call_outcome retention (the only export-then-delete) ----------

const OUTCOME_SEL = `FROM mcpflow_call_outcome o WHERE o.workspace_id = ? AND o.created_at < ? AND o.state <> 'pending'
  AND o.result_ciphertext IS NULL`;
const OUTCOME_COLS = [
  "call_id", "pending_call_id", "workspace_id", "agent_id", "key_id", "idempotency_key", "qualified_tool", "args_hash",
  "async", "state", "final_outcome", "result_status", "created_at", "completed_at", "result_bytes", "result_truncated",
  "result_read_at", "result_purged_at", "result_stored_at", "result_expires_at", "result_purge_reason",
]; // never the result ciphertext

function outcomeArchiveName(dir: string, ws: string, before: string): string {
  return join(dir, `call_outcome_${ws}_before-${before.slice(0, 7)}.jsonl`);
}

function countOutcomeRows(db: DatabaseSync, ws: string, before: string): number {
  return Number((db.prepare(`SELECT count(*) AS n ${OUTCOME_SEL}`).get(ws, before) as { n: number }).n);
}

function exportRows(db: DatabaseSync, sql: string, params: unknown[], cols: string[], path: string): { tmp: string; n: number; maxRowid: number } {
  const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  let n = 0;
  let after = 0;
  try {
    for (;;) {
      const page = db.prepare(`SELECT rowid AS _rid, ${cols.join(", ")} ${sql} AND rowid > ? ORDER BY rowid LIMIT 1000`)
        .all(...(params as never[]), after) as Array<Record<string, unknown>>;
      if (!page.length) break;
      writeSync(fd, page.map(({ _rid, ...r }) => JSON.stringify(r)).join("\n") + "\n");
      n += page.length;
      after = Number(page.at(-1)!._rid);
    }
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    rmSync(tmp, { force: true });
    throw err;
  }
  closeSync(fd);
  return { tmp, n, maxRowid: after };
}

function retainOutcomes(
  db: DatabaseSync,
  opts: { workspaceId: string; before: string; archiveDir: string; actor: string },
  file: string,
): number {
  const { workspaceId: ws, before } = opts;
  const out = exportRows(db, OUTCOME_SEL, [ws, before], OUTCOME_COLS.map((c) => `o.${c}`), file);
  fsyncDir(opts.archiveDir);
  const trig = db.prepare(`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = 'mcpflow_call_outcome_no_delete'`).get() as { sql: string } | undefined;
  if (!trig) {
    rmSync(out.tmp, { force: true });
    throw new Error("missing trigger mcpflow_call_outcome_no_delete");
  }
  db.exec("BEGIN IMMEDIATE;");
  try {
    db.exec("DROP TRIGGER mcpflow_call_outcome_no_delete;");
    const n = Number(db.prepare(`DELETE FROM mcpflow_call_outcome WHERE rowid IN (SELECT o.rowid ${OUTCOME_SEL} AND o.rowid <= ?)`).run(ws, before, out.maxRowid).changes);
    if (n !== out.n) throw new Error(`state retention mismatch: exported ${out.n}, deleting ${n}`);
    db.exec(`${trig.sql};`);
    db.prepare(
      `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, lifecycle_action, actor, args_redacted)
       VALUES ('lifecycle', ?, ?, 'state_retention', ?, ?)`,
    ).run(`lc_${randomBytes(12).toString("hex")}`, ws, opts.actor, JSON.stringify({ before, call_outcome: n, file }));
    db.exec("COMMIT;");
  } catch (err) {
    try {
      db.exec("ROLLBACK;");
    } catch {
      /* keep the original error */
    }
    rmSync(out.tmp, { force: true });
    throw err;
  }
  renameSync(out.tmp, file);
  fsyncDir(opts.archiveDir);
  return out.n;
}

function fsyncDir(dir: string): void {
  try {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    /* some platforms cannot fsync a directory */
  }
}
