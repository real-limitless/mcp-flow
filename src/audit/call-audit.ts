/**
 * T3.1 / T3.3 — read side and retention for mcpflow_call_audit (db-t3.1).
 * The write path lives in the policy enforcer (decision + completion rows) and the
 * agent directory (lifecycle rows). This module never UPDATEs or DELETEs on the normal path.
 */
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, renameSync, rmSync, writeSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { CALL_AUDIT_NO_DELETE_TRIGGER } from "../db/migrations/0002_call_audit.js";

export interface CallAuditFilter {
  from?: string;
  to?: string;
  agentId?: string;
  keyId?: string;
  projectId?: string;
  backendSlug?: string;
  tool?: string;
  eventType?: "decision" | "completion" | "lifecycle";
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
  archived: Record<string, number>;
  deleted: number;
  files: string[];
}

/**
 * Retention maintenance path (separate from the gateway request path):
 * - dry run by default (counts only, nothing written or deleted); pass execute: true to act
 * - `before` must be a month boundary AND at least `minMonths` (default 12) in the past
 * - lifecycle rows (key/agent history) are never deleted
 * - archives: <archiveDir>/call_audit_<ws>_<YYYY-MM>.jsonl, mode 0600, fsynced, written to a temp
 *   name and renamed only after the delete commits; never overwrites; temps removed on failure
 * - delete: ONE BEGIN IMMEDIATE txn: drop no-delete trigger, delete exactly the exported rows,
 *   recreate trigger, append lifecycle row (audit_retention)
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
  const cutoff = retentionCutoff(opts.now ?? new Date(), minMonths);
  if (new Date(opts.before).getTime() > new Date(cutoff).getTime()) {
    throw new Error(`before (${opts.before}) is newer than the retention floor ${cutoff} (${minMonths} months)`);
  }
  const rows = db
    .prepare(
      `SELECT ${CALL_AUDIT_COLUMNS.join(", ")} FROM mcpflow_call_audit
        WHERE workspace_id = ? AND ts < ? AND event_type <> 'lifecycle' ORDER BY audit_id`,
    )
    .all(opts.workspaceId, opts.before) as Record<string, unknown>[];
  const byMonth = new Map<string, Record<string, unknown>[]>();
  for (const r of rows) {
    const m = String(r.ts).slice(0, 7);
    (byMonth.get(m) ?? byMonth.set(m, []).get(m)!).push(r);
  }
  const archived: Record<string, number> = {};
  for (const [m, list] of byMonth) archived[m] = list.length;
  const finalName = (m: string) => join(opts.archiveDir, `call_audit_${opts.workspaceId}_${m}.jsonl`);
  if (!execute) return { dryRun: true, archived, deleted: 0, files: [...byMonth.keys()].map(finalName) };

  mkdirSync(opts.archiveDir, { recursive: true, mode: 0o700 });
  for (const m of byMonth.keys()) {
    if (existsSync(finalName(m))) throw new Error(`EEXIST: archive already exists: ${finalName(m)}`);
  }
  const temps: Array<[string, string]> = [];
  const cleanup = () => {
    for (const [t] of temps) rmSync(t, { force: true });
  };
  try {
    for (const [m, list] of byMonth) {
      const tmp = `${finalName(m)}.tmp-${randomBytes(6).toString("hex")}`;
      const fd = openSync(tmp, "wx", 0o600);
      temps.push([tmp, finalName(m)]);
      try {
        writeSync(fd, list.map((r) => JSON.stringify(r)).join("\n") + "\n");
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
    }
    fsyncDir(opts.archiveDir);
  } catch (err) {
    cleanup();
    throw err;
  }
  const files = temps.map(([, f]) => f);
  const maxId = rows.length ? Number(rows.at(-1)!.audit_id) : 0;
  let deleted = 0;
  db.exec("BEGIN IMMEDIATE;");
  try {
    db.exec("DROP TRIGGER mcpflow_call_audit_no_delete;");
    const res = db
      .prepare(
        `DELETE FROM mcpflow_call_audit
          WHERE workspace_id = ? AND ts < ? AND audit_id <= ? AND event_type <> 'lifecycle'`,
      )
      .run(opts.workspaceId, opts.before, maxId);
    deleted = Number(res.changes);
    if (deleted !== rows.length) throw new Error(`retention mismatch: exported ${rows.length}, deleting ${deleted}`);
    db.exec(CALL_AUDIT_NO_DELETE_TRIGGER);
    db.prepare(
      `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, lifecycle_action, actor, args_redacted)
       VALUES ('lifecycle', ?, ?, 'audit_retention', ?, ?)`,
    ).run(
      `lc_${randomBytes(12).toString("hex")}`,
      opts.workspaceId,
      opts.actor,
      JSON.stringify({ before: opts.before, deleted, archived, files }),
    );
    db.exec("COMMIT;");
  } catch (err) {
    try {
      db.exec("ROLLBACK;");
    } catch {
      /* keep the original error */
    }
    cleanup();
    throw err;
  }
  for (const [t, f] of temps) renameSync(t, f);
  fsyncDir(opts.archiveDir);
  return { dryRun: false, archived, deleted, files };
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
