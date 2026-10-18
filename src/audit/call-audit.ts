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
  /** Security R2-6: resolved rows older than `before` in the outcome / pending-call tables */
  state: { call_outcome: number; pending_call: number };
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
  // Security T2.5 R-4: the floor cannot be disabled or inverted
  if (!Number.isInteger(minMonths) || minMonths < 1) throw new Error("minMonths must be an integer ≥ 1");
  const cutoff = retentionCutoff(opts.now ?? new Date(), minMonths);
  if (new Date(opts.before).getTime() > new Date(cutoff).getTime()) {
    throw new Error(`before (${opts.before}) is newer than the retention floor ${cutoff} (${minMonths} months)`);
  }
  // L-7: count per month without loading rows; then process ONE month at a time (bounded memory),
  // each in its own archive file and its own transaction.
  const months = (db
    .prepare(
      `SELECT substr(ts, 1, 7) AS m, count(*) AS n FROM mcpflow_call_audit
        WHERE workspace_id = ? AND ts < ? AND event_type <> 'lifecycle' GROUP BY m ORDER BY m`,
    )
    .all(opts.workspaceId, opts.before) as Array<{ m: string; n: number }>);
  const archived: Record<string, number> = {};
  for (const { m, n } of months) archived[m] = Number(n);
  const finalName = (m: string) => join(opts.archiveDir, `call_audit_${opts.workspaceId}_${m}.jsonl`);
  const stateFiles = stateArchiveNames(opts.archiveDir, opts.workspaceId, opts.before);
  if (!execute) {
    return {
      dryRun: true, archived, deleted: 0, files: [...months.map(({ m }) => finalName(m)), stateFiles.call_outcome, stateFiles.pending_call],
      state: countStateRows(db, opts.workspaceId, opts.before),
    };
  }

  mkdirSync(opts.archiveDir, { recursive: true, mode: 0o700 });
  for (const f of [...months.map(({ m }) => finalName(m)), stateFiles.call_outcome, stateFiles.pending_call]) {
    if (existsSync(f)) throw new Error(`EEXIST: archive already exists: ${f}`);
  }
  const files: string[] = [];
  let deleted = 0;
  for (const { m } of months) {
    const from = `${m}-01T00:00:00.000Z`;
    const [y, mo] = m.split("-").map(Number) as [number, number];
    const to = new Date(Date.UTC(y, mo, 1)).toISOString();
    const upper = to < opts.before ? to : opts.before;
    const tmp = `${finalName(m)}.tmp-${randomBytes(6).toString("hex")}`;
    let count = 0;
    let maxId = 0;
    const fd = openSync(tmp, "wx", 0o600);
    try {
      // stream the month in pages of 1000 rows
      let after = 0;
      for (;;) {
        const page = db
          .prepare(
            `SELECT ${CALL_AUDIT_COLUMNS.join(", ")} FROM mcpflow_call_audit
              WHERE workspace_id = ? AND ts >= ? AND ts < ? AND event_type <> 'lifecycle' AND audit_id > ?
              ORDER BY audit_id LIMIT 1000`,
          )
          .all(opts.workspaceId, from, upper, after) as Record<string, unknown>[];
        if (!page.length) break;
        writeSync(fd, page.map((r) => JSON.stringify(r)).join("\n") + "\n");
        count += page.length;
        after = Number(page.at(-1)!.audit_id);
        maxId = after;
      }
      fsyncSync(fd);
    } catch (err) {
      closeSync(fd);
      rmSync(tmp, { force: true });
      throw err;
    }
    closeSync(fd);
    fsyncDir(opts.archiveDir);
    db.exec("BEGIN IMMEDIATE;");
    try {
      db.exec("DROP TRIGGER mcpflow_call_audit_no_delete;");
      const res = db
        .prepare(
          `DELETE FROM mcpflow_call_audit
            WHERE workspace_id = ? AND ts >= ? AND ts < ? AND audit_id <= ? AND event_type <> 'lifecycle'`,
        )
        .run(opts.workspaceId, from, upper, maxId);
      const n = Number(res.changes);
      if (n !== count) throw new Error(`retention mismatch for ${m}: exported ${count}, deleting ${n}`);
      db.exec(CALL_AUDIT_NO_DELETE_TRIGGER);
      db.prepare(
        `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, lifecycle_action, actor, args_redacted)
         VALUES ('lifecycle', ?, ?, 'audit_retention', ?, ?)`,
      ).run(
        `lc_${randomBytes(12).toString("hex")}`,
        opts.workspaceId,
        opts.actor,
        JSON.stringify({ before: opts.before, month: m, deleted: n, file: finalName(m) }),
      );
      db.exec("COMMIT;");
      deleted += n;
    } catch (err) {
      try {
        db.exec("ROLLBACK;");
      } catch {
        /* keep the original error */
      }
      rmSync(tmp, { force: true });
      throw err;
    }
    renameSync(tmp, finalName(m));
    fsyncDir(opts.archiveDir);
    files.push(finalName(m));
    archived[m] = count;
  }
  const state = retainStateTables(db, opts, stateFiles);
  files.push(stateFiles.call_outcome, stateFiles.pending_call);
  return { dryRun: false, archived, deleted, files, state };
}

// ---------- R2-6: outcome + pending-call retention ----------

const OUTCOME_SEL = `FROM mcpflow_call_outcome o WHERE o.workspace_id = ? AND o.created_at < ? AND o.state <> 'pending'`;
/** Resolved holds that nothing still references: grants (never deleted) and outcomes that are kept. */
const PENDING_SEL = `FROM mcpflow_pending_call p
  WHERE p.workspace_id = ? AND p.created_at < ? AND p.status <> 'pending'
    AND NOT (p.status = 'approved' AND p.dispatched_at IS NULL AND p.abandoned_at IS NULL)
    AND NOT EXISTS (SELECT 1 FROM mcpflow_policy_grant g WHERE g.source_pending_call_id = p.id)
    AND NOT EXISTS (SELECT 1 FROM mcpflow_call_outcome o2 WHERE o2.pending_call_id = p.id
                     AND NOT (o2.workspace_id = ? AND o2.created_at < ? AND o2.state <> 'pending'))`;
const OUTCOME_COLS = [
  "call_id", "pending_call_id", "workspace_id", "agent_id", "key_id", "idempotency_key", "qualified_tool", "args_hash",
  "async", "state", "final_outcome", "result_status", "created_at", "completed_at", "result_bytes", "result_truncated",
  "result_read_at", "result_purged_at",
]; // never the result ciphertext
const PENDING_COLS = [
  "id", "call_id", "workspace_id", "agent_id", "key_id", "session_id", "project_id", "backend_slug", "tool", "qualified_tool",
  "placement", "device_id", "args_redacted", "args_hash", "matched_rules", "approvers", "reason_to_agent", "created_at",
  "expires_at", "status", "decided_by", "decided_at", "note", "dispatched_at", "grant_id", "abandoned_at",
]; // never the args ciphertext

function stateArchiveNames(dir: string, ws: string, before: string) {
  const tag = `before-${before.slice(0, 7)}`;
  return {
    call_outcome: join(dir, `call_outcome_${ws}_${tag}.jsonl`),
    pending_call: join(dir, `pending_call_${ws}_${tag}.jsonl`),
  };
}

function countStateRows(db: DatabaseSync, ws: string, before: string) {
  return {
    call_outcome: Number((db.prepare(`SELECT count(*) AS n ${OUTCOME_SEL}`).get(ws, before) as { n: number }).n),
    pending_call: Number((db.prepare(`SELECT count(*) AS n ${PENDING_SEL}`).get(ws, before, ws, before) as { n: number }).n),
  };
}

function exportRows(db: DatabaseSync, sql: string, params: unknown[], cols: string[], path: string): { tmp: string; n: number } {
  const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  let n = 0;
  try {
    let after = 0;
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
  return { tmp, n };
}

function retainStateTables(
  db: DatabaseSync,
  opts: { workspaceId: string; before: string; archiveDir: string; actor: string },
  files: { call_outcome: string; pending_call: string },
): { call_outcome: number; pending_call: number } {
  const { workspaceId: ws, before } = opts;
  const pend = exportRows(db, PENDING_SEL, [ws, before, ws, before], PENDING_COLS.map((c) => `p.${c}`), files.pending_call);
  let out: { tmp: string; n: number };
  try {
    out = exportRows(db, OUTCOME_SEL, [ws, before], OUTCOME_COLS.map((c) => `o.${c}`), files.call_outcome);
  } catch (err) {
    rmSync(pend.tmp, { force: true });
    throw err;
  }
  fsyncDir(opts.archiveDir);
  const triggers = ["mcpflow_call_outcome_no_delete", "mcpflow_pending_call_no_delete"].map((name) => {
    const r = db.prepare(`SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?`).get(name) as { sql: string } | undefined;
    if (!r) throw new Error(`missing trigger ${name}`);
    return { name, sql: r.sql };
  });
  db.exec("BEGIN IMMEDIATE;");
  try {
    // the pending set is computed before the outcome delete, against the same snapshot as the export
    const pendIds = (db.prepare(`SELECT p.id ${PENDING_SEL}`).all(ws, before, ws, before) as Array<{ id: string }>).map((r) => r.id);
    for (const t of triggers) db.exec(`DROP TRIGGER ${t.name};`);
    const nOut = Number(db.prepare(`DELETE FROM mcpflow_call_outcome WHERE rowid IN (SELECT o.rowid ${OUTCOME_SEL})`).run(ws, before).changes);
    let nPend = 0;
    const del = db.prepare(`DELETE FROM mcpflow_pending_call WHERE id = ?`);
    for (const id of pendIds) nPend += Number(del.run(id).changes);
    if (nOut !== out.n || nPend !== pend.n) {
      throw new Error(`state retention mismatch: exported ${out.n}/${pend.n}, deleting ${nOut}/${nPend}`);
    }
    for (const t of triggers) db.exec(`${t.sql};`);
    db.prepare(
      `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, lifecycle_action, actor, args_redacted)
       VALUES ('lifecycle', ?, ?, 'state_retention', ?, ?)`,
    ).run(`lc_${randomBytes(12).toString("hex")}`, ws, opts.actor,
      JSON.stringify({ before, call_outcome: nOut, pending_call: nPend, files: [files.call_outcome, files.pending_call] }));
    db.exec("COMMIT;");
  } catch (err) {
    try {
      db.exec("ROLLBACK;");
    } catch {
      /* keep the original error */
    }
    rmSync(out.tmp, { force: true });
    rmSync(pend.tmp, { force: true });
    throw err;
  }
  renameSync(out.tmp, files.call_outcome);
  renameSync(pend.tmp, files.pending_call);
  fsyncDir(opts.archiveDir);
  return { call_outcome: out.n, pending_call: pend.n };
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
