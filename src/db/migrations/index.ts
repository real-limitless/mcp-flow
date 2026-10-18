import type { DatabaseSync } from "node:sqlite";
import { MIGRATION_0001 } from "./0001_agents_keys.js";
import { MIGRATION_0002 } from "./0002_call_audit.js";
import { MIGRATION_0003 } from "./0003_policy_pending.js";
import { MIGRATION_0004 } from "./0004_push_approver.js";
import { MIGRATION_0005 } from "./0005_grant_revocation.js";
import { MIGRATION_0006 } from "./0006_outcomes_epoch.js";
import { MIGRATION_0007 } from "./0007_session_id_prefix.js";
import { MIGRATION_0008 } from "./0008_idempotency_per_agent.js";
import { MIGRATION_0009 } from "./0009_agent_bootstrap_session_guard.js";
import { MIGRATION_0010 } from "./0010_policy_grant.js";
import { MIGRATION_0011 } from "./0011_policy_v10.js";
import { MIGRATION_0012 } from "./0012_call_outcome_v11.js";
import { MIGRATION_0013 } from "./0013_call_audit_purge_actor.js";
import { MIGRATION_0014 } from "./0014_agent_bootstrap_upd_scope.js";
import { tableRebuildPreflight, type PreflightDeps } from "./preflight.js";

export interface Migration {
  id: string;
  sql: string;
  /** Runs before BEGIN IMMEDIATE when the migration is pending; throw to refuse (nothing applied). */
  preflight?: (db: DatabaseSync, deps?: PreflightDeps) => void;
}

/** Ordered, append-only list. Never edit a shipped migration; add a new one. */
export const MIGRATIONS: readonly Migration[] = [
  { id: "0001_agents_keys", sql: MIGRATION_0001 },
  { id: "0002_call_audit", sql: MIGRATION_0002 },
  { id: "0003_policy_pending", sql: MIGRATION_0003 },
  { id: "0004_push_approver", sql: MIGRATION_0004 },
  { id: "0005_grant_revocation", sql: MIGRATION_0005 },
  { id: "0006_outcomes_epoch", sql: MIGRATION_0006 },
  { id: "0007_session_id_prefix", sql: MIGRATION_0007 },
  { id: "0008_idempotency_per_agent", sql: MIGRATION_0008 },
  { id: "0009_agent_bootstrap_session_guard", sql: MIGRATION_0009 },
  { id: "0010_policy_grant", sql: MIGRATION_0010 },
  { id: "0011_policy_v10", sql: MIGRATION_0011 },
  {
    id: "0012_call_outcome_v11",
    sql: MIGRATION_0012,
    // Database (approval of afcbc646): 0012 also rebuilds call_audit; a pre-0012 DB gets the same
    // disk check + row count/ETA log as 0013 (runner-side; the 0012 file is unchanged).
    preflight: tableRebuildPreflight("0012_call_outcome_v11", "mcpflow_call_audit"),
  },
  {
    id: "0013_call_audit_purge_actor",
    sql: MIGRATION_0013,
    // Database ops: full call_audit rebuild under the write lock; disk check + row count/ETA log.
    preflight: tableRebuildPreflight("0013_call_audit_purge_actor", "mcpflow_call_audit"),
  },
  { id: "0014_agent_bootstrap_upd_scope", sql: MIGRATION_0014 },
];

export const SQLITE_BUSY_TIMEOUT_MS = 5000;

/** Per-connection pragmas required by the mcpflow_* schema (Database, 2026-10-14). */
/** PM: cap the WAL file left on disk after a checkpoint (MCP_FLOW_JOURNAL_SIZE_LIMIT_MB, default 64 MiB). */
export const DEFAULT_JOURNAL_SIZE_LIMIT_BYTES = 64 * 1024 * 1024;

export interface ConnectionPragmaOptions {
  /** PRAGMA journal_size_limit in bytes (default DEFAULT_JOURNAL_SIZE_LIMIT_BYTES). */
  journalSizeLimitBytes?: number;
}

export function applyConnectionPragmas(db: DatabaseSync, opts: ConnectionPragmaOptions = {}): void {
  // PM: new (empty) DBs get auto_vacuum = INCREMENTAL; it only takes effect before the first table.
  // Existing DBs keep their mode until the offline `mcp-flow db vacuum` (src/db/maintenance.ts).
  const empty = Number((db.prepare(`SELECT count(*) AS n FROM sqlite_master`).get() as { n: number }).n) === 0;
  if (empty) db.exec("PRAGMA auto_vacuum = INCREMENTAL;");
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec(`PRAGMA busy_timeout = ${SQLITE_BUSY_TIMEOUT_MS};`);
  const limit = opts.journalSizeLimitBytes ?? DEFAULT_JOURNAL_SIZE_LIMIT_BYTES;
  if (!Number.isSafeInteger(limit) || limit < 0) throw new Error("journalSizeLimitBytes must be a non-negative integer");
  db.exec(`PRAGMA journal_size_limit = ${limit};`);
}

/**
 * Apply pending migrations, each in its own BEGIN IMMEDIATE transaction.
 * This is the only place mcpflow_* DDL runs; the request path never runs DDL.
 */
export interface RunMigrationsOptions {
  /** Injected into each migration's preflight (tests: fake free space / log sink / env). */
  preflight?: PreflightDeps;
}

export function runMigrations(db: DatabaseSync, upTo?: string, opts: RunMigrationsOptions = {}): string[] {
  // Security R5-6: table rebuilds (0010, 0012, 0013) rely on RENAME updating FK references in other
  // tables, which needs legacy_alter_table OFF (the SQLite default). Pin it rather than assume it.
  db.exec("PRAGMA legacy_alter_table = OFF;");
  const legacyAlter = Number(Object.values(db.prepare("PRAGMA legacy_alter_table").get() as Record<string, unknown>)[0]);
  if (legacyAlter !== 0) throw new Error("migrations need PRAGMA legacy_alter_table = OFF");
  db.exec(`CREATE TABLE IF NOT EXISTS mcpflow_schema_migrations (
    id TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
  ) STRICT;`);
  const done = new Set(
    (db.prepare(`SELECT id FROM mcpflow_schema_migrations`).all() as Array<{ id: string }>).map(
      (r) => r.id,
    ),
  );
  const applied: string[] = [];
  for (const m of MIGRATIONS) {
    if (!done.has(m.id)) {
      m.preflight?.(db, opts.preflight);
      db.exec("BEGIN IMMEDIATE;");
      try {
        db.exec(m.sql);
        db.prepare(`INSERT INTO mcpflow_schema_migrations (id, applied_at) VALUES (?, ?)`).run(
          m.id,
          new Date().toISOString(),
        );
        db.exec("COMMIT;");
      } catch (err) {
        // QA v5.6 §5: on a full disk (SQLITE_FULL / IOERR) SQLite may already have rolled the
        // transaction back; a bare ROLLBACK then throws "no transaction is active" and hid the real
        // error. Roll back only an open transaction, and never let a rollback failure replace it.
        let rollback = "";
        if (db.isTransaction) {
          try {
            db.exec("ROLLBACK;");
          } catch (rbErr) {
            rollback = ` (rollback also failed: ${(rbErr as Error).message})`;
          }
        }
        throw new Error(`migration ${m.id} failed: ${(err as Error).message}${rollback}`, { cause: err });
      }
      applied.push(m.id);
    }
    if (upTo && m.id === upTo) break;
  }
  return applied;
}
