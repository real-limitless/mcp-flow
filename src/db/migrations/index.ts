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

export interface Migration {
  id: string;
  sql: string;
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
  { id: "0012_call_outcome_v11", sql: MIGRATION_0012 },
];

export const SQLITE_BUSY_TIMEOUT_MS = 5000;

/** Per-connection pragmas required by the mcpflow_* schema (Database, 2026-10-14). */
export function applyConnectionPragmas(db: DatabaseSync): void {
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec(`PRAGMA busy_timeout = ${SQLITE_BUSY_TIMEOUT_MS};`);
}

/**
 * Apply pending migrations, each in its own BEGIN IMMEDIATE transaction.
 * This is the only place mcpflow_* DDL runs; the request path never runs DDL.
 */
export function runMigrations(db: DatabaseSync, upTo?: string): string[] {
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
      db.exec("BEGIN IMMEDIATE;");
      try {
        db.exec(m.sql);
        db.prepare(`INSERT INTO mcpflow_schema_migrations (id, applied_at) VALUES (?, ?)`).run(
          m.id,
          new Date().toISOString(),
        );
        db.exec("COMMIT;");
      } catch (err) {
        db.exec("ROLLBACK;");
        throw new Error(`migration ${m.id} failed: ${(err as Error).message}`);
      }
      applied.push(m.id);
    }
    if (upTo && m.id === upTo) break;
  }
  return applied;
}
