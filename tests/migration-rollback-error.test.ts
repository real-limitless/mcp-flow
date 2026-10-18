/**
 * QA v5.6 §5 (minor): with MCP_FLOW_MIGRATE_SKIP_DISK_CHECK=1 on a full disk, SQLite rolled the
 * migration's transaction back by itself (SQLITE_FULL) and the runner's ROLLBACK then threw
 * "cannot rollback - no transaction is active", hiding the real error. The original error is kept.
 */
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { applyConnectionPragmas, MIGRATIONS, runMigrations } from "../src/db/migrations/index.js";

/** A DatabaseSync whose next migration body behaves like SQLITE_FULL with an automatic rollback. */
function fullDiskOnce(real: DatabaseSync, migrationSql: string, opts: { rollbackThrows?: boolean } = {}): DatabaseSync {
  let tripped = false;
  return new Proxy(real, {
    get(target, prop) {
      if (prop === "exec") {
        return (sql: string) => {
          if (!tripped && sql === migrationSql) {
            tripped = true;
            if (!opts.rollbackThrows) target.exec("ROLLBACK;"); // SQLite's own rollback
            throw Object.assign(new Error("database or disk is full"), { code: "ERR_SQLITE_ERROR", errcode: 13 });
          }
          if (opts.rollbackThrows && sql === "ROLLBACK;") throw new Error("disk I/O error");
          return target.exec(sql);
        };
      }
      const v = Reflect.get(target, prop, target);
      return typeof v === "function" ? v.bind(target) : v;
    },
  }) as DatabaseSync;
}

describe("migration failure keeps the original error", () => {
  const last = MIGRATIONS[MIGRATIONS.length - 1]!;
  const prev = MIGRATIONS[MIGRATIONS.length - 2]!;

  it("transaction already rolled back by SQLite: the disk-full error is reported, not 'no transaction is active'", () => {
    const d = new DatabaseSync(":memory:");
    applyConnectionPragmas(d);
    runMigrations(d, prev.id);
    let err: Error | undefined;
    try {
      runMigrations(fullDiskOnce(d, last.sql), undefined, { preflight: { freeBytes: () => 1e15, log: () => {}, env: {} } });
    } catch (e) {
      err = e as Error;
    }
    expect(err?.message).toBe(`migration ${last.id} failed: database or disk is full`);
    expect(err?.message).not.toMatch(/no transaction is active/);
    expect((err?.cause as Error).message).toBe("database or disk is full");
    expect(d.isTransaction).toBe(false);
    // nothing applied; a later run (disk freed) applies it
    expect(d.prepare(`SELECT count(*) AS n FROM mcpflow_schema_migrations WHERE id = ?`).get(last.id)).toEqual({ n: 0 });
    expect(runMigrations(d)).toEqual([last.id]);
  });

  it("a rollback that fails too is appended, never replaces the original", () => {
    const d = new DatabaseSync(":memory:");
    applyConnectionPragmas(d);
    runMigrations(d, prev.id);
    let msg = "";
    try {
      runMigrations(fullDiskOnce(d, last.sql, { rollbackThrows: true }));
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toBe(`migration ${last.id} failed: database or disk is full (rollback also failed: disk I/O error)`);
    if (d.isTransaction) d.exec("ROLLBACK;");
  });
});
