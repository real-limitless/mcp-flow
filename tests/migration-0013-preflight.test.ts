/** Database ops (review of f9388505): 0013 disk preflight + row-count/ETA log. No real secrets. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { DISK_CHECK_OVERRIDE_ENV, MigrationPreflightError, estimateRebuildSeconds } from "../src/db/migrations/preflight.js";
import { seedWorkspace } from "./helpers/migration-seed.js";

const ID = "0013_call_audit_purge_actor";
const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

/** File-backed DB at 0012 with `n` call_audit rows. */
function fileAt0012(n: number): { d: DatabaseSync; path: string } {
  const dir = mkdtempSync(join(tmpdir(), "mf-0013-pre-"));
  dirs.push(dir);
  const path = join(dir, "db.sqlite");
  const d = new DatabaseSync(path);
  applyConnectionPragmas(d);
  runMigrations(d, "0012_call_outcome_v11");
  const { ws, chen } = seedWorkspace(d);
  const ins = d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, actor, error_code) VALUES ('result_purge', ?, ?, ?, NULL, 'purged:expired')`);
  d.exec("BEGIN");
  for (let i = 0; i < n; i++) ins.run(`c${i}`, ws, chen);
  d.exec("COMMIT");
  return { d, path };
}
const applied = (d: DatabaseSync) => (d.prepare(`SELECT id FROM mcpflow_schema_migrations WHERE id = ?`).all(ID) as unknown[]).length;
const actorNulls = (d: DatabaseSync) => Number((d.prepare(`SELECT count(*) AS n FROM mcpflow_call_audit WHERE actor IS NULL`).get() as { n: number }).n);

describe("0013 disk preflight", () => {
  it("refuses with a clear typed error when free disk < 2x DB size; nothing is applied", () => {
    const { d } = fileAt0012(50);
    const lines: string[] = [];
    let err: unknown;
    try {
      runMigrations(d, ID, { preflight: { freeBytes: () => 1024, log: (l) => lines.push(l), env: {} } });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(MigrationPreflightError);
    const msg = (err as Error).message;
    expect(msg).toContain("0013_call_audit_purge_actor refused");
    expect(msg).toContain("2x the DB size");
    expect(msg).toContain("50 rows");
    expect(msg).toContain(`${DISK_CHECK_OVERRIDE_ENV}=1`);
    expect(applied(d)).toBe(0);
    expect(actorNulls(d)).toBe(50); // untouched
    expect(d.prepare("SELECT 1 FROM sqlite_master WHERE name = 'mcpflow_call_audit_old'").get()).toBeUndefined();
    // not inside a transaction: a later (healthy) run proceeds
    runMigrations(d, ID, { preflight: { freeBytes: () => 1e15, log: () => {}, env: {} } });
    expect(applied(d)).toBe(1);
    expect(actorNulls(d)).toBe(0);
  });

  it(`${DISK_CHECK_OVERRIDE_ENV}=1 overrides the refusal and logs a warning`, () => {
    const { d } = fileAt0012(3);
    const lines: string[] = [];
    runMigrations(d, ID, { preflight: { freeBytes: () => 0, log: (l) => lines.push(l), env: { [DISK_CHECK_OVERRIDE_ENV]: "1" } } });
    expect(applied(d)).toBe(1);
    expect(lines.some((l) => l.includes("WARNING free disk") && l.includes(DISK_CHECK_OVERRIDE_ENV))).toBe(true);
  });

  it("only exactly '1' overrides", () => {
    const { d } = fileAt0012(3);
    expect(() => runMigrations(d, ID, { preflight: { freeBytes: () => 0, log: () => {}, env: { [DISK_CHECK_OVERRIDE_ENV]: "true" } } })).toThrow(MigrationPreflightError);
  });

  it("counts the WAL in the DB size and passes at exactly 2x", () => {
    const { d } = fileAt0012(5);
    const pages = Number((d.prepare("PRAGMA page_count").get() as Record<string, number>).page_count);
    const psize = Number((d.prepare("PRAGMA page_size").get() as Record<string, number>).page_size);
    const wal = 4096;
    const need = 2 * (pages * psize + wal);
    expect(() => runMigrations(d, ID, { preflight: { freeBytes: () => need - 1, fileBytes: () => wal, log: () => {}, env: {} } })).toThrow(/refused/);
    runMigrations(d, ID, { preflight: { freeBytes: () => need, fileBytes: () => wal, log: () => {}, env: {} } });
    expect(applied(d)).toBe(1);
  });

  it("logs the row count and an estimated time before the rebuild", () => {
    const { d } = fileAt0012(7);
    const lines: string[] = [];
    runMigrations(d, ID, { preflight: { freeBytes: () => 1e15, log: (l) => lines.push(l), env: {} } });
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/migration 0013_call_audit_purge_actor: rebuilding mcpflow_call_audit: 7 rows, DB .*; estimated \d+ s holding the write lock/);
  });

  it("uses the real filesystem by default (temp dir has room for a tiny DB)", () => {
    const { d } = fileAt0012(2);
    runMigrations(d, ID, { preflight: { log: () => {}, env: {} } });
    expect(applied(d)).toBe(1);
  });

  it("estimate matches the measured points (1M ~20 s, 10M ~9.5 min)", () => {
    expect(estimateRebuildSeconds(1_000_000)).toBeCloseTo(20, 5);
    expect(estimateRebuildSeconds(10_000_000)).toBeCloseTo(570, 5);
    expect(estimateRebuildSeconds(0)).toBe(0);
  });

  it(":memory: DBs skip the disk check and an empty table logs nothing", () => {
    const d = new DatabaseSync(":memory:");
    applyConnectionPragmas(d);
    const lines: string[] = [];
    runMigrations(d, undefined, { preflight: { freeBytes: () => 0, log: (l) => lines.push(l), env: {} } });
    expect(lines).toEqual([]);
  });
});
