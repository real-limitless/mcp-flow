/** Database (approval of afcbc646, optional): a pre-0012 DB gets the call_audit rebuild disk check. No real secrets. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { DISK_CHECK_OVERRIDE_ENV, MigrationPreflightError } from "../src/db/migrations/preflight.js";
import { seedWorkspace } from "./helpers/migration-seed.js";

const ID = "0012_call_outcome_v11";
const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

/** File-backed DB at 0011 with `n` call_audit lifecycle rows. */
function fileAt0011(n: number): DatabaseSync {
  const dir = mkdtempSync(join(tmpdir(), "mf-0012-pre-"));
  dirs.push(dir);
  const d = new DatabaseSync(join(dir, "db.sqlite"));
  applyConnectionPragmas(d);
  runMigrations(d, "0011_policy_v10");
  const { ws, chen } = seedWorkspace(d);
  const ins = d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, lifecycle_action, actor) VALUES ('lifecycle', ?, ?, ?, 'agent_create', ?)`);
  d.exec("BEGIN");
  for (let i = 0; i < n; i++) ins.run(`lc${i}`, ws, chen, chen);
  d.exec("COMMIT");
  return d;
}
const applied = (d: DatabaseSync, id: string) => (d.prepare(`SELECT id FROM mcpflow_schema_migrations WHERE id = ?`).all(id) as unknown[]).length;
const rows = (d: DatabaseSync) => Number((d.prepare(`SELECT count(*) AS n FROM mcpflow_call_audit`).get() as { n: number }).n);

describe("0012 disk preflight (runner-side)", () => {
  it("refuses below 2x the DB size; nothing applied; a later healthy run proceeds", () => {
    const d = fileAt0011(40);
    let err: unknown;
    try {
      runMigrations(d, undefined, { preflight: { freeBytes: () => 1024, log: () => {}, env: {} } });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(MigrationPreflightError);
    expect((err as Error).message).toContain("0012_call_outcome_v11 refused");
    expect((err as Error).message).toContain("40 rows");
    expect((err as Error).message).toContain(`${DISK_CHECK_OVERRIDE_ENV}=1`);
    expect(applied(d, ID)).toBe(0);
    expect(rows(d)).toBe(40);
    const lines: string[] = [];
    runMigrations(d, undefined, { preflight: { freeBytes: () => 1e15, log: (l) => lines.push(l), env: {} } });
    expect(applied(d, ID)).toBe(1);
    expect(applied(d, "0013_call_audit_purge_actor")).toBe(1);
    expect(rows(d)).toBe(40);
    // one row-count/ETA line per rebuild: 0012, then 0013
    expect(lines.map((l) => l.match(/migration (\S+): rebuilding mcpflow_call_audit: 40 rows/)?.[1])).toEqual([ID, "0013_call_audit_purge_actor"]);
  });

  it(`${DISK_CHECK_OVERRIDE_ENV}=1 overrides with the warning line; only exactly '1'`, () => {
    const d = fileAt0011(3);
    expect(() => runMigrations(d, ID, { preflight: { freeBytes: () => 0, log: () => {}, env: { [DISK_CHECK_OVERRIDE_ENV]: "yes" } } })).toThrow(MigrationPreflightError);
    const lines: string[] = [];
    runMigrations(d, ID, { preflight: { freeBytes: () => 0, log: (l) => lines.push(l), env: { [DISK_CHECK_OVERRIDE_ENV]: "1" } } });
    expect(applied(d, ID)).toBe(1);
    expect(lines.some((l) => l.includes(`migration ${ID}: WARNING free disk`) && l.includes(DISK_CHECK_OVERRIDE_ENV))).toBe(true);
  });

  it("a DB already past 0012 does not run the 0012 check", () => {
    const d = fileAt0011(0);
    runMigrations(d, ID, { preflight: { freeBytes: () => 1e15, log: () => {}, env: {} } });
    const lines: string[] = [];
    runMigrations(d, undefined, { preflight: { freeBytes: () => 1e15, log: (l) => lines.push(l), env: {} } });
    expect(lines.some((l) => l.includes(ID))).toBe(false);
  });
});
