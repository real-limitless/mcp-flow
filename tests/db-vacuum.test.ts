/** PM: incremental vacuum. New DBs INCREMENTAL; offline one-time conversion; retention gives pages back. */
import { randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { runAuditRetention } from "../src/audit/call-audit.js";
import { acquireGatewayLock } from "../src/db/gateway-lock.js";
import { autoVacuumMode, convertToIncrementalVacuum, incrementalVacuum, spaceStats } from "../src/db/maintenance.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { Store } from "../src/db/store.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";

const dirs: string[] = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), "mcp-flow-vac-")); dirs.push(d); return d; };
afterEach(() => { while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true }); });
const hex = (n = 12) => randomBytes(n).toString("hex");
const WS = "ws_" + "7".repeat(24);

describe("auto_vacuum mode", () => {
  it("a new DB is INCREMENTAL (applyConnectionPragmas and Store)", () => {
    const db = new DatabaseSync(join(tmp(), "n.db"));
    applyConnectionPragmas(db);
    runMigrations(db);
    expect(autoVacuumMode(db)).toBe("incremental");
    db.close();
    const s = new Store(join(tmp(), "s.db"), Buffer.alloc(32, 3).toString("base64"));
    expect(autoVacuumMode(s.db)).toBe("incremental");
    s.db.close();
  });

  it("an existing DB keeps its mode on open (the pragma would not take effect without VACUUM)", () => {
    const path = join(tmp(), "old.db");
    const raw = new DatabaseSync(path);
    raw.exec("CREATE TABLE legacy (x)");
    raw.close();
    const db = new DatabaseSync(path);
    applyConnectionPragmas(db);
    expect(autoVacuumMode(db)).toBe("none");
    db.close();
  });
});

describe("mcp-flow db vacuum (offline one-time conversion)", () => {
  const legacyDb = () => {
    const path = join(tmp(), "legacy.db");
    const db = new DatabaseSync(path);
    db.exec("PRAGMA auto_vacuum = NONE; CREATE TABLE t (b BLOB); CREATE TABLE keep (v TEXT);");
    const ins = db.prepare("INSERT INTO t VALUES (randomblob(2000))");
    for (let i = 0; i < 400; i++) ins.run();
    db.prepare("INSERT INTO keep VALUES ('still here')").run();
    db.exec("DELETE FROM t WHERE rowid > 200");
    expect(spaceStats(db).freelistCount).toBeGreaterThan(0);
    db.close();
    return path;
  };

  it("switches an existing DB to INCREMENTAL with a full VACUUM; data intact; idempotent; --check changes nothing", async () => {
    const path = legacyDb();
    const check = await convertToIncrementalVacuum(path, { check: true });
    expect(check).toMatchObject({ changed: false, before: { autoVacuum: "none" } });
    const out = await convertToIncrementalVacuum(path);
    expect(out.changed).toBe(true);
    expect(out.before.autoVacuum).toBe("none");
    expect(out.after).toMatchObject({ autoVacuum: "incremental", freelistCount: 0 });
    expect(out.after.pageCount).toBeLessThan(out.before.pageCount);
    const db = new DatabaseSync(path);
    expect(autoVacuumMode(db)).toBe("incremental");
    expect(db.prepare("SELECT v FROM keep").all()).toEqual([{ v: "still here" }]);
    expect(db.prepare("SELECT count(*) n FROM t").get()).toEqual({ n: 200 });
    expect(db.prepare("PRAGMA integrity_check").get()).toEqual({ integrity_check: "ok" });
    db.close();
    expect((await convertToIncrementalVacuum(path)).changed).toBe(false);
  });

  it("is refused while a gateway holds the DB lock", async () => {
    const path = legacyDb();
    const lock = await acquireGatewayLock(path);
    expect(lock).not.toBeNull();
    try {
      await expect(convertToIncrementalVacuum(path)).rejects.toThrow(/running gateway/);
    } finally {
      lock!.release();
    }
    expect((await convertToIncrementalVacuum(path)).changed).toBe(true);
  });

  it("is never reachable from the gateway: only the CLI references it; no route/tool/server code runs VACUUM", () => {
    const root = join(__dirname, "..");
    const files = (d: string): string[] => readdirSync(d).flatMap((f) => {
      const p = join(d, f);
      return statSync(p).isDirectory() ? files(p) : /\.(ts|js)$/.test(f) ? [p] : [];
    });
    const refs: string[] = [];
    const vacuums: string[] = [];
    for (const f of files(join(root, "src"))) {
      const rel = relative(root, f);
      const s = readFileSync(f, "utf8");
      if (/convertToIncrementalVacuum/.test(s)) refs.push(rel);
      // executed SQL only (exec/prepare string literals), not comments or help text
      if (/exec\(\s*["'`](PRAGMA auto_vacuum\s*=|VACUUM\b)/i.test(s)) vacuums.push(rel);
    }
    expect(refs.sort()).toEqual(["src/cli.ts", "src/db/maintenance.ts"]);
    expect(vacuums.sort()).toEqual(["src/db/maintenance.ts", "src/db/migrations/index.ts"]);
  });
});

describe("incremental_vacuum after a retention delete", () => {
  function seeded(incremental: boolean) {
    const path = join(tmp(), "r.db");
    const db = new DatabaseSync(path);
    if (!incremental) db.exec("CREATE TABLE _force_old_mode (x)"); // not empty -> stays auto_vacuum NONE
    applyConnectionPragmas(db);
    runMigrations(db);
    const dir = new AgentDirectory(db, derivePolicyKeys("vac"));
    const chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: [], createdBy: chen });
    const key = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
    const ins = db.prepare(`INSERT INTO mcpflow_call_outcome (call_id, workspace_id, agent_id, key_id, args_hash, qualified_tool, state, final_outcome, result_status, created_at, completed_at)
                            VALUES (?, ?, ?, ?, ?, ?, 'executed', 'executed', 'ok', '2025-03-01T00:00:00.000Z', '2025-03-01T00:00:01.000Z')`);
    db.exec("BEGIN;");
    for (let i = 0; i < 3000; i++) ins.run(`call_${hex()}`, WS, bot, key, hex(32), `gh__${"t".repeat(300)}_${i}`);
    db.exec("COMMIT;");
    db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    return { db, chen };
  }
  const retain = (db: DatabaseSync, chen: string) =>
    runAuditRetention(db, { workspaceId: WS, before: "2025-09-01T00:00:00.000Z", archiveDir: join(tmp(), "arch"), actor: chen, execute: true, now: new Date("2026-10-14T00:00:00Z") });

  it("INCREMENTAL DB: the freelist left by the delete is released; the file shrinks", () => {
    const { db, chen } = seeded(true);
    const before = spaceStats(db);
    expect(before.autoVacuum).toBe("incremental");
    const out = retain(db, chen);
    expect(out.state.call_outcome).toBe(3000);
    expect(out.vacuum).toMatchObject({ autoVacuum: "incremental", ran: true, freelistAfter: 0 });
    expect(out.vacuum!.freelistBefore).toBeGreaterThan(50);
    expect(out.vacuum!.freedPages).toBe(out.vacuum!.freelistBefore);
    const after = spaceStats(db);
    expect(after.freelistCount).toBe(0);
    expect(after.pageCount).toBeLessThan(before.pageCount - 50);
    db.close();
  });

  it("control: a DB not yet converted keeps the freelist (helper is a no-op until `db vacuum`)", () => {
    const { db, chen } = seeded(false);
    const out = retain(db, chen);
    expect(out.vacuum).toMatchObject({ autoVacuum: "none", ran: false, freedPages: 0 });
    expect(spaceStats(db).freelistCount).toBeGreaterThan(50);
    db.close();
  });

  it("incrementalVacuum(N) frees at most N pages; rejects bad N and use inside a transaction", () => {
    const { db, chen } = seeded(true);
    db.exec("CREATE TRIGGER _no_auto AFTER DELETE ON mcpflow_call_outcome BEGIN SELECT 1; END;"); // harmless
    const out = retain(db, chen); // releases everything
    expect(out.vacuum!.freelistAfter).toBe(0);
    db.exec("CREATE TABLE junk (b BLOB);");
    const ins = db.prepare("INSERT INTO junk VALUES (randomblob(4000))");
    for (let i = 0; i < 100; i++) ins.run();
    db.exec("DROP TABLE junk;");
    const free = spaceStats(db).freelistCount;
    expect(free).toBeGreaterThan(20);
    expect(incrementalVacuum(db, 10)).toMatchObject({ ran: true, freedPages: 10, freelistAfter: free - 10 });
    expect(() => incrementalVacuum(db, 0)).toThrow(/positive/);
    db.exec("BEGIN;");
    expect(() => incrementalVacuum(db)).toThrow(/outside a transaction/);
    db.exec("ROLLBACK;");
    expect(incrementalVacuum(db).freelistAfter).toBe(0);
    db.close();
  });
});
