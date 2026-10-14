/** Security T2.5 Re-review 3: R3-1..R3-4 and the M-5 cutover flag. */
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";

const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

async function boot(overrides: Record<string, unknown> = {}): Promise<RunningServer> {
  const d = mkdtempSync(join(tmpdir(), "rr3-")); tmp.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: Buffer.alloc(32, 5).toString("base64"), adminToken: "rr3-admin", host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default", ...overrides });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const gw = await startServer(cfg);
  cleanups.push(() => gw.close());
  return gw;
}

const init = (gw: RunningServer, token: string) =>
  fetch(`${gw.url}/mcp`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
  });

describe("M-5 refuse legacy keys on /mcp (cutover flag)", () => {
  for (const on of [false, true]) {
    it(`flag ${on ? "ON" : "OFF (default)"}: legacy key ${on ? "refused 403" : "accepted"}; agent key accepted; bad token 401`, async () => {
      const gw = await boot(on ? { refuseLegacyMcpKeys: true } : {});
      expect(loadConfig({ masterKeyRaw: "x", adminToken: "y" }).refuseLegacyMcpKeys).toBe(false); // default off
      const ws = gw.store.ensureWorkspace("default").id;
      const legacy = gw.store.createApiKey(ws, "legacy", { projects: ["*"] } as never);
      const id = gw.store.identity;
      const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
      const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
      const botTok = id.createKey({ agentId: bot, createdBy: chen }).token;
      const lr = await init(gw, legacy.token);
      if (on) {
        expect(lr.status).toBe(403);
        expect(await lr.text()).toMatch(/legacy keys are not accepted/);
      } else {
        expect(lr.status).toBe(200);
      }
      expect((await init(gw, botTok)).status).toBe(200);
      expect((await init(gw, "mf_" + "q".repeat(40))).status).toBe(401);
    });
  }
});

import { DatabaseSync } from "node:sqlite";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";

describe("R3-4 migration 0008 with pre-existing duplicate idempotency keys", () => {
  it("does not fail; keeps the earliest row's key, de-keys later ones, leaves other agents alone, records a note", () => {
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db, "0007_session_id_prefix");
    const dir = new AgentDirectory(db, derivePolicyKeys("rr3"));
    const WS = "ws_" + "c".repeat(24);
    const chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const other = dir.createAgent({ workspaceId: WS, name: "other", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const k1 = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
    const k2 = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
    dir.revokeKey(k1, chen, "rotate"); // max two live keys: revoke one to mint a third
    const k3 = dir.createKey({ agentId: bot, createdBy: chen }).keyId;

    const ko = dir.createKey({ agentId: other, createdBy: chen }).keyId;
    const ins = db.prepare(`INSERT INTO mcpflow_call_outcome (call_id, workspace_id, agent_id, key_id, idempotency_key, args_hash, created_at) VALUES (?,?,?,?,?,'h',?)`);
    ins.run("call_b", WS, bot, k2, "dup", "2026-10-01T00:00:02.000Z");
    ins.run("call_a", WS, bot, k1, "dup", "2026-10-01T00:00:01.000Z"); // earliest: keeps the key
    ins.run("call_c", WS, bot, k3, "dup", "2026-10-01T00:00:03.000Z");
    ins.run("call_o", WS, other, ko, "dup", "2026-10-01T00:00:00.000Z"); // different agent: untouched
    ins.run("call_u", WS, bot, k1, "uniq", "2026-10-01T00:00:04.000Z");
    expect(() => runMigrations(db)).not.toThrow();
    const keyOf = (id: string) => (db.prepare(`SELECT idempotency_key k FROM mcpflow_call_outcome WHERE call_id = ?`).get(id) as { k: string | null }).k;
    expect([keyOf("call_a"), keyOf("call_b"), keyOf("call_c"), keyOf("call_o"), keyOf("call_u")]).toEqual(["dup", null, null, "dup", "uniq"]);
    expect(JSON.parse((db.prepare(`SELECT note FROM mcpflow_migration_note WHERE migration_id='0008_idempotency_per_agent'`).get() as { note: string }).note)).toEqual({ dekeyed_duplicates: 2 });
    // identity trigger is back, and the per-agent index is in force
    expect(() => db.prepare(`UPDATE mcpflow_call_outcome SET idempotency_key='x' WHERE call_id='call_u'`).run()).toThrow(/immutable/);
    expect(() => ins.run("call_d", WS, bot, k2, "dup", "2026-10-02T00:00:00.000Z")).toThrow(/UNIQUE/);
  });

  it("clean DB: no note row", () => {
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db);
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_migration_note`).get() as { n: number }).n).toBe(0);
  });
});

import { readFileSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { acquireGatewayLock, lockIdentity } from "../src/db/gateway-lock.js";

const lockDir = () => {
  const d = mkdtempSync(join(tmpdir(), "rr3-lock-")); tmp.push(d);
  const dbPath = join(d, "t.db");
  return { dbPath, lockPath: `${dbPath}.gateway.lock` };
};
const staleLock = (lockPath: string, nonce: string) => {
  writeFileSync(lockPath, JSON.stringify({ nonce, pid: 99999999, host: "gone", bootId: null, pidNs: null, started: "x" }));
  const old = new Date(Date.now() - 120_000);
  utimesSync(lockPath, old, old);
};
const nonceAt = (p: string) => JSON.parse(readFileSync(p, "utf8")).nonce as string;

describe("R3-1 stale-lock takeover race: only one starter wins", () => {
  it("B judged the lock stale, but A replaced it first: B puts A's lock back and loses", async () => {
    const { dbPath, lockPath } = lockDir();
    staleLock(lockPath, "stale");
    const aBody = JSON.stringify({ nonce: "A-fresh", pid: 1, host: "a", bootId: null, pidNs: null, started: "now" });
    // between B's staleness check and B's rename, A takes over (fresh lock with its own nonce)
    await expect(acquireGatewayLock(dbPath, { settleMs: 1, hooks: { beforeRename: () => writeFileSync(lockPath, aBody) } }))
      .rejects.toThrow(/another mcp-flow gateway/);
    expect(nonceAt(lockPath)).toBe("A-fresh"); // A's lock restored, untouched
  });

  it("a winner whose fresh lock is replaced before the settle read-back loses (no two holders)", async () => {
    const { dbPath, lockPath } = lockDir();
    staleLock(lockPath, "stale");
    await expect(acquireGatewayLock(dbPath, { settleMs: 20, hooks: {
      afterCreate: () => writeFileSync(lockPath, JSON.stringify({ nonce: "B", pid: 2, host: "b", bootId: null, pidNs: null, started: "now" })),
    } })).rejects.toThrow(/another mcp-flow gateway/);
    expect(nonceAt(lockPath)).toBe("B");
  });

  it("the lock file carries a random nonce; the acquirer reads its own nonce back", async () => {
    const { dbPath, lockPath } = lockDir();
    const l = (await acquireGatewayLock(dbPath, { settleMs: 1 }))!;
    expect(l.nonce).toMatch(/^[0-9a-f]{32}$/);
    expect(nonceAt(lockPath)).toBe(l.nonce);
    l.release();
  });
});

describe("R3-2 heartbeat self-fencing", () => {
  it("lock module: when another process owns the file, the old holder does NOT refresh it and calls onLost", async () => {
    const { dbPath, lockPath } = lockDir();
    const lost: string[] = [];
    const l = (await acquireGatewayLock(dbPath, { settleMs: 1, heartbeatMs: 20, onLost: (r) => lost.push(r) }))!;
    writeFileSync(lockPath, JSON.stringify({ nonce: "new-owner", pid: 2, host: "b", bootId: null, pidNs: null, started: "now" }));
    const past = new Date(Date.now() - 120_000);
    utimesSync(lockPath, past, past);
    await new Promise((r) => setTimeout(r, 120));
    expect(lost).toHaveLength(1);
    expect(lost[0]).toMatch(/taken over/);
    expect(statSync(lockPath).mtimeMs).toBeLessThan(Date.now() - 60_000); // not refreshed by us
    expect(nonceAt(lockPath)).toBe("new-owner");
    l.release(); // must not delete the new owner's lock
    expect(nonceAt(lockPath)).toBe("new-owner");
  });

  it("server: losing the lock stops serving and calls the exit handler", async () => {
    const d = mkdtempSync(join(tmpdir(), "rr3-srv-")); tmp.push(d);
    const dbPath = join(d, "t.db");
    const cfg = loadConfig({ dbPath, masterKeyRaw: Buffer.alloc(32, 5).toString("base64"), adminToken: "rr3-admin", host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    cfg.port = (probe.address() as { port: number }).port;
    await new Promise<void>((r) => probe.close(() => r()));
    const lost: string[] = [];
    const gw = await startServer(cfg, { lockHeartbeatMs: 20, onLockLost: (r) => lost.push(r) });
    cleanups.push(() => gw.close());
    expect((await fetch(`${gw.url}/health`).catch(() => null))?.status ?? 0).toBeGreaterThan(0);
    writeFileSync(`${dbPath}.gateway.lock`, JSON.stringify({ nonce: "other", pid: 2, host: "b", bootId: null, pidNs: null, started: "now" }));
    await new Promise((r) => setTimeout(r, 150));
    expect(lost).toHaveLength(1);
    await expect(fetch(`${gw.url}/health`)).rejects.toThrow(); // no longer accepting connections
  });
});

describe("R3-3 hostname + pid alone is not trusted", () => {
  it("fresh lock with our hostname and our pid but a different boot id / pid namespace is NOT stale", async () => {
    const { dbPath, lockPath } = lockDir();
    writeFileSync(lockPath, JSON.stringify({ nonce: "other-ctr", pid: process.pid, host: lockIdentity().host, bootId: "other-boot", pidNs: "pid:[1]", started: "x" }));
    await expect(acquireGatewayLock(dbPath, { settleMs: 1 })).rejects.toThrow(/another mcp-flow gateway/);
    writeFileSync(lockPath, JSON.stringify({ nonce: "other-ctr", pid: 99999999, host: lockIdentity().host, started: "x" })); // dead-looking pid, no ns info
    await expect(acquireGatewayLock(dbPath, { settleMs: 1 })).rejects.toThrow(/another mcp-flow gateway/);
  });

  it("same host + boot id + pid namespace and a dead pid IS stale (fast takeover still works locally)", async () => {
    const id = lockIdentity();
    if (!id.bootId || !id.pidNs) return; // non-Linux: only the mtime rule applies
    const { dbPath, lockPath } = lockDir();
    writeFileSync(lockPath, JSON.stringify({ nonce: "dead", pid: 2 ** 22 + 4321, ...id, started: "x" }));
    const l = (await acquireGatewayLock(dbPath, { settleMs: 1 }))!;
    expect(nonceAt(lockPath)).toBe(l.nonce);
    l.release();
  });
});
