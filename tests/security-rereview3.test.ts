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
