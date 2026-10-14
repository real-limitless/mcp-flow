// QA T2.5 v5: M-5 flag + 0008 upgrade with duplicates. No secrets printed.
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { argsHash } from "../src/policy/crypto.js";
import { PolicyEnforcer } from "../src/policy/enforcer.js";

const tmp: string[] = [];
const gws: RunningServer[] = [];
afterEach(async () => { while (gws.length) await gws.pop()!.close().catch(() => {}); while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true }); delete process.env.MCP_FLOW_REFUSE_LEGACY_MCP_KEYS; });

async function boot(over: Record<string, unknown> = {}) {
  const d = mkdtempSync(join(tmpdir(), "qa-v5-")); tmp.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: Buffer.alloc(32, 3).toString("base64"), adminToken: "qa-v5-admin-token", host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default", ...over } as never);
  const probe = createServer(); await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port; await new Promise<void>((r) => probe.close(() => r()));
  const gw = await startServer(cfg); gws.push(gw); return gw;
}
const init = (gw: RunningServer, token: string) => fetch(`${gw.url}/mcp`, {
  method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
});

describe("QA-v5 M-5 refuse legacy keys on /mcp", () => {
  it("m5a env parsing table", () => {
    const table: Record<string, boolean> = {};
    for (const v of ["true", "TRUE", "True", " true ", "1", "false", "FALSE", "0", "", "yes", "on", "2", "enabled", "tru", "1 ", " 1", "01", "true1"]) {
      process.env.MCP_FLOW_REFUSE_LEGACY_MCP_KEYS = v;
      table[JSON.stringify(v)] = loadConfig({ masterKeyRaw: "x", adminToken: "y" } as never).refuseLegacyMcpKeys!;
    }
    delete process.env.MCP_FLOW_REFUSE_LEGACY_MCP_KEYS;
    table["<unset>"] = loadConfig({ masterKeyRaw: "x", adminToken: "y" } as never).refuseLegacyMcpKeys!;
    console.log("QA-m5a", JSON.stringify(table));
    for (const k of ['"true"', '"TRUE"', '"True"', '"1"']) expect(table[k]).toBe(true);
    for (const k of ['"false"', '"0"', '""', '"<unset>"', '"yes"', '"on"', '"2"', '"garbage"'].filter((x) => x in table)) expect(table[k]).toBe(false);
    expect(table["<unset>"]).toBe(false);
  });

  for (const on of [false, true]) {
    it(`m5b server flag ${on ? "ON" : "OFF"}: legacy key + legacy session vs agent key + agent session; refusal audited`, async () => {
      if (on) process.env.MCP_FLOW_REFUSE_LEGACY_MCP_KEYS = "TRUE";
      const gw = await boot();
      const ws = gw.store.ensureWorkspace("default").id;
      gw.store.createProject(ws, { slug: "p1", title: "P1", backendSlugs: [] });
      const legacy = gw.store.createApiKey(ws, "legacy", { projects: ["*"] } as never);
      let legacySess: string | null = null;
      try { legacySess = (gw.store.createProjectSession(ws, (legacy as any).id ?? (legacy as any).keyId, "p1") as any).token ?? null; } catch { legacySess = null; }
      const id = gw.store.identity;
      const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
      const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
      const bk = id.createKey({ agentId: bot, createdBy: chen });
      const sess = id.createSession({ agentId: bot, keyId: bk.keyId, keyExpiresAt: new Date(Date.now() + 86400e3).toISOString(), effectiveProjects: ["p1"] } as any, "p1");
      const auditBefore = gw.store.listAudit(ws, { limit: 500 }).length;
      const st = {
        legacyKey: (await init(gw, legacy.token)).status,
        legacySession: legacySess ? (await init(gw, legacySess)).status : "n/a",
        agentKey: (await init(gw, bk.token)).status,
        agentSession: (await init(gw, sess.token)).status,
        badToken: (await init(gw, "mf_" + "q".repeat(40))).status,
      };
      const newAudit = gw.store.listAudit(ws, { limit: 500 }).slice(0, gw.store.listAudit(ws, { limit: 500 }).length - auditBefore);
      const refusalAudited = newAudit.some((a: any) => /legacy|refus|denied|unauthor/i.test(JSON.stringify(a)));
      console.log(`QA-m5b ${on ? "ON" : "OFF"}`, JSON.stringify({ st, refusalAudited, newAuditActions: newAudit.map((a: any) => a.action) }));
      expect(st.agentKey).toBe(200); expect(st.agentSession).toBe(200); expect(st.badToken).toBe(401);
      if (on) { expect(st.legacyKey).toBe(403); if (legacySess) expect(st.legacySession).toBe(403); expect.soft(refusalAudited, "legacy refusal should be audited").toBe(true); }
      else { expect(st.legacyKey).toBe(200); }
    });
  }
});

describe("QA-v5 0008 upgrade with duplicate idempotency keys", () => {
  it("u1 upgrade succeeds, earliest keeps key, outcome data preserved, per-agent idempotency afterwards", async () => {
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db, "0007_session_id_prefix");
    const keys = derivePolicyKeys("qa-v5-0008");
    const dir = new AgentDirectory(db, keys);
    const WS = "ws_" + "d".repeat(24);
    const chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const other = dir.createAgent({ workspaceId: WS, name: "other", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const k1 = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
    const k2 = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
    const ko = dir.createKey({ agentId: other, createdBy: chen }).keyId;
    const H = argsHash(keys.argsHmac, { x: 1 });
    const ins = db.prepare(`INSERT INTO mcpflow_call_outcome (call_id, workspace_id, agent_id, key_id, idempotency_key, qualified_tool, args_hash, state, final_outcome, result_status, created_at, completed_at, result_bytes)
                            VALUES (?,?,?,?,?,'shell__run_command',?,?,?,?,?,?,?)`);
    const T = "2026-10-01T00:00:00.000Z";
    // same agent, same key "dup": three rows; two share created_at (tie broken by call_id)
    ins.run("call_b2", WS, bot, k2, "dup", H, "executed", "executed", "ok", T, T, 11);
    ins.run("call_b1", WS, bot, k1, "dup", H, "not_executed", "denied", "not_dispatched", T, T, null);
    ins.run("call_b3", WS, bot, k2, "dup2", H, "unknown", "error", "error", "2026-10-02T00:00:00.000Z", T, null);
    ins.run("call_b4", WS, bot, k1, "dup2", H, "executed", "executed", "ok", "2026-10-03T00:00:00.000Z", T, 5);
    // other agent, same "dup"
    ins.run("call_o1", WS, other, ko, "dup", H, "executed", "executed", "ok", "2026-09-01T00:00:00.000Z", T, 7);
    const snap = () => db.prepare(`SELECT call_id, idempotency_key k, state, final_outcome, result_status, result_bytes, completed_at FROM mcpflow_call_outcome ORDER BY call_id`).all();
    const before = snap();
    expect(() => runMigrations(db)).not.toThrow();
    const after = snap() as any[];
    const keysAfter = Object.fromEntries(after.map((r) => [r.call_id, r.k]));
    const dataSame = before.every((b: any, i) => JSON.stringify({ ...b, k: null }) === JSON.stringify({ ...after[i], k: null }));
    const note = (db.prepare(`SELECT note FROM mcpflow_migration_note`).get() as any)?.note;
    // idempotency afterwards via the real enforcer
    const pe = new PolicyEnforcer({ db, keys });
    const ctx = (agentId: string, keyId: string) => ({ workspaceId: WS, agentId, agentName: "x", keyId, keyPrefix: null, sessionId: null, projectId: "p1", backendSlug: "shell", tool: "run_command", qualifiedTool: "shell__run_command", placement: "remote", deviceId: null });
    let ran = 0;
    const dispatch = async () => { ran++; return { content: [{ type: "text" as const, text: "ran" }] }; };
    const rBotK2 = await pe.enforce({ ctx: ctx(bot, k2), args: { x: 1 }, dispatch, idempotencyKey: "dup" });
    const rBotK1dup2 = await pe.enforce({ ctx: ctx(bot, k1), args: { x: 1 }, dispatch, idempotencyKey: "dup2" });
    const rOther = await pe.enforce({ ctx: ctx(other, ko), args: { x: 1 }, dispatch, idempotencyKey: "dup" });
    const rBotConflict = await pe.enforce({ ctx: ctx(bot, k1), args: { x: 2 }, dispatch, idempotencyKey: "dup" });
    const t = (r: any) => JSON.parse(r.content[0].text);
    console.log("QA-u1", JSON.stringify({ keysAfter, dataSame, note, replays: { botDup: [t(rBotK2).code, t(rBotK2).state, t(rBotK2).call_id], botDup2: [t(rBotK1dup2).state, t(rBotK1dup2).call_id], otherDup: [t(rOther).state, t(rOther).call_id], conflict: t(rBotConflict).reason }, ran }));
    // tie (same created_at): call_b1 < call_b2 by call_id -> b1 keeps "dup"
    expect(keysAfter).toEqual({ call_b1: "dup", call_b2: null, call_b3: "dup2", call_b4: null, call_o1: "dup" });
    expect(dataSame).toBe(true);
    expect(JSON.parse(note)).toEqual({ dekeyed_duplicates: 2 });
    expect(ran).toBe(0);
    expect(t(rBotK2).call_id ?? "call_b1").toBe("call_b1");
    expect(t(rBotK2).state).toBe("not_executed");
    expect(t(rBotK1dup2).state).toBe("unknown");
    expect(t(rOther).state).toBe("executed");
    expect(t(rBotConflict).reason).toBe("idempotency_conflict");
  });
});
