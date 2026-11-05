import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory, RESOLVE_CACHE_MS } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";

const WS = "ws_" + "a".repeat(24);
let db: DatabaseSync;
let dir: AgentDirectory;
let now: number;
let chen: string;

function setup() {
  db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  now = Date.now();
  dir = new AgentDirectory(db, derivePolicyKeys("unit-test-dev-key"), () => now);
  chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
}

function bot(name: string, projects = ["gb_devops"]) {
  return dir.createAgent({ workspaceId: WS, name, owner: "chen", kind: "grokbot", projects, createdBy: chen });
}

describe("AgentDirectory (T1.3 resolution)", () => {
  beforeEach(setup);

  it("resolves a key to its agent with key ∩ agent projects", () => {
    const a = bot("grokbot-backend", ["gb_devops", "wiki"]);
    const k = dir.createKey({ agentId: a, createdBy: chen, projects: ["wiki"] });
    expect(k.token.startsWith("mf_")).toBe(true);
    expect(k.prefix).toBe(k.token.slice(3, 15));
    const r = dir.resolveKey(k.token, "100.64.0.56");
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.agent).toMatchObject({ agentId: a, agentName: "grokbot-backend", owner: "chen", keyId: k.keyId, isAdmin: false });
    expect(r.agent.effectiveProjects).toEqual(["wiki"]);
    const used = db.prepare(`SELECT last_used_ip FROM mcpflow_api_key WHERE id=?`).get(k.keyId) as { last_used_ip: string };
    expect(used.last_used_ip).toBe("100.64.0.56");
  });

  it("never stores the plaintext secret", () => {
    const k = dir.createKey({ agentId: bot("b"), createdBy: chen });
    const row = db.prepare(`SELECT secret_hash FROM mcpflow_api_key WHERE id=?`).get(k.keyId) as { secret_hash: string };
    expect(row.secret_hash).not.toContain(k.token);
    expect(row.secret_hash.startsWith("sha256-pepper$v1$")).toBe(true);
    const audit = JSON.stringify(db.prepare(`SELECT * FROM mcpflow_call_audit`).all());
    expect(audit).not.toContain(k.token);
  });

  it("rejects a wrong secret with a known prefix only for the legacy path (unknown), never ok", () => {
    const k = dir.createKey({ agentId: bot("b"), createdBy: chen });
    const forged = k.token.slice(0, 15) + "x".repeat(k.token.length - 15);
    expect(dir.resolveKey(forged).status).toBe("unknown");
    expect(dir.resolveKey("mf_short").status).toBe("unknown");
    expect(dir.resolveKey("not-a-key").status).toBe("unknown");
  });

  it("revoking one agent leaves the others working (plan 'done when')", () => {
    const a = bot("a");
    const b = bot("b");
    const ka = dir.createKey({ agentId: a, createdBy: chen });
    const kb = dir.createKey({ agentId: b, createdBy: chen });
    expect(dir.resolveKey(ka.token).status).toBe("ok"); // warm the cache
    dir.revokeAgent(a, chen, "test");
    expect(dir.resolveKey(ka.token).status).toBe("unauthorized");
    expect(dir.resolveKey(kb.token).status).toBe("ok");
  });

  it("suspended agent and revoked key are rejected immediately despite the cache", () => {
    const a = bot("a");
    const k1 = dir.createKey({ agentId: a, createdBy: chen });
    expect(dir.resolveKey(k1.token).status).toBe("ok");
    dir.revokeKey(k1.keyId, chen, "leaked");
    expect(dir.resolveKey(k1.token).status).toBe("unauthorized");
    const k2 = dir.createKey({ agentId: a, createdBy: chen });
    expect(dir.resolveKey(k2.token).status).toBe("ok");
    dir.suspendAgent(a, chen);
    expect(dir.resolveKey(k2.token).status).toBe("unauthorized");
  });

  it("expired key is rejected, including from cache", () => {
    const k = dir.createKey({ agentId: bot("a"), createdBy: chen, ttlDays: 1 });
    expect(dir.resolveKey(k.token).status).toBe("ok");
    now += 2 * 86_400_000;
    expect(dir.resolveKey(k.token).status).toBe("unauthorized");
  });

  it("cache: a change made by another process (no in-process bump) applies on the next lookup (Security L-5)", () => {
    const k = dir.createKey({ agentId: bot("a"), createdBy: chen });
    expect(dir.resolveKey(k.token).status).toBe("ok");
    // change state behind the directory's back: the DB epoch trigger invalidates the cache entry
    db.prepare(`UPDATE mcpflow_agent SET status='suspended' WHERE name='a'`).run();
    expect(dir.resolveKey(k.token).status).toBe("unauthorized");
    expect(RESOLVE_CACHE_MS).toBeLessThanOrEqual(5_000);
    void now;
  });

  it("no projects in key ∩ agent is forbidden", () => {
    const k = dir.createKey({ agentId: bot("a", []), createdBy: chen });
    expect(dir.resolveKey(k.token)).toMatchObject({ status: "forbidden", reason: "no_projects" });
  });

  it("key projects must be a subset of agent projects", () => {
    expect(() => dir.createKey({ agentId: bot("a", ["gb_devops"]), createdBy: chen, projects: ["other"] })).toThrow(/FOREIGN KEY/);
  });

  it("rotation: two live keys, old one rotating with forced expiry ≤ 7 days; third rejected", () => {
    const a = bot("a");
    const k1 = dir.createKey({ agentId: a, createdBy: chen });
    const k2 = dir.rotateKey(k1.keyId, chen);
    expect(dir.resolveKey(k1.token).status).toBe("ok");
    expect(dir.resolveKey(k2.token).status).toBe("ok");
    const old = db.prepare(`SELECT status, expires_at FROM mcpflow_api_key WHERE id=?`).get(k1.keyId) as { status: string; expires_at: string };
    expect(old.status).toBe("rotating");
    expect(Date.parse(old.expires_at) - now).toBeLessThanOrEqual(7 * 86_400_000 + 1000);
    expect(() => dir.createKey({ agentId: a, createdBy: chen })).toThrow(/2 live keys/);
  });

  it("sessions: bound to agent/key/project, outlive neither key nor revocation", () => {
    const a = bot("a", ["gb_devops", "wiki"]);
    const k = dir.createKey({ agentId: a, createdBy: chen, ttlDays: 1 });
    const r = dir.resolveKey(k.token);
    if (r.status !== "ok") throw new Error("resolve");
    expect(() => dir.createSession(r.agent, "secret-project")).toThrow(/not permitted/);
    const s = dir.createSession(r.agent, "wiki", 7 * 86_400_000);
    expect(Date.parse(s.expiresAt)).toBeLessThanOrEqual(Date.parse(r.agent.keyExpiresAt));
    const rs = dir.resolveSession(s.token);
    expect(rs.status).toBe("ok");
    if (rs.status === "ok") {
      expect(rs.agent.agentId).toBe(a);
      expect(rs.agent.sessionProject).toBe("wiki");
    }
    dir.revokeKey(k.keyId, chen, "r");
    expect(dir.resolveSession(s.token).status).toBe("unauthorized");
    expect(dir.resolveSession("mf_sess_nope").status).toBe("unknown");
  });

  it("lifecycle actions write audit rows with an agt_ actor", () => {
    const a = bot("a");
    const k = dir.createKey({ agentId: a, createdBy: chen });
    dir.revokeKey(k.keyId, chen, "r");
    dir.suspendAgent(a, chen);
    const rows = db
      .prepare(`SELECT lifecycle_action, actor FROM mcpflow_call_audit WHERE event_type='lifecycle' ORDER BY audit_id`)
      .all() as Array<{ lifecycle_action: string; actor: string }>;
    expect(rows.map((r) => r.lifecycle_action)).toEqual([
      "workspace_bootstrap", "agent_create", "key_create", "key_revoke", "agent_suspend",
    ]);
    expect(rows.every((r) => r.actor === chen)).toBe(true);
  });

  it("only human agents may be admin", () => {
    expect(() =>
      dir.createAgent({ workspaceId: WS, name: "x", owner: "chen", kind: "grokbot", isAdmin: true, projects: [], createdBy: chen }),
    ).toThrow(/CHECK/);
  });
});

// ---------------- gateway integration ----------------

const master = Buffer.alloc(32, 5).toString("base64");
const admin = "test-admin-token-identity";
const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

async function boot(): Promise<RunningServer> {
  const d = mkdtempSync(join(tmpdir(), "mcp-flow-id-"));
  tmp.push(d);
  const cfg = loadConfig({
    dbPath: join(d, "t.db"), masterKeyRaw: master, adminToken: admin,
    host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default",
    policyDevKeyRaw: "integration-dev-key",
  });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

async function connect(url: string, token: string): Promise<Client> {
  const client = new Client({ name: "t", version: "1" });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${url}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
    }),
  );
  cleanups.push(() => client.close());
  return client;
}

function text(res: unknown): string {
  return ((res as { content: Array<{ text: string }> }).content[0]!.text);
}

describe("gateway stamps the agent on every request", () => {
  it("mf_status, project 403, sessions, revocation and legacy keys", async () => {
    const gw = await boot();
    const ws = gw.store.ensureWorkspace("default");
    gw.store.createProject(ws.id, { slug: "gb_devops", title: "DevOps" });
    gw.store.createProject(ws.id, { slug: "wiki", title: "Wiki" });
    const id = gw.store.identity;
    const human = id.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
    const a = id.createAgent({ workspaceId: ws.id, name: "grokbot-backend", owner: "chen", kind: "grokbot", projects: ["gb_devops"], createdBy: human });
    const b = id.createAgent({ workspaceId: ws.id, name: "grokbot-devops", owner: "chen", kind: "grokbot", projects: ["gb_devops"], createdBy: human });
    const ka = id.createKey({ agentId: a, createdBy: human });
    const kb = id.createKey({ agentId: b, createdBy: human });

    const ca = await connect(gw.url, ka.token);
    const status = JSON.parse(text(await ca.callTool({ name: "mf_status", arguments: {} })));
    expect(status.agent).toMatchObject({ id: a, name: "grokbot-backend", keyId: ka.keyId, effectiveProjects: ["gb_devops"] });
    expect(JSON.stringify(status)).not.toContain(ka.token);

    const denied = await ca.callTool({ name: "mf_use_project", arguments: { project: "wiki" } });
    expect(denied.isError).toBe(true);
    expect(text(denied)).toMatch(/403/);

    const used = JSON.parse(text(await ca.callTool({ name: "mf_use_project", arguments: { project: "gb_devops" } })));
    expect(used.ok).toBe(true);
    expect(used.mcpSessionId).toMatch(new RegExp(`^agent:${a}:${ka.keyId}:[0-9a-f]{32}$`));
    expect(used.sessionToken.startsWith("mf_sess_")).toBe(true);

    const cs = await connect(gw.url, used.sessionToken);
    const sStatus = JSON.parse(text(await cs.callTool({ name: "mf_status", arguments: {} })));
    expect(sStatus.agent.id).toBe(a);
    expect(sStatus.project.slug).toBe("gb_devops");

    // revoke agent A: its key and session stop, agent B keeps working
    id.revokeAgent(a, human, "test");
    const post = (tok: string) =>
      fetch(`${gw.url}/mcp`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
      });
    expect((await post(ka.token)).status).toBe(401);
    expect((await post(used.sessionToken)).status).toBe(401);
    expect((await post(kb.token)).status).toBe(200);

    // legacy keys still work (compatibility mode until T1.4), with no agent stamped
    const legacy = gw.store.createApiKey(ws.id, "Bot_Engineer_Alex");
    const cl = await connect(gw.url, legacy.token);
    const lStatus = JSON.parse(text(await cl.callTool({ name: "mf_status", arguments: {} })));
    expect(lStatus.agent).toBeNull();
    expect(lStatus.keyName).toBe("Bot_Engineer_Alex");
  });
});

describe("agent session ids (T1.1 §3.5)", () => {
  it("are random per client, returned in Mcp-Session-Id, and not shared across clients", async () => {
    const gw = await boot();
    const ws = gw.store.ensureWorkspace("default");
    gw.store.createProject(ws.id, { slug: "gb_devops", title: "DevOps" });
    gw.store.createProject(ws.id, { slug: "wiki", title: "Wiki" });
    const id = gw.store.identity;
    const human = id.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
    const a = id.createAgent({ workspaceId: ws.id, name: "bot", owner: "chen", kind: "grokbot", projects: ["gb_devops", "wiki"], createdBy: human });
    const k = id.createKey({ agentId: a, createdBy: human });

    // two concurrent clients on the same key
    const [c1, c2] = await Promise.all([connect(gw.url, k.token), connect(gw.url, k.token)]);
    const [u1, u2] = await Promise.all([
      c1.callTool({ name: "mf_use_project", arguments: { project: "gb_devops", mintSessionToken: false } }),
      c2.callTool({ name: "mf_use_project", arguments: { project: "wiki", mintSessionToken: false } }),
    ]);
    const s1 = JSON.parse(text(u1)).mcpSessionId as string;
    const s2 = JSON.parse(text(u2)).mcpSessionId as string;
    expect(s1).not.toBe(s2);
    // each client keeps its own binding (the SDK echoes Mcp-Session-Id)
    const st1 = JSON.parse(text(await c1.callTool({ name: "mf_status", arguments: {} })));
    const st2 = JSON.parse(text(await c2.callTool({ name: "mf_status", arguments: {} })));
    expect(st1.project.slug).toBe("gb_devops");
    expect(st2.project.slug).toBe("wiki");

    // a client that doesn't echo gets a fresh id every time and no inherited binding
    const raw = async (headers: Record<string, string> = {}) =>
      fetch(`${gw.url}/mcp`, {
        method: "POST",
        headers: { Authorization: `Bearer ${k.token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream", ...headers },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mf_status", arguments: {} } }),
      });
    const r1 = await raw();
    const r2 = await raw();
    const h1 = r1.headers.get("mcp-session-id")!;
    const h2 = r2.headers.get("mcp-session-id")!;
    expect(h1).toMatch(new RegExp(`^agent:${a}:${k.keyId}:[0-9a-f]{32}$`));
    expect(h2).not.toBe(h1);
    const body = await r1.json() as { result: { content: Array<{ text: string }> } };
    // no inherited binding: falls back to the agent's first permitted project, never c2's "wiki"
    expect(JSON.parse(body.result.content[0]!.text).project.slug).toBe("gb_devops");

    // the old deterministic id (and another key's id) is not accepted as a binding
    const guess = await raw({ "mcp-session-id": `agent:${a}:${k.keyId}` });
    expect(guess.headers.get("mcp-session-id")).not.toBe(`agent:${a}:${k.keyId}`);
    const gBody = await guess.json() as { result: { content: Array<{ text: string }> } };
    expect(JSON.parse(gBody.result.content[0]!.text).project.slug).toBe("gb_devops");
    const k2 = id.createKey({ agentId: a, createdBy: human });
    const stolen = await fetch(`${gw.url}/mcp`, {
      method: "POST",
      headers: { Authorization: `Bearer ${k2.token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream", "mcp-session-id": s2 },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "mf_status", arguments: {} } }),
    });
    expect(stolen.headers.get("mcp-session-id")).not.toBe(s2);
    const sBody = await stolen.json() as { result: { content: Array<{ text: string }> } };
    expect(JSON.parse(sBody.result.content[0]!.text).project.slug).toBe("gb_devops"); // not c2's "wiki"
  });

  it("ids carry 128 bits of randomness", async () => {
    const { newAgentSessionId } = await import("../src/identity/auth-context.js");
    const ids = new Set(Array.from({ length: 2000 }, () => newAgentSessionId({ agentId: "agt_x", keyId: "key_y" })));
    expect(ids.size).toBe(2000);
    for (const sid of [...ids].slice(0, 5)) expect(sid).toMatch(/^agent:agt_x:key_y:[0-9a-f]{32}$/);
  });
});
