/** Frontend GAP-1..4 read endpoints: admin/approver scoping, no secrets. */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { loadConfig } from "../src/config.js";
import { startServer } from "../src/server.js";

const master = Buffer.alloc(32, 41).toString("base64");
const ADMIN = "read-admin-token";
const cleanups: Array<() => Promise<void>> = [];
const tmp: string[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

async function upstream() {
  const http = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
    const s = new Server({ name: "u", version: "1" }, { capabilities: { tools: {} } });
    s.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: ["echo", "run_command", "merge", "write"].map((n) => ({ name: n, description: `d-${n}`, inputSchema: { type: "object" as const } })),
    }));
    s.setRequestHandler(CallToolRequestSchema, async () => ({ content: [] }));
    const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await s.connect(t);
    await t.handleRequest(req, res, body);
  });
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  cleanups.push(() => new Promise((r) => http.close(() => r())));
  return `http://127.0.0.1:${(http.address() as { port: number }).port}/mcp`;
}

async function boot() {
  const url = await upstream();
  const d = mkdtempSync(join(tmpdir(), "read-ep-"));
  tmp.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: master, adminToken: ADMIN, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const gw = await startServer(cfg);
  cleanups.push(() => gw.close());
  const ws = gw.store.ensureWorkspace("default").id;
  const id = gw.store.identity;
  const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
  const chenK = id.createKey({ agentId: chen, createdBy: chen });
  const ana = id.createAgent({ workspaceId: ws, name: "ana", owner: "ana", kind: "human", projects: [], createdBy: chen });
  const anaK = id.createKey({ agentId: ana, createdBy: chen });
  const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  const botK = id.createKey({ agentId: bot, createdBy: chen });
  const resolved = id.resolveKey(botK.token);
  if (resolved.status !== "ok") throw new Error("bot key did not resolve");
  const sess = id.createSession(resolved.agent, "p1");
  const be = await fetch(`${gw.url}/v1/backends`, { method: "POST", headers: { Authorization: `Bearer ${ADMIN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ slug: "shell", url, transport: "streamable-http", enabled: true, placement: { mode: "remote" } }) });
  expect(be.status).toBeLessThan(300);
  gw.store.createProject(ws, { slug: "p1", title: "P1", backendSlugs: ["shell"] });
  const db = gw.store.db;
  const rule = (effect: string, tools: string[], matchArgs: unknown[] = [], approvers = [chen]) => {
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    const appr = effect === "require_approval";
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_backends, match_tools, match_args, effect, approvers, approval_timeout_s, created_by)
                VALUES (?,1,'t','["shell"]',?,?,?,?,?,?)`).run(rid, JSON.stringify(tools), JSON.stringify(matchArgs), effect, appr ? JSON.stringify(approvers) : null, appr ? 30 : null, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    db.exec("COMMIT;");
    return rid;
  };
  rule("allow", ["echo", "write"]);
  rule("deny", ["write"], [{ path: "$.path", op: "prefix", value: "/etc" }]);
  const mergeRule = rule("require_approval", ["merge"], [], [ana]);
  // run_command: no rule -> denied
  const get = (tok: string, path: string) => fetch(`${gw.url}${path}`, { headers: { Authorization: `Bearer ${tok}` } });
  const secrets = [chenK.token, anaK.token, botK.token, sess?.token].filter(Boolean) as string[];
  const hashes = (db.prepare(`SELECT secret_hash, prefix FROM mcpflow_api_key`).all() as Array<{ secret_hash: string; prefix: string }>);
  const noSecrets = (body: string) => {
    for (const s of secrets) expect(body).not.toContain(s);
    for (const h of hashes) {
      expect(body).not.toContain(h.secret_hash);
      expect(body).not.toContain(`"${h.prefix}"`);
    }
    expect(body).not.toMatch(/secret_hash|token_hash|"prefix"/);
  };
  return { gw, ws, chen, chenK, ana, anaK, bot, botK, get, noSecrets, mergeRule };
}

describe("admin UI read endpoints", () => {
  it("GAP-1 GET /v1/agents: admins only, agents with projects and keys, no key material", async () => {
    const e = await boot();
    for (const tok of [e.anaK.token, e.botK.token]) expect((await e.get(tok, "/v1/agents")).status).toBe(403);
    // V3-F2: 401 only for a missing or bad token
    expect((await fetch(`${e.gw.url}/v1/agents`)).status).toBe(401);
    expect((await e.get("mf_" + "z".repeat(40), "/v1/agents")).status).toBe(401);
    expect((await e.get("not-a-token", "/v1/agents")).status).toBe(401);
    for (const tok of [ADMIN, e.chenK.token]) {
      const r = await e.get(tok, "/v1/agents");
      expect(r.status).toBe(200);
      const text = await r.text();
      e.noSecrets(text);
      const { agents } = JSON.parse(text) as { agents: Array<Record<string, any>> };
      expect(agents.map((a) => a.name)).toEqual(["ana", "bot", "chen"]);
      const bot = agents.find((a) => a.name === "bot")!;
      expect(bot).toMatchObject({ kind: "grokbot", is_admin: false, status: "active", projects: ["p1"] });
      expect(bot.keys[0]).toMatchObject({ id: e.botK.keyId, status: "active" });
    }
    expect((await e.get(ADMIN, `/v1/agents/${e.bot}`)).status).toBe(200);
    expect((await e.get(ADMIN, `/v1/agents/agt_nope`)).status).toBe(404);
  });

  it("GAP-2 GET /v1/policy/rules: admins see all with versions; approvers see only rules listing them", async () => {
    const e = await boot();
    const r = await e.get(ADMIN, "/v1/policy/rules");
    expect(r.status).toBe(200);
    const { rules } = (await r.json()) as { rules: Array<Record<string, any>> };
    expect(rules).toHaveLength(3);
    const m = rules.find((x) => x.id === e.mergeRule)!;
    expect(m).toMatchObject({ active: true, current_version: 1, current: { effect: "require_approval", approvers: [e.ana], match_tools: ["merge"] } });
    expect(m.versions).toHaveLength(1);
    expect((await e.get(e.botK.token, "/v1/policy/rules")).status).toBe(403);
    expect((await e.get(e.anaK.token, "/v1/policy/rules")).status).toBe(403);
    const mine = (await (await e.get(e.anaK.token, "/v1/policy/approvals/rules")).json()) as { rules: Array<{ id: string }> };
    expect(mine.rules.map((x) => x.id)).toEqual([e.mergeRule]);
    expect((await e.get(e.botK.token, "/v1/policy/approvals/rules")).status).toBe(403);
  });

  it("GAP-3 GET /v1/backends/:id/tools: discovered tools, admins only", async () => {
    const e = await boot();
    const r = await e.get(ADMIN, "/v1/backends/shell/tools");
    expect(r.status).toBe(200);
    const body = (await r.json()) as { tools: Array<Record<string, unknown>> };
    expect(body.tools.map((t) => t.name)).toEqual(["shell__echo", "shell__merge", "shell__run_command", "shell__write"]);
    expect(body.tools[0]).toMatchObject({ upstream_name: "echo" });
    expect((await e.get(e.botK.token, "/v1/backends/shell/tools")).status).toBe(403);
    expect((await e.get(ADMIN, "/v1/backends/nope/tools")).status).toBe(404);
  });

  it("GAP-4 GET /v1/agents/:id/reach: per-project tool effect and live sessions, no tokens", async () => {
    const e = await boot();
    // human admin agents only: the env break-glass token (and legacy scopes.admin keys) get 403
    expect((await e.get(ADMIN, `/v1/agents/${e.bot}/reach`)).status).toBe(403);
    const legacy = e.gw.store.createApiKey(e.ws, "ops", { admin: true });
    expect((await e.get(legacy.token, `/v1/agents/${e.bot}`)).status).toBe(200); // still an admin elsewhere
    expect((await e.get(legacy.token, `/v1/agents/${e.bot}/reach`)).status).toBe(403);
    const r = await e.get(e.chenK.token, `/v1/agents/${e.bot}/reach`);
    expect(r.status).toBe(200);
    const text = await r.text();
    e.noSecrets(text);
    const body = JSON.parse(text) as { projects: Array<{ project: string; tools: Array<{ name: string; effect: string }>; sessions: unknown[] }> };
    const p1 = body.projects.find((p) => p.project === "p1")!;
    expect(Object.fromEntries(p1.tools.map((t) => [t.name, t.effect]))).toEqual({
      shell__echo: "allow", shell__merge: "require_approval", shell__run_command: "denied", shell__write: "conditional",
    });
    expect(p1.sessions.length).toBeGreaterThanOrEqual(1);
    expect(Object.keys(p1.sessions[0] as object).sort()).toEqual(["created_at", "expires_at", "key_id", "session_id"]);
    expect((p1.sessions[0] as { session_id: string }).session_id).toMatch(/^sess_/); // I-3
    expect((await e.get(e.anaK.token, `/v1/agents/${e.bot}/reach`)).status).toBe(403);
  });
});
