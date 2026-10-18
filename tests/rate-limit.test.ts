/** PM: per-agent tools/call rate limit (in-memory token bucket per agent_id, MCP_FLOW_RATE_LIMIT_PER_MIN, off by default). */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer } from "../src/policy/enforcer.js";
import { AgentRateLimiter, parseRateLimitPerMin } from "../src/policy/rate-limit.js";

const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

describe("AgentRateLimiter (token bucket)", () => {
  const fake = () => { const c = { t: 1_000_000 }; return { c, clock: () => c.t }; };

  it("off: 0 / unset / invalid parse to 0; an enforcer without a limit never refuses", () => {
    for (const raw of [undefined, null, "", "0", "abc", "-5", "1.5", " "]) expect(parseRateLimitPerMin(raw as string | undefined)).toBe(0);
    expect(parseRateLimitPerMin("60")).toBe(60);
    expect(parseRateLimitPerMin(" 7 ")).toBe(7);
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db);
    for (const off of [undefined, 0]) {
      const pe = new PolicyEnforcer({ db, keys: derivePolicyKeys("rl"), rateLimitPerMin: off });
      expect(pe.rateLimiter).toBeNull();
      for (let i = 0; i < 1000; i++) expect(pe.rateLimit({ workspaceId: "ws_x", agentId: "agt_x", keyId: "key_x" }, "a__b", {})).toBeNull();
    }
    expect(loadConfig({ dbPath: ":memory:" }).rateLimitPerMin).toBe(0);
    expect(() => new AgentRateLimiter(0)).toThrow();
  });

  it("under the limit: N calls in a burst pass; over: the next is refused with retry_after", () => {
    const { clock } = fake();
    const rl = new AgentRateLimiter(5, { clock });
    for (let i = 0; i < 5; i++) expect(rl.take("agt_a")).toMatchObject({ ok: true, remaining: 4 - i });
    const r = rl.take("agt_a");
    expect(r.ok).toBe(false);
    expect((r as { retryAfterMs: number }).retryAfterMs).toBe(12_000); // 5/min -> one token per 12 s
    expect(rl.take("agt_a").ok).toBe(false); // refusals don't go negative or stack up
  });

  it("per-agent isolation: one agent's burst doesn't touch another's bucket", () => {
    const { clock } = fake();
    const rl = new AgentRateLimiter(3, { clock });
    for (let i = 0; i < 3; i++) rl.take("agt_a");
    expect(rl.take("agt_a").ok).toBe(false);
    for (let i = 0; i < 3; i++) expect(rl.take("agt_b").ok).toBe(true);
    expect(rl.take("agt_b").ok).toBe(false);
  });

  it("refill: continuous at N/min, capped at N", () => {
    const { c, clock } = fake();
    const rl = new AgentRateLimiter(6, { clock }); // one token per 10 s
    for (let i = 0; i < 6; i++) rl.take("agt_a");
    expect(rl.take("agt_a").ok).toBe(false);
    c.t += 9_999;
    expect(rl.take("agt_a").ok).toBe(false);
    c.t += 1;
    expect(rl.take("agt_a").ok).toBe(true);
    expect(rl.take("agt_a").ok).toBe(false);
    c.t += 3_600_000; // an hour idle: back to full, never more than N
    for (let i = 0; i < 6; i++) expect(rl.take("agt_a").ok).toBe(true);
    expect(rl.take("agt_a").ok).toBe(false);
    c.t -= 5_000; // clock going backwards neither refills nor breaks it
    expect(rl.take("agt_a").ok).toBe(false);
  });

  it("buckets are capped: 1000 distinct agents never hold more than maxBuckets entries", () => {
    const { clock } = fake();
    const rl = new AgentRateLimiter(2, { clock, maxBuckets: 3 });
    for (let i = 0; i < 1000; i++) rl.take(`agt_spam${i}`);
    expect(rl.size).toBe(3);
  });

  it("on overflow, buckets that refilled to full go first (lossless), before any partly-used one", () => {
    const { c, clock } = fake();
    const rl = new AgentRateLimiter(2, { clock, maxBuckets: 2 });
    rl.take("agt_old"); // old: 1 token left (LRU)
    c.t += 1;
    rl.take("agt_a"); rl.take("agt_a"); // a: drained
    c.t += 30_000; // old refills to full (2); a only to 1
    rl.take("agt_new"); // overflow: old is full -> dropped; a (partly used) kept
    expect(rl.size).toBe(2);
    expect(rl.take("agt_a")).toMatchObject({ ok: true, remaining: 0 }); // a kept its partial state
    expect(rl.take("agt_a").ok).toBe(false);
  });

  it("a drained bucket is kept over full ones when the cap is hit (no time passing)", () => {
    const { clock } = fake();
    const rl = new AgentRateLimiter(2, { clock, maxBuckets: 2 });
    rl.take("agt_a"); rl.take("agt_a"); // a: 0 tokens
    // a new agent arrives: the cap is 2, a + new fit
    rl.take("agt_b"); // b: 1 token (not full)
    // third agent: nobody is full, LRU (a was used before b) would go -> a is evicted; so use a again first
    rl.take("agt_a"); // refused, but touches a (most recently used now)
    rl.take("agt_c"); // evicts b (LRU), not a
    expect(rl.take("agt_a").ok).toBe(false);
    expect(rl.size).toBe(2);
  });
});

describe("enforcer: over the limit = audited deny + not_dispatched completion", () => {
  it("writes decision deny/rate_limited and completion denied/not_dispatched; reply carries retry_after_ms", () => {
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db);
    const WS = "ws_" + "5".repeat(24);
    const dir = new AgentDirectory(db, derivePolicyKeys("rl"));
    const chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const key = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
    const pe = new PolicyEnforcer({ db, keys: derivePolicyKeys("rl"), rateLimitPerMin: 2 });
    const who = { workspaceId: WS, agentId: bot, agentName: "bot", keyId: key, projectId: "p1" };
    expect(pe.rateLimit(who, "gh__merge", { pr: 1 })).toBeNull();
    expect(pe.rateLimit(who, "gh__merge", { pr: 1 })).toBeNull();
    const r = pe.rateLimit(who, "gh__merge", { pr: 1, token: "ghp_secretsecretsecretsecret1234" })!;
    expect(r.isError).toBe(true);
    const p = JSON.parse((r.content[0] as { text: string }).text);
    expect(p).toMatchObject({ code: "policy_denied", reason: "rate_limited", limit_per_min: 2 });
    expect(p.retry_after_ms).toBeGreaterThan(0);
    const rows = db.prepare(`SELECT event_type, policy_decision, final_outcome, result_status, error_code, agent_id, args_redacted FROM mcpflow_call_audit WHERE event_type IN ('decision','completion') ORDER BY audit_id`).all() as Array<Record<string, unknown>>;
    expect(rows.map(({ args_redacted, ...x }) => x)).toEqual([
      { event_type: "decision", policy_decision: "deny", final_outcome: null, result_status: null, error_code: "rate_limited", agent_id: bot },
      { event_type: "completion", policy_decision: null, final_outcome: "denied", result_status: "not_dispatched", error_code: "rate_limited", agent_id: bot },
    ]);
    expect(String(rows[0]!.args_redacted)).not.toContain("ghp_secret");
  });
});

describe("gateway: tools/call over the limit never reaches the backend", () => {
  async function spyUpstream() {
    const seen: string[] = [];
    const http = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
      const s = new Server({ name: "spy", version: "1" }, { capabilities: { tools: {} } });
      s.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: "echo", inputSchema: { type: "object" as const } }] }));
      s.setRequestHandler(CallToolRequestSchema, async (r) => { seen.push(r.params.name); return { content: [{ type: "text", text: "ran" }] }; });
      const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await s.connect(t);
      await t.handleRequest(req, res, body);
    });
    await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
    cleanups.push(() => new Promise((r) => http.close(() => r())));
    return { url: `http://127.0.0.1:${(http.address() as { port: number }).port}/mcp`, seen };
  }

  it("limit 3/min: 3 calls dispatched, the 4th and 5th refused (rate_limited) with 0 upstream calls; another agent unaffected", async () => {
    const up = await spyUpstream();
    const d = mkdtempSync(join(tmpdir(), "mcp-flow-rl-"));
    tmp.push(d);
    const ADMIN = randomBytes(24).toString("hex");
    const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: Buffer.alloc(32, 9).toString("base64"), adminToken: ADMIN, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default", rateLimitPerMin: 3 });
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    cfg.port = (probe.address() as { port: number }).port;
    await new Promise<void>((r) => probe.close(() => r()));
    const gw: RunningServer = await startServer(cfg);
    cleanups.push(() => gw.close());
    const ws = gw.store.ensureWorkspace("default").id;
    const id = gw.store.identity;
    const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
    const mk = (name: string) => {
      const a = id.createAgent({ workspaceId: ws, name, owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
      return { a, tok: id.createKey({ agentId: a, createdBy: chen }).token };
    };
    const bot = mk("bot");
    const bot2 = mk("bot2");
    const be = await fetch(`${gw.url}/v1/backends`, { method: "POST", headers: { Authorization: `Bearer ${ADMIN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "shell", url: up.url, transport: "streamable-http", enabled: true, placement: { mode: "remote" } }) });
    expect(be.status).toBeLessThan(300);
    gw.store.createProject(ws, { slug: "p1", title: "P1", backendSlugs: ["shell"] });
    const db = gw.store.db;
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, created_by) VALUES (?,1,'rl','["*"]','allow',?)`).run(rid, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    db.exec("COMMIT;");
    const connect = async (tok: string) => {
      const client = new Client({ name: "rl", version: "1" });
      await client.connect(new StreamableHTTPClientTransport(new URL(`${gw.url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${tok}` } } }));
      cleanups.push(() => client.close());
      await client.callTool({ name: "mf_use_project", arguments: { project: "p1", mintSessionToken: false } });
      return client;
    };
    const c1 = await connect(bot.tok);
    const out: string[] = [];
    for (let i = 0; i < 5; i++) {
      const r: any = await c1.callTool({ name: "shell__echo", arguments: { i } });
      out.push(r.isError ? JSON.parse(r.content[0].text).reason : r.content[0].text);
    }
    expect(out).toEqual(["ran", "ran", "ran", "rate_limited", "rate_limited"]);
    expect(up.seen).toHaveLength(3);
    // other agent has its own bucket
    const c2 = await connect(bot2.tok);
    const r2: any = await c2.callTool({ name: "shell__echo", arguments: {} });
    expect(r2.isError).toBeFalsy();
    expect(up.seen).toHaveLength(4);
    // unknown tools are rate limited too (no audit flooding through refusals)
    const r3: any = await c1.callTool({ name: "shell__nope", arguments: {} });
    expect(JSON.parse(r3.content[0].text).reason).toBe("rate_limited");
    const limited = db.prepare(`SELECT event_type, final_outcome, result_status FROM mcpflow_call_audit WHERE error_code = 'rate_limited' AND agent_id = ? ORDER BY audit_id`).all(bot.a);
    expect(limited).toHaveLength(6); // 3 refusals x (decision + completion)
    expect(limited.filter((r: any) => r.event_type === "completion").every((r: any) => r.final_outcome === "denied" && r.result_status === "not_dispatched")).toBe(true);
  }, 30_000);
});
