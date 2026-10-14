import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer, type PendingNotice } from "../src/policy/enforcer.js";
import type { CallContext } from "../src/policy/engine.js";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";

const WS = "ws_" + "b".repeat(24);
const keys = derivePolicyKeys("policy-unit-dev-key");

let db: DatabaseSync;
let dir: AgentDirectory;
let pe: PolicyEnforcer;
let chen: string;
let bot: string;
let botKey: string;
let notices: PendingNotice[];
let auditFail: boolean;

function setup() {
  db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  dir = new AgentDirectory(db, keys);
  chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
  bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["gb_devops"], createdBy: chen });
  botKey = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
  notices = [];
  auditFail = false;
  pe = new PolicyEnforcer({ db, keys, notify: async (n) => void notices.push(n), auditFault: () => auditFail });
}

function rule(r: {
  effect: "allow" | "deny" | "require_approval";
  priority?: number;
  backends?: string[];
  tools?: string[];
  agents?: string[];
  projects?: string[];
  args?: unknown[];
  timeoutS?: number;
  approvers?: string[];
  reason?: string;
}): string {
  const id = `rule_${randomBytes(12).toString("hex")}`;
  const appr = r.effect === "require_approval";
  db.exec("BEGIN IMMEDIATE;");
  db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, WS, chen);
  db.prepare(
    `INSERT INTO mcpflow_policy_rule_version (rule_id, version, priority, description, match_agents, match_projects,
       match_backends, match_tools, match_args, effect, approval_timeout_s, approvers, reason_to_agent, created_by)
     VALUES (?,1,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    id, r.priority ?? 100, `${r.effect} rule`, JSON.stringify(r.agents ?? ["*"]), JSON.stringify(r.projects ?? ["*"]),
    JSON.stringify(r.backends ?? ["*"]), JSON.stringify(r.tools ?? ["*"]), JSON.stringify(r.args ?? []), r.effect,
    appr ? (r.timeoutS ?? 300) : null, appr ? JSON.stringify(r.approvers ?? [chen]) : null, r.reason ?? null, chen,
  );
  db.prepare(`UPDATE mcpflow_policy_rule SET current_version = 1 WHERE id = ?`).run(id);
  db.exec("COMMIT;");
  return id;
}

function ctx(over: Partial<CallContext> = {}): CallContext {
  return {
    workspaceId: WS, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null,
    projectId: "gb_devops", backendSlug: "gh-repos-shell", tool: "run_command",
    qualifiedTool: "gh-repos-shell__run_command", placement: "remote", deviceId: null, ...over,
  };
}

function stub() {
  const calls: Array<Record<string, unknown>> = [];
  const dispatch = async (a: Record<string, unknown>): Promise<CallToolResult> => {
    calls.push(structuredClone(a));
    return { content: [{ type: "text", text: "ran" }] };
  };
  return { calls, dispatch };
}

const payload = (r: CallToolResult) => JSON.parse((r.content[0] as { text: string }).text);
const rows = (callIdFilter = "") =>
  db.prepare(`SELECT * FROM mcpflow_call_audit WHERE event_type <> 'lifecycle' ${callIdFilter} ORDER BY audit_id`).all() as Array<Record<string, unknown>>;
const waitFor = async (cond: () => boolean, ms = 2000) => {
  const t = Date.now();
  while (!cond()) {
    if (Date.now() - t > ms) throw new Error("timeout waiting");
    await new Promise((r) => setTimeout(r, 5));
  }
};
const pendingId = () => (db.prepare(`SELECT id FROM mcpflow_pending_call ORDER BY created_at DESC LIMIT 1`).get() as { id: string }).id;

describe("T2.2 decisions", () => {
  beforeEach(setup);

  it("default deny: no matching rule never dispatches and is audited", async () => {
    const s = stub();
    const r = await pe.enforce({ ctx: ctx(), args: { command: "ls" }, dispatch: s.dispatch });
    expect(s.calls).toHaveLength(0);
    expect(payload(r)).toMatchObject({ code: "policy_denied", reason: "no_matching_rule" });
    const a = rows();
    expect(a.map((x) => [x.event_type, x.policy_decision, x.final_outcome, x.result_status])).toEqual([
      ["decision", "deny", null, null],
      ["completion", null, "denied", "not_dispatched"],
    ]);
    expect(a[0]!.call_id).toBe(a[1]!.call_id);
  });

  it("allow dispatches once and records executed/ok", async () => {
    const id = rule({ effect: "allow", backends: ["gh-repos-shell"] });
    const s = stub();
    const r = await pe.enforce({ ctx: ctx(), args: { command: "ls" }, dispatch: s.dispatch });
    expect(r.isError).toBeFalsy();
    expect(s.calls).toHaveLength(1);
    const c = rows().at(-1)!;
    expect(c).toMatchObject({ final_outcome: "executed", result_status: "ok", rule_id: id, rule_version: 1 });
  });

  it("deny beats require_approval and allow regardless of priority", async () => {
    rule({ effect: "allow", priority: 1 });
    rule({ effect: "require_approval", priority: 2 });
    const d = rule({ effect: "deny", priority: 999, reason: "no shell" });
    const s = stub();
    const r = await pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch });
    expect(s.calls).toHaveLength(0);
    expect(payload(r)).toMatchObject({ reason: "rule_deny", rule_id: d, message: "no shell" });
    expect(notices).toHaveLength(0);
  });

  it("arg matchers: regex deny on parsed args; missing path is no match", async () => {
    rule({ effect: "allow" });
    rule({ effect: "deny", args: [{ path: "$.command", op: "regex", value: "(rm |git push|ghp_)" }] });
    const s = stub();
    expect(payload(await pe.enforce({ ctx: ctx(), args: { command: "git push origin" }, dispatch: s.dispatch })).reason).toBe("rule_deny");
    expect((await pe.enforce({ ctx: ctx(), args: { command: "ls" }, dispatch: s.dispatch })).isError).toBeFalsy();
    expect((await pe.enforce({ ctx: ctx(), args: { other: "rm -rf" }, dispatch: s.dispatch })).isError).toBeFalsy();
    expect(s.calls).toHaveLength(2);
  });

  it("a broken rule fails closed (policy_unavailable)", async () => {
    rule({ effect: "allow" });
    rule({ effect: "deny", args: [{ path: "$.command", op: "bogus", value: 1 }] });
    const s = stub();
    const r = await pe.enforce({ ctx: ctx(), args: { command: "ls" }, dispatch: s.dispatch });
    expect(payload(r).reason).toBe("policy_unavailable");
    expect(s.calls).toHaveLength(0);
  });

  it("unsafe regex in a rule fails closed", async () => {
    rule({ effect: "allow" });
    rule({ effect: "deny", args: [{ path: "$.command", op: "regex", value: "(a)\\1" }] });
    const s = stub();
    expect(payload(await pe.enforce({ ctx: ctx(), args: { command: "aa" }, dispatch: s.dispatch })).reason).toBe("policy_unavailable");
    expect(s.calls).toHaveLength(0);
  });

  it("audit_unavailable: failed decision write denies, holds nothing, dispatches nothing", async () => {
    rule({ effect: "allow" });
    rule({ effect: "require_approval", tools: ["write_file"] });
    auditFail = true;
    const s = stub();
    expect(payload(await pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch })).reason).toBe("audit_unavailable");
    expect(payload(await pe.enforce({ ctx: ctx({ tool: "write_file" }), args: {}, dispatch: s.dispatch })).reason).toBe("audit_unavailable");
    expect(s.calls).toHaveLength(0);
    expect(rows()).toHaveLength(0);
    expect((db.prepare(`SELECT count(*) AS n FROM mcpflow_pending_call`).get() as { n: number }).n).toBe(0);
    expect(notices).toHaveLength(0);
  });

  it("backend error -> executed/error; gateway throw after dispatch -> error/error", async () => {
    rule({ effect: "allow" });
    await pe.enforce({ ctx: ctx(), args: {}, dispatch: async () => ({ isError: true, content: [{ type: "text", text: "boom" }] }) });
    await pe.enforce({ ctx: ctx(), args: {}, dispatch: async () => ({ isError: true, content: [{ type: "text", text: "request timed out" }] }) });
    await pe.enforce({ ctx: ctx(), args: {}, dispatch: async () => { throw new Error("stream lost"); } });
    const c = rows().filter((r) => r.event_type === "completion");
    expect(c.map((r) => [r.final_outcome, r.result_status])).toEqual([
      ["executed", "error"], ["executed", "timeout"], ["error", "error"],
    ]);
    expect(c[2]!.error_code).toBe("gateway_dispatch_failed");
  });
});

describe("T2.2 holds", () => {
  beforeEach(setup);

  it("approved: dispatches exactly once with the stored args, approver recorded, ciphertext purged", async () => {
    rule({ effect: "require_approval", timeoutS: 30 });
    const s = stub();
    const args = { command: "deploy" };
    const p = pe.enforce({ ctx: ctx(), args, dispatch: s.dispatch });
    await waitFor(() => notices.length === 1);
    args.command = "rm -rf /"; // caller mutation after submit must not matter
    const pc = notices[0]!.pendingCallId;
    expect(notices[0]).toMatchObject({ agentName: "bot", projectId: "gb_devops", backendSlug: "gh-repos-shell", approvers: [chen] });
    expect(pe.decide(pc, chen, "approved", "ok")).toEqual({ ok: true });
    expect(pe.decide(pc, chen, "approved").ok).toBe(false); // second click is a no-op
    const r = await p;
    expect(r.isError).toBeFalsy();
    expect(s.calls).toEqual([{ command: "deploy" }]);
    const row = db.prepare(`SELECT status, dispatched_at, args_ciphertext FROM mcpflow_pending_call WHERE id=?`).get(pc) as Record<string, unknown>;
    expect(row.status).toBe("approved");
    expect(row.dispatched_at).not.toBeNull();
    expect(row.args_ciphertext).toBeNull();
    expect(rows().at(-1)).toMatchObject({ final_outcome: "executed", approver: chen, pending_call_id: pc });
  });

  it("concurrent approvals dispatch once", async () => {
    const other = dir.createAgent({ workspaceId: WS, name: "lead", owner: "chen", kind: "human", projects: [], createdBy: chen });
    rule({ effect: "require_approval", approvers: [chen, other] });
    const s = stub();
    const p = pe.enforce({ ctx: ctx(), args: { n: 1 }, dispatch: s.dispatch });
    await waitFor(() => notices.length === 1);
    const pc = notices[0]!.pendingCallId;
    const results = [pe.decide(pc, chen, "approved"), pe.decide(pc, other, "approved"), pe.approveSimilar(pc, other, 10)];
    expect(results.filter((x) => x.ok)).toHaveLength(1);
    await p;
    expect(s.calls).toHaveLength(1);
  });

  it("human deny returns approval_denied with the note; nothing dispatched", async () => {
    rule({ effect: "require_approval" });
    const s = stub();
    const p = pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch });
    await waitFor(() => notices.length === 1);
    pe.decide(notices[0]!.pendingCallId, chen, "denied", "not today");
    const r = payload(await p);
    expect(r).toMatchObject({ reason: "approval_denied", note: "not today" });
    expect(s.calls).toHaveLength(0);
    expect(rows().at(-1)).toMatchObject({ final_outcome: "approval_denied", result_status: "not_dispatched", approver: chen });
  });

  it("timeout = deny; a late approval is rejected and never dispatches", async () => {
    rule({ effect: "require_approval", timeoutS: 1 });
    const s = stub();
    const r = payload(await pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch }));
    expect(r.reason).toBe("approval_timeout");
    const pc = pendingId();
    expect(pe.decide(pc, chen, "approved").ok).toBe(false);
    expect(s.calls).toHaveLength(0);
    expect(rows().at(-1)).toMatchObject({ final_outcome: "approval_expired", result_status: "not_dispatched" });
  }, 5000);

  it("self-approval and non-approver decisions are rejected", async () => {
    const h2 = dir.createAgent({ workspaceId: WS, name: "h2", owner: "chen", kind: "human", projects: ["gb_devops"], createdBy: chen });
    const h2key = dir.createKey({ agentId: h2, createdBy: chen }).keyId;
    rule({ effect: "require_approval", approvers: [chen, h2] });
    const s = stub();
    const p = pe.enforce({ ctx: ctx({ agentId: h2, keyId: h2key, agentName: "h2" }), args: {}, dispatch: s.dispatch });
    await waitFor(() => notices.length === 1);
    const pc = notices[0]!.pendingCallId;
    expect(pe.decide(pc, h2, "approved")).toMatchObject({ ok: false, error: expect.stringMatching(/self-approval/) });
    expect(pe.decide(pc, bot, "approved")).toMatchObject({ ok: false });
    pe.decide(pc, chen, "denied");
    await p;
    expect(s.calls).toHaveLength(0);
  });

  it("revoking the agent cancels its pending call", async () => {
    rule({ effect: "require_approval", timeoutS: 30 });
    const s = stub();
    const p = pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch });
    await waitFor(() => notices.length === 1);
    dir.revokeAgent(bot, chen, "compromised");
    expect(pe.decide(notices[0]!.pendingCallId, chen, "approved").ok).toBe(false);
    expect(payload(await p).reason).toBe("cancelled");
    expect(s.calls).toHaveLength(0);
    expect(rows().at(-1)).toMatchObject({ final_outcome: "cancelled", result_status: "not_dispatched" });
  });

  it("client disconnect cancels the hold", async () => {
    rule({ effect: "require_approval", timeoutS: 30 });
    const s = stub();
    const ac = new AbortController();
    const p = pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch, signal: ac.signal });
    await waitFor(() => notices.length === 1);
    ac.abort();
    expect(payload(await p).reason).toBe("cancelled");
    expect(pe.decide(notices[0]!.pendingCallId, chen, "approved").ok).toBe(false);
    expect(s.calls).toHaveLength(0);
  });

  it("approve-similar grant: later identical-scope calls run without a hold, up to max_uses; never overrides deny", async () => {
    rule({ effect: "require_approval", timeoutS: 30 });
    const s = stub();
    const p = pe.enforce({ ctx: ctx(), args: { command: "ls" }, dispatch: s.dispatch });
    await waitFor(() => notices.length === 1);
    const g = pe.approveSimilar(notices[0]!.pendingCallId, chen, 10, { maxUses: 1 });
    expect(g.ok).toBe(true);
    await p;
    const r2 = await pe.enforce({ ctx: ctx(), args: { command: "pwd" }, dispatch: s.dispatch });
    expect(r2.isError).toBeFalsy();
    expect(s.calls).toHaveLength(2);
    expect(rows().filter((r) => r.event_type === "decision").at(-1)!.grant_id).toBe(g.ok ? g.grantId : null);
    // use exhausted -> holds again
    const p3 = pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch });
    await waitFor(() => notices.length === 2);
    pe.decide(notices[1]!.pendingCallId, chen, "denied");
    await p3;
    // a deny rule beats any grant
    const p4 = pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch });
    await waitFor(() => notices.length === 3);
    pe.approveSimilar(notices[2]!.pendingCallId, chen, 10);
    await p4;
    rule({ effect: "deny" });
    expect(payload(await pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch })).reason).toBe("rule_deny");
    expect(s.calls).toHaveLength(3);
  });

  it("a grant for another tool or agent does not apply", async () => {
    rule({ effect: "require_approval", timeoutS: 30 });
    const s = stub();
    const p = pe.enforce({ ctx: ctx(), args: {}, dispatch: s.dispatch });
    await waitFor(() => notices.length === 1);
    pe.approveSimilar(notices[0]!.pendingCallId, chen, 10);
    await p;
    const p2 = pe.enforce({ ctx: ctx({ tool: "other_tool", qualifiedTool: "gh-repos-shell__other_tool" }), args: {}, dispatch: s.dispatch });
    await waitFor(() => notices.length === 2);
    pe.decide(notices[1]!.pendingCallId, chen, "denied");
    expect(payload(await p2).reason).toBe("approval_denied");
  });
});

// ---------------- gateway: bypass attempts against a real upstream ----------------

const master = Buffer.alloc(32, 11).toString("base64");
const admin = "test-admin-token-policy";
const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

async function upstreamCounting() {
  const counter = { calls: 0 };
  const httpServer = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
    if (body?.method === "tools/call") counter.calls += 1;
    const server = new McpServer({ name: "up", version: "1" });
    server.registerTool("echo", { description: "e", inputSchema: { text: z.string() } }, async ({ text }) => ({
      content: [{ type: "text", text: `echo:${text}` }],
    }));
    server.registerTool("run_command", { description: "r", inputSchema: { command: z.string() } }, async () => ({
      content: [{ type: "text", text: "ran" }],
    }));
    const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(t);
    await t.handleRequest(req, res, body);
  });
  await new Promise<void>((r) => httpServer.listen(0, "127.0.0.1", r));
  const port = (httpServer.address() as { port: number }).port;
  cleanups.push(() => new Promise((r) => httpServer.close(() => r())));
  return { url: `http://127.0.0.1:${port}/mcp`, counter };
}

async function boot(): Promise<RunningServer> {
  const d = mkdtempSync(join(tmpdir(), "mcp-flow-pol-"));
  tmp.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: master, adminToken: admin, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

describe("gateway enforcement (bypass attempts)", () => {
  it("denied backend tool never reaches the backend by any exposed name", async () => {
    const up = await upstreamCounting();
    const gw = await boot();
    const ws = gw.store.ensureWorkspace("default");
    const be = await fetch(`${gw.url}/v1/backends`, {
      method: "POST",
      headers: { Authorization: `Bearer ${admin}`, "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "shell", url: up.url, transport: "streamable-http", enabled: true, placement: { mode: "remote" } }),
    });
    expect(be.status).toBeLessThan(300);
    gw.store.createProject(ws.id, { slug: "gb_devops", title: "DevOps", backendSlugs: ["shell"] });
    const id = gw.store.identity;
    const human = id.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
    const a = id.createAgent({ workspaceId: ws.id, name: "bot", owner: "chen", kind: "grokbot", projects: ["gb_devops"], createdBy: human });
    const k = id.createKey({ agentId: a, createdBy: human });
    // allow echo, deny run_command (by routed backend + tool)
    const db = gw.store.db;
    const mk = (effect: string, tools: string[]) => {
      const rid = `rule_${randomBytes(12).toString("hex")}`;
      db.exec("BEGIN IMMEDIATE;");
      db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws.id, human);
      db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_backends, match_tools, effect, created_by) VALUES (?,1,'t','["shell"]',?,?,?)`).run(rid, JSON.stringify(tools), effect, human);
      db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
      db.exec("COMMIT;");
    };
    mk("allow", ["echo"]);
    mk("deny", ["run_command"]);

    const client = new Client({ name: "t", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${gw.url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${k.token}` } } }));
    cleanups.push(() => client.close());
    await client.callTool({ name: "mf_use_project", arguments: { project: "gb_devops", mintSessionToken: false } });

    const ok = await client.callTool({ name: "shell__echo", arguments: { text: "hi" } });
    expect(JSON.stringify(ok)).toContain("echo:hi");
    const before = up.counter.calls;
    expect(before).toBe(1);

    const attempts: Array<{ name: string; arguments: Record<string, unknown> }> = [
      { name: "shell__run_command", arguments: { command: "rm -rf /" } },
      { name: "mf_call_tool", arguments: { name: "shell__run_command", arguments: { command: "x" } } },
      { name: "mf_call_tool", arguments: { name: "  shell__run_command  ", arguments: { command: "x" } } },
      { name: "SHELL__run_command", arguments: { command: "x" } },
      { name: "mf_call_tool", arguments: { name: "Shell__run_command", arguments: {} } },
      { name: "shell__run_command ", arguments: {} },
    ];
    for (const at of attempts) {
      const r = await client.callTool(at).catch((e: Error) => ({ isError: true, content: [{ type: "text", text: e.message }] }));
      expect(r.isError).toBe(true);
    }
    expect(up.counter.calls).toBe(before);

    // no rule for an unknown tool name variant on the allowed backend: default deny
    const unk = await client.callTool({ name: "shell__echo2", arguments: {} });
    expect(unk.isError).toBe(true);
    expect(up.counter.calls).toBe(before);

    // audit: every agent call has a decision row
    const n = (db.prepare(`SELECT count(*) AS n FROM mcpflow_call_audit WHERE event_type='decision' AND agent_id=?`).get(a) as { n: number }).n;
    expect(n).toBeGreaterThanOrEqual(4);
  });
});
