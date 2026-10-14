// QA T2.5 suite (from /workspace/mcp-flow-qa/qa-t25.test.ts), wired into the suite.
// Only change from QA's file: e5 asserts 404 (spec keeps no-existence-oracle 404 for non-approvers).
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";
import type { CallContext } from "../src/policy/engine.js";

const master = Buffer.alloc(32, 7).toString("base64");
const ADMIN = "qa-admin-token";
const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

/** Spy upstream. Case/whitespace-INSENSITIVE tool lookup, like many real servers. */
async function spyUpstream() {
  const seen: string[] = [];
  const http = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
    const s = new Server({ name: "spy", version: "1" }, { capabilities: { tools: {} } });
    s.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: ["echo", "run_command", "boom"].map((n) => ({ name: n, inputSchema: { type: "object" as const } })),
    }));
    s.setRequestHandler(CallToolRequestSchema, async (r) => {
      seen.push(r.params.name);
      const n = r.params.name.trim().toLowerCase();
      if (n === "boom") return { isError: true, content: [{ type: "text", text: "boom" }] };
      return { content: [{ type: "text", text: `ran:${n}` }] };
    });
    const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await s.connect(t);
    await t.handleRequest(req, res, body);
  });
  await new Promise<void>((r) => http.listen(0, "127.0.0.1", r));
  cleanups.push(() => new Promise((r) => http.close(() => r())));
  return { url: `http://127.0.0.1:${(http.address() as { port: number }).port}/mcp`, seen };
}

async function boot() {
  const d = mkdtempSync(join(tmpdir(), "qa-t25-"));
  tmp.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: master, adminToken: ADMIN, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const gw: RunningServer = await startServer(cfg);
  cleanups.push(() => gw.close());
  const ws = gw.store.ensureWorkspace("default").id;
  const id = gw.store.identity;
  const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
  const chenTok = id.createKey({ agentId: chen, createdBy: chen }).token;
  const bob = id.createAgent({ workspaceId: ws, name: "bob", owner: "bob", kind: "human", projects: [], createdBy: chen });
  const bobK = id.createKey({ agentId: bob, createdBy: chen });
  const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  const botK = id.createKey({ agentId: bot, createdBy: chen });
  const db = gw.store.db;
  const rule = (effect: string, tools: string[], timeout = 300, backends = ["*"]) => {
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    const appr = effect === "require_approval";
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_backends, match_tools, effect, approvers, approval_timeout_s, created_by)
                VALUES (?,1,'qa',?,?,?,?,?,?)`).run(rid, JSON.stringify(backends), JSON.stringify(tools), effect, appr ? JSON.stringify([chen]) : null, appr ? timeout : null, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    db.exec("COMMIT;");
    return rid;
  };
  const api = (tok: string | null, path: string, body?: unknown) =>
    fetch(`${gw.url}/v1/policy/approvals${path}`, {
      method: body === undefined ? "GET" : "POST",
      headers: { ...(tok ? { Authorization: `Bearer ${tok}` } : {}), "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  const ctx = (tool = "run_command"): CallContext => ({
    workspaceId: ws, agentId: bot, agentName: "bot", keyId: botK.keyId, keyPrefix: null, sessionId: null,
    projectId: "p1", backendSlug: "shell", tool, qualifiedTool: `shell__${tool}`, placement: "remote", deviceId: null,
  });
  const auditRows = () => db.prepare(`SELECT * FROM mcpflow_call_audit WHERE event_type <> 'lifecycle' ORDER BY audit_id`).all() as Array<Record<string, any>>;
  return { gw, ws, db, chen, chenTok, bob, bobK, bot, botK, rule, api, ctx, auditRows };
}

function spy() {
  const calls: unknown[] = [];
  return { calls, dispatch: async (a: Record<string, unknown>) => { calls.push(a); return { content: [{ type: "text" as const, text: "ok" }] }; } };
}
async function waitPending(db: any) {
  for (let i = 0; i < 200; i++) {
    const r = db.prepare(`SELECT id FROM mcpflow_pending_call WHERE status='pending' ORDER BY created_at DESC LIMIT 1`).get();
    if (r) return r.id as string;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("no pending");
}

describe("QA-a denied never reaches backend", () => {
  it("a1 explicit deny: spy 0 calls", async () => {
    const e = await boot();
    e.rule("allow", ["*"]); e.rule("deny", ["run_command"]);
    const s = spy();
    const r = await e.gw.store.policy.enforce({ ctx: e.ctx(), args: { command: "rm" }, dispatch: s.dispatch });
    expect(r.isError).toBe(true);
    expect(s.calls).toHaveLength(0);
  });
  it("a2 pending then rejected via REST deny: spy 0 calls", async () => {
    const e = await boot();
    e.rule("require_approval", ["run_command"]);
    const s = spy();
    const p = e.gw.store.policy.enforce({ ctx: e.ctx(), args: {}, dispatch: s.dispatch });
    const id = await waitPending(e.db);
    expect((await e.api(e.chenTok, `/${id}/deny`, { note: "no" })).status).toBe(200);
    const r = await p;
    expect(JSON.parse((r.content[0] as any).text).reason).toBe("approval_denied");
    expect(s.calls).toHaveLength(0);
  });
});

describe("QA-b timeout = deny", () => {
  it("b1 unanswered approval times out, spy 0, late REST approve 409", async () => {
    const e = await boot();
    e.rule("require_approval", ["run_command"], 1);
    const s = spy();
    const r = await e.gw.store.policy.enforce({ ctx: e.ctx(), args: {}, dispatch: s.dispatch });
    expect(JSON.parse((r.content[0] as any).text).reason).toBe("approval_timeout");
    expect(s.calls).toHaveLength(0);
    const id = (e.db.prepare(`SELECT id, status FROM mcpflow_pending_call`).get() as any);
    const late = await e.api(e.chenTok, `/${id.id}/approve`, {});
    expect(late.status).toBe(409);
    await new Promise((r) => setTimeout(r, 300));
    expect(s.calls).toHaveLength(0);
    expect(e.auditRows().at(-1)).toMatchObject({ final_outcome: "approval_expired", result_status: "not_dispatched" });
  }, 8000);
});

describe("QA-c bypass via names (gateway, real MCP client, case-insensitive spy upstream)", () => {
  it("c1 every variant of a denied tool is refused and never hits upstream", async () => {
    const up = await spyUpstream();
    const e = await boot();
    const be = await fetch(`${e.gw.url}/v1/backends`, { method: "POST", headers: { Authorization: `Bearer ${ADMIN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "shell", url: up.url, transport: "streamable-http", enabled: true, placement: { mode: "remote" } }) });
    expect(be.status).toBeLessThan(300);
    e.gw.store.createProject(e.ws, { slug: "p1", title: "P1", backendSlugs: ["shell"] });
    // realistic config: allow everything on the backend, deny one dangerous tool
    e.rule("allow", ["*"], 300, ["shell"]);
    e.rule("deny", ["run_command"], 300, ["shell"]);
    const client = new Client({ name: "qa", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${e.gw.url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${e.botK.token}` } } }));
    cleanups.push(() => client.close());
    await client.callTool({ name: "mf_use_project", arguments: { project: "p1", mintSessionToken: false } });
    const ok = await client.callTool({ name: "shell__echo", arguments: {} });
    expect(ok.isError).toBeFalsy();
    up.seen.length = 0;
    const names = [
      "shell__run_command", "run_command", "SHELL__run_command", "Shell__run_command",
      "shell__RUN_COMMAND", "shell__Run_Command", "shell__run_command ", " shell__run_command",
      "shell__run_command\t", "shell__ run_command", "shell__run_command\u200b", "shell__run\u200b_command",
      "shell__run_comm\u0430nd" /* cyrillic a */, "shell__ｒｕｎ_command" /* fullwidth */, "shell__shell__run_command",
      "shell___run_command", "mf_run_command", "mf_admin_run_command", "__run_command",
    ];
    const results: Record<string, string> = {};
    for (const n of names) {
      for (const via of ["direct", "mf_call_tool"] as const) {
        const req = via === "direct" ? { name: n, arguments: { command: "x" } } : { name: "mf_call_tool", arguments: { name: n, arguments: { command: "x" } } };
        const before = up.seen.length;
        const r: any = await client.callTool(req).catch((err: Error) => ({ isError: true, content: [{ type: "text", text: err.message }] }));
        results[`${via}:${JSON.stringify(n)}`] = `${r.isError ? "refused" : "OK"} upstream+${up.seen.length - before}`;
      }
    }
    console.log("QA-c results\n" + Object.entries(results).map(([k, v]) => `  ${k} -> ${v}`).join("\n"));
    console.log("QA-c upstream saw:", JSON.stringify(up.seen));
    expect(up.seen.filter((n) => n.trim().toLowerCase().replace(/\u200b/g, "") === "run_command")).toEqual([]);
  });
});

describe("QA-d audit row per call", () => {
  it("d1 allowed/denied/timeout/error/approval-denied each: exactly 1 decision + 1 completion, correct outcome", async () => {
    const e = await boot();
    e.rule("allow", ["echo", "boom"]); e.rule("deny", ["run_command"]);
    e.rule("require_approval", ["slow"], 1); e.rule("require_approval", ["held"], 30);
    const pe = e.gw.store.policy;
    const s = spy();
    await pe.enforce({ ctx: e.ctx("echo"), args: {}, dispatch: s.dispatch });
    await pe.enforce({ ctx: e.ctx("run_command"), args: {}, dispatch: s.dispatch });
    await pe.enforce({ ctx: e.ctx("slow"), args: {}, dispatch: s.dispatch });
    await pe.enforce({ ctx: e.ctx("boom"), args: {}, dispatch: async () => ({ isError: true, content: [{ type: "text", text: "x" }] }) });
    await pe.enforce({ ctx: e.ctx("boom"), args: {}, dispatch: async () => { throw new Error("lost"); } });
    const p = pe.enforce({ ctx: e.ctx("held"), args: {}, dispatch: s.dispatch });
    pe.decide(await waitPending(e.db), e.chen, "denied");
    await p;
    const rows = e.auditRows();
    const by = new Map<string, any[]>();
    for (const r of rows) by.set(r.call_id, [...(by.get(r.call_id) ?? []), r]);
    const summary = [...by.values()].map((g) => ({
      tool: g[0].tool, decisions: g.filter((x) => x.event_type === "decision").length,
      completions: g.filter((x) => x.event_type === "completion").length,
      outcome: g.find((x) => x.event_type === "completion")?.final_outcome, status: g.find((x) => x.event_type === "completion")?.result_status,
    }));
    console.log("QA-d", JSON.stringify(summary));
    expect(summary).toHaveLength(6);
    for (const x of summary) { expect(x.decisions).toBe(1); expect(x.completions).toBe(1); }
    expect(summary.map((x) => [x.tool, x.outcome, x.status])).toEqual([
      ["echo", "executed", "ok"], ["run_command", "denied", "not_dispatched"], ["slow", "approval_expired", "not_dispatched"],
      ["boom", "executed", "error"], ["boom", "error", "error"], ["held", "approval_denied", "not_dispatched"],
    ]);
  }, 8000);

  it("d2 gateway bypass attempts (unknown backend / no project) also write a call_audit row", async () => {
    const e = await boot();
    e.gw.store.createProject(e.ws, { slug: "p1", title: "P1", backendSlugs: [] });
    const client = new Client({ name: "qa", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${e.gw.url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${e.botK.token}` } } }));
    cleanups.push(() => client.close());
    const before = e.auditRows().length;
    const r1: any = await client.callTool({ name: "ghost__run_command", arguments: {} }).catch((x: Error) => ({ isError: true, t: x.message }));
    await client.callTool({ name: "mf_use_project", arguments: { project: "p1", mintSessionToken: false } });
    const r2: any = await client.callTool({ name: "ghost__run_command", arguments: {} }).catch((x: Error) => ({ isError: true, t: x.message }));
    expect(r1.isError && r2.isError).toBe(true);
    const callAudit = e.auditRows().length - before;
    const legacy = e.gw.store.listAudit(e.ws, { limit: 100 }).filter((a: any) => (a.tool ?? "").includes("ghost")).length;
    console.log(`QA-d2 call_audit rows added=${callAudit}; legacy audit_events rows=${legacy}`);
    expect(callAudit).toBeGreaterThanOrEqual(2);
    const done = e.auditRows().slice(before).filter((r) => r.event_type === "completion");
    expect(done.length).toBeGreaterThanOrEqual(2);
    for (const r of done) expect(r).toMatchObject({ final_outcome: "error", result_status: "not_dispatched" });
  });
});

describe("QA-e /v1/policy/approvals REST", () => {
  it("e1 list/get/approve/deny, 409, 403, 401, 404", async () => {
    const e = await boot();
    e.rule("require_approval", ["run_command"], 30);
    const out: Record<string, number> = {};
    // held call 1 -> approve
    const s = spy();
    const p1 = e.gw.store.policy.enforce({ ctx: e.ctx(), args: { n: 1 }, dispatch: s.dispatch });
    const id1 = await waitPending(e.db);
    const list = await e.api(e.chenTok, "/pending"); out.list = list.status;
    expect(((await list.json()) as any).pending.map((x: any) => x.id)).toContain(id1);
    out.get = (await e.api(e.chenTok, `/${id1}`)).status;
    out.history = (await e.api(e.chenTok, "/history")).status;
    out.listRoot = (await e.api(e.chenTok, "")).status;
    out.unauth = (await e.api(null, "/pending")).status;
    out.unauthGet = (await e.api(null, `/${id1}`)).status;
    out.unauthApprove = (await e.api(null, `/${id1}/approve`, {})).status;
    out.badToken = (await e.api("mf_" + "z".repeat(40), "/pending")).status;
    out.adminToken = (await e.api(ADMIN, "/pending")).status;
    out.botNonHuman = (await e.api(e.botK.token, `/${id1}/approve`, {})).status;
    out.nonApproverHumanGet = (await e.api(e.bobK.token, `/${id1}`)).status;
    out.nonApproverHumanApprove = (await e.api(e.bobK.token, `/${id1}/approve`, {})).status;
    out.unknownGet = (await e.api(e.chenTok, `/pc_doesnotexist`)).status;
    out.unknownApprove = (await e.api(e.chenTok, `/pc_doesnotexist/approve`, {})).status;
    out.unknownDeny = (await e.api(e.chenTok, `/pc_doesnotexist/deny`, {})).status;
    // Security H-1 re-review: approve now requires the args_sha256 the approver saw (400 without it)
    out.approveNoHash = (await e.api(e.chenTok, `/${id1}/approve`, {})).status;
    const seen = ((await (await e.api(e.chenTok, `/${id1}`)).json()) as { args_sha256: string }).args_sha256;
    out.approve = (await e.api(e.chenTok, `/${id1}/approve`, { args_sha256: seen })).status;
    await p1;
    out.approveAgain = (await e.api(e.chenTok, `/${id1}/approve`, {})).status;
    out.denyAfterApprove = (await e.api(e.chenTok, `/${id1}/deny`, {})).status;
    // held call 2 -> deny
    const p2 = e.gw.store.policy.enforce({ ctx: e.ctx(), args: { n: 2 }, dispatch: s.dispatch });
    const id2 = await waitPending(e.db);
    out.deny = (await e.api(e.chenTok, `/${id2}/deny`, {})).status;
    await p2;
    out.denyAgain = (await e.api(e.chenTok, `/${id2}/deny`, {})).status;
    out.approveAfterDeny = (await e.api(e.chenTok, `/${id2}/approve`, {})).status;
    // revoked human key
    e.gw.store.identity.revokeKey(e.bobK.keyId, e.chen, "qa");
    out.revokedKey = (await e.api(e.bobK.token, "/pending")).status;
    console.log("QA-e", JSON.stringify(out));
    expect(s.calls).toHaveLength(1);
    expect(out).toMatchObject({
      list: 200, get: 200, history: 200, unauth: 401, unauthGet: 401, unauthApprove: 401, badToken: 401, adminToken: 401,
      approveNoHash: 400, botNonHuman: 403, unknownGet: 404, unknownApprove: 404, unknownDeny: 404, approve: 200, approveAgain: 409,
      denyAfterApprove: 409, deny: 200, denyAgain: 409, approveAfterDeny: 409, revokedKey: 401,
    });
    // spec decision (PM): non-approvers get 404, no existence oracle
    expect(out.nonApproverHumanGet).toBe(404);
    expect(out.nonApproverHumanApprove).toBe(404);
  }, 10000);
});
