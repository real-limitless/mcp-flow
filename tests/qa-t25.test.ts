// QA T2.5 suite v5 (QA-owned copy). v1-v4 kept alongside; v5-only cases in qa-v5.test.ts.
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
async function spyUpstream(toolNames: string[] = ["echo", "run_command", "boom"]) {
  const seen: string[] = [];
  const http = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
    const s = new Server({ name: "spy", version: "1" }, { capabilities: { tools: {} } });
    s.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: toolNames.map((n) => ({ name: n, inputSchema: { type: "object" as const } })),
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

// ======================= v2 additions =======================
import { encryptArgs } from "../src/policy/crypto.js";

async function gwWithBackends(e: Awaited<ReturnType<typeof boot>>, backends: Record<string, string>, projectBackends: string[]) {
  for (const [slug, url] of Object.entries(backends)) {
    const be = await fetch(`${e.gw.url}/v1/backends`, { method: "POST", headers: { Authorization: `Bearer ${ADMIN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ slug, url, transport: "streamable-http", enabled: true, placement: { mode: "remote" } }) });
    expect(be.status).toBeLessThan(300);
  }
  e.gw.store.createProject(e.ws, { slug: "p1", title: "P1", backendSlugs: projectBackends });
  const client = new Client({ name: "qa", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${e.gw.url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${e.botK.token}` } } }));
  cleanups.push(() => client.close());
  await client.callTool({ name: "mf_use_project", arguments: { project: "p1", mintSessionToken: false } });
  return client;
}

describe("QA-c2 expanded bypass (v2)", () => {
  it("c2 NFKC/NFD, homoglyph backend, NUL, RTL, long names, cross-backend routing never reach the denied tool", async () => {
    const shell = await spyUpstream(["echo", "run_command", "caf\u00e9"]);
    const safe = await spyUpstream(["echo", "run_command"]);
    const e = await boot();
    e.rule("allow", ["*"], 300, ["shell"]);
    e.rule("deny", ["run_command", "caf\u00e9"], 300, ["shell"]);
    e.rule("allow", ["*"], 300, ["safe"]);
    const client = await gwWithBackends(e, { shell: shell.url, safe: safe.url }, ["shell", "safe"]);
    expect((await client.callTool({ name: "shell__echo", arguments: {} })).isError).toBeFalsy();
    shell.seen.length = 0;
    const long = (n: number) => "shell__run_command" + "x".repeat(n);
    const names = [
      "shell__caf\u00e9", "shell__cafe\u0301" /* NFD */, "shell__run_command".normalize("NFD"),
      "\uff53hell__run_command" /* fullwidth s, NFKC->shell */, "shell__run_\ufb00" /* ligature */, "shell\uff3f\uff3frun_command" /* fullwidth __ */,
      "\u0455hell__run_command" /* cyrillic dze */, "sh\u0435ll__run_command" /* cyrillic e */,
      "shell__run_command\u0000", "shell\u0000__run_command", "shell__\u0000run_command",
      "shell__\u202erun_command", "\u202eshell__run_command", "shell__run_command\u202c", "shell__\u200frun_command",
      long(1000), long(100000), "shell__" + "run_command".repeat(5000), "s".repeat(10000) + "__run_command",
      "safe__shell__run_command", "safe__run_command/../shell__run_command", "safe__../shell__run_command",
    ];
    const res: Record<string, string> = {};
    for (const n of names) for (const via of ["direct", "mf_call_tool"] as const) {
      const req = via === "direct" ? { name: n, arguments: {} } : { name: "mf_call_tool", arguments: { name: n, arguments: {} } };
      const b = shell.seen.length;
      const r: any = await client.callTool(req).catch((err: Error) => ({ isError: true, content: [{ type: "text", text: err.message.slice(0, 80) }] }));
      res[`${via}:${JSON.stringify(n.length > 60 ? n.slice(0, 30) + `…(${n.length})` : n)}`] = `${r.isError ? "refused" : "OK"} shellUpstream+${shell.seen.length - b}`;
    }
    // control: different allowed backend with its own run_command is legitimately allowed
    const ctl: any = await client.callTool({ name: "safe__run_command", arguments: {} });
    console.log("QA-c2\n" + Object.entries(res).map(([k, v]) => `  ${k} -> ${v}`).join("\n"));
    console.log("QA-c2 control safe__run_command ->", ctl.isError ? "refused" : "OK", "safe saw", JSON.stringify(safe.seen));
    expect(shell.seen).toEqual([]);
    expect(Object.values(res).every((v) => v.startsWith("refused"))).toBe(true);
    // every refusal is call-audited
    const refusals = e.auditRows().filter((r) => r.event_type === "decision" && r.policy_decision === "deny").length;
    expect(refusals).toBeGreaterThanOrEqual(names.length * 2);
  }, 60000);
});

describe("QA-f H-1 args integrity (v2)", () => {
  it("f1 approve with mismatched args_sha256 -> 409, backend never called, attempt audited", async () => {
    const e = await boot();
    e.rule("require_approval", ["run_command"], 30);
    const s = spy();
    const p = e.gw.store.policy.enforce({ ctx: e.ctx(), args: { command: "deploy" }, dispatch: s.dispatch });
    const id = await waitPending(e.db);
    const g: any = await (await e.api(e.chenTok, `/${id}`)).json();
    expect(g.args_full).toEqual({ command: "deploy" });
    expect(typeof g.args_sha256).toBe("string");
    const bad = await e.api(e.chenTok, `/${id}/approve`, { args_sha256: "0".repeat(64) });
    const badSim = await e.api(e.chenTok, `/${id}/approve-similar`, { minutes: 5, args_sha256: "0".repeat(64) });
    const auditEv = e.gw.store.listAudit(e.ws, { limit: 100 }).filter((a: any) => a.action.startsWith("policy.approval.")).map((a: any) => ({ action: a.action, d: typeof a.detail === "string" ? JSON.parse(a.detail) : a.detail }));
    console.log("QA-f1", bad.status, await bad.text(), badSim.status, "approval audit events:", JSON.stringify(auditEv.map((a: any) => a.action)));
    expect(bad.status).toBe(409);
    expect(badSim.status).toBe(409);
    expect(s.calls).toHaveLength(0);
    const ok = await e.api(e.chenTok, `/${id}/approve`, { args_sha256: g.args_sha256 });
    expect(ok.status).toBe(200);
    await p;
    expect(s.calls).toEqual([{ command: "deploy" }]);
    expect(auditEv.find((a: any) => a.action === "policy.approval.approve" && a.d.ok === false && a.d.error === "args_mismatch")).toBeTruthy();
    expect(auditEv.find((a: any) => a.action === "policy.approval.approve_similar" && a.d.ok === false && a.d.error === "args_mismatch")).toBeTruthy();
  }, 10000);

  it("f2 args tamper after hold: DB triggers block it; with triggers dropped (raw-DB attacker) approve-echo 409 and dispatch refuses changed args; audited", async () => {
    const e = await boot();
    e.rule("require_approval", ["run_command"], 30);
    const s = spy();
    const p = e.gw.store.policy.enforce({ ctx: e.ctx(), args: { command: "ls" }, dispatch: s.dispatch });
    const id = await waitPending(e.db);
    const g: any = await (await e.api(e.chenTok, `/${id}`)).json();
    const keys = (e.gw.store as any).policyKeys;
    const evil = encryptArgs(keys.argsEnc, { command: "rm -rf /" });
    const trig: Record<string, string> = {};
    try { e.db.prepare(`UPDATE mcpflow_pending_call SET args_ciphertext=? WHERE id=?`).run(evil, id); trig.cipher = "ALLOWED"; } catch (x) { trig.cipher = "blocked: " + (x as Error).message; }
    try { e.db.prepare(`UPDATE mcpflow_pending_call SET args_hash='x' WHERE id=?`).run(id); trig.hash = "ALLOWED"; } catch (x) { trig.hash = "blocked: " + (x as Error).message; }
    e.db.exec(`DROP TRIGGER mcpflow_pending_call_ciphertext; DROP TRIGGER mcpflow_pending_call_snapshot;`);
    e.db.prepare(`UPDATE mcpflow_pending_call SET args_ciphertext=? WHERE id=?`).run(evil, id);
    const get2 = await e.api(e.chenTok, `/${id}`);
    const appEcho = await e.api(e.chenTok, `/${id}/approve`, { args_sha256: g.args_sha256 });
    const appNo = await e.api(e.chenTok, `/${id}/approve`, { args_sha256: g.args_sha256 });
    const appNoBody = await appNo.json();
    // P3: approve must not 200 on tampered args; clean up the hold by denying
    await e.api(e.chenTok, `/${id}/deny`, {});
    const r: any = await p;
    const last = e.auditRows().at(-1);
    console.log("QA-f2", JSON.stringify({ trig, get: get2.status, approveEcho: appEcho.status, approveRetry: appNo.status, approveRetryErr: appNoBody.error, agent: r.content[0].text.slice(0, 100), last: { o: last?.final_outcome, s: last?.result_status, e: last?.error_code } }));
    expect(trig.cipher.startsWith("blocked")).toBe(true);
    expect(trig.hash.startsWith("blocked")).toBe(true);
    expect(get2.status).toBe(409);
    expect(appEcho.status).toBe(409);
    expect(s.calls).toHaveLength(0);
    expect(r.isError).toBe(true);
    expect(appNo.status).toBe(409);
    expect(appNoBody.error).toBe("args_integrity");
    expect(last).toMatchObject({ result_status: "not_dispatched" });
  }, 10000);
});

describe("QA-g hidden always-denied tools (v2)", () => {
  it("g1 tools/list + mf_list_tools hide always-denied, keep allowed & arg-conditional; hidden call denied + audited", async () => {
    const up = await spyUpstream(["echo", "run_command", "boom", "other"]);
    const e = await boot();
    e.rule("allow", ["echo", "boom"], 300, ["shell"]);
    e.rule("deny", ["run_command"], 300, ["shell"]);
    e.rule("require_approval", ["boom"], 300, ["shell"]);
    // conditional deny on echo (args) must NOT hide echo
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    e.db.exec("BEGIN IMMEDIATE;");
    e.db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, e.ws, e.chen);
    e.db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_backends, match_tools, match_args, effect, created_by) VALUES (?,1,'qa','["shell"]','["echo"]',?, 'deny', ?)`)
      .run(rid, JSON.stringify([{ path: "$.text", op: "regex", value: "secret" }]), e.chen);
    e.db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    e.db.exec("COMMIT;");
    const client = await gwWithBackends(e, { shell: up.url }, ["shell"]);
    const listed = (await client.listTools()).tools.map((t) => t.name).filter((n) => n.startsWith("shell__")).sort();
    const mfl: any = await client.callTool({ name: "mf_list_tools", arguments: { all: true } });
    const mfNames = JSON.parse(mfl.content[0].text).tools.map((t: any) => t.name).sort();
    const b = e.auditRows().length;
    const hid: any = await client.callTool({ name: "shell__run_command", arguments: {} });
    const hid2: any = await client.callTool({ name: "mf_call_tool", arguments: { name: "shell__other", arguments: {} } });
    const added = e.auditRows().slice(b).filter((r) => r.event_type === "decision");
    console.log("QA-g", JSON.stringify({ listed, mfNames, hid: hid.isError, hid2: hid2.isError, audit: added.map((r) => [r.tool, r.policy_decision, r.error_code]) }));
    expect(listed).toEqual(["shell__boom", "shell__echo"]);
    expect(mfNames).toEqual(["shell__boom", "shell__echo"]);
    expect(hid.isError && hid2.isError).toBe(true);
    expect(up.seen).toEqual([]);
    expect(added).toHaveLength(2);
    expect(added.every((r) => r.policy_decision === "deny")).toBe(true);
  });
});

// ======================= v3 additions =======================
const approvalEvents = (e: any) => e.gw.store.listAudit(e.ws, { limit: 200 })
  .filter((a: any) => a.action.startsWith("policy.approval."))
  .map((a: any) => ({ action: a.action, d: typeof a.detail === "string" ? JSON.parse(a.detail) : a.detail }));

describe("QA-h args_sha256 required (v3)", () => {
  it("h1 missing/malformed hash -> 400 on approve and approve-similar, backend never called, audited ok:false", async () => {
    const e = await boot();
    e.rule("require_approval", ["run_command"], 30);
    const s = spy();
    const p = e.gw.store.policy.enforce({ ctx: e.ctx(), args: { command: "x" }, dispatch: s.dispatch });
    const id = await waitPending(e.db);
    const st: Record<string, unknown> = {};
    for (const [k, path, body] of [
      ["approveMissing", "approve", {}], ["approveNull", "approve", { args_sha256: null }], ["approveShort", "approve", { args_sha256: "abc" }],
      ["approveUpper", "approve", { args_sha256: "A".repeat(64) }],
      ["similarMissing", "approve-similar", { minutes: 5 }], ["similarShort", "approve-similar", { minutes: 5, args_sha256: "zz" }],
    ] as Array<[string, string, Record<string, unknown>]>) {
      const r = await e.api(e.chenTok, `/${id}/${path}`, body);
      st[k] = `${r.status} ${((await r.json()) as any).error}`;
    }
    const ev = approvalEvents(e).filter((a: any) => a.d.ok === false && a.d.error === "args_sha256_required");
    console.log("QA-h1", JSON.stringify(st), "audited:", ev.map((a: any) => a.action));
    await e.api(e.chenTok, `/${id}/deny`, {});
    await p;
    expect(Object.values(st).every((v) => String(v).startsWith("400 args_sha256_required"))).toBe(true);
    expect(s.calls).toHaveLength(0);
    expect(ev.filter((a: any) => a.action === "policy.approval.approve")).toHaveLength(4);
    expect(ev.filter((a: any) => a.action === "policy.approval.approve_similar")).toHaveLength(2);
  }, 10000);
});

describe("QA-timer close() while a hold is open (v3)", () => {
  it("t1 no 'database is not open' after close() with an open hold", async () => {
    const errs: unknown[] = [];
    const onErr = (x: unknown) => errs.push(x);
    process.on("uncaughtException", onErr);
    process.on("unhandledRejection", onErr);
    const e = await boot();
    e.rule("require_approval", ["run_command"], 30);
    const s = spy();
    void e.gw.store.policy.enforce({ ctx: e.ctx(), args: {}, dispatch: s.dispatch }).catch(onErr);
    await waitPending(e.db);
    await e.gw.close();
    await new Promise((r) => setTimeout(r, 1500));
    process.off("uncaughtException", onErr);
    process.off("unhandledRejection", onErr);
    console.log("QA-t1 errors after close:", errs.map((x) => String((x as Error)?.message ?? x)));
    expect(errs.filter((x) => /database is not open/.test(String((x as Error)?.message ?? x)))).toEqual([]);
    expect(s.calls).toHaveLength(0);
  }, 10000);
});

// --- restart helpers: same DB file across two gateway processes-in-test ---
async function startAt(dbPath: string) {
  const cfg = loadConfig({ dbPath, masterKeyRaw: master, adminToken: ADMIN, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  return startServer(cfg);
}

describe("QA-i R-1 idempotency + restart recovery (v3)", () => {
  it("i1 approve then same decision again: one dispatch, second 409, no duplicate call_audit outcome", async () => {
    const e = await boot();
    e.rule("require_approval", ["run_command"], 30);
    const s = spy();
    const p = e.gw.store.policy.enforce({ ctx: e.ctx(), args: { n: 1 }, dispatch: s.dispatch, idempotencyKey: "qa-i1" });
    const id = await waitPending(e.db);
    const h = ((await (await e.api(e.chenTok, `/${id}`)).json()) as any).args_sha256;
    const a1 = await e.api(e.chenTok, `/${id}/approve`, { args_sha256: h });
    const a2 = await e.api(e.chenTok, `/${id}/approve`, { args_sha256: h });
    const r1: any = await p;
    // agent re-sends the same call with the same idempotency key -> replay, no re-run
    const r2: any = await e.gw.store.policy.enforce({ ctx: e.ctx(), args: { n: 1 }, dispatch: s.dispatch, idempotencyKey: "qa-i1" });
    const r3: any = await e.gw.store.policy.enforce({ ctx: e.ctx(), args: { n: 2 }, dispatch: s.dispatch, idempotencyKey: "qa-i1" });
    const rows = e.auditRows();
    const callIds = new Set(rows.map((r) => r.call_id));
    const completions = rows.filter((r) => r.event_type === "completion");
    console.log("QA-i1", JSON.stringify({ a1: a1.status, a2: a2.status, r1: r1.content[0].text.slice(0, 60), r2: r2.content[0].text.slice(0, 160), r3: r3.content[0].text.slice(0, 120), calls: s.calls.length, callIds: callIds.size, completions: completions.map((c) => c.final_outcome) }));
    expect(a1.status).toBe(200);
    expect(a2.status).toBe(409);
    expect(s.calls).toHaveLength(1);
    expect(completions).toHaveLength(1);
    expect(r2.content[0].text).toMatch(/executed|ok/);
    expect(r3.content[0].text).toMatch(/idempotency_conflict/);
  }, 10000);

  it("i2 restart mid-hold: pending cancelled on restart, resend with same key replays not_executed, never runs", async () => {
    const d = mkdtempSync(join(tmpdir(), "qa-t25-rs-")); tmp.push(d);
    const db = join(d, "t.db");
    const e = await boot(); // seeds identities in its own db; we only reuse helpers
    await e.gw.close();
    // build our own world on db
    let gw = await startAt(db);
    const ws = gw.store.ensureWorkspace("default").id;
    const id = gw.store.identity;
    const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
    const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const bk = id.createKey({ agentId: bot, createdBy: chen });
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    gw.store.db.exec("BEGIN IMMEDIATE;");
    gw.store.db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws, chen);
    gw.store.db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, approvers, approval_timeout_s, created_by) VALUES (?,1,'qa','["run_command"]','require_approval',?,30,?)`).run(rid, JSON.stringify([chen]), chen);
    gw.store.db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    gw.store.db.exec("COMMIT;");
    const ctx: CallContext = { workspaceId: ws, agentId: bot, agentName: "bot", keyId: bk.keyId, keyPrefix: null, sessionId: null, projectId: "p1", backendSlug: "shell", tool: "run_command", qualifiedTool: "shell__run_command", placement: "remote", deviceId: null };
    const s = spy();
    // (A) mid-hold
    void gw.store.policy.enforce({ ctx, args: { a: 1 }, dispatch: s.dispatch, idempotencyKey: "qa-hold" }).catch(() => {});
    const pidA = await waitPending(gw.store.db);
    await gw.close();
    gw = await startAt(db);
    const rowA = gw.store.db.prepare(`SELECT status, note FROM mcpflow_pending_call WHERE id=?`).get(pidA) as any;
    const replayA: any = await gw.store.policy.enforce({ ctx, args: { a: 1 }, dispatch: s.dispatch, idempotencyKey: "qa-hold" });
    // (B) mid-dispatch: backend hangs after approval
    let started = 0;
    const hang = async () => { started++; return new Promise<never>(() => {}); };
    void gw.store.policy.enforce({ ctx, args: { b: 1 }, dispatch: hang as any, idempotencyKey: "qa-disp" }).catch(() => {});
    const pidB = await waitPending(gw.store.db);
    gw.store.policy.decide(pidB, chen, "approved");
    for (let i = 0; i < 100 && !started; i++) await new Promise((r) => setTimeout(r, 20));
    await gw.close();
    gw = await startAt(db);
    const outB = gw.store.db.prepare(`SELECT state, final_outcome FROM mcpflow_call_outcome WHERE idempotency_key='qa-disp'`).get() as any;
    const replayB: any = await gw.store.policy.enforce({ ctx, args: { b: 1 }, dispatch: s.dispatch, idempotencyKey: "qa-disp" });
    // (C) approved but never dispatched (approve lands while gateway is down)
    void gw.store.policy.enforce({ ctx, args: { c: 1 }, dispatch: s.dispatch, idempotencyKey: "qa-abandon" }).catch(() => {});
    const pidC = await waitPending(gw.store.db);
    await gw.close();
    const { DatabaseSync } = await import("node:sqlite");
    const raw = new DatabaseSync(db);
    raw.prepare(`UPDATE mcpflow_pending_call SET status='approved', decided_by=?, decided_at=? WHERE id=?`).run(chen, new Date().toISOString(), pidC);
    raw.close();
    gw = await startAt(db);
    cleanups.push(() => gw.close());
    const rowC = gw.store.db.prepare(`SELECT status, abandoned_at, dispatched_at, args_ciphertext IS NULL AS purged FROM mcpflow_pending_call WHERE id=?`).get(pidC) as any;
    const replayC: any = await gw.store.policy.enforce({ ctx, args: { c: 1 }, dispatch: s.dispatch, idempotencyKey: "qa-abandon" });
    const comps = (cid: string) => (gw.store.db.prepare(`SELECT count(*) n FROM mcpflow_call_audit a JOIN mcpflow_pending_call p ON p.call_id=a.call_id WHERE p.id=? AND a.event_type='completion'`).get(cid) as any).n;
    const out = {
      A: { status: rowA.status, note: rowA.note, replay: replayA.content[0].text.slice(0, 140), completions: comps(pidA) },
      B: { started, outcome: outB, replay: replayB.content[0].text.slice(0, 140), completions: comps(pidB) },
      C: { row: rowC, replay: replayC.content[0].text.slice(0, 140), completions: comps(pidC) },
      spyCalls: s.calls.length,
    };
    console.log("QA-i2", JSON.stringify(out));
    expect(rowA.status).toBe("cancelled");
    expect(replayA.content[0].text).toMatch(/not_executed|cancel/);
    expect(started).toBe(1);
    expect(outB.state).toBe("unknown");
    expect(replayB.content[0].text).toMatch(/unknown/);
    expect(rowC.abandoned_at).not.toBeNull();
    expect(rowC.dispatched_at).toBeNull();
    expect(replayC.content[0].text).toMatch(/not_executed/);
    expect(s.calls).toHaveLength(0);
    for (const k of ["A", "B", "C"] as const) expect((out as any)[k].completions).toBe(1);
  }, 30000);
});

describe("QA-j GAP read endpoints (v3)", () => {
  it("j1 auth + data, no secrets/args leaked", async () => {
    const up = await spyUpstream(["echo", "run_command"]);
    const e = await boot();
    e.rule("allow", ["echo"], 300, ["shell"]);
    e.rule("require_approval", ["run_command"], 30, ["shell"]);
    const client = await gwWithBackends(e, { shell: up.url }, ["shell"]);
    void client;
    // a held call with a secret-looking arg; and a live session token
    const s = spy();
    const p = e.gw.store.policy.enforce({ ctx: e.ctx(), args: { command: "deploy", token: "ghp_QASECRETQASECRETQASECRET1234567890" }, dispatch: s.dispatch });
    const pid = await waitPending(e.db);
    const sess = e.gw.store.identity.createSession({ agentId: e.bot, keyId: e.botK.keyId, keyExpiresAt: new Date(Date.now() + 86400e3).toISOString(), effectiveProjects: ["p1"] } as any, "p1");
    const be = (e.db.prepare(`SELECT id FROM backends WHERE slug='shell'`).get() as any).id;
    const paths = ["/v1/agents", `/v1/agents/${e.bot}`, "/v1/policy/rules", `/v1/backends/${be}/tools`, `/v1/agents/${e.bot}/reach`, "/v1/policy/approvals/rules"];
    const call = async (tok: string | null, path: string) => {
      const r = await fetch(`${e.gw.url}${path}`, { headers: tok ? { Authorization: `Bearer ${tok}` } : {} });
      return { status: r.status, body: await r.text() };
    };
    const secrets = [e.botK.token, e.chenTok, e.bobK.token, sess.token, ADMIN, "ghp_QASECRET", "token_hash", "key_hash", "secret_hash", "args_ciphertext", "headers_enc"];
    const res: Record<string, any> = {};
    for (const path of paths) {
      const anon = await call(null, path), bot = await call(e.botK.token, path), bob = await call(e.bobK.token, path);
      const chen = await call(e.chenTok, path), admin = await call(ADMIN, path);
      const okBody = path.includes("/approvals/") ? chen : admin;
      const leaks = secrets.filter((x) => okBody.body.includes(x) || chen.body.includes(x));
      res[path] = { anon: anon.status, bot: bot.status, nonApprover: bob.status, chen: chen.status, admin: admin.status, leaks, bobBody: path.includes("/approvals/") ? bob.body.slice(0, 80) : undefined };
    }
    // v4: reach is human-admin-agent only; env ADMIN token -> 403
    expect((await call(ADMIN, `/v1/agents/${e.bot}/reach`)).status).toBe(403);
    const reach = JSON.parse((await call(e.chenTok, `/v1/agents/${e.bot}/reach`)).body);
    const rules = JSON.parse((await call(e.chenTok, "/v1/policy/approvals/rules")).body);
    console.log("QA-j1", JSON.stringify(res));
    console.log("QA-j1 reach", JSON.stringify(reach).slice(0, 600));
    console.log("QA-j1 approverRules count", rules.rules?.length);
    await e.api(e.chenTok, `/${pid}/deny`, {}); await p;
    for (const path of paths) {
      expect(res[path].anon).toBe(401);
      expect([401, 403]).toContain(res[path].bot);
      expect(res[path].leaks).toEqual([]);
    }
    expect(res["/v1/policy/approvals/rules"].bot).toBe(403);
    expect(res["/v1/policy/approvals/rules"].chen).toBe(200);
    expect(JSON.parse(res["/v1/policy/approvals/rules"].bobBody ?? "{}").rules ?? []).toEqual([]);
    expect(rules.rules).toHaveLength(1);
    const effects = Object.fromEntries(reach.projects[0].tools.map((t: any) => [t.name, t.effect]));
    expect(effects).toEqual({ shell__echo: "allow", shell__run_command: "require_approval" });
  }, 20000);
});


// ======================= v4 additions =======================
// Enumerated from src/api/app.ts + src/api/read-endpoints.ts (admin router, mounted at /v1) @ 78d38bb6
const ADMIN_ROUTES: Array<[string, string]> = [
  ["GET", "/workspace"], ["PATCH", "/workspace/policy"], ["POST", "/keys"], ["GET", "/keys"], ["PATCH", "/keys/x"], ["DELETE", "/keys/x"],
  ["GET", "/backends"], ["GET", "/backends/x"], ["POST", "/backends"], ["PATCH", "/backends/x"], ["DELETE", "/backends/x"], ["POST", "/backends/x/test"],
  ["GET", "/devices"], ["POST", "/devices"], ["PATCH", "/devices/x"], ["DELETE", "/devices/x"],
  ["GET", "/catalog/search"], ["GET", "/catalog/entries/x"], ["POST", "/catalog/sync"], ["POST", "/catalog/install"],
  ["GET", "/audit/calls"], ["GET", "/audit"], ["GET", "/projects"], ["GET", "/projects/x"], ["POST", "/projects"], ["PATCH", "/projects/x"], ["DELETE", "/projects/x"],
  ["GET", "/authz/rules"], ["POST", "/authz/rules"], ["PATCH", "/authz/rules/x"], ["DELETE", "/authz/rules/x"],
  ["GET", "/approvals"], ["POST", "/approvals/x/decision"],
  ["GET", "/operators/mfa"], ["POST", "/operators/mfa/begin"], ["POST", "/operators/mfa/confirm"], ["POST", "/operators/mfa/disable"],
  ["GET", "/push/vapid"], ["GET", "/push/subscriptions"], ["POST", "/push/subscriptions"], ["DELETE", "/push/subscriptions/x"],
  ["GET", "/agents"], ["GET", "/policy/rules"], ["GET", "/backends/x/tools"], ["GET", "/agents/reach?ids=x"], ["GET", "/agents/x"], ["GET", "/agents/x/reach"],
];

describe("QA-v4 admin router auth matrix (V3-F2)", () => {
  it("m1 every /v1 admin route: 401 none/bad token, 403 bot + non-admin human; no side effects", async () => {
    const e = await boot();
    const before = (e.db.prepare(`SELECT (SELECT count(*) FROM backends)+(SELECT count(*) FROM mcpflow_api_key)+(SELECT count(*) FROM projects) n`).get() as any).n;
    const rows: string[] = [];
    const bad: string[] = [];
    for (const [m, path] of ADMIN_ROUTES) {
      const go = async (tok: string | null) => (await fetch(`${e.gw.url}/v1${path}`, {
        method: m, headers: { ...(tok ? { Authorization: `Bearer ${tok}` } : {}), "content-type": "application/json" },
        body: m === "GET" || m === "DELETE" ? undefined : "{}",
      })).status;
      const r = { none: await go(null), bad: await go("mf_" + "q".repeat(40)), junk: await go("not-a-token"), bot: await go(e.botK.token), human: await go(e.bobK.token) };
      rows.push(`${m} /v1${path}: none=${r.none} bad=${r.bad} junk=${r.junk} bot=${r.bot} nonAdminHuman=${r.human}`);
      if (r.none !== 401 || r.bad !== 401 || r.junk !== 401 || r.bot !== 403 || r.human !== 403) bad.push(rows.at(-1)!);
    }
    const after = (e.db.prepare(`SELECT (SELECT count(*) FROM backends)+(SELECT count(*) FROM mcpflow_api_key)+(SELECT count(*) FROM projects) n`).get() as any).n;
    console.log("QA-m1 routes=" + ADMIN_ROUTES.length + "\n" + rows.join("\n"));
    expect(bad).toEqual([]);
    expect(after).toBe(before);
  }, 30000);
});

describe("QA-v4 batch reach GET /v1/agents/reach?ids=", () => {
  it("r1 auth matrix, limits, edge ids, no leaks, equals single-id reach", async () => {
    const up = await spyUpstream(["echo", "run_command"]);
    const e = await boot();
    e.rule("allow", ["echo"], 300, ["shell"]);
    e.rule("require_approval", ["run_command"], 30, ["shell"]);
    await gwWithBackends(e, { shell: up.url }, ["shell"]);
    const id = e.gw.store.identity;
    const extra: string[] = [];
    for (let i = 0; i < 50; i++) extra.push(id.createAgent({ workspaceId: e.ws, name: `a${i}`, owner: "chen", kind: "grokbot", projects: i % 2 ? ["p1"] : [], createdBy: e.chen }));
    const s = spy();
    const p = e.gw.store.policy.enforce({ ctx: e.ctx(), args: { command: "deploy", token: "ghp_QASECRETQASECRETQASECRET1234567890" }, dispatch: s.dispatch });
    const pid = await waitPending(e.db);
    const sess = id.createSession({ agentId: e.bot, keyId: e.botK.keyId, keyExpiresAt: new Date(Date.now() + 86400e3).toISOString(), effectiveProjects: ["p1"] } as any, "p1");
    const get = async (tok: string | null, q: string) => {
      const r = await fetch(`${e.gw.url}/v1/agents/reach${q}`, { headers: tok ? { Authorization: `Bearer ${tok}` } : {} });
      return { status: r.status, text: await r.text() };
    };
    const q1 = `?ids=${e.bot}`;
    const auth = {
      none: (await get(null, q1)).status, bad: (await get("mf_" + "z".repeat(40), q1)).status, bot: (await get(e.botK.token, q1)).status,
      nonAdminHuman: (await get(e.bobK.token, q1)).status, envAdmin: (await get(ADMIN, q1)).status, humanAdmin: (await get(e.chenTok, q1)).status,
    };
    const one = await get(e.chenTok, q1);
    const fifty = await get(e.chenTok, `?ids=${extra.join(",")}`);
    const fiftyOne = await get(e.chenTok, `?ids=${[...extra, e.bot].join(",")}`);
    const fiftyDupPlus = await get(e.chenTok, `?ids=${[...extra, extra[0]].join(",")}`); // 51 raw, 50 unique
    const edge = {
      empty: await get(e.chenTok, "?ids="), missing: await get(e.chenTok, ""), commas: await get(e.chenTok, "?ids=,,,"),
      dup: await get(e.chenTok, `?ids=${e.bot},${e.bot}`), malformed: await get(e.chenTok, `?ids=${encodeURIComponent("'; DROP TABLE x;--,<script>,../../etc")}`),
      unknown: await get(e.chenTok, "?ids=agt_000000000000000000000000"), huge: await get(e.chenTok, `?ids=${"a".repeat(20000)}`),
    };
    const summary = Object.fromEntries(Object.entries(edge).map(([k, v]) => [k, `${v.status} ${v.text.slice(0, 110)}`]));
    const leakNeedles = [e.botK.token, e.chenTok, e.bobK.token, sess.token, ADMIN, "ghp_QASECRET", "token_hash", "key_hash", "secret", "ciphertext", "deploy"];
    const leaks = leakNeedles.filter((n) => [one, fifty].some((r) => r.text.includes(n)));
    const batch = JSON.parse(fifty.text);
    let mismatches = 0;
    for (const a of [...batch.agents, ...JSON.parse(one.text).agents]) {
      const single = JSON.parse((await get(e.chenTok, "").then(() => fetch(`${e.gw.url}/v1/agents/${a.agent.id}/reach`, { headers: { Authorization: `Bearer ${e.chenTok}` } })).then((r) => r.text())));
      const strip = (x: any) => JSON.stringify({ agent: x.agent, projects: x.projects });
      if (strip(single) !== strip(a)) { mismatches++; if (mismatches < 3) console.log("QA-r1 mismatch", strip(single).slice(0, 300), "VS", strip(a).slice(0, 300)); }
    }
    console.log("QA-r1", JSON.stringify({ auth, one: one.status, fifty: [fifty.status, batch.agents?.length], fiftyOne: [fiftyOne.status, fiftyOne.text.slice(0, 80)], fiftyDupPlus: fiftyDupPlus.status, edge: summary, leaks, mismatches, sessionShown: one.text.includes(sess.sessionId) }));
    await e.api(e.chenTok, `/${pid}/deny`, {}); await p;
    expect(auth).toEqual({ none: 401, bad: 401, bot: 403, nonAdminHuman: 403, envAdmin: 403, humanAdmin: 200 });
    expect(fifty.status).toBe(200); expect(batch.agents).toHaveLength(50);
    expect(fiftyOne.status).toBe(400);
    expect(edge.empty.status).toBe(400); expect(edge.missing.status).toBe(400);
    expect(JSON.parse(edge.dup.text).agents).toHaveLength(1);
    expect(JSON.parse(edge.unknown.text).not_found).toEqual(["agt_000000000000000000000000"]);
    expect(edge.malformed.status).toBe(200);
    expect(leaks).toEqual([]);
    expect(mismatches).toBe(0);
  }, 30000);
});
