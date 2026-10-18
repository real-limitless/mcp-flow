/** PM-approved extras: hide always-denied tools, 15 s progress during a hold, approval_pending early return. */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, CallToolResultSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { startServer } from "../src/server.js";

const master = Buffer.alloc(32, 31).toString("base64");
const ADMIN = "hold-ux-admin";
const cleanups: Array<() => Promise<void>> = [];
const tmp: string[] = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

async function spyUpstream() {
  const seen: Array<{ name: string; args: unknown }> = [];
  const http = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
    const s = new Server({ name: "spy", version: "1" }, { capabilities: { tools: {} } });
    s.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: ["echo", "run_command", "merge", "write", "orphan"].map((n) => ({ name: n, inputSchema: { type: "object" as const } })),
    }));
    s.setRequestHandler(CallToolRequestSchema, async (r) => {
      seen.push({ name: r.params.name, args: r.params.arguments });
      return { content: [{ type: "text", text: `ran:${r.params.name}` }] };
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
  const up = await spyUpstream();
  const d = mkdtempSync(join(tmpdir(), "hold-ux-"));
  tmp.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: master, adminToken: ADMIN, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const gw = await startServer(cfg);
  cleanups.push(() => gw.close());
  (gw.store.policy as unknown as { deps: { progressIntervalMs: number } }).deps.progressIntervalMs = 100;
  const ws = gw.store.ensureWorkspace("default").id;
  const id = gw.store.identity;
  const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
  const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  const botK = id.createKey({ agentId: bot, createdBy: chen });
  const be = await fetch(`${gw.url}/v1/backends`, { method: "POST", headers: { Authorization: `Bearer ${ADMIN}`, "Content-Type": "application/json" },
    body: JSON.stringify({ slug: "shell", url: up.url, transport: "streamable-http", enabled: true, placement: { mode: "remote" } }) });
  expect(be.status).toBeLessThan(300);
  gw.store.createProject(ws, { slug: "p1", title: "P1", backendSlugs: ["shell"] });
  const db = gw.store.db;
  const rule = (effect: string, tools: string[], matchArgs: unknown[] = []) => {
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    const appr = effect === "require_approval";
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_backends, match_tools, match_args, effect, approvers, approval_timeout_s, created_by)
                VALUES (?,1,'t','["shell"]',?,?,?,?,?,?)`).run(rid, JSON.stringify(tools), JSON.stringify(matchArgs), effect, appr ? JSON.stringify([chen]) : null, appr ? 30 : null, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    db.exec("COMMIT;");
  };
  rule("allow", ["echo", "run_command", "write"]);
  rule("deny", ["run_command"]); // unconditional deny -> hidden
  rule("deny", ["write"], [{ path: "$.path", op: "prefix", value: "/etc" }]); // conditional -> listed
  rule("require_approval", ["merge"]);
  // "orphan": no allow/approval rule -> default deny -> hidden
  const client = new Client({ name: "ux", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${gw.url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${botK.token}` } } }));
  cleanups.push(() => client.close());
  await client.callTool({ name: "mf_use_project", arguments: { project: "p1", mintSessionToken: false } });
  const pending = async () => {
    for (let i = 0; i < 300; i++) {
      const r = db.prepare(`SELECT id FROM mcpflow_pending_call WHERE status='pending' ORDER BY created_at DESC LIMIT 1`).get() as { id: string } | undefined;
      if (r) return r.id;
      await new Promise((r) => setTimeout(r, 10));
    }
    throw new Error("no pending");
  };
  return { gw, chen, client, up, pending };
}
const text = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]!.text);

describe("hold UX extras", () => {
  it("tools/list hides tools denied for every args; conditionally denied and approval tools stay", async () => {
    const e = await boot();
    const names = (await e.client.listTools()).tools.map((t) => t.name).filter((n) => n.startsWith("shell__")).sort();
    expect(names).toEqual(["shell__echo", "shell__merge", "shell__write"]);
    // hiding is display only: calling a hidden tool is still refused by policy, never dispatched
    const r = await e.client.callTool({ name: "shell__run_command", arguments: {} });
    expect(r.isError).toBe(true);
    expect(e.up.seen).toHaveLength(0);
  });

  it("sends progress notifications while a call is held", async () => {
    const e = await boot();
    const progress: Array<{ progress: number; message?: string }> = [];
    const call = e.client.callTool({ name: "shell__merge", arguments: { pr: 1 } }, CallToolResultSchema, {
      onprogress: (p) => progress.push(p as { progress: number; message?: string }),
      timeout: 10_000,
    });
    const pc = await e.pending();
    await new Promise((r) => setTimeout(r, 450));
    expect(e.gw.store.policy.decide(pc, e.chen, "approved").ok).toBe(true);
    const r = await call;
    expect(text(r)).toBe("ran:merge");
    expect(progress.length).toBeGreaterThanOrEqual(2);
    expect(progress[0]!.message).toContain(pc);
  });

  it("approval_pending early return: immediate answer, re-readable result after approval (was one-time), dispatched once", async () => {
    const e = await boot();
    const r = await e.client.callTool({ name: "shell__merge", arguments: { pr: 2 }, _meta: { "mcp-flow/approval": "async" } });
    const body = JSON.parse(text(r));
    expect(body.code).toBe("approval_pending");
    const pc = body.pending_call_id as string;
    expect(JSON.parse(text(await e.client.callTool({ name: "mf_pending_result", arguments: { pending_call_id: pc } }))).status).toBe("not_ready");
    expect(JSON.parse(text(await e.client.callTool({ name: "mf_pending_status", arguments: { pending_call_id: pc } }))).status).toBe("pending");
    expect(e.up.seen).toHaveLength(0);
    e.gw.store.policy.decide(pc, e.chen, "approved");
    let out: unknown;
    for (let i = 0; i < 100; i++) {
      out = await e.client.callTool({ name: "mf_pending_result", arguments: { pending_call_id: pc } });
      if (!text(out).includes("not_ready")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(text(out)).toBe("ran:merge");
    expect(e.up.seen).toEqual([{ name: "merge", args: { pr: 2 } }]);
    // T2.1 §11: re-readable until it expires (read-once removed); nothing runs again
    expect(text(await e.client.callTool({ name: "mf_pending_result", arguments: { pending_call_id: pc } }))).toBe("ran:merge");
    expect(JSON.parse(text(await e.client.callTool({ name: "mf_pending_status", arguments: { pending_call_id: pc } })))).toMatchObject({ status: "approved", outcome: "executed", dispatched: true });
    // via mf_call_tool flag, then denied
    const r2 = await e.client.callTool({ name: "mf_call_tool", arguments: { name: "shell__merge", arguments: { pr: 3 }, async_approval: true } });
    const pc2 = JSON.parse(text(r2)).pending_call_id as string;
    e.gw.store.policy.decide(pc2, e.chen, "denied");
    for (let i = 0; i < 100; i++) {
      out = await e.client.callTool({ name: "mf_pending_result", arguments: { pending_call_id: pc2 } });
      if (!text(out).includes("not_ready")) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    expect(JSON.parse(text(out)).reason).toBe("approval_denied");
    expect(e.up.seen).toHaveLength(1);
  });

  it("another agent cannot read a pending result; the same agent can with any of its keys (T2.1 §11)", async () => {
    const e = await boot();
    const r = await e.client.callTool({ name: "shell__merge", arguments: { pr: 4 }, _meta: { "mcp-flow/approval": "async" } });
    const pc = JSON.parse(text(r)).pending_call_id as string;
    e.gw.store.policy.decide(pc, e.chen, "approved");
    const row = e.gw.store.db.prepare(`SELECT agent_id, key_id FROM mcpflow_pending_call WHERE id=?`).get(pc) as { agent_id: string; key_id: string };
    for (let i = 0; i < 100 && e.up.seen.length === 0; i++) await new Promise((r) => setTimeout(r, 20));
    for (let i = 0; i < 100 && e.gw.store.policy.takeAsyncResult(pc, row.agent_id) === "not_ready"; i++) await new Promise((r) => setTimeout(r, 20));
    expect(e.gw.store.policy.takeAsyncResult(pc, `agt_${"e".repeat(24)}`)).toBe("gone");
    expect(text(e.gw.store.policy.takeAsyncResult(pc, row.agent_id))).toBe("ran:merge");
  });
});
