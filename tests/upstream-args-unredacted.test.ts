/**
 * P1 report (Dokploy compose env update received FEATHERLESS_API_KEY=[REDACTED]): the gateway must
 * forward tool args to the backend verbatim. Redaction applies only to the audit, logs and responses.
 * FAKE is a made-up value shaped so every gateway redaction rule fires on it.
 */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { z } from "zod";
import { loadConfig } from "../src/config.js";
import { startServer } from "../src/server.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer, type PendingNotice } from "../src/policy/enforcer.js";
import type { CallContext } from "../src/policy/engine.js";

const FAKE = "sk-FAKEfeatherlessTEST0000000000000000";
const WS = "ws_" + "c".repeat(24);
const keys = derivePolicyKeys("upstream-args-dev-key");
let db: DatabaseSync, pe: PolicyEnforcer, chen: string, ctx: CallContext, notices: PendingNotice[];
let logs: string[];

const composeArgs = () => ({
  composeId: "cmp_1",
  env: `FEATHERLESS_API_KEY=${FAKE}\nLOG_LEVEL=info`,
  FEATHERLESS_API_KEY: FAKE,
  nested: { apiKey: FAKE, list: [`Bearer ${FAKE}`] },
});

beforeEach(() => {
  db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  const dir = new AgentDirectory(db, keys);
  chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
  const bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p"], createdBy: chen });
  const botKey = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
  notices = [];
  pe = new PolicyEnforcer({ db, keys, notify: async (n) => void notices.push(n) });
  ctx = { workspaceId: WS, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null, projectId: "p",
    backendSlug: "dokploy", tool: "compose_update_env", qualifiedTool: "dokploy__compose_update_env", placement: "remote", deviceId: null };
  logs = [];
  for (const m of ["log", "error", "warn", "info"] as const) vi.spyOn(console, m).mockImplementation((...a) => void logs.push(a.map(String).join(" ")));
});
const cleanups: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  vi.restoreAllMocks();
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
});

function rule(effect: "allow" | "require_approval") {
  const id = `rule_${randomBytes(12).toString("hex")}`;
  db.exec("BEGIN IMMEDIATE;");
  db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, WS, chen);
  db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, approval_timeout_s, approvers, created_by)
              VALUES (?,1,'t','["*"]',?,?,?,?)`).run(id, effect, effect === "allow" ? null : 30, effect === "allow" ? null : JSON.stringify([chen]), chen);
  db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(id);
  db.exec("COMMIT;");
}

function backend() {
  const received: Array<Record<string, unknown>> = [];
  return { received, dispatch: async (a: Record<string, unknown>): Promise<CallToolResult> => {
    received.push(structuredClone(a));
    return { content: [{ type: "text", text: "ok" }] };
  } };
}

function assertRedactedEverywhere(result: CallToolResult) {
  const audit = JSON.stringify(db.prepare(`SELECT * FROM mcpflow_call_audit`).all());
  const pending = JSON.stringify(db.prepare(`SELECT args_redacted FROM mcpflow_pending_call`).all());
  expect(audit).toContain("[redacted]");
  for (const s of [audit, pending, logs.join("\n"), JSON.stringify(result), JSON.stringify(notices)]) expect(s).not.toContain(FAKE);
}

describe("upstream args are never redacted", () => {
  it("allow: the backend receives the original secret; audit, logs and response are redacted; caller object untouched", async () => {
    rule("allow");
    const b = backend();
    const args = composeArgs();
    const r = await pe.enforce({ ctx, args, dispatch: b.dispatch });
    expect(b.received).toEqual([composeArgs()]);
    expect(args).toEqual(composeArgs()); // audit sanitizing did not mutate in place
    assertRedactedEverywhere(r);
  });

  it("approval replay: the backend receives the original secret decrypted from the hold", async () => {
    rule("require_approval");
    const b = backend();
    const p = pe.enforce({ ctx, args: composeArgs(), dispatch: b.dispatch });
    for (let i = 0; i < 400 && !notices.length; i++) await new Promise((x) => setTimeout(x, 5));
    expect(pe.decide(notices[0]!.pendingCallId, chen, "approved").ok).toBe(true);
    const r = await p;
    expect(b.received).toEqual([composeArgs()]);
    assertRedactedEverywhere(r);
  });
});

describe("upstream args are never redacted (HTTP /mcp end to end)", () => {
  it("direct and mf_call_tool calls reach the backend with the original secret; audit and response are redacted", async () => {
    const wire: unknown[] = [];
    const up = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
      if (body?.method === "tools/call") wire.push(body.params.arguments);
      const server = new McpServer({ name: "dokploy", version: "1" });
      server.registerTool("compose_update_env", { description: "e", inputSchema: { composeId: z.string(), env: z.string() } }, async () => ({ content: [{ type: "text", text: "updated" }] }));
      const t = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      await server.connect(t);
      await t.handleRequest(req, res, body);
    });
    await new Promise<void>((r) => up.listen(0, "127.0.0.1", r));
    cleanups.push(() => new Promise((r) => up.close(() => r(null))));
    const d = mkdtempSync(join(tmpdir(), "mf-unred-"));
    cleanups.push(async () => rmSync(d, { recursive: true, force: true }));
    const admin = "unred-admin";
    const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: Buffer.alloc(32, 9).toString("base64"), adminToken: admin, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    cfg.port = (probe.address() as { port: number }).port;
    await new Promise<void>((r) => probe.close(() => r()));
    const gw = await startServer(cfg);
    cleanups.push(() => gw.close());
    const ws = gw.store.ensureWorkspace("default");
    const be = await fetch(`${gw.url}/v1/backends`, { method: "POST", headers: { Authorization: `Bearer ${admin}`, "Content-Type": "application/json" },
      body: JSON.stringify({ slug: "dokploy", url: `http://127.0.0.1:${(up.address() as { port: number }).port}/mcp`, transport: "streamable-http", enabled: true, placement: { mode: "remote" } }) });
    expect(be.status).toBeLessThan(300);
    gw.store.createProject(ws.id, { slug: "devops", title: "DevOps", backendSlugs: ["dokploy"] });
    const id = gw.store.identity;
    const human = id.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
    const a = id.createAgent({ workspaceId: ws.id, name: "bot", owner: "chen", kind: "grokbot", projects: ["devops"], createdBy: human });
    const k = id.createKey({ agentId: a, createdBy: human });
    const gdb = gw.store.db;
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    gdb.exec("BEGIN IMMEDIATE;");
    gdb.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws.id, human);
    gdb.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_backends, match_tools, effect, created_by) VALUES (?,1,'t','["dokploy"]','["compose_update_env"]','allow',?)`).run(rid, human);
    gdb.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    gdb.exec("COMMIT;");
    const client = new Client({ name: "t", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${gw.url}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${k.token}` } } }));
    cleanups.push(() => client.close());
    await client.callTool({ name: "mf_use_project", arguments: { project: "devops", mintSessionToken: false } });
    const args = { composeId: "cmp_1", env: `FEATHERLESS_API_KEY=${FAKE}\nLOG_LEVEL=info` };
    const r1 = await client.callTool({ name: "dokploy__compose_update_env", arguments: args });
    const r2 = await client.callTool({ name: "mf_call_tool", arguments: { name: "dokploy__compose_update_env", arguments: args } });
    expect(wire).toEqual([args, args]);
    const audit = JSON.stringify([gdb.prepare(`SELECT * FROM mcpflow_call_audit`).all(), gdb.prepare(`SELECT * FROM audit_events`).all()]);
    expect(audit).toContain("FEATHERLESS_API_KEY=[redacted]");
    for (const s of [audit, logs.join("\n"), JSON.stringify(r1), JSON.stringify(r2)]) expect(s).not.toContain(FAKE);
  });
});
