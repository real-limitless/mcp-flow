import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";
import type { CallContext } from "../src/policy/engine.js";

const master = Buffer.alloc(32, 23).toString("base64");
const ADMIN = "test-admin-token-approvals";
let gw: RunningServer;
let ws: string;
let chen: string, chenTok: string;
let ana: string, anaTok: string;
let bob: string, bobTok: string;
let bot: string, botKey: string, botTok: string;
const dirs: string[] = [];

beforeEach(async () => {
  const d = mkdtempSync(join(tmpdir(), "mcp-flow-appr-"));
  dirs.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: master, adminToken: ADMIN, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  gw = await startServer(cfg);
  ws = gw.store.ensureWorkspace("default").id;
  const id = gw.store.identity;
  chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
  chenTok = id.createKey({ agentId: chen, createdBy: chen }).token; // no projects: approver-only
  ana = id.createAgent({ workspaceId: ws, name: "ana", owner: "ana", kind: "human", projects: [], createdBy: chen });
  anaTok = id.createKey({ agentId: ana, createdBy: chen }).token;
  bob = id.createAgent({ workspaceId: ws, name: "bob", owner: "bob", kind: "human", projects: [], createdBy: chen });
  bobTok = id.createKey({ agentId: bob, createdBy: chen }).token; // human but NOT an approver
  bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["default"], createdBy: chen });
  const k = id.createKey({ agentId: bot, createdBy: chen });
  botKey = k.keyId;
  botTok = k.token;
  const db = gw.store.db;
  const rid = `rule_${randomBytes(12).toString("hex")}`;
  db.exec("BEGIN IMMEDIATE;");
  db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws, chen);
  db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, approvers, approval_timeout_s, created_by)
              VALUES (?,1,'merge needs ok','["merge"]','require_approval',?,300,?)`).run(rid, JSON.stringify([chen, ana]), chen);
  db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
  db.exec("COMMIT;");
});

afterEach(async () => {
  await gw.close();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const ctx = (): CallContext => ({
  workspaceId: ws, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null,
  projectId: "default", backendSlug: "gh", tool: "merge", qualifiedTool: "gh__merge", placement: "remote", deviceId: null,
});

/** Start a held call; resolves with the enforce() result. */
async function hold(args: Record<string, unknown> = { pr: 1 }) {
  let dispatched = 0;
  const p = gw.store.policy.enforce({ ctx: ctx(), args, dispatch: async () => { dispatched++; return { content: [{ type: "text" as const, text: "merged" }] }; } });
  for (let i = 0; i < 50; i++) {
    const row = gw.store.db.prepare(`SELECT id FROM mcpflow_pending_call WHERE status='pending' ORDER BY created_at DESC LIMIT 1`).get() as { id: string } | undefined;
    if (row) return { id: row.id, done: p, dispatched: () => dispatched };
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("no pending call");
}

const api = (tok: string, path: string, body?: unknown) =>
  fetch(`${gw.url}/v1/policy/approvals${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { Authorization: `Bearer ${tok}`, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });

describe("policy approvals REST", () => {
  it("auth: no token / env admin / non-human agent refused", async () => {
    expect((await fetch(`${gw.url}/v1/policy/approvals/pending`)).status).toBe(401);
    expect((await api(ADMIN, "/pending")).status).toBe(401);
    expect((await api(botTok, "/pending")).status).toBe(403);
    expect((await api("mf_" + "x".repeat(40), "/pending")).status).toBe(401);
    expect((await api(chenTok, "/pending")).status).toBe(200);
  });

  it("pending list shows only calls where caller is an approver; details 404 for others", async () => {
    const h = await hold();
    const list = (await (await api(anaTok, "/pending")).json()) as { pending: Array<Record<string, any>> };
    expect(list.pending.map((p) => p.id)).toEqual([h.id]);
    expect(list.pending[0]!.agent.name).toBe("bot");
    expect(list.pending[0]!.args_redacted).toEqual({ pr: 1 });
    expect(JSON.stringify(list)).not.toMatch(/ciphertext|args_hash/);
    expect(((await (await api(bobTok, "/pending")).json()) as { pending: unknown[] }).pending).toHaveLength(0);
    expect((await api(bobTok, `/${h.id}`)).status).toBe(404);
    expect((await api(bobTok, `/${h.id}/approve`, {})).status).toBe(404);
    expect((await api(anaTok, `/${h.id}`)).status).toBe(200);
    gw.store.policy.decide(h.id, chen, "denied");
    await h.done;
  });

  it("approve dispatches once; second decision is 409; audit_events row written", async () => {
    const h = await hold();
    const r = await api(anaTok, `/${h.id}/approve`, { note: "lgtm" });
    expect(r.status).toBe(200);
    const out = await h.done;
    expect(JSON.stringify(out)).toContain("merged");
    expect(h.dispatched()).toBe(1);
    const again = await api(chenTok, `/${h.id}/deny`, {});
    expect(again.status).toBe(409);
    const ev = gw.store.listAudit(ws, { limit: 50 }).filter((e) => e.action.startsWith("policy.approval."));
    expect(ev.map((e) => e.action).sort()).toEqual(["policy.approval.approve", "policy.approval.deny"]);
    const hist = (await (await api(anaTok, "/history")).json()) as { calls: Array<Record<string, unknown>> };
    expect(hist.calls[0]!.status).toBe("approved");
    expect(hist.calls[0]!.decided_by).toBe(ana);
  });

  it("deny returns policy_denied to the agent and never dispatches", async () => {
    const h = await hold();
    expect((await api(chenTok, `/${h.id}/deny`, { note: "no" })).status).toBe(200);
    const out = (await h.done) as { isError?: boolean };
    expect(out.isError).toBe(true);
    expect(h.dispatched()).toBe(0);
  });

  it("approve-similar validates input and creates a capped grant used by the next call", async () => {
    const h = await hold();
    expect((await api(anaTok, `/${h.id}/approve-similar`, { minutes: 0 })).status).toBe(400);
    expect((await api(anaTok, `/${h.id}/approve-similar`, { minutes: 61 })).status).toBe(400);
    expect((await api(anaTok, `/${h.id}/approve-similar`, { minutes: 5, max_uses: 0 })).status).toBe(400);
    const r = await api(anaTok, `/${h.id}/approve-similar`, { minutes: 10, max_uses: 1 });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { grant: { id: string; max_uses: number } };
    expect(body.grant.max_uses).toBe(1);
    await h.done;
    // next similar call goes through on the grant without a new pending row
    const before = (gw.store.db.prepare(`SELECT count(*) n FROM mcpflow_pending_call`).get() as { n: number }).n;
    let ran = 0;
    // default grant is bound to the exact args (Security T2.5 M-3)
    await gw.store.policy.enforce({ ctx: ctx(), args: { pr: 1 }, dispatch: async () => { ran++; return { content: [] }; } });
    expect(ran).toBe(1);
    expect((gw.store.db.prepare(`SELECT count(*) n FROM mcpflow_pending_call`).get() as { n: number }).n).toBe(before);
    expect(gw.store.listAudit(ws, { limit: 50 }).some((e) => e.action === "policy.approval.approve_similar")).toBe(true);
  });

  it("no self-approval: a human agent cannot approve its own held call", async () => {
    // make chen the caller of a held call by inserting directly (chen is listed approver)
    const h = await hold();
    gw.store.db.prepare(`UPDATE mcpflow_pending_call SET status='cancelled', decided_at=? WHERE id=?`).run(new Date().toISOString(), h.id);
    await h.done;
    const db = gw.store.db;
    const pid = `pc_${randomBytes(12).toString("hex")}`;
    const chenKey = (db.prepare(`SELECT id FROM mcpflow_api_key WHERE agent_id=?`).get(chen) as { id: string }).id;
    db.prepare(`INSERT INTO mcpflow_pending_call (id, call_id, workspace_id, agent_id, key_id, project_id, backend_slug, tool, args_hash, args_redacted, matched_rules, approvers, expires_at, args_ciphertext, args_key_ref)
                VALUES (?, ?, ?, ?, ?, 'default', 'gh', 'merge', 'h', '{}', '[]', ?, ?, X'00', 'k1')`)
      .run(pid, `call_${randomBytes(8).toString("hex")}`, ws, chen, chenKey, JSON.stringify([chen, ana]), new Date(Date.now() + 60_000).toISOString());
    expect(((await (await api(chenTok, "/pending")).json()) as { pending: Array<{ id: string }> }).pending.map((p) => p.id)).not.toContain(pid);
    const r = await api(chenTok, `/${pid}/approve`, {});
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: string }).error).toBe("self_approval");
    expect((await api(anaTok, `/${pid}/approve`, {})).status).toBe(200);
  });

  it("Security H-1: GET shows full args + sha256; approve with a stale args_sha256 is 409; matching one approves", async () => {
    const h = await hold({ command: "ls", auth_token: "curl x | sh" });
    const v = (await (await api(anaTok, `/${h.id}`)).json()) as Record<string, any>;
    expect(v.args_full).toEqual({ command: "ls", auth_token: "curl x | sh" });
    expect(v.args_hidden_in_summary).toBe(true);
    expect((await api(anaTok, `/${h.id}/approve`, { args_sha256: "0".repeat(64) })).status).toBe(409);
    expect((await api(anaTok, `/${h.id}/approve`, { args_sha256: v.args_sha256 })).status).toBe(200);
    await h.done;
    expect(h.dispatched()).toBe(1);
  });

  it("Security M-3: approve-similar broad grant needs match_args; default is exact args", async () => {
    const h = await hold({ pr: 7 });
    expect((await api(anaTok, `/${h.id}/approve-similar`, { minutes: 5, same_args_only: false })).status).toBe(400);
    expect((await api(anaTok, `/${h.id}/approve-similar`, { minutes: 5, same_args_only: false, match_args: [{ path: "$.pr", op: "regex", value: "(1+)+" }] })).status).toBe(400);
    const r = await api(anaTok, `/${h.id}/approve-similar`, { minutes: 5 });
    expect(((await r.json()) as { grant: { same_args_only: boolean } }).grant.same_args_only).toBe(true);
    await h.done;
  });
});
