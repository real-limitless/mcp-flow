/** Security T2.5 re-review (4428066f): R-1..R-4, M-2/L-7/L-9 completions. (H-1, R-6, L-5 live in the API/identity suites.) */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer, type PendingNotice } from "../src/policy/enforcer.js";
import type { CallContext } from "../src/policy/engine.js";
import { sanitizeForAudit } from "../src/audit/sanitize.js";
import { runAuditRetention } from "../src/audit/call-audit.js";
import { adminErrorText } from "../src/mcp/admin-tools.js";
import { loadConfig } from "../src/config.js";
import { startServer } from "../src/server.js";

const WS = "ws_" + "f".repeat(24);
const keys = derivePolicyKeys("rereview-dev-key");
let db: DatabaseSync;
let chen: string, bot: string, botKey: string;
let notices: PendingNotice[];
const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

function setup() {
  db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  const dir = new AgentDirectory(db, keys);
  chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
  bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  botKey = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
  notices = [];
  for (const [effect, tools] of [["require_approval", ["merge"]], ["allow", ["echo"]]] as const) {
    const id = `rule_${randomBytes(12).toString("hex")}`;
    const appr = effect === "require_approval";
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, WS, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, approvers, approval_timeout_s, created_by)
                VALUES (?,1,'t',?,?,?,?,?)`).run(id, JSON.stringify(tools), effect, appr ? JSON.stringify([chen]) : null, appr ? 30 : null, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(id);
    db.exec("COMMIT;");
  }
}
const enforcer = (extra: Record<string, unknown> = {}) =>
  new PolicyEnforcer({ db, keys, notify: async (n) => { notices.push(n); }, ...extra });
const ctx = (tool: string): CallContext => ({
  workspaceId: WS, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null,
  projectId: "p1", backendSlug: "gh", tool, qualifiedTool: `gh__${tool}`, placement: "remote", deviceId: null,
});
const body = (r: { content: unknown[] }) => JSON.parse((r.content[0] as { text: string }).text);
const waitFor = async (f: () => boolean) => {
  for (let i = 0; i < 300 && !f(); i++) await new Promise((r) => setTimeout(r, 10));
  if (!f()) throw new Error("timeout");
};
const pcRow = (id: string) => db.prepare(`SELECT * FROM mcpflow_pending_call WHERE id = ?`).get(id) as Record<string, unknown>;

describe("R-1 durable outcomes, idempotency, restart recovery", () => {
  beforeEach(setup);

  it("async result survives a restart and is re-readable within its window (T2.1 §11; was read-once); every read audited", async () => {
    const pe1 = enforcer();
    let ran = 0;
    const r = await pe1.enforce({ ctx: ctx("merge"), args: { pr: 1 }, asyncApproval: true, dispatch: async () => { ran++; return { content: [{ type: "text", text: "merged" }] }; } });
    const pc = body(r).pending_call_id as string;
    pe1.decide(pc, chen, "approved");
    await waitFor(() => (db.prepare(`SELECT result_ciphertext FROM mcpflow_call_outcome WHERE pending_call_id=?`).get(pc) as { result_ciphertext: unknown }).result_ciphertext != null);
    const pe2 = enforcer(); // "restart"
    expect(pe2.recoverOrphans()).toMatchObject({ cancelled: 0, abandoned: 0, unknown: 0, byWorkspace: {} });
    const got = pe2.takeAsyncResult(pc, bot);
    expect((got as { content: Array<{ text: string }> }).content[0]!.text).toBe("merged");
    // re-readable (an agent that disconnects mid-read does not lose it)
    expect((pe2.takeAsyncResult(pc, bot) as { content: Array<{ text: string }> }).content[0]!.text).toBe("merged");
    const reads = db.prepare(`SELECT actor, agent_id, error_code FROM mcpflow_call_audit WHERE event_type = 'result_read' ORDER BY audit_id`).all();
    expect(reads).toEqual([{ actor: bot, agent_id: bot, error_code: null }, { actor: bot, agent_id: bot, error_code: null }]);
    expect(pe2.pendingStatus(pc, bot)).toMatchObject({ outcome: "executed", dispatched: true });
    expect(ran).toBe(1);
  });

  it("restart: pending hold -> cancelled/not_executed; approved-undispatched -> abandoned, never dispatched; ciphertext purged", async () => {
    const pe1 = enforcer();
    let ran = 0;
    const d = async () => { ran++; return { content: [] }; };
    const a = body(await pe1.enforce({ ctx: ctx("merge"), args: { pr: 1 }, asyncApproval: true, dispatch: d })).pending_call_id as string;
    const b = body(await pe1.enforce({ ctx: ctx("merge"), args: { pr: 2 }, asyncApproval: true, dispatch: d })).pending_call_id as string;
    // b approved in the DB but its waiter "died" before it polled
    db.prepare(`UPDATE mcpflow_pending_call SET status='approved', decided_by=?, decided_at=? WHERE id=?`).run(chen, new Date().toISOString(), b);
    const pe2 = enforcer();
    expect(pe2.recoverOrphans()).toMatchObject({ cancelled: 1, abandoned: 1 });
    await new Promise((r) => setTimeout(r, 400)); // the old waiter wakes up and tries to dispatch
    expect(ran).toBe(0);
    expect(pcRow(a)).toMatchObject({ status: "cancelled", args_ciphertext: null });
    expect(pcRow(b)).toMatchObject({ status: "approved", dispatched_at: null, args_ciphertext: null });
    expect(pcRow(b).abandoned_at).toBeTruthy();
    expect(pe2.pendingStatus(a, bot)).toMatchObject({ outcome: "not_executed" });
    expect(pe2.pendingStatus(b, bot)).toMatchObject({ outcome: "not_executed", dispatched: false });
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET dispatched_at=? WHERE id=?`).run(new Date().toISOString(), b)).toThrow(/abandoned/);
    // exactly one completion per call
    for (const pc of [a, b]) {
      const cid = String(pcRow(pc).call_id);
      expect((db.prepare(`SELECT count(*) n FROM mcpflow_call_audit WHERE call_id=? AND event_type='completion'`).get(cid) as { n: number }).n).toBe(1);
    }
  });

  it("restart: dispatched but never completed -> unknown (tell the agent not to retry blindly)", async () => {
    const pe1 = enforcer();
    const r = await pe1.enforce({ ctx: ctx("merge"), args: { pr: 3 }, asyncApproval: true, dispatch: () => new Promise(() => {}) });
    const pc = body(r).pending_call_id as string;
    pe1.decide(pc, chen, "approved");
    await waitFor(() => pcRow(pc).dispatched_at != null);
    const pe2 = enforcer();
    expect(pe2.recoverOrphans()).toMatchObject({ unknown: 1 });
    expect(pe2.pendingStatus(pc, bot)).toMatchObject({ outcome: "unknown", dispatched: true });
    expect(body(pe2.takeAsyncResult(pc, bot) as never)).toMatchObject({ state: "unknown" });
    expect(pcRow(pc).args_ciphertext).toBeNull();
  });

  it("idempotency key: a re-send never runs twice; different args are refused; held calls replay approval_pending", async () => {
    const pe = enforcer();
    let ran = 0;
    const d = async () => { ran++; return { content: [{ type: "text" as const, text: `run#${ran}` }] }; };
    const r1 = await pe.enforce({ ctx: ctx("echo"), args: { x: 1 }, idempotencyKey: "k-1", dispatch: d });
    const r2 = await pe.enforce({ ctx: ctx("echo"), args: { x: 1 }, idempotencyKey: "k-1", dispatch: d });
    expect(ran).toBe(1);
    expect((r1.content[0] as { text: string }).text).toBe("run#1");
    expect((r2.content[0] as { text: string }).text).toBe("run#1"); // stored result replayed
    expect(body(await pe.enforce({ ctx: ctx("echo"), args: { x: 2 }, idempotencyKey: "k-1", dispatch: d })).reason).toBe("idempotency_conflict");
    expect(body(await pe.enforce({ ctx: ctx("echo"), args: {}, idempotencyKey: "bad key with spaces", dispatch: d })).reason).toBe("invalid_idempotency_key");
    const h1 = body(await pe.enforce({ ctx: ctx("merge"), args: { pr: 5 }, idempotencyKey: "k-2", asyncApproval: true, dispatch: d }));
    const h2 = body(await pe.enforce({ ctx: ctx("merge"), args: { pr: 5 }, idempotencyKey: "k-2", asyncApproval: true, dispatch: d }));
    expect(h2).toMatchObject({ code: "approval_pending", pending_call_id: h1.pending_call_id, replayed: true });
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_pending_call`).get() as { n: number }).n).toBe(1);
    pe.decide(h1.pending_call_id, chen, "denied");
    await waitFor(() => (db.prepare(`SELECT state FROM mcpflow_call_outcome WHERE pending_call_id=?`).get(h1.pending_call_id) as { state: string }).state !== "pending");
    expect(ran).toBe(1);
    // after a restart, the same key still replays (never runs again)
    const pe2 = enforcer();
    await pe2.enforce({ ctx: ctx("echo"), args: { x: 1 }, idempotencyKey: "k-1", dispatch: d });
    expect(ran).toBe(1);
  });
});

describe("R-2 result store caps", () => {
  beforeEach(setup);
  it("per-result cap truncates; total cap purges oldest (quota); TTL purges (expired); every purge audited", async () => {
    const pe = enforcer({ maxResultBytes: 1024, maxResultTotalBytes: 3000, resultTtlMs: 300 });
    const big = async () => ({ content: [{ type: "text" as const, text: "x".repeat(10_000) }] });
    for (let i = 0; i < 5; i++) await pe.enforce({ ctx: ctx("echo"), args: { i }, idempotencyKey: `cap-${i}`, dispatch: big });
    const rows = db.prepare(`SELECT result_bytes, result_truncated, result_ciphertext IS NOT NULL AS kept, result_purge_reason FROM mcpflow_call_outcome ORDER BY rowid`).all() as Array<{ result_bytes: number; result_truncated: number; kept: number; result_purge_reason: string | null }>;
    expect(rows.every((r) => r.result_truncated === 1 && r.result_bytes <= 1024)).toBe(true);
    const kept = rows.filter((r) => r.kept);
    expect(kept.reduce((s, r) => s + r.result_bytes, 0)).toBeLessThanOrEqual(3000);
    expect(rows[0]).toMatchObject({ kept: 0, result_purge_reason: "quota" }); // oldest purged first
    const quota = rows.filter((r) => r.result_purge_reason === "quota").length;
    await new Promise((r) => setTimeout(r, 350)); // the 300 ms window (from store time) passes
    expect(pe.purgeResults()).toBe(kept.length);
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_call_outcome WHERE result_ciphertext IS NOT NULL`).get() as { n: number }).n).toBe(0);
    const audit = db.prepare(`SELECT error_code, count(*) n FROM mcpflow_call_audit WHERE event_type = 'result_purge' GROUP BY error_code ORDER BY error_code`).all();
    expect(audit).toEqual([{ error_code: "purged:expired", n: kept.length }, { error_code: "purged:quota", n: quota }]);
    // outcome metadata survives the purge
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_call_outcome WHERE state='executed'`).get() as { n: number }).n).toBe(5);
  });

});

describe("R-3 /mcp body limit", () => {
  it("413 before anything parses an oversized body", async () => {
    const prev = process.env.MCP_FLOW_MAX_BODY_BYTES;
    process.env.MCP_FLOW_MAX_BODY_BYTES = "65536";
    const d = mkdtempSync(join(tmpdir(), "rr-")); tmp.push(d);
    const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: Buffer.alloc(32, 3).toString("base64"), adminToken: "rr-admin", host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    cfg.port = (probe.address() as { port: number }).port;
    await new Promise<void>((r) => probe.close(() => r()));
    const gw = await startServer(cfg);
    cleanups.push(() => gw.close());
    try {
      const big = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "x", arguments: { pad: "y".repeat(200_000) }, _meta: { progressToken: 1 } } });
      const r = await fetch(`${gw.url}/mcp`, { method: "POST", headers: { Authorization: "Bearer rr-admin", "content-type": "application/json", accept: "application/json, text/event-stream" }, body: big });
      expect(r.status).toBe(413);
    } finally {
      if (prev === undefined) delete process.env.MCP_FLOW_MAX_BODY_BYTES;
      else process.env.MCP_FLOW_MAX_BODY_BYTES = prev;
    }
  });
});

describe("R-4 / L-7 retention", () => {
  beforeEach(setup);
  it("rejects minMonths < 1, negative, NaN, fractional", () => {
    for (const minMonths of [0, -120, Number.NaN, 1.5]) {
      expect(() => runAuditRetention(db, { workspaceId: WS, before: "2020-01-01T00:00:00.000Z", archiveDir: "/tmp/never", actor: chen, minMonths })).toThrow(/minMonths/);
    }
  });
  it("processes month by month in pages, one lifecycle row per month", () => {
    const ins = db.prepare(`INSERT INTO mcpflow_call_audit (ts, event_type, call_id, workspace_id, agent_id, policy_decision) VALUES (?, 'decision', ?, ?, ?, 'allow')`);
    db.exec("BEGIN;");
    for (let i = 0; i < 2500; i++) ins.run(`2025-07-${String(1 + (i % 28)).padStart(2, "0")}T00:00:00.000Z`, `c${i}`, WS, bot);
    for (let i = 0; i < 3; i++) ins.run("2025-08-05T00:00:00.000Z", `d${i}`, WS, bot);
    db.exec("COMMIT;");
    const archive = mkdtempSync(join(tmpdir(), "rr-arch-")); tmp.push(archive);
    const out = runAuditRetention(db, { workspaceId: WS, before: "2025-09-01T00:00:00.000Z", archiveDir: archive, actor: chen, execute: true });
    expect(out.archived).toEqual({ "2025-07": 2500, "2025-08": 3 });
    expect(out.deleted).toBe(2503);
    expect(readFileSync(out.files[0]!, "utf8").trim().split("\n")).toHaveLength(2500);
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_call_audit WHERE lifecycle_action='audit_retention'`).get() as { n: number }).n).toBe(2);
  });
});

describe("M-2 redaction (re-review gaps)", () => {
  it("camelCase keys, Authorization: token, opaque high-entropy values; digests/uuids/benign keys kept", () => {
    const opaque = "aB3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ2cD4eF6gH8j";
    const out = sanitizeForAudit({
      apiToken: "a", authToken: "b", githubToken: "c", clientSecret: "d", accessKeyId: "AKIAABCDEFGHIJKLMNOP",
      header: "Authorization: token ghx_abc123secretvalue", value: opaque,
      sha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", uuid: "123e4567-e89b-12d3-a456-426614174000",
      primaryKey: "id", idempotencyKey: "k-1", max_tokens: 5,
    }) as Record<string, unknown>;
    for (const k of ["apiToken", "authToken", "githubToken", "clientSecret", "value"]) expect(out[k]).toBe("[redacted]");
    expect(JSON.stringify(out)).not.toContain("ghx_abc123secretvalue");
    expect(JSON.stringify(out)).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(out).toMatchObject({ sha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", uuid: "123e4567-e89b-12d3-a456-426614174000", primaryKey: "id", idempotencyKey: "k-1", max_tokens: 5 });
  });
  it("a secret straddling the 16 KB cut is still caught; nothing past the kept prefix is stored", () => {
    const pat = "ghp_" + "Z".repeat(36);
    const s = JSON.stringify(sanitizeForAudit({ c: "x".repeat(16_384 - 10) + pat + "y".repeat(5_000_000) }));
    expect(s).not.toContain("ZZZZZZZZZZ");
    expect(s.length).toBeLessThan(20_000);
  });
});

describe("L-9 admin tool errors", () => {
  it("are redacted and capped", () => {
    const t = adminErrorText("mf_admin_x", new Error("connect https://u:s3cr3t@db.internal failed " + "z".repeat(1000)));
    expect(t).not.toContain("s3cr3t");
    expect(t.length).toBeLessThanOrEqual(301);
  });
});
