/** Security T2.5 Re-review 2 (0a83b25e): R2-1..R2-4, R2-6, R2-7, I-3, GAP-4 scope. */
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
import { decryptArgs } from "../src/policy/crypto.js";
import type { CallContext } from "../src/policy/engine.js";
import { sanitizeForAudit } from "../src/audit/sanitize.js";
import { runAuditRetention } from "../src/audit/call-audit.js";
import { adminErrorText } from "../src/mcp/admin-tools.js";
import { loadConfig } from "../src/config.js";
import { startServer } from "../src/server.js";
import { acquireGatewayLock, lockIdentity } from "../src/db/gateway-lock.js";
import { writeFileSync, existsSync, utimesSync, statSync } from "node:fs";
import { hostname } from "node:os";

const WS = "ws_" + "e".repeat(24);
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
};
void [readFileSync, sanitizeForAudit, runAuditRetention, adminErrorText, loadConfig, startServer, createServer, mkdtempSync, tmpdir, join, body, waitFor, enforcer, ctx, cleanups, tmp, notices];

describe("I-3 session ids", () => {
  it("new session ids use sess_ (tokens keep mf_sess_); legacy mf_sess_ ids survive migration 0007", () => {
    db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db, "0006_outcomes_epoch");
    const dir = new AgentDirectory(db, keys);
    chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const k = dir.createKey({ agentId: bot, createdBy: chen });
    const legacyId = "mf_sess_" + "a".repeat(24);
    db.prepare(`INSERT INTO mcpflow_session (id, token_hash, agent_id, key_id, project_id, expires_at) VALUES (?,?,?,?,?,?)`)
      .run(legacyId, "h".repeat(64), bot, k.keyId, "p1", new Date(Date.now() + 3600e3).toISOString());
    runMigrations(db);
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_resolvable_session WHERE session_id = ?`).get(legacyId) as { n: number }).n).toBe(1);
    const r = dir.resolveKey(k.token);
    if (r.status !== "ok") throw new Error("resolve");
    const s = dir.createSession(r.agent, "p1");
    expect(s.sessionId).toMatch(/^sess_[0-9a-f]{24}$/);
    expect(s.token.startsWith("mf_sess_")).toBe(true);
    const back = dir.resolveSession(s.token);
    expect(back.status).toBe("ok");
    expect(back.status === "ok" && back.agent.sessionId).toBe(s.sessionId);
    // revoke cascade still works on the rebuilt table
    dir.revokeKey(k.keyId, chen, "test");
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_session WHERE revoked_at IS NULL`).get() as { n: number }).n).toBe(0);
    expect(() => db.prepare(`INSERT INTO mcpflow_session (id, token_hash, agent_id, key_id, project_id, expires_at) VALUES ('x_1','h2',?,?,?,?)`)
      .run(bot, k.keyId, "p1", new Date(Date.now() + 3600e3).toISOString())).toThrow();
  });
});

describe("R2-1 / R2-2 idempotency scope", () => {
  it("R2-1: a re-send on a rotated key with the same idempotency key replays, never runs again", async () => {
    setup();
    const pe = enforcer();
    let runs = 0;
    const d = async () => { runs++; return { content: [{ type: "text" as const, text: "ok" }] }; };
    await pe.enforce({ ctx: ctx("echo"), args: { x: 1 }, idempotencyKey: "rot-1", dispatch: d });
    const rotated = new AgentDirectory(db, keys).rotateKey(botKey, chen);
    const r = await pe.enforce({ ctx: { ...ctx("echo"), keyId: rotated.keyId }, args: { x: 1 }, idempotencyKey: "rot-1", dispatch: d });
    expect(runs).toBe(1);
    expect(JSON.stringify(r)).toContain("ok");
    // the DB enforces it too: a second row for (agent, key) on another key is refused
    expect(() => db.prepare(`INSERT INTO mcpflow_call_outcome (call_id, workspace_id, agent_id, key_id, idempotency_key, args_hash) VALUES ('c_x',?,?,?,'rot-1','h')`)
      .run(WS, bot, rotated.keyId)).toThrow(/UNIQUE/);
  });

  it("R2-2: same key + same args on a different tool or backend is idempotency_conflict, not a replay", async () => {
    setup();
    const pe = enforcer();
    let runs = 0;
    const d = async () => { runs++; return { content: [{ type: "text" as const, text: "ran" }] }; };
    await pe.enforce({ ctx: ctx("echo"), args: { x: 1 }, idempotencyKey: "t-1", dispatch: d });
    const otherBackend = { ...ctx("echo"), backendSlug: "gl", qualifiedTool: "gl__echo" };
    expect(body(await pe.enforce({ ctx: otherBackend, args: { x: 1 }, idempotencyKey: "t-1", dispatch: d })).reason).toBe("idempotency_conflict");
    expect(body(await pe.enforce({ ctx: ctx("merge"), args: { x: 1 }, idempotencyKey: "t-1", dispatch: d })).reason).toBe("idempotency_conflict");
    expect(runs).toBe(1);
  });
});

describe("R2-3 per-agent result quota", () => {
  it("an agent flooding results evicts only its own; other agents' unread results survive", async () => {
    setup();
    const dir = new AgentDirectory(db, keys);
    const bot2 = dir.createAgent({ workspaceId: WS, name: "bot2", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const bot2Key = dir.createKey({ agentId: bot2, createdBy: chen }).keyId;
    const pe = enforcer({ maxResultBytes: 1024, maxResultAgentBytes: 2500, maxResultTotalBytes: 1_000_000 });
    const big = async () => ({ content: [{ type: "text" as const, text: "x".repeat(10_000) }] });
    await pe.enforce({ ctx: ctx("echo"), args: { mine: 1 }, idempotencyKey: "a-1", dispatch: big });
    for (let i = 0; i < 6; i++) {
      await pe.enforce({ ctx: { ...ctx("echo"), agentId: bot2, agentName: "bot2", keyId: bot2Key }, args: { i }, idempotencyKey: `f-${i}`, dispatch: big });
    }
    const kept = (agent: string) => db.prepare(`SELECT coalesce(sum(result_bytes),0) t, count(*) n FROM mcpflow_call_outcome WHERE agent_id = ? AND result_ciphertext IS NOT NULL`).get(agent) as { t: number; n: number };
    expect(kept(bot).n).toBe(1);
    expect(kept(bot2).t).toBeLessThanOrEqual(2500);
    expect(kept(bot2).n).toBeGreaterThan(0);
  });
});

describe("R2-7 key separation and per-workspace recovery audit", () => {
  it("results are encrypted under result-enc, not args-enc", async () => {
    setup();
    expect(keys.resultEnc.equals(keys.argsEnc)).toBe(false);
    const pe = enforcer();
    await pe.enforce({ ctx: ctx("echo"), args: { x: 1 }, idempotencyKey: "enc-1", dispatch: async () => ({ content: [{ type: "text" as const, text: "secret-ish" }] }) });
    const ct = (db.prepare(`SELECT result_ciphertext FROM mcpflow_call_outcome WHERE idempotency_key='enc-1'`).get() as { result_ciphertext: Uint8Array }).result_ciphertext;
    expect(() => decryptArgs(keys.argsEnc, ct)).toThrow();
    expect(JSON.stringify(decryptArgs(keys.resultEnc, ct))).toContain("secret-ish");
  });

  it("recoverOrphans reports per-workspace counts (only affected workspaces)", async () => {
    setup();
    new AgentDirectory(db, keys).bootstrapWorkspace("ws_" + "d".repeat(24), { name: "other", owner: "other" });
    const pe = enforcer();
    void pe.enforce({ ctx: ctx("merge"), args: { pr: 1 }, dispatch: async () => ({ content: [] }) });
    await waitFor(() => notices.length === 1);
    pe.close();
    const rec = enforcer().recoverOrphans();
    expect(rec.byWorkspace).toEqual({ [WS]: { cancelled: 1, abandoned: 0, unknown: 0 } });
  });
});

describe("R2-4 single gateway per DB", () => {
  const cfgFor = async (dbPath: string) => {
    const cfg = loadConfig({ dbPath, masterKeyRaw: Buffer.alloc(32, 9).toString("base64"), adminToken: "t-admin-lock", host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    cfg.port = (probe.address() as { port: number }).port;
    await new Promise<void>((r) => probe.close(() => r()));
    return cfg;
  };

  it("a second gateway on the same DB refuses to start; after close a new one starts", async () => {
    const d = mkdtempSync(join(tmpdir(), "lock-")); tmp.push(d);
    const dbPath = join(d, "t.db");
    const a = await startServer(await cfgFor(dbPath));
    expect(existsSync(`${dbPath}.gateway.lock`)).toBe(true);
    await expect(startServer(await cfgFor(dbPath))).rejects.toThrow(/another mcp-flow gateway process holds/);
    // the refused start did not run recovery against A's DB: A still serves
    expect(a.store.db.prepare("SELECT 1 AS x").get()).toEqual({ x: 1 });
    await a.close();
    expect(existsSync(`${dbPath}.gateway.lock`)).toBe(false);
    const b = await startServer(await cfgFor(dbPath));
    await b.close();
  });

  it("takes over a stale lock (dead pid in our host/boot/pid-namespace, or no heartbeat for 30 s); refuses a live one", async () => {
    const d = mkdtempSync(join(tmpdir(), "lock-")); tmp.push(d);
    const dbPath = join(d, "t.db");
    const lockPath = `${dbPath}.gateway.lock`;
    writeFileSync(lockPath, JSON.stringify({ nonce: "old", pid: 2 ** 22 + 12345, ...lockIdentity(), started: "x" }));
    const l1 = (await acquireGatewayLock(dbPath, { settleMs: 1 }))!;
    l1.release();
    writeFileSync(lockPath, JSON.stringify({ nonce: "live", pid: process.ppid, host: "elsewhere", started: "x" }));
    await expect(acquireGatewayLock(dbPath, { settleMs: 1 })).rejects.toThrow(/another mcp-flow gateway/);
    const old = new Date(Date.now() - 60_000);
    utimesSync(lockPath, old, old);
    const l2 = (await acquireGatewayLock(dbPath, { settleMs: 1 }))!;
    expect(JSON.parse(readFileSync(lockPath, "utf8")).pid).toBe(process.pid);
    l2.release();
    expect(await acquireGatewayLock(":memory:")).toBeNull();
  });
});

describe("R2-6 retention covers the outcome table only (T2.1 §12)", () => {
  it("archives (0600, no ciphertext) and deletes resolved outcome rows older than `before`; pending_call and call_audit rows are never deleted", async () => {
    setup();
    const old = Date.parse("2025-06-10T00:00:00.000Z");
    const peOld = enforcer({ clock: () => old });
    await peOld.enforce({ ctx: ctx("echo"), args: { x: 1 }, idempotencyKey: "old-1", dispatch: async () => ({ content: [{ type: "text" as const, text: "r" }] }) });
    void peOld.enforce({ ctx: ctx("merge"), args: { pr: 1 }, idempotencyKey: "old-2", asyncApproval: true, dispatch: async () => ({ content: [] }) });
    await waitFor(() => notices.length === 1);
    peOld.close();
    enforcer().recoverOrphans(); // old hold -> cancelled
    const pe = enforcer();
    void pe.enforce({ ctx: ctx("merge"), args: { pr: 2 }, dispatch: async () => ({ content: [] }) }); // recent, open
    await waitFor(() => notices.length === 2);
    const count = (t: string) => (db.prepare(`SELECT count(*) n FROM ${t}`).get() as { n: number }).n;
    expect(count("mcpflow_call_outcome")).toBe(2);
    expect(count("mcpflow_pending_call")).toBe(2);
    const archive = mkdtempSync(join(tmpdir(), "rr2-arch-")); tmp.push(archive);
    const base = { workspaceId: WS, before: "2025-09-01T00:00:00.000Z", archiveDir: archive, actor: chen, now: new Date("2026-10-14T00:00:00Z") };
    pe.purgeResults(); // the old stored result's 24 h window ended long ago: payload purged (only then is the row eligible)
    const auditCount = count("mcpflow_call_audit");
    const dry = runAuditRetention(db, base);
    expect(dry.state).toEqual({ call_outcome: 2 });
    const out = runAuditRetention(db, { ...base, execute: true });
    expect(out.state).toEqual({ call_outcome: 2 });
    expect(count("mcpflow_call_outcome")).toBe(0);
    expect(count("mcpflow_pending_call")).toBe(2); // never deleted (§12)
    expect(count("mcpflow_call_audit")).toBe(auditCount + 1); // + the state_retention lifecycle row
    expect(out.files.some((f) => f.includes("pending_call_"))).toBe(false);
    const of = out.files.find((f) => f.includes("call_outcome_"))!;
    expect(readFileSync(of, "utf8")).not.toMatch(/ciphertext/);
    expect(statSync(of).mode & 0o777).toBe(0o600);
    // no-delete triggers are back
    expect(() => db.prepare(`DELETE FROM mcpflow_pending_call`).run()).toThrow(/never deleted/);
    expect(db.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_call_outcome_no_delete'`).get()).toBeTruthy();
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_call_audit WHERE lifecycle_action='state_retention'`).get() as { n: number }).n).toBe(1);
    pe.close();
  });
});
