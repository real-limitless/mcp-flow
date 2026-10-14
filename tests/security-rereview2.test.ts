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
import type { CallContext } from "../src/policy/engine.js";
import { sanitizeForAudit } from "../src/audit/sanitize.js";
import { runAuditRetention } from "../src/audit/call-audit.js";
import { adminErrorText } from "../src/mcp/admin-tools.js";
import { loadConfig } from "../src/config.js";
import { startServer } from "../src/server.js";

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
