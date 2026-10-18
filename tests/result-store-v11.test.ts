/** T2.1 §11/§12 result store on 0012: owner-or-admin audited reads, re-readable window from store time, quota/TTL purges audited. */
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it } from "vitest";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer } from "../src/policy/enforcer.js";
import type { CallContext } from "../src/policy/engine.js";

const WS = "ws_" + "9".repeat(24);
const keys = derivePolicyKeys("result-store-v11-dev");
let db: DatabaseSync;
let dir: AgentDirectory;
let chen: string, ana: string, bot: string, botKey: string, bot2: string, bot2Key: string;

beforeEach(() => {
  db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  dir = new AgentDirectory(db, keys);
  chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" }); // active human admin
  ana = dir.createAgent({ workspaceId: WS, name: "ana", owner: "chen", kind: "human", projects: ["p1"], createdBy: chen }); // human, not admin
  bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  botKey = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
  bot2 = dir.createAgent({ workspaceId: WS, name: "bot2", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  bot2Key = dir.createKey({ agentId: bot2, createdBy: chen }).keyId;
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
});
const ctx = (tool: string, agentId = bot, keyId = botKey, agentName = "bot"): CallContext => ({
  workspaceId: WS, agentId, agentName, keyId, keyPrefix: null, sessionId: null,
  projectId: "p1", backendSlug: "gh", tool, qualifiedTool: `gh__${tool}`, placement: "remote", deviceId: null,
});
const txt = (r: unknown) => ((r as { content: Array<{ text: string }> }).content[0]!.text);
const waitFor = async (f: () => boolean) => {
  for (let i = 0; i < 300 && !f(); i++) await new Promise((r) => setTimeout(r, 10));
  if (!f()) throw new Error("timeout");
};
const reads = () => db.prepare(`SELECT actor, agent_id, key_id, error_code FROM mcpflow_call_audit WHERE event_type = 'result_read' ORDER BY audit_id`).all();

async function heldResult(pe: PolicyEnforcer, text = "merged"): Promise<string> {
  const r = await pe.enforce({ ctx: ctx("merge"), args: { pr: randomBytes(3).toString("hex") }, asyncApproval: true, dispatch: async () => ({ content: [{ type: "text", text }] }) });
  const pc = JSON.parse(txt(r)).pending_call_id as string;
  pe.decide(pc, chen, "approved");
  await waitFor(() => (db.prepare(`SELECT result_stored_at FROM mcpflow_call_outcome WHERE pending_call_id = ?`).get(pc) as { result_stored_at: string | null }).result_stored_at != null);
  return pc;
}

describe("audited reads (owner or active human admin)", () => {
  it("owner and admin read (re-readable); other agent and non-admin human get 'gone'; every attempt audited", async () => {
    const pe = new PolicyEnforcer({ db, keys });
    const pc = await heldResult(pe);
    expect(txt(pe.takeAsyncResult(pc, bot))).toBe("merged");
    expect(txt(pe.takeAsyncResult(pc, bot))).toBe("merged");
    expect(txt(pe.takeAsyncResult(pc, chen))).toBe("merged");
    expect(pe.takeAsyncResult(pc, bot2)).toBe("gone");
    expect(pe.takeAsyncResult(pc, ana)).toBe("gone");
    db.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(chen);
    expect(pe.takeAsyncResult(pc, chen)).toBe("gone"); // admin no longer active
    expect(pe.takeAsyncResult(`pc_${"0".repeat(24)}`, bot)).toBe("gone"); // unknown: nothing to audit
    expect(reads()).toEqual([
      { actor: bot, agent_id: bot, key_id: botKey, error_code: null },
      { actor: bot, agent_id: bot, key_id: botKey, error_code: null },
      { actor: chen, agent_id: bot, key_id: botKey, error_code: null },
      { actor: bot2, agent_id: bot, key_id: botKey, error_code: "result_forbidden" },
      { actor: ana, agent_id: bot, key_id: botKey, error_code: "result_forbidden" },
      { actor: chen, agent_id: bot, key_id: botKey, error_code: "result_forbidden" },
    ]);
  });

  it("not_ready is audited; a read whose audit row cannot be written returns nothing (fail closed)", async () => {
    let fail = false;
    const pe = new PolicyEnforcer({ db, keys, auditFault: () => fail });
    const r = await pe.enforce({ ctx: ctx("merge"), args: { pr: 1 }, asyncApproval: true, dispatch: async () => ({ content: [{ type: "text", text: "secret-result" }] }) });
    const pc = JSON.parse(txt(r)).pending_call_id as string;
    expect(pe.takeAsyncResult(pc, bot)).toBe("not_ready");
    expect(reads()).toEqual([{ actor: bot, agent_id: bot, key_id: botKey, error_code: "result_not_ready" }]);
    pe.decide(pc, chen, "approved");
    await waitFor(() => (db.prepare(`SELECT result_stored_at FROM mcpflow_call_outcome WHERE pending_call_id = ?`).get(pc) as { result_stored_at: string | null }).result_stored_at != null);
    fail = true;
    const denied = pe.takeAsyncResult(pc, bot);
    expect(JSON.stringify(denied)).not.toContain("secret-result");
    expect(JSON.parse(txt(denied))).toMatchObject({ code: "policy_denied", reason: "audit_unavailable" });
    expect(reads()).toHaveLength(1);
  });

  it("idempotent replay goes through the audited read", async () => {
    const pe = new PolicyEnforcer({ db, keys });
    let ran = 0;
    const d = async () => ({ content: [{ type: "text" as const, text: `run#${++ran}` }] });
    expect(txt(await pe.enforce({ ctx: ctx("echo"), args: { a: 1 }, idempotencyKey: "k1", dispatch: d }))).toBe("run#1");
    expect(txt(await pe.enforce({ ctx: ctx("echo"), args: { a: 1 }, idempotencyKey: "k1", dispatch: d }))).toBe("run#1");
    expect(ran).toBe(1);
    expect(reads()).toEqual([{ actor: bot, agent_id: bot, key_id: botKey, error_code: null }]);
  });
});

describe("24 h window from store time", () => {
  it("result_expires_at = result_stored_at + 24 h, and stored_at is when the result was stored (not the decision)", async () => {
    const pe = new PolicyEnforcer({ db, keys });
    const r = await pe.enforce({ ctx: ctx("merge"), args: { pr: 2 }, asyncApproval: true, dispatch: async () => ({ content: [] }) });
    const pc = JSON.parse(txt(r)).pending_call_id as string;
    await new Promise((res) => setTimeout(res, 50)); // the approver takes a while
    pe.decide(pc, chen, "approved");
    await waitFor(() => (db.prepare(`SELECT result_stored_at FROM mcpflow_call_outcome WHERE pending_call_id = ?`).get(pc) as { result_stored_at: string | null }).result_stored_at != null);
    const o = db.prepare(`SELECT created_at, result_stored_at, result_expires_at FROM mcpflow_call_outcome WHERE pending_call_id = ?`).get(pc) as Record<string, string>;
    expect(Date.parse(o.result_stored_at!) - Date.parse(o.created_at!)).toBeGreaterThanOrEqual(50);
    expect(Date.parse(o.result_expires_at!) - Date.parse(o.result_stored_at!)).toBe(24 * 3_600_000);
  });

  it("after the window a read never serves the result; it is purged (expired) and audited", async () => {
    const pe = new PolicyEnforcer({ db, keys, resultTtlMs: 100 });
    const pc = await heldResult(pe, "late");
    await new Promise((res) => setTimeout(res, 150));
    const r = pe.takeAsyncResult(pc, bot);
    expect(JSON.stringify(r)).not.toContain("late");
    expect(JSON.parse(txt(r))).toMatchObject({ code: "call_outcome", state: "executed", error_code: "result_purged", reason: "purged:expired" });
    expect(db.prepare(`SELECT error_code FROM mcpflow_call_audit WHERE event_type = 'result_purge'`).all()).toEqual([{ error_code: "purged:expired" }]);
  });
});

describe("quota purge (§12): never refuses a store; per-agent evicts own oldest; global evicts oldest overall", () => {
  const run = async (pe: PolicyEnforcer, who: "bot" | "bot2", i: number) => {
    const c = who === "bot" ? ctx("echo") : ctx("echo", bot2, bot2Key, "bot2");
    await pe.enforce({ ctx: c, args: { i }, idempotencyKey: `${who}-${i}`, dispatch: async () => ({ content: [{ type: "text", text: "y".repeat(300) }] }) });
  };
  const state = () => db.prepare(`SELECT agent_id, idempotency_key k, result_ciphertext IS NOT NULL AS kept, result_purge_reason r FROM mcpflow_call_outcome ORDER BY rowid`).all() as Array<{ agent_id: string; k: string; kept: number; r: string | null }>;

  it("per-agent cap: bot's overflow evicts only bot's oldest; bot2 untouched", async () => {
    const pe = new PolicyEnforcer({ db, keys, maxResultAgentBytes: 1000, maxResultTotalBytes: 1_000_000 });
    await run(pe, "bot2", 0);
    for (let i = 0; i < 5; i++) await run(pe, "bot", i);
    const s = state();
    expect(s.filter((x) => x.agent_id === bot2).every((x) => x.kept === 1)).toBe(true);
    const mine = s.filter((x) => x.agent_id === bot);
    expect(mine.at(-1)!.kept).toBe(1); // the newest store always lands
    const evicted = mine.filter((x) => !x.kept);
    expect(evicted.length).toBeGreaterThan(0);
    expect(evicted.every((x) => x.r === "quota")).toBe(true);
    expect(mine.slice(0, evicted.length).every((x) => !x.kept)).toBe(true); // oldest first
    // reading a quota-purged result: result_purged / purged:quota
    const victim = db.prepare(`SELECT call_id FROM mcpflow_call_outcome WHERE result_purge_reason = 'quota' ORDER BY rowid LIMIT 1`).get() as { call_id: string };
    const prior = db.prepare(`SELECT idempotency_key FROM mcpflow_call_outcome WHERE call_id = ?`).get(victim.call_id) as { idempotency_key: string };
    const replay = await pe.enforce({ ctx: ctx("echo"), args: { i: Number(prior.idempotency_key.split("-")[1]) }, idempotencyKey: prior.idempotency_key, dispatch: async () => ({ content: [] }) });
    expect(JSON.parse(txt(replay))).toMatchObject({ code: "call_outcome", error_code: "result_purged", reason: "purged:quota", replayed: true });
    expect(db.prepare(`SELECT error_code FROM mcpflow_call_audit WHERE event_type = 'result_read' ORDER BY audit_id DESC LIMIT 1`).get()).toEqual({ error_code: "result_purged" });
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_call_audit WHERE event_type = 'result_purge' AND error_code = 'purged:quota' AND agent_id = ?`).get(bot) as { n: number }).n)
      .toBe(evicted.length);
  });

  it("global cap: the oldest results overall go first, whoever owns them", async () => {
    const pe = new PolicyEnforcer({ db, keys, maxResultAgentBytes: 1_000_000, maxResultTotalBytes: 1000 });
    await run(pe, "bot2", 0);
    await run(pe, "bot", 0);
    await run(pe, "bot", 1);
    await run(pe, "bot", 2);
    const s = state();
    expect(s[0]).toMatchObject({ agent_id: bot2, kept: 0, r: "quota" });
    expect(s.at(-1)!.kept).toBe(1);
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_call_audit WHERE event_type = 'result_purge'`).get() as { n: number }).n)
      .toBe(s.filter((x) => !x.kept).length);
  });
});
