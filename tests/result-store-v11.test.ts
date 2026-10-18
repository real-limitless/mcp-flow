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

  it("R5-3: an active human admin of ANOTHER workspace can't read the result (same answer as unknown; audited forbidden)", async () => {
    const WS2 = "ws_" + "8".repeat(24);
    const eve = dir.bootstrapWorkspace(WS2, { name: "eve", owner: "eve" }); // active human admin, but of WS2
    const pe = new PolicyEnforcer({ db, keys });
    const pc = await heldResult(pe, "ws1-secret");
    const r = pe.takeAsyncResult(pc, eve);
    expect(r).toBe("gone");
    expect(JSON.stringify(r)).not.toContain("ws1-secret");
    expect(pe.takeAsyncResult(`pc_${"0".repeat(24)}`, eve)).toBe("gone"); // identical to an unknown id
    expect(txt(pe.takeAsyncResult(pc, chen))).toBe("ws1-secret"); // the owner workspace's admin still can
    expect(reads()).toEqual([
      { actor: eve, agent_id: bot, key_id: botKey, error_code: "result_forbidden" },
      { actor: chen, agent_id: bot, key_id: botKey, error_code: null },
    ]);
  });

  it("R5-4: repeated not_ready polls are coalesced per (call, reader); every serve and terminal error is still one row", async () => {
    const pe = new PolicyEnforcer({ db, keys });
    const r = await pe.enforce({ ctx: ctx("merge"), args: { pr: 9 }, asyncApproval: true, dispatch: async () => ({ content: [{ type: "text", text: "done" }] }) });
    const pc = JSON.parse(txt(r)).pending_call_id as string;
    for (let i = 0; i < 50; i++) expect(pe.takeAsyncResult(pc, bot)).toBe("not_ready");
    for (let i = 0; i < 20; i++) expect(pe.takeAsyncResult(pc, chen)).toBe("not_ready"); // the admin polls too
    for (let i = 0; i < 3; i++) expect(pe.takeAsyncResult(pc, bot2)).toBe("gone"); // forbidden: each attempt audited
    expect(reads()).toEqual([
      { actor: bot, agent_id: bot, key_id: botKey, error_code: "result_not_ready" },
      { actor: chen, agent_id: bot, key_id: botKey, error_code: "result_not_ready" },
      { actor: bot2, agent_id: bot, key_id: botKey, error_code: "result_forbidden" },
      { actor: bot2, agent_id: bot, key_id: botKey, error_code: "result_forbidden" },
      { actor: bot2, agent_id: bot, key_id: botKey, error_code: "result_forbidden" },
    ]);
    pe.decide(pc, chen, "approved");
    await waitFor(() => (db.prepare(`SELECT result_stored_at FROM mcpflow_call_outcome WHERE pending_call_id = ?`).get(pc) as { result_stored_at: string | null }).result_stored_at != null);
    expect(txt(pe.takeAsyncResult(pc, bot))).toBe("done");
    expect(txt(pe.takeAsyncResult(pc, bot))).toBe("done");
    expect(reads().slice(5)).toEqual([
      { actor: bot, agent_id: bot, key_id: botKey, error_code: null },
      { actor: bot, agent_id: bot, key_id: botKey, error_code: null },
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
    expect(db.prepare(`SELECT actor, agent_id, error_code FROM mcpflow_call_audit WHERE event_type = 'result_purge'`).all())
      .toEqual([{ actor: "system:sweeper", agent_id: bot, error_code: "purged:expired" }]);
  });

  it("the periodic sweep also purges as system:sweeper with reason expired", async () => {
    const pe = new PolicyEnforcer({ db, keys, resultTtlMs: 50 });
    await heldResult(pe, "swept");
    await new Promise((res) => setTimeout(res, 100));
    expect(pe.purgeResults()).toBe(1);
    expect(db.prepare(`SELECT result_purge_reason FROM mcpflow_call_outcome WHERE result_purged_at IS NOT NULL`).all()).toEqual([{ result_purge_reason: "expired" }]);
    expect(db.prepare(`SELECT actor, agent_id, error_code FROM mcpflow_call_audit WHERE event_type = 'result_purge'`).all())
      .toEqual([{ actor: "system:sweeper", agent_id: bot, error_code: "purged:expired" }]);
  });
});

describe("read gate uses the DB clock (same clock as the 0012 expiry trigger)", () => {
  it("enforcer clock behind the DB clock: once SQLite says expired the read is refused; no purge until both clocks agree", async () => {
    let skew = 0;
    const pe = new PolicyEnforcer({ db, keys, resultTtlMs: 50, clock: () => Date.now() + skew });
    const pc = await heldResult(pe, "secret-result");
    await new Promise((res) => setTimeout(res, 100)); // DB clock: expired
    skew = -3_600_000; // the gateway clock is an hour behind: it still thinks the window is open
    const exp = (db.prepare(`SELECT result_expires_at e FROM mcpflow_call_outcome WHERE pending_call_id = ?`).get(pc) as { e: string }).e;
    expect(new Date(Date.now() + skew).toISOString() < exp).toBe(true);
    const r = pe.takeAsyncResult(pc, bot);
    expect(JSON.stringify(r)).not.toContain("secret-result");
    expect(JSON.parse(txt(r))).toMatchObject({ error_code: "result_purged", reason: "purged:expired" });
    expect(reads().at(-1)).toMatchObject({ actor: bot, error_code: "result_purged" });
    // the admin is refused too
    expect(JSON.stringify(pe.takeAsyncResult(pc, chen))).not.toContain("secret-result");
    // purge needs both clocks: neither the read nor the sweep purged it yet
    expect(pe.purgeResults()).toBe(0);
    expect(db.prepare(`SELECT result_ciphertext IS NOT NULL AS kept, result_purged_at FROM mcpflow_call_outcome WHERE pending_call_id = ?`).get(pc))
      .toEqual({ kept: 1, result_purged_at: null });
    expect((db.prepare(`SELECT count(*) n FROM mcpflow_call_audit WHERE event_type = 'result_purge'`).get() as { n: number }).n).toBe(0);
    // once the gateway clock agrees, the sweep purges it (system:sweeper, expired)
    skew = 0;
    expect(pe.purgeResults()).toBe(1);
    expect(db.prepare(`SELECT actor, error_code FROM mcpflow_call_audit WHERE event_type = 'result_purge'`).all())
      .toEqual([{ actor: "system:sweeper", error_code: "purged:expired" }]);
  });

  it("enforcer clock ahead of the DB clock: the DB window decides; no early purge, no audit_unavailable", async () => {
    let skew = 0;
    const pe = new PolicyEnforcer({ db, keys, resultTtlMs: 3_600_000, clock: () => Date.now() + skew });
    const pc = await heldResult(pe, "still-valid");
    skew = 2 * 3_600_000; // the gateway thinks the window closed an hour ago; SQLite does not
    const r = pe.takeAsyncResult(pc, bot);
    expect(txt(r)).toBe("still-valid");
    expect(reads().at(-1)).toMatchObject({ actor: bot, error_code: null });
    expect(pe.purgeResults()).toBe(0);
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
    expect(db.prepare(`SELECT DISTINCT actor, error_code FROM mcpflow_call_audit WHERE event_type = 'result_purge'`).all())
      .toEqual([{ actor: "system:quota", error_code: "purged:quota" }]);
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
