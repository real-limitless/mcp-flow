/** 0011_policy_v10: up/down/up; agent matchers; cancel_reason; no_active_approver at hold time and on approver loss. */
import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/db/migrations/index.js";
import { MIGRATION_0011_DOWN } from "../src/db/migrations/0011_policy_v10.js";
import {
  fkClean, integrityOk, iso, mkid, openAt, rollback, schemaSnapshot, seedAgent, seedKey, seedPending, seedRule, seedWorkspace,
} from "./helpers/migration-seed.js";

const ID = "0011_policy_v10";
type D = ReturnType<typeof openAt>;

function at0010() {
  const d = openAt("0010_policy_grant");
  const { ws, chen } = seedWorkspace(d);
  const ana = seedAgent(d, ws, "ana", chen, "human");
  const bot = seedAgent(d, ws, "bot", chen);
  const k = seedKey(d, bot, chen);
  return { d, ws, chen, ana, bot, k };
}
function addVersion(d: D, rule: string, by: string, matchAgents: unknown, version = 2) {
  d.exec("BEGIN;");
  try {
    d.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, effect, created_by, match_agents) VALUES (?, ?, 't', 'allow', ?, ?)`)
      .run(rule, version, by, JSON.stringify(matchAgents));
    d.prepare(`UPDATE mcpflow_policy_rule SET current_version = ? WHERE id = ?`).run(version, rule);
    d.exec("COMMIT;");
  } catch (e) {
    d.exec("ROLLBACK;");
    throw e;
  }
}
const pcRow = (d: D, id: string) =>
  d.prepare(`SELECT status, note, cancel_reason FROM mcpflow_pending_call WHERE id = ?`).get(id) as Record<string, unknown>;

describe("0011 up/down/up", () => {
  it("adds min_approvals/cancel_reason, notes name matchers, rolls back to the 0010 schema; FK/integrity clean", () => {
    const { d, ws, chen, bot, k } = at0010();
    const rule = seedRule(d, ws, chen);
    addVersion(d, rule, chen, ["bot"]); // legacy name matcher, allowed before 0011
    const pc = seedPending(d, { ws, agent: bot, key: k, approvers: [chen] });
    const before = schemaSnapshot(d);
    runMigrations(d, ID);
    expect(d.prepare(`SELECT min_approvals FROM mcpflow_policy_rule_version WHERE rule_id = ? AND version = 2`).get(rule)).toEqual({ min_approvals: 1 });
    expect(pcRow(d, pc)).toMatchObject({ status: "pending", cancel_reason: null });
    expect((d.prepare(`SELECT note FROM mcpflow_migration_note WHERE migration_id = ?`).all(ID) as Array<{ note: string }>).map((r) => JSON.parse(r.note)))
      .toEqual([{ versions_with_non_id_agent_matchers: 1 }]);
    expect(fkClean(d)).toEqual([]);
    rollback(d, ID, MIGRATION_0011_DOWN);
    expect(schemaSnapshot(d)).toEqual(before);
    runMigrations(d, ID);
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);
  });
});

describe("0011 behaviour", () => {
  it("match_agents: ['*'] or agt_ ids of this workspace only", () => {
    const { d, ws, chen, bot } = at0010();
    runMigrations(d);
    const rule = seedRule(d, ws, chen);
    expect(() => addVersion(d, rule, chen, ["bot"])).toThrow(/match_agents (must be|references an unknown)/);
    expect(() => addVersion(d, rule, chen, ["*", bot])).toThrow(/match_agents (must be|references an unknown)/);
    expect(() => addVersion(d, rule, chen, [])).toThrow(/match_agents (must be|references an unknown)/);
    expect(() => addVersion(d, rule, chen, [mkid("agt")])).toThrow(/unknown agent/);
    const other = seedWorkspace(d);
    expect(() => addVersion(d, rule, chen, [other.chen])).toThrow(/unknown agent/);
    expect(() => addVersion(d, rule, chen, [bot])).not.toThrow();
    expect(() => addVersion(d, rule, chen, ["*"], 3)).not.toThrow();
  });

  it("min_approvals defaults to 1 and must be >= 1", () => {
    const { d, ws, chen } = at0010();
    runMigrations(d);
    const rule = seedRule(d, ws, chen);
    expect(d.prepare(`SELECT min_approvals FROM mcpflow_policy_rule_version WHERE rule_id = ?`).get(rule)).toEqual({ min_approvals: 1 });
    expect(() => d.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, effect, created_by, min_approvals) VALUES (?, 2, 't', 'allow', ?, 0)`)
      .run(rule, chen)).toThrow(/CHECK/);
  });

  it("a hold needs an active human approver", () => {
    const { d, ws, chen, ana, bot, k } = at0010();
    runMigrations(d);
    d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(ana);
    expect(() => seedPending(d, { ws, agent: bot, key: k, approvers: [ana] })).toThrow(/no_active_approver/);
    expect(() => seedPending(d, { ws, agent: bot, key: k, approvers: [ana, chen] })).not.toThrow();
  });

  it("losing the last active approver cancels with no_active_approver; one left keeps the hold", () => {
    const { d, ws, chen, ana, bot, k } = at0010();
    runMigrations(d);
    const solo = seedPending(d, { ws, agent: bot, key: k, approvers: [ana] });
    const both = seedPending(d, { ws, agent: bot, key: k, approvers: [ana, chen] });
    d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(ana);
    expect(pcRow(d, solo)).toEqual({ status: "cancelled", note: "no_active_approver", cancel_reason: "no_active_approver" });
    expect(pcRow(d, both)).toMatchObject({ status: "pending", cancel_reason: null });
  });

  it("cascade cancels carry agent_suspended / agent_revoked / key_revoked", () => {
    const { d, ws, chen, bot, k } = at0010();
    runMigrations(d);
    const p1 = seedPending(d, { ws, agent: bot, key: k, approvers: [chen] });
    d.prepare(`UPDATE mcpflow_api_key SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = 't' WHERE id = ?`).run(iso(), chen, k);
    expect(pcRow(d, p1)).toMatchObject({ status: "cancelled", cancel_reason: "key_revoked" });

    const bot2 = seedAgent(d, ws, "bot2", chen);
    const k2 = seedKey(d, bot2, chen);
    const p2 = seedPending(d, { ws, agent: bot2, key: k2, approvers: [chen] });
    d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(bot2);
    expect(pcRow(d, p2)).toMatchObject({ status: "cancelled", cancel_reason: "agent_suspended" });

    const bot3 = seedAgent(d, ws, "bot3", chen);
    const k3 = seedKey(d, bot3, chen);
    const p3 = seedPending(d, { ws, agent: bot3, key: k3, approvers: [chen] });
    d.prepare(`UPDATE mcpflow_agent SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = 't' WHERE id = ?`).run(iso(), chen, bot3);
    expect(pcRow(d, p3)).toMatchObject({ status: "cancelled", cancel_reason: "agent_revoked" });
  });

  it("cancel_reason is set once, only together with status cancelled, from the allowed list", () => {
    const { d, ws, chen, bot, k } = at0010();
    runMigrations(d);
    const pc = seedPending(d, { ws, agent: bot, key: k, approvers: [chen] });
    expect(() => d.prepare(`UPDATE mcpflow_pending_call SET cancel_reason = 'shutdown' WHERE id = ?`).run(pc)).toThrow(/set once, only on cancel/);
    expect(() => d.prepare(`UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = ?, cancel_reason = 'bogus' WHERE id = ?`).run(iso(), pc)).toThrow(/CHECK/);
    d.prepare(`UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = ?, cancel_reason = 'client_disconnected' WHERE id = ?`).run(iso(), pc);
    expect(() => d.prepare(`UPDATE mcpflow_pending_call SET cancel_reason = 'shutdown' WHERE id = ?`).run(pc)).toThrow(/set once/);
  });
});
