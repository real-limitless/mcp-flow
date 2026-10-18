/** 0010_policy_grant: up/down/up with referenced grants, use limit dropped + noted, 0005 auto-revoke on the new table. */
import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/db/migrations/index.js";
import { MIGRATION_0010_DOWN } from "../src/db/migrations/0010_policy_grant.js";
import {
  approvePending, fkClean, integrityOk, iso, openAt, rollback, schemaSnapshot, seedAgent, seedKey,
  seedLegacyGrant, seedPending, seedRule, seedWorkspace,
} from "./helpers/migration-seed.js";

const ID = "0010_policy_grant";

function at0009() {
  const d = openAt("0009_agent_bootstrap_session_guard");
  const { ws, chen } = seedWorkspace(d);
  const ana = seedAgent(d, ws, "ana", chen, "human");
  const bot = seedAgent(d, ws, "bot", chen);
  const k = seedKey(d, bot, chen);
  const rule = seedRule(d, ws, chen);
  const pc = seedPending(d, { ws, agent: bot, key: k, approvers: [chen, ana] });
  approvePending(d, pc, chen);
  const pc2 = seedPending(d, { ws, agent: bot, key: k, approvers: [chen, ana] });
  approvePending(d, pc2, ana);
  const g1 = seedLegacyGrant(d, { pc, ws, agent: bot, by: chen, rules: [rule], maxUses: 3 });
  const g2 = seedLegacyGrant(d, { pc: pc2, ws, agent: bot, by: ana, rules: [rule] });
  d.prepare(`UPDATE mcpflow_approval_grant SET use_count = 1 WHERE id = ?`).run(g1);
  d.prepare(`UPDATE mcpflow_pending_call SET grant_id = ? WHERE id = ?`).run(g1, pc);
  return { d, ws, chen, ana, bot, rule, pc, g1, g2 };
}
const grants = (d: ReturnType<typeof openAt>) =>
  d.prepare(`SELECT id, granted_by, revoked_at, revoked_reason FROM mcpflow_policy_grant ORDER BY id`).all() as Array<Record<string, unknown>>;

describe("0010 up/down/up", () => {
  it("keeps grants and pending_call.grant_id refs, drops the use limit, notes it; FK/integrity clean", () => {
    const { d, pc, g1, g2 } = at0009();
    const before = schemaSnapshot(d);
    runMigrations(d, ID);
    expect(grants(d).map((g) => g.id).sort()).toEqual([g1, g2].sort());
    expect(d.prepare(`SELECT grant_id FROM mcpflow_pending_call WHERE id = ?`).get(pc)).toEqual({ grant_id: g1 });
    const cols = (d.prepare(`PRAGMA table_info(mcpflow_policy_grant)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(cols).toContain("created_at");
    expect(cols).not.toContain("max_uses");
    expect(cols).not.toContain("use_count");
    expect(cols).not.toContain("granted_at");
    expect(d.prepare(`SELECT note FROM mcpflow_migration_note WHERE migration_id = ?`).all(ID).map((r) => JSON.parse(String((r as { note: string }).note))))
      .toEqual([{ grants_with_use_limit_dropped: 1 }]);
    expect(d.prepare(`SELECT count(*) n FROM mcpflow_live_policy_grant`).get()).toEqual({ n: 2 });
    expect(fkClean(d)).toEqual([]);

    rollback(d, ID, MIGRATION_0010_DOWN);
    expect(schemaSnapshot(d)).toEqual(before);
    expect(d.prepare(`SELECT grant_id FROM mcpflow_pending_call WHERE id = ?`).get(pc)).toEqual({ grant_id: g1 });
    expect(d.prepare(`SELECT count(*) n FROM mcpflow_approval_grant WHERE max_uses IS NULL AND use_count = 0`).get()).toEqual({ n: 2 });
    expect(fkClean(d)).toEqual([]);

    runMigrations(d, ID);
    expect(grants(d)).toHaveLength(2);
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);
  });
});

describe("0010 auto-revoke triggers on mcpflow_policy_grant", () => {
  it("rule change revokes grants that override it", () => {
    const { d, rule } = at0009();
    runMigrations(d);
    d.prepare(`UPDATE mcpflow_policy_rule SET enabled = 0 WHERE id = ?`).run(rule);
    for (const g of grants(d)) expect(g.revoked_reason).toBe(`rule changed: ${rule}`);
    expect(d.prepare(`SELECT count(*) n FROM mcpflow_live_policy_grant`).get()).toEqual({ n: 0 });
  });

  it("granter leaving active revokes only that granter's grants", () => {
    const { d, ana, g1, g2 } = at0009();
    runMigrations(d);
    d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(ana);
    const byId = Object.fromEntries(grants(d).map((g) => [g.id, g]));
    expect(byId[g2]!.revoked_reason).toBe("granter no longer active");
    expect(byId[g1]!.revoked_at).toBeNull();
  });

  it("new grants must be live, from a call the same human approved; snapshot immutable", () => {
    const { d, ws, chen, bot, pc, g1 } = at0009();
    runMigrations(d);
    const ins = (by: string, revoked: string | null) =>
      d.prepare(`INSERT INTO mcpflow_policy_grant (id, source_pending_call_id, workspace_id, agent_id, project_id, backend_slug, tool,
          overrides_rule_ids, granted_by, expires_at, revoked_at, revoked_by) VALUES (?, ?, ?, ?, 'gb_devops', 'gh-repos-shell', 'run_command', '["rule_x"]', ?, ?, ?, ?)`)
        .run(`grt_${"a".repeat(24)}`, pc, ws, bot, by, iso(600_000), revoked, revoked ? by : null);
    expect(() => ins(bot, null)).toThrow(/active human|same human approved/);
    expect(() => ins(chen, iso())).toThrow(/inserted live/);
    expect(() => d.prepare(`UPDATE mcpflow_policy_grant SET tool = 'x' WHERE id = ?`).run(g1)).toThrow(/immutable/);
  });
});

describe("R5-6: the runner pins legacy_alter_table = OFF", () => {
  it("a connection with legacy_alter_table = ON still migrates 0010 with pending_call following the renamed grant table", () => {
    const { d, pc, g1 } = at0009();
    d.exec("PRAGMA legacy_alter_table = ON;");
    expect(Number(Object.values(d.prepare("PRAGMA legacy_alter_table").get() as Record<string, unknown>)[0])).toBe(1);
    runMigrations(d);
    expect(Number(Object.values(d.prepare("PRAGMA legacy_alter_table").get() as Record<string, unknown>)[0])).toBe(0);
    const fks = d.prepare(`SELECT "table", "from" FROM pragma_foreign_key_list('mcpflow_pending_call')`).all() as Array<{ table: string; from: string }>;
    expect(fks).toContainEqual({ table: "mcpflow_policy_grant", from: "grant_id" });
    expect(fks.some((f) => f.table === "mcpflow_approval_grant")).toBe(false);
    expect(d.prepare(`SELECT grant_id FROM mcpflow_pending_call WHERE id = ?`).get(pc)).toEqual({ grant_id: g1 });
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);
  });
});
