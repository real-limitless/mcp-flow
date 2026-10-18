/** 0013_call_audit_purge_actor: purge rows get a system actor matching the reason; rebuild keeps rows/ids/sequence; down/up. */
import { describe, expect, it } from "vitest";
import { MIGRATIONS, runMigrations } from "../src/db/migrations/index.js";
import { MIGRATION_0013_DOWN } from "../src/db/migrations/0013_call_audit_purge_actor.js";
import { CALL_AUDIT_NO_DELETE_TRIGGER } from "../src/db/migrations/0002_call_audit.js";
import { fkClean, hex, integrityOk, openAt, rollback, schemaSnapshot, seedAgent, seedKey, seedWorkspace } from "./helpers/migration-seed.js";

const ID = "0013_call_audit_purge_actor";
type D = ReturnType<typeof openAt>;

/** A DB exactly as QA's 1a90e2bc left it: 0012 applied, purge rows written with actor NULL. */
function at0012() {
  const d = openAt("0012_call_outcome_v11");
  const { ws, chen } = seedWorkspace(d);
  const bot = seedAgent(d, ws, "bot", chen);
  const k = seedKey(d, bot, chen);
  const call = `call_${hex()}`;
  const ins = d.prepare(`INSERT INTO mcpflow_call_audit (audit_id, event_type, call_id, workspace_id, agent_id, policy_decision) VALUES (?, 'decision', ?, ?, ?, 'allow')`);
  for (const id of [3, 4]) ins.run(id, call, ws, bot);
  d.prepare(`UPDATE sqlite_sequence SET seq = 500 WHERE name = 'mcpflow_call_audit'`).run();
  d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, key_id, actor) VALUES ('result_read', ?, ?, ?, ?, ?)`).run(call, ws, bot, k, chen);
  const purge = d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, key_id, error_code) VALUES ('result_purge', ?, ?, ?, ?, ?)`);
  purge.run(call, ws, bot, k, "purged:expired");
  purge.run(call, ws, bot, k, "purged:quota");
  return { d, ws, chen, bot, k, call };
}
const seq = (d: D) => (d.prepare(`SELECT seq FROM sqlite_sequence WHERE name = 'mcpflow_call_audit'`).get() as { seq: number }).seq;
const rows = (d: D) => d.prepare(`SELECT audit_id, event_type, actor, error_code FROM mcpflow_call_audit ORDER BY audit_id`).all();
const notes = (d: D) => (d.prepare(`SELECT note FROM mcpflow_migration_note WHERE migration_id = ?`).all(ID) as Array<{ note: string }>).map((r) => JSON.parse(r.note));
const callAuditSchema = (d: D) => schemaSnapshot(d).filter((s) => s.includes("mcpflow_call_audit"));

describe("0013 up/down/up from a 1a90e2bc (0012) database", () => {
  it("backfills purge-row actors from the reason; keeps rows, ids and the sequence; down restores 0012; FK/integrity clean", () => {
    const { d, chen } = at0012();
    expect(MIGRATIONS.map((m) => m.id)).toContain(ID);
    const before = schemaSnapshot(d);
    runMigrations(d, ID);
    const up = [
      { audit_id: 3, event_type: "decision", actor: null, error_code: null },
      { audit_id: 4, event_type: "decision", actor: null, error_code: null },
      { audit_id: 501, event_type: "result_read", actor: chen, error_code: null },
      { audit_id: 502, event_type: "result_purge", actor: "system:sweeper", error_code: "purged:expired" },
      { audit_id: 503, event_type: "result_purge", actor: "system:quota", error_code: "purged:quota" },
    ];
    expect(rows(d)).toEqual(up);
    expect(seq(d)).toBe(503);
    expect(notes(d)).toEqual([{ null_backfilled: 2, agt_actor_overwritten: 0 }]);
    expect((d.prepare(`SELECT sql FROM sqlite_master WHERE name = 'mcpflow_call_audit_no_delete'`).get() as { sql: string }).sql.trim())
      .toBe(CALL_AUDIT_NO_DELETE_TRIGGER.trim().replace(/;$/, ""));
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);

    rollback(d, ID, MIGRATION_0013_DOWN);
    expect(schemaSnapshot(d)).toEqual(before);
    expect(seq(d)).toBe(503);
    expect(rows(d)).toEqual(up.map((r) => (r.event_type === "result_purge" ? { ...r, actor: null } : r)));

    runMigrations(d, ID);
    expect(rows(d)).toEqual(up);
    expect(seq(d)).toBe(503);
    expect(notes(d)).toEqual([{ null_backfilled: 2, agt_actor_overwritten: 0 }, { null_backfilled: 2, agt_actor_overwritten: 0 }]);
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);
  });

  it("a fresh DB and an upgraded DB end with the same call_audit schema; no note when there is nothing to backfill", () => {
    const fresh = openAt();
    const { d } = at0012();
    runMigrations(d);
    expect(callAuditSchema(d)).toEqual(callAuditSchema(fresh));
    expect(callAuditSchema(fresh).length).toBeGreaterThan(5);
    expect(notes(fresh)).toEqual([]);
  });
});

describe("0013 note counts overwritten agt_ actors (Database review of f9388505; dbdocs-test/r5/edge.py)", () => {
  it("a 0012 purge row with an agt_ actor becomes the system actor and is counted as agt_actor_overwritten", () => {
    const { d, ws, chen, bot, k, call } = at0012();
    d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, key_id, actor, error_code) VALUES ('result_purge', ?, ?, ?, ?, ?, 'purged:quota')`).run(call, ws, bot, k, chen);
    d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, key_id, actor, error_code) VALUES ('result_purge', ?, ?, ?, ?, ?, 'purged:expired')`).run(call, ws, bot, k, bot);
    runMigrations(d, ID);
    expect(d.prepare(`SELECT actor, error_code FROM mcpflow_call_audit WHERE event_type = 'result_purge' ORDER BY audit_id`).all()).toEqual([
      { actor: "system:sweeper", error_code: "purged:expired" },
      { actor: "system:quota", error_code: "purged:quota" },
      { actor: "system:quota", error_code: "purged:quota" },
      { actor: "system:sweeper", error_code: "purged:expired" },
    ]);
    expect(notes(d)).toEqual([{ null_backfilled: 2, agt_actor_overwritten: 2 }]);
  });

  it("edge.py shape: only an agt_ purge row (no NULLs) still writes a note", () => {
    const d = openAt("0012_call_outcome_v11");
    const { ws, chen } = seedWorkspace(d);
    d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, actor, error_code) VALUES ('result_purge', 'x', ?, ?, ?, 'purged:quota')`).run(ws, chen, chen);
    runMigrations(d, ID);
    expect(d.prepare(`SELECT actor FROM mcpflow_call_audit`).all()).toEqual([{ actor: "system:quota" }]);
    expect(notes(d)).toEqual([{ null_backfilled: 0, agt_actor_overwritten: 1 }]);
  });

  it("rows that already carry their system actor are neither counted nor noted", () => {
    const fresh = openAt();
    expect(notes(fresh)).toEqual([]);
  });
});

describe("0013 CHECKs", () => {
  it("result_purge needs a system actor matching its purged:<reason>; system actors only on purge rows; still append-only", () => {
    const { d, ws, bot, call } = at0012();
    runMigrations(d);
    const purge = (actor: string | null, code: string) =>
      d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, actor, error_code) VALUES ('result_purge', ?, ?, ?, ?, ?)`).run(call, ws, bot, actor, code);
    expect(() => purge("system:sweeper", "oops")).toThrow(/CHECK/);
    expect(() => purge(null, "purged:expired")).toThrow(/CHECK/); // actor required (IS, not =)
    expect(() => purge(bot, "purged:expired")).toThrow(/CHECK/); // never an agt_ id
    expect(() => purge(`agt_${"0".repeat(24)}`, "purged:quota")).toThrow(/CHECK/); // nor a fake one
    expect(() => purge("system:quota", "purged:expired")).toThrow(/CHECK/); // actor must match the reason
    expect(() => purge("system:sweeper", "purged:quota")).toThrow(/CHECK/);
    expect(() => purge("system:other", "purged:quota")).toThrow(/CHECK/);
    purge("system:sweeper", "purged:expired");
    purge("system:quota", "purged:quota");
    expect(() => d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, actor) VALUES ('result_read', ?, ?, ?, 'system:sweeper')`).run(call, ws, bot)).toThrow(/CHECK/);
    expect(() => d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, lifecycle_action, actor) VALUES ('lifecycle', ?, ?, 'x', 'system:quota')`).run(call, ws)).toThrow(/CHECK/);
    expect(() => d.prepare(`UPDATE mcpflow_call_audit SET error_code = NULL`).run()).toThrow(/append-only/);
    expect(() => d.prepare(`DELETE FROM mcpflow_call_audit`).run()).toThrow(/append-only/);
  });
});
