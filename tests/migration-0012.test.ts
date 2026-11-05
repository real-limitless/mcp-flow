/** 0012_call_outcome_v11: call_audit rebuild keeps rows/ids/sequence; outcome backfill; triggers; down maps result_read/result_purge. */
import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/db/migrations/index.js";
import { MIGRATION_0012_DOWN } from "../src/db/migrations/0012_call_outcome_v11.js";
import { CALL_AUDIT_NO_DELETE_TRIGGER } from "../src/db/migrations/0002_call_audit.js";
import { fkClean, hex, integrityOk, iso, openAt, rollback, schemaSnapshot, seedAgent, seedKey, seedWorkspace } from "./helpers/migration-seed.js";

const ID = "0012_call_outcome_v11";
type D = ReturnType<typeof openAt>;

function at0011() {
  const d = openAt("0011_policy_v10");
  const { ws, chen } = seedWorkspace(d);
  const bot = seedAgent(d, ws, "bot", chen);
  const k = seedKey(d, bot, chen);
  // audit rows with a retention-style gap: sqlite_sequence at 100
  const ins = d.prepare(`INSERT INTO mcpflow_call_audit (audit_id, event_type, call_id, workspace_id, agent_id, policy_decision) VALUES (?, 'decision', ?, ?, ?, 'allow')`);
  for (const id of [7, 8, 9]) ins.run(id, `call_${hex()}`, ws, bot);
  d.prepare(`UPDATE sqlite_sequence SET seq = 100 WHERE name = 'mcpflow_call_audit'`).run();
  const outcome = (o: { stored?: boolean; readAt?: string | null; completedAt: string }) => {
    const id = `call_${hex()}`;
    d.prepare(`INSERT INTO mcpflow_call_outcome (call_id, workspace_id, agent_id, key_id, args_hash, state, final_outcome, result_status, created_at, completed_at,
                 result_ciphertext, result_bytes, result_read_at) VALUES (?, ?, ?, ?, ?, 'executed', 'executed', 'ok', ?, ?, ?, ?, ?)`)
      .run(id, ws, bot, k, hex(32), o.completedAt, o.completedAt, o.stored ? Buffer.from("ct") : null, o.stored ? 2 : null, o.readAt ?? null);
    return id;
  };
  const stored = outcome({ stored: true, completedAt: iso(-3_600_000) });
  const consumed = outcome({ readAt: iso(-60_000), completedAt: iso(-7_200_000) });
  return { d, ws, chen, bot, k, stored, consumed };
}
const seq = (d: D) => (d.prepare(`SELECT seq FROM sqlite_sequence WHERE name = 'mcpflow_call_audit'`).get() as { seq: number }).seq;
const auditIds = (d: D) => (d.prepare(`SELECT audit_id FROM mcpflow_call_audit ORDER BY audit_id`).all() as Array<{ audit_id: number }>).map((r) => r.audit_id);
const oc = (d: D, id: string) => d.prepare(`SELECT * FROM mcpflow_call_outcome WHERE call_id = ?`).get(id) as Record<string, unknown>;

describe("0012 up/down/up", () => {
  it("keeps audit rows, ids and the sequence; backfills results; down maps new event types to lifecycle; FK/integrity clean", () => {
    const { d, ws, chen, bot, k, stored, consumed } = at0011();
    const before = schemaSnapshot(d);
    runMigrations(d, ID);
    expect(auditIds(d)).toEqual([7, 8, 9]);
    expect(seq(d)).toBe(100);
    const s = oc(d, stored);
    expect(s.result_stored_at).toBe(s.completed_at);
    expect(Date.parse(String(s.result_expires_at)) - Date.parse(String(s.result_stored_at))).toBe(24 * 3_600_000);
    expect(oc(d, consumed)).toMatchObject({ result_purge_reason: "legacy_read_once", result_ciphertext: null });
    expect(oc(d, consumed).result_purged_at).toBeTruthy();
    // the no-delete trigger is byte-identical to the constant retention code would recreate
    expect((d.prepare(`SELECT sql FROM sqlite_master WHERE name = 'mcpflow_call_audit_no_delete'`).get() as { sql: string }).sql.trim())
      .toBe(CALL_AUDIT_NO_DELETE_TRIGGER.trim().replace(/;$/, ""));
    d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, key_id, actor) VALUES ('result_read', ?, ?, ?, ?, ?)`).run(stored, ws, bot, k, chen);
    d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, key_id, error_code) VALUES ('result_purge', ?, ?, ?, ?, 'purged:quota')`).run(stored, ws, bot, k);
    expect(auditIds(d)).toEqual([7, 8, 9, 101, 102]);
    expect(fkClean(d)).toEqual([]);

    rollback(d, ID, MIGRATION_0012_DOWN);
    expect(schemaSnapshot(d)).toEqual(before);
    expect(seq(d)).toBe(102);
    expect(d.prepare(`SELECT audit_id, event_type, lifecycle_action, actor FROM mcpflow_call_audit WHERE audit_id > 100 ORDER BY audit_id`).all()).toEqual([
      { audit_id: 101, event_type: "lifecycle", lifecycle_action: "result_read", actor: chen },
      { audit_id: 102, event_type: "lifecycle", lifecycle_action: "result_purge", actor: bot },
    ]);
    const notes = (d.prepare(`SELECT note FROM mcpflow_migration_note WHERE migration_id = ?`).all(`${ID}:down`) as Array<{ note: string }>).map((r) => JSON.parse(r.note));
    expect(notes).toEqual([{ result_read_rows_mapped_to_lifecycle: 1 }, { result_purge_rows_mapped_to_lifecycle: 1 }]);

    runMigrations(d, ID);
    expect(auditIds(d)).toEqual([7, 8, 9, 101, 102]);
    expect(seq(d)).toBe(102);
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);
  });
});

describe("0012 triggers", () => {
  const fresh = () => {
    const x = at0011();
    runMigrations(x.d, ID);
    const id = `call_${hex()}`;
    x.d.prepare(`INSERT INTO mcpflow_call_outcome (call_id, workspace_id, agent_id, key_id, args_hash, state, final_outcome, result_status, completed_at)
                 VALUES (?, ?, ?, ?, ?, 'executed', 'executed', 'ok', ?)`).run(id, x.ws, x.bot, x.k, hex(32), iso());
    return { ...x, id };
  };
  const store = (d: D, id: string, hours = 24) =>
    d.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = ?, result_bytes = 2, result_stored_at = ?, result_expires_at = ? WHERE call_id = ?`)
      .run(Buffer.from("ct"), iso(), iso(hours * 3_600_000), id);

  it("store is write-once with a <= 24 h window; no read-once; expired purge only after expiry; quota purge any time; terminal", () => {
    const { d, id } = fresh();
    expect(() => store(d, id, 25)).toThrow(/write-once/);
    store(d, id);
    expect(() => d.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = ? WHERE call_id = ?`).run(Buffer.from("other"), id)).toThrow(/write-once/);
    expect(() => d.prepare(`UPDATE mcpflow_call_outcome SET result_read_at = ? WHERE call_id = ?`).run(iso(), id)).toThrow(/read-once removed/);
    expect(() => d.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = NULL WHERE call_id = ?`).run(id)).toThrow(/purge needs/);
    expect(() => d.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = NULL, result_purged_at = ?, result_purge_reason = 'expired' WHERE call_id = ?`).run(iso(), id)).toThrow(/expired only after/);
    d.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = NULL, result_purged_at = ?, result_purge_reason = 'quota' WHERE call_id = ?`).run(iso(), id);
    expect(() => d.prepare(`UPDATE mcpflow_call_outcome SET result_purge_reason = 'expired' WHERE call_id = ?`).run(id)).toThrow(/terminal/);
    expect(() => store(d, id)).toThrow(/write-once/);
    expect(() => d.prepare(`DELETE FROM mcpflow_call_outcome WHERE call_id = ?`).run(id)).toThrow(/never deleted/);
  });

  it("call_audit result_read needs actor + agent; result_purge needs a purged:<reason> code; still append-only", () => {
    const { d, ws, bot, id } = fresh();
    expect(() => d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id) VALUES ('result_read', ?, ?, ?)`).run(id, ws, bot)).toThrow(/CHECK/);
    expect(() => d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, actor, policy_decision) VALUES ('result_read', ?, ?, ?, ?, 'allow')`).run(id, ws, bot, bot)).toThrow(/CHECK/);
    expect(() => d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, error_code) VALUES ('result_purge', ?, ?, ?, 'oops')`).run(id, ws, bot)).toThrow(/CHECK/);
    d.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, error_code) VALUES ('result_purge', ?, ?, ?, 'purged:expired')`).run(id, ws, bot);
    expect(() => d.prepare(`UPDATE mcpflow_call_audit SET error_code = NULL`).run()).toThrow(/append-only/);
    expect(() => d.prepare(`DELETE FROM mcpflow_call_audit`).run()).toThrow(/append-only/);
  });
});
