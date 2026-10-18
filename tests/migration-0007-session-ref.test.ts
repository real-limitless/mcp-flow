/** 0007 fix: pending_call rows that reference a session survive the mcpflow_session rebuild. */
import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/db/migrations/index.js";
import { fkClean, integrityOk, openAt, seedAgent, seedKey, seedLegacySession, seedPending, seedWorkspace } from "./helpers/migration-seed.js";

describe("0007_session_id_prefix with session refs", () => {
  it("migrates when a pending_call references a session; refs restored, FK and integrity clean", () => {
    const d = openAt("0006_outcomes_epoch");
    const { ws, chen } = seedWorkspace(d);
    const bot = seedAgent(d, ws, "bot", chen);
    const k = seedKey(d, bot, chen);
    const s1 = seedLegacySession(d, bot, k); // pre-0007 rows are legacy
    const s2 = seedLegacySession(d, bot, k);
    const p1 = seedPending(d, { ws, agent: bot, key: k, approvers: [chen], session: s1 });
    const p2 = seedPending(d, { ws, agent: bot, key: k, approvers: [chen], session: s2 });
    const p3 = seedPending(d, { ws, agent: bot, key: k, approvers: [chen], session: null });
    expect(() => runMigrations(d, "0007_session_id_prefix")).not.toThrow();
    const rows = d.prepare(`SELECT id, session_id FROM mcpflow_pending_call ORDER BY id`).all() as Array<{ id: string; session_id: string | null }>;
    const by = Object.fromEntries(rows.map((r) => [r.id, r.session_id]));
    expect(by[p1]).toBe(s1);
    expect(by[p2]).toBe(s2);
    expect(by[p3]).toBeNull();
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);
    // snapshot trigger is back: session_id is immutable again
    expect(() => d.prepare(`UPDATE mcpflow_pending_call SET session_id = NULL WHERE id = ?`).run(p1)).toThrow(/snapshot is immutable/);
    // FK still enforced against the rebuilt table, and the temp table is gone
    expect(() => seedPending(d, { ws, agent: bot, key: k, approvers: [chen], session: "sess_" + "0".repeat(24) })).toThrow(/FOREIGN KEY/);
    expect(d.prepare(`SELECT name FROM temp.sqlite_master WHERE name = 'mcpflow_tmp_session_ref'`).all()).toEqual([]);
    // later migrations still apply on top
    expect(() => runMigrations(d)).not.toThrow();
    expect(fkClean(d)).toEqual([]);
  });
});
