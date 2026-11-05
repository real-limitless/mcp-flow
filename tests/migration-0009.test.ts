/** 0009_agent_bootstrap_session_guard: up/down/up, guards, legacy mf_sess_ sessions kept but cascaded. */
import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/db/migrations/index.js";
import { MIGRATION_0009_DOWN } from "../src/db/migrations/0009_agent_bootstrap_session_guard.js";
import {
  hex, iso, DAY, fkClean, integrityOk, mkid, openAt, rollback, schemaSnapshot,
  seedAgent, seedKey, seedLegacySession, seedSession, seedWorkspace,
} from "./helpers/migration-seed.js";

const ID = "0009_agent_bootstrap_session_guard";
const live = (d: ReturnType<typeof openAt>, sid: string) =>
  (d.prepare(`SELECT revoked_at FROM mcpflow_session WHERE id = ?`).get(sid) as { revoked_at: string | null }).revoked_at === null;

function at0008() {
  const d = openAt("0008_idempotency_per_agent");
  const { ws, chen } = seedWorkspace(d);
  const bot = seedAgent(d, ws, "bot", chen);
  const k = seedKey(d, bot, chen);
  return { d, ws, chen, bot, k };
}

describe("0009 up/down/up", () => {
  it("applies, rolls back to the exact 0008 schema, re-applies; FK and integrity clean", () => {
    const { d, bot, k } = at0008();
    const legacy = seedLegacySession(d, bot, k);
    const before = schemaSnapshot(d);
    runMigrations(d, ID);
    expect(live(d, legacy)).toBe(true); // legacy session NOT revoked (Database update)
    expect(fkClean(d)).toEqual([]);
    rollback(d, ID, MIGRATION_0009_DOWN);
    expect(schemaSnapshot(d)).toEqual(before);
    runMigrations(d, ID);
    expect(live(d, legacy)).toBe(true);
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);
  });

  it("revokes only sessions whose token_hash looks like a token, and notes the count", () => {
    const { d, bot, k } = at0008();
    const bad = `sess_${hex()}`;
    d.prepare(`INSERT INTO mcpflow_session (id, token_hash, agent_id, key_id, project_id, expires_at) VALUES (?, ?, ?, ?, 'p', ?)`)
      .run(bad, `mf_sess_FAKEnotARealToken${hex(4)}`, bot, k, iso(DAY));
    const ok = seedSession(d, bot, k, "sess_");
    runMigrations(d, ID);
    expect(live(d, bad)).toBe(false);
    expect(live(d, ok)).toBe(true);
    const notes = d.prepare(`SELECT note FROM mcpflow_migration_note WHERE migration_id = ?`).all(ID) as Array<{ note: string }>;
    expect(notes.map((n) => JSON.parse(n.note))).toEqual([{ non_hash_token_rows_revoked: 1 }]);
  });
});

describe("0009 guards", () => {
  it("bootstrap: one created_by NULL human admin per workspace; created_by immutable", () => {
    const { d, ws, chen, bot } = at0008();
    runMigrations(d);
    expect(() => d.prepare(`INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by) VALUES (?, ?, 'x', 'chen', 'grokbot', 0, NULL)`).run(mkid("agt"), ws))
      .toThrow(/only the bootstrap human admin/);
    expect(() => d.prepare(`INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by) VALUES (?, ?, 'h2', 'chen', 'human', 1, NULL)`).run(mkid("agt"), ws))
      .toThrow(/UNIQUE/);
    expect(() => d.prepare(`UPDATE mcpflow_agent SET created_by = ? WHERE id = ?`).run(bot, chen)).toThrow(/immutable/);
    // a second workspace gets its own bootstrap admin
    expect(() => seedWorkspace(d)).not.toThrow();
  });

  it("new session ids must be sess_<24 hex> with a hashed token, for an active agent and live key", () => {
    const { d, chen, bot, k } = at0008();
    runMigrations(d);
    expect(() => seedSession(d, bot, k, "sess_")).not.toThrow();
    expect(() => seedSession(d, bot, k, "mf_sess_")).toThrow(/sess_<24 hex>/);
    expect(() => d.prepare(`INSERT INTO mcpflow_session (id, token_hash, agent_id, key_id, project_id, expires_at) VALUES (?, ?, ?, ?, 'p', ?)`)
      .run(`sess_${hex()}`, "plain-not-a-hash", bot, k, iso(DAY))).toThrow(/token_hash must be a hash/);
    expect(() => d.prepare(`INSERT INTO mcpflow_api_key (id, agent_id, prefix, secret_hash, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?)`)
      .run(mkid("key"), bot, "abcdefghijkl", "mf_FAKEnotAKey", iso(DAY), chen)).toThrow(/secret_hash must be a hash/);
    d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(bot);
    expect(() => seedSession(d, bot, k, "sess_")).toThrow(/active agent and a live key/);
  });
});

describe("legacy mf_sess_ sessions end at once on key revoke, agent revoke, agent suspend", () => {
  const cases: Array<[string, (d: ReturnType<typeof openAt>, o: { chen: string; bot: string; k: string }) => void]> = [
    ["key revoked", (d, o) => d.prepare(`UPDATE mcpflow_api_key SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = 'test' WHERE id = ?`).run(iso(), o.chen, o.k)],
    ["agent revoked", (d, o) => d.prepare(`UPDATE mcpflow_agent SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = 'test' WHERE id = ?`).run(iso(), o.chen, o.bot)],
    ["agent suspended", (d, o) => d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(o.bot)],
  ];
  for (const [name, act] of cases) {
    it(name, () => {
      const { d, chen, bot, k } = at0008();
      const legacy = seedLegacySession(d, bot, k);
      runMigrations(d);
      const modern = seedSession(d, bot, k, "sess_");
      expect(live(d, legacy)).toBe(true);
      const resolvable = () => (d.prepare(`SELECT session_id FROM mcpflow_resolvable_session ORDER BY session_id`).all() as Array<{ session_id: string }>).map((r) => r.session_id);
      expect(resolvable()).toContain(legacy);
      act(d, { chen, bot, k });
      expect(live(d, legacy)).toBe(false);
      expect(live(d, modern)).toBe(false);
      expect(resolvable()).toEqual([]);
    });
  }
});
