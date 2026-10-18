/** 0014_agent_bootstrap_upd_scope (R5-5): a pre-0009 bootstrap violation row can be suspended and revoked; the rule itself is unchanged. */
import { describe, expect, it } from "vitest";
import { runMigrations } from "../src/db/migrations/index.js";
import { MIGRATION_0014_DOWN } from "../src/db/migrations/0014_agent_bootstrap_upd_scope.js";
import { fkClean, integrityOk, mkid, openAt, rollback, schemaSnapshot, seedAgent, seedKey, seedSession, seedWorkspace } from "./helpers/migration-seed.js";

const ID = "0014_agent_bootstrap_upd_scope";

/** A DB with a legacy bad row (created_by NULL, not a human admin) written before 0009 existed. */
function withViolation() {
  const d = openAt("0008_idempotency_per_agent");
  const { ws, chen } = seedWorkspace(d);
  const bot = seedAgent(d, ws, "bot", chen);
  // the bad row lives in a second workspace (0009's unique index allows one created_by NULL row per workspace)
  const ws2 = mkid("ws");
  const bad = mkid("agt");
  d.exec("BEGIN IMMEDIATE;");
  d.prepare(`INSERT INTO mcpflow_workspace (id, owner_principal_id) VALUES (?, ?)`).run(ws2, bad);
  d.prepare(`INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by) VALUES (?, ?, 'legacy-bot', 'ops', 'grokbot', 0, NULL)`).run(bad, ws2);
  d.exec("COMMIT;");
  const badKey = seedKey(d, bad, chen);
  const badSession = seedSession(d, bad, badKey);
  runMigrations(d, "0013_call_audit_purge_actor");
  return { d, ws, chen, bot, bad, badSession };
}
const status = (d: ReturnType<typeof openAt>, id: string) => (d.prepare(`SELECT status FROM mcpflow_agent WHERE id = ?`).get(id) as { status: string }).status;

describe("0014 (R5-5)", () => {
  it("before 0014 the violation row is frozen; after it, suspend (with its session cascade) and revoke work", () => {
    const { d, chen, bad, badSession } = withViolation();
    const note = d.prepare(`SELECT note FROM mcpflow_migration_note WHERE migration_id = '0009_agent_bootstrap_session_guard'`).all() as Array<{ note: string }>;
    expect(note.map((n) => JSON.parse(n.note))).toContainEqual({ bootstrap_violations: 1 });
    expect(() => d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(bad)).toThrow(/created_by is immutable/);
    runMigrations(d);
    d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(bad);
    expect(status(d, bad)).toBe("suspended");
    // the suspend cascade (0001 mcpflow_agent_revoke_sessions) ends its sessions
    expect((d.prepare(`SELECT revoked_at FROM mcpflow_session WHERE id = ?`).get(badSession) as { revoked_at: string | null }).revoked_at).toBeTruthy();
    d.prepare(`UPDATE mcpflow_agent SET status = 'revoked', revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ','now'), revoked_by = ?, revoked_reason = 'R5-5 cleanup' WHERE id = ?`).run(chen, bad);
    expect(status(d, bad)).toBe("revoked");
    expect(fkClean(d)).toEqual([]);
    expect(integrityOk(d)).toBe(true);
  });

  it("the bootstrap rule still holds: created_by immutable, no demotion, no new created_by NULL", () => {
    const { d, chen, bot, bad } = withViolation();
    runMigrations(d);
    expect(() => d.prepare(`UPDATE mcpflow_agent SET created_by = ? WHERE id = ?`).run(bot, chen)).toThrow(/immutable/);
    expect(() => d.prepare(`UPDATE mcpflow_agent SET created_by = NULL WHERE id = ?`).run(bot)).toThrow(/immutable/);
    expect(() => d.prepare(`UPDATE mcpflow_agent SET is_admin = 0 WHERE id = ?`).run(chen)).toThrow(/demoted/);
    expect(() => d.prepare(`UPDATE mcpflow_agent SET kind = 'grokbot' WHERE id = ?`).run(chen)).toThrow(/demoted/);
    expect(() => d.prepare(`UPDATE mcpflow_agent SET kind = 'human' WHERE id = ?`).run(bad)).toThrow(/demoted/); // still not a human admin
    d.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(chen); // status of the bootstrap admin is not frozen either
    expect(status(d, chen)).toBe("suspended");
  });

  it("down/up restores the 0009 trigger text exactly", () => {
    const { d } = withViolation();
    const before = schemaSnapshot(d);
    runMigrations(d);
    expect(schemaSnapshot(d)).not.toEqual(before);
    rollback(d, ID, MIGRATION_0014_DOWN);
    expect(schemaSnapshot(d)).toEqual(before);
    runMigrations(d);
    expect((d.prepare(`SELECT sql FROM sqlite_master WHERE name = 'mcpflow_agent_bootstrap_upd'`).get() as { sql: string }).sql).toMatch(/BEFORE UPDATE OF created_by, kind, is_admin ON mcpflow_agent/);
  });
});
