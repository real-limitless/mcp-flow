/** 0015_call_payload: up creates the table; down refuses while ciphertext remains. */
import { describe, expect, it } from "vitest";
import { MIGRATION_0015_DOWN } from "../src/db/migrations/0015_call_payload.js";
import { runMigrations } from "../src/db/migrations/index.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { insertCallPayload, prepareCallPayload } from "../src/audit/call-payload.js";
import { openAt, rollback, seedWorkspace } from "./helpers/migration-seed.js";

const ID = "0015_call_payload";

describe("0015_call_payload", () => {
  it("down drops the table and columns when no payload rows exist, and up restores them", () => {
    const d = openAt();
    rollback(d, ID, MIGRATION_0015_DOWN);
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_call_payload'`).get()).toBeUndefined();
    const dropped = (d.prepare(`PRAGMA table_info(mcpflow_call_audit)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(dropped).not.toContain("request_payload_hash");
    expect(runMigrations(d)).toEqual([ID]);
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_call_payload'`).get()).toBeTruthy();
  });

  it("down refuses while a ciphertext row exists and leaves the row in place", () => {
    const d = openAt();
    const { ws, chen } = seedWorkspace(d);
    const callId = "call_down_guard";
    d.prepare(
      `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, policy_decision, actor) VALUES ('decision', ?, ?, 'allow', ?)`,
    ).run(callId, ws, chen);
    const keys = derivePolicyKeys("migration-0015");
    const prepared = prepareCallPayload(keys, "request", { note: "keep" }, "echo");
    insertCallPayload(d, keys, { callId, phase: "request", workspaceId: ws, red: prepared.red });
    expect(() => rollback(d, ID, MIGRATION_0015_DOWN)).toThrow();
    expect(d.prepare(`SELECT count(*) AS n FROM mcpflow_call_payload`).get()).toEqual({ n: 1 });
    expect(d.prepare(`SELECT id FROM mcpflow_schema_migrations WHERE id = ?`).get(ID)).toBeTruthy();
  });
});
