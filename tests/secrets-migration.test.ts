/** Secrets B migrations 0016–0019: schema, guards, and down-migration refusal. */
import { describe, expect, it } from "vitest";
import { MIGRATION_0016_DOWN } from "../src/db/migrations/0016_secret.js";
import { MIGRATION_0017_DOWN } from "../src/db/migrations/0017_secret_sink_grant.js";
import { MIGRATION_0018_DOWN } from "../src/db/migrations/0018_secret_value_index.js";
import { MIGRATION_0019_DOWN } from "../src/db/migrations/0019_secret_reveal.js";
import { runMigrations } from "../src/db/migrations/index.js";
import { fkClean, mkid, openAt, rollback, seedAgent, seedKey, seedWorkspace } from "./helpers/migration-seed.js";

const DOWNS = [
  ["0019_secret_reveal", MIGRATION_0019_DOWN],
  ["0018_secret_value_index", MIGRATION_0018_DOWN],
  ["0017_secret_sink_grant", MIGRATION_0017_DOWN],
  ["0016_secret", MIGRATION_0016_DOWN],
] as const;

function tableSql(d: ReturnType<typeof openAt>, name: string): string {
  const row = d.prepare(`SELECT sql FROM sqlite_master WHERE name = ?`).get(name) as { sql: string };
  return row.sql;
}

describe("secrets schema 0016–0019", () => {
  it("creates STRICT tables with id checks and ON DELETE RESTRICT", () => {
    const d = openAt();
    for (const name of ["mcpflow_secret", "mcpflow_secret_version", "mcpflow_secret_sink", "mcpflow_secret_grant", "mcpflow_secret_value_index", "mcpflow_reveal_event"]) {
      const sql = tableSql(d, name);
      expect(sql).toContain("STRICT");
      expect(sql).toContain("ON DELETE RESTRICT");
    }
    expect(tableSql(d, "mcpflow_secret")).toContain("sec_");
    expect(tableSql(d, "mcpflow_secret_sink")).toContain("snk_");
    expect(tableSql(d, "mcpflow_secret_grant")).toContain("sgr_");
    expect(tableSql(d, "mcpflow_reveal_event")).toContain("rev_");
    const cols = (d.prepare(`PRAGMA table_info(mcpflow_api_key)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(cols).toEqual(expect.arrayContaining(["can_reveal_secrets", "can_import_secrets", "reveal_requires_approval"]));
    expect(fkClean(d)).toEqual([]);
  });

  it("down drops empty secrets tables and up restores them", () => {
    const d = openAt();
    for (const [id, sql] of DOWNS) rollback(d, id, sql);
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_secret'`).get()).toBeUndefined();
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_reveal_event'`).get()).toBeUndefined();
    const cols = (d.prepare(`PRAGMA table_info(mcpflow_api_key)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(cols).not.toContain("can_reveal_secrets");
    expect(runMigrations(d)).toEqual(DOWNS.map(([id]) => id).reverse());
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_secret'`).get()).toBeTruthy();
  });

  it("down refuses while a secret version row exists and leaves the ciphertext in place", () => {
    const d = openAt();
    const { ws, chen } = seedWorkspace(d);
    const key = seedKey(d, chen, chen);
    const secret = mkid("sec");
    d.prepare(
      `INSERT INTO mcpflow_secret (
         id, workspace_id, project_id, name, type, generator_json, current_version, created_by_key, created_by_agent
       ) VALUES (?, ?, 'default', 'db', 'token', '{}', 1, ?, ?)`,
    ).run(secret, ws, key, chen);
    d.prepare(
      `INSERT INTO mcpflow_secret_version (
         secret_id, version, state, ciphertext, wrapped_dek, kek_id, value_hmac, created_by_key
       ) VALUES (?, 1, 'active', ?, ?, 'file:kek:v1', ?, ?)`,
    ).run(secret, Buffer.from("ciphertext-bytes"), Buffer.from("wrapped-dek"), "ab".repeat(32), key);
    expect(() => rollback(d, "0016_secret", MIGRATION_0016_DOWN)).toThrow();
    expect(d.prepare(`SELECT count(*) AS n FROM mcpflow_secret_version`).get()).toEqual({ n: 1 });
    expect(d.prepare(`SELECT id FROM mcpflow_schema_migrations WHERE id = '0016_secret'`).get()).toBeTruthy();
  });

  it("refuses a non-human key that clears the reveal approval or sets import", () => {
    const d = openAt();
    const { ws, chen } = seedWorkspace(d);
    const bot = seedAgent(d, ws, "bot", chen);
    const botKey = seedKey(d, bot, chen);
    const humanKey = seedKey(d, chen, chen);
    expect(() => d.prepare(`UPDATE mcpflow_api_key SET can_import_secrets = 1 WHERE id = ?`).run(botKey)).toThrow(/human-only/);
    expect(() => d.prepare(`UPDATE mcpflow_api_key SET reveal_requires_approval = 0 WHERE id = ?`).run(botKey)).toThrow(/human-only/);
    d.prepare(`UPDATE mcpflow_api_key SET can_import_secrets = 1, can_reveal_secrets = 1 WHERE id = ?`).run(humanKey);
    const row = d.prepare(`SELECT can_import_secrets AS i, can_reveal_secrets AS r FROM mcpflow_api_key WHERE id = ?`).get(humanKey);
    expect(row).toEqual({ i: 1, r: 1 });
  });

  it("refuses to delete a secret that still has a version", () => {
    const d = openAt();
    const { ws, chen } = seedWorkspace(d);
    const key = seedKey(d, chen, chen);
    const secret = mkid("sec");
    d.prepare(
      `INSERT INTO mcpflow_secret (
         id, workspace_id, project_id, name, type, generator_json, current_version, created_by_key, created_by_agent
       ) VALUES (?, ?, 'default', 'keep', 'token', '{}', 1, ?, ?)`,
    ).run(secret, ws, key, chen);
    d.prepare(
      `INSERT INTO mcpflow_secret_version (
         secret_id, version, state, ciphertext, wrapped_dek, kek_id, value_hmac, created_by_key
       ) VALUES (?, 1, 'active', ?, ?, 'file:kek:v1', ?, ?)`,
    ).run(secret, Buffer.from("ct"), Buffer.from("wk"), "cd".repeat(32), key);
    expect(() => d.prepare(`DELETE FROM mcpflow_secret WHERE id = ?`).run(secret)).toThrow(/FOREIGN KEY|RESTRICT/i);
  });
});
