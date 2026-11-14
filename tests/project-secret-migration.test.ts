/** Migration 0022: project secret scope, reversible while empty. */
import { describe, expect, it } from "vitest";
import { MIGRATION_0022_DOWN } from "../src/db/migrations/0022_project_secret_scope.js";
import { runMigrations } from "../src/db/migrations/index.js";
import { mkid, openAt, rollback, seedKey, seedWorkspace } from "./helpers/migration-seed.js";

describe("project secret scope 0022", () => {
  it("adds the scope column off by default and the three tables", () => {
    const d = openAt();
    const cols = (d.prepare(`PRAGMA table_info(mcpflow_api_key)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(cols).toContain("secrets_project_write");
    const { chen } = seedWorkspace(d);
    const key = seedKey(d, chen, chen);
    const flag = d.prepare(`SELECT secrets_project_write AS n FROM mcpflow_api_key WHERE id = ?`).get(key) as { n: number };
    expect(flag.n).toBe(0);
    for (const name of ["mcpflow_project_env_target", "mcpflow_secret_upload", "mcpflow_project_secret_approval"]) {
      const sql = (d.prepare(`SELECT sql FROM sqlite_master WHERE name = ?`).get(name) as { sql: string }).sql;
      expect(sql).toContain("STRICT");
    }
    expect((d.prepare(`SELECT sql FROM sqlite_master WHERE name = 'mcpflow_secret_upload'`).get() as { sql: string }).sql).toContain("token_hash");
    expect((d.prepare(`SELECT sql FROM sqlite_master WHERE name = 'mcpflow_secret_upload'`).get() as { sql: string }).sql).not.toContain("ciphertext");
  });

  it("down drops an empty scope and up restores it", () => {
    const d = openAt();
    rollback(d, "0022_project_secret_scope", MIGRATION_0022_DOWN);
    const cols = (d.prepare(`PRAGMA table_info(mcpflow_api_key)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(cols).not.toContain("secrets_project_write");
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_secret_upload'`).get()).toBeUndefined();
    expect(runMigrations(d)).toEqual(["0022_project_secret_scope"]);
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_project_env_target'`).get()).toBeTruthy();
  });

  it("down refuses while a target row or a granted flag exists", () => {
    const d = openAt();
    const { ws, chen } = seedWorkspace(d);
    const key = seedKey(d, chen, chen);
    d.prepare(
      `INSERT INTO mcpflow_project_env_target (id, workspace_id, project_id, backend_slug, compose_id, tier)
       VALUES (?, ?, 'app', 'cmp', 'cmp_test_1', 'DEVELOPMENT')`,
    ).run(mkid("etg"), ws);
    expect(() => rollback(d, "0022_project_secret_scope", MIGRATION_0022_DOWN)).toThrow();
    expect(d.prepare(`SELECT count(*) AS n FROM mcpflow_project_env_target`).get()).toEqual({ n: 1 });
    d.prepare(`DELETE FROM mcpflow_project_env_target`).run();
    d.prepare(`UPDATE mcpflow_api_key SET secrets_project_write = 1 WHERE id = ?`).run(key);
    expect(() => rollback(d, "0022_project_secret_scope", MIGRATION_0022_DOWN)).toThrow();
    expect(d.prepare(`SELECT id FROM mcpflow_schema_migrations WHERE id = '0022_project_secret_scope'`).get()).toBeTruthy();
  });
});
