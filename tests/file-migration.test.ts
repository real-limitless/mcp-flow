import { describe, expect, it } from "vitest";
import { MIGRATION_0026_DOWN } from "../src/db/migrations/0026_file_sink_template.js";
import { runMigrations } from "../src/db/migrations/index.js";
import { openAt, rollback, seedWorkspace } from "./helpers/migration-seed.js";

describe("file sink migration 0026", () => {
  it("stores refs only and down refuses while a row exists", () => {
    const db = openAt();
    const sql = (db.prepare(`SELECT sql FROM sqlite_master WHERE name = 'mcpflow_file_template'`).get() as { sql: string }).sql;
    expect(sql).toContain("STRICT");
    expect(sql).toContain("secret://");
    expect(sql.toLowerCase()).not.toContain("content");
    expect(sql.toLowerCase()).not.toContain("value");
    const { ws } = seedWorkspace(db);
    db.prepare(
      `INSERT INTO mcpflow_file_template (
         workspace_id, backend_slug, compose_id, mount_path, mount_id, ref, version
       ) VALUES (?, 'cmp', 'cmp_test_1', '/run/secrets/api.key', 'mnt_1', 'secret://app/apikey', 1)`,
    ).run(ws);
    expect(() => rollback(db, "0026_file_sink_template", MIGRATION_0026_DOWN)).toThrow();
    expect(db.prepare(`SELECT count(*) AS n FROM mcpflow_file_template`).get()).toEqual({ n: 1 });
    db.prepare(`DELETE FROM mcpflow_file_template`).run();
    rollback(db, "0026_file_sink_template", MIGRATION_0026_DOWN);
    expect(db.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_file_template'`).get()).toBeUndefined();
    expect(runMigrations(db)).toEqual(["0026_file_sink_template"]);
  });
});
