/** Migration 0023: agent-key tool prefix allowlist, reversible while empty. */
import { describe, expect, it } from "vitest";
import { MIGRATION_0023_DOWN } from "../src/db/migrations/0023_agent_key_tool_allowlist.js";
import { runMigrations } from "../src/db/migrations/index.js";
import { openAt, rollback, seedKey, seedWorkspace } from "./helpers/migration-seed.js";

describe("agent key tool allowlist 0023", () => {
  it("adds a nullable JSON allowlist and an epoch trigger", () => {
    const d = openAt();
    const cols = (d.prepare(`PRAGMA table_info(mcpflow_api_key)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(cols).toContain("tool_prefix_allowlist");
    const { chen } = seedWorkspace(d);
    const key = seedKey(d, chen, chen);
    const row = d.prepare(`SELECT tool_prefix_allowlist AS p FROM mcpflow_api_key WHERE id = ?`).get(key) as { p: string | null };
    expect(row.p).toBeNull();
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_epoch_key_allowlist'`).get()).toBeTruthy();
  });

  it("down drops an empty allowlist and up restores it", () => {
    const d = openAt();
    rollback(d, "0023_agent_key_tool_allowlist", MIGRATION_0023_DOWN);
    const cols = (d.prepare(`PRAGMA table_info(mcpflow_api_key)`).all() as Array<{ name: string }>).map((c) => c.name);
    expect(cols).not.toContain("tool_prefix_allowlist");
    expect(runMigrations(d)).toEqual(["0023_agent_key_tool_allowlist"]);
    expect(d.prepare(`SELECT name FROM sqlite_master WHERE name = 'mcpflow_epoch_key_allowlist'`).get()).toBeTruthy();
  });

  it("down refuses while a key has an allowlist set", () => {
    const d = openAt();
    const { chen } = seedWorkspace(d);
    const key = seedKey(d, chen, chen);
    d.prepare(`UPDATE mcpflow_api_key SET tool_prefix_allowlist = ? WHERE id = ?`).run(JSON.stringify(["demo__"]), key);
    expect(() => rollback(d, "0023_agent_key_tool_allowlist", MIGRATION_0023_DOWN)).toThrow();
    expect(d.prepare(`SELECT id FROM mcpflow_schema_migrations WHERE id = '0023_agent_key_tool_allowlist'`).get()).toBeTruthy();
    d.prepare(`UPDATE mcpflow_api_key SET tool_prefix_allowlist = NULL WHERE id = ?`).run(key);
    expect(() => rollback(d, "0023_agent_key_tool_allowlist", MIGRATION_0023_DOWN)).not.toThrow();
  });
});
