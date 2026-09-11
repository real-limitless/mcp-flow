import { describe, expect, it } from "vitest";
import { searchCatalogTools } from "../src/mcp/dynamic-tools.js";
import { SessionToolSetMap } from "../src/mcp/session-tools.js";
import {
  clampToolSearchLimit,
  DYNAMIC_LIST_DEFAULT_LIMIT,
  DYNAMIC_LIST_MAX_LIMIT,
  isDynamicTools,
  toolEnabledInWorkingSet,
} from "../src/types.js";

describe("dynamic tool search", () => {
  const catalog = [
    { name: "gh__create_pr", description: "Open a pull request", backend: "gh" },
    { name: "gh__list_issues", description: "List issues", backend: "gh" },
    { name: "up__echo", description: "Echo text", backend: "up" },
  ];

  it("filters by query with name ranked above description", () => {
    const hits = searchCatalogTools(catalog, { q: "echo", limit: 10 });
    expect(hits.map((h) => h.name)).toEqual(["up__echo"]);
  });

  it("filters by backend slug", () => {
    const hits = searchCatalogTools(catalog, { backend: "gh", limit: 10 });
    expect(hits.map((h) => h.name)).toEqual(["gh__create_pr", "gh__list_issues"]);
  });

  it("caps results", () => {
    const hits = searchCatalogTools(catalog, { limit: 1 });
    expect(hits).toHaveLength(1);
  });
});

describe("working set + hot prefixes", () => {
  it("stores names per session/key", () => {
    const map = new SessionToolSetMap();
    map.add("sess-1", "key-a", ["up__echo"]);
    expect([...map.get("sess-1", "key-a")]).toEqual(["up__echo"]);
    expect(map.get("sess-1", "key-b").size).toBe(0);
    map.remove("sess-1", "key-a", ["up__echo"]);
    expect(map.get("sess-1", "key-a").size).toBe(0);
  });

  it("treats hot prefixes as enabled when dynamic", () => {
    const scopes = { dynamicTools: true, dynamicToolsHot: ["gh__"] };
    expect(isDynamicTools(scopes)).toBe(true);
    expect(toolEnabledInWorkingSet("gh__create_pr", new Set(), scopes)).toBe(true);
    expect(toolEnabledInWorkingSet("up__echo", new Set(), scopes)).toBe(false);
    expect(
      toolEnabledInWorkingSet("up__echo", new Set(["up__echo"]), scopes),
    ).toBe(true);
  });

  it("clamps search limit", () => {
    expect(clampToolSearchLimit(undefined)).toBe(DYNAMIC_LIST_DEFAULT_LIMIT);
    expect(clampToolSearchLimit(999)).toBe(DYNAMIC_LIST_MAX_LIMIT);
    expect(clampToolSearchLimit(0)).toBe(DYNAMIC_LIST_DEFAULT_LIMIT);
  });
});
