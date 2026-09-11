import { describe, expect, it } from "vitest";
import { searchCatalogTools } from "../src/mcp/dynamic-tools.js";
import { SessionToolSetMap } from "../src/mcp/session-tools.js";
import {
  clampToolSearchLimit,
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
    expect(hits.tools.map((h) => h.name)).toEqual(["up__echo"]);
    expect(hits.total).toBe(1);
    expect(hits.hasMore).toBe(false);
  });

  it("filters by backend slug", () => {
    const hits = searchCatalogTools(catalog, { backend: "gh", limit: 10 });
    expect(hits.tools.map((h) => h.name)).toEqual(["gh__create_pr", "gh__list_issues"]);
  });

  it("caps results when limit is set", () => {
    const hits = searchCatalogTools(catalog, { limit: 1 });
    expect(hits.tools).toHaveLength(1);
    expect(hits.total).toBe(3);
    expect(hits.hasMore).toBe(true);
  });

  it("returns the full catalog when limit is omitted", () => {
    const many = Array.from({ length: 80 }, (_, i) => ({
      name: `up__tool_${String(i).padStart(3, "0")}`,
      description: `Tool ${i}`,
      backend: "up",
    }));
    const hits = searchCatalogTools(many, {});
    expect(hits.tools).toHaveLength(80);
    expect(hits.total).toBe(80);
    expect(hits.hasMore).toBe(false);
  });

  it("pages with offset", () => {
    const many = Array.from({ length: 80 }, (_, i) => ({
      name: `up__tool_${String(i).padStart(3, "0")}`,
      description: `Tool ${i}`,
      backend: "up",
    }));
    const page = searchCatalogTools(many, { limit: 10, offset: 70 });
    expect(page.tools).toHaveLength(10);
    expect(page.tools[0]?.name).toBe("up__tool_070");
    expect(page.total).toBe(80);
    expect(page.hasMore).toBe(false);
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
    expect(clampToolSearchLimit(undefined)).toBe(DYNAMIC_LIST_MAX_LIMIT);
    expect(clampToolSearchLimit(99999)).toBe(DYNAMIC_LIST_MAX_LIMIT);
    expect(clampToolSearchLimit(0)).toBe(DYNAMIC_LIST_MAX_LIMIT);
    expect(clampToolSearchLimit(10)).toBe(10);
  });
});
