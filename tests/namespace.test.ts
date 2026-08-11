import { describe, expect, it } from "vitest";
import {
  namespaceTool,
  parseNamespacedTool,
} from "../src/mcp/upstream.js";

describe("namespace", () => {
  it("round-trips slug__tool", () => {
    expect(namespaceTool("gh", "list_issues")).toBe("gh__list_issues");
    expect(parseNamespacedTool("gh__list_issues")).toEqual({
      slug: "gh",
      tool: "list_issues",
    });
    expect(parseNamespacedTool("gh__a__b")).toEqual({
      slug: "gh",
      tool: "a__b",
    });
    expect(parseNamespacedTool("nounderscore")).toBeNull();
  });
});
