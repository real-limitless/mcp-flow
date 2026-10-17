import { afterEach, describe, expect, it } from "vitest";
import {
  SessionProjectMap,
  globalSessionProjects,
} from "../src/mcp/session-project.js";
import {
  forgetMcpSession,
  globalSessionToolSets,
  SessionToolSetMap,
} from "../src/mcp/session-tools.js";

const maps: Array<{ stop(): void }> = [];

afterEach(() => {
  while (maps.length) maps.pop()!.stop();
  for (const id of ["sess-close", "sess-owned", "sess-split"]) {
    globalSessionProjects.clear(id);
    globalSessionToolSets.delete(id);
  }
});

const project = {
  projectId: "p1",
  projectSlug: "alpha",
  keyId: "key-a",
};

describe("session maps", () => {
  it("caps entries and evicts the least recently used", () => {
    const projects = new SessionProjectMap(2);
    maps.push(projects);
    projects.set("a", project);
    projects.set("b", { ...project, projectId: "p2" });
    expect(projects.get("a")?.projectId).toBe("p1");
    projects.set("c", { ...project, projectId: "p3" });
    expect(projects.get("b")).toBeNull();
    expect(projects.get("a")?.projectId).toBe("p1");
    expect(projects.get("c")?.projectId).toBe("p3");
    expect(projects.size).toBeLessThanOrEqual(2);
  });

  it("sweeps expired rows without a read", async () => {
    const projects = new SessionProjectMap(8);
    maps.push(projects);
    projects.set("stale", project, 15);
    await new Promise((resolve) => setTimeout(resolve, 30));
    projects.sweep();
    expect(projects.size).toBe(0);
  });

  it("drops project and tool state when the session closes", () => {
    const tools = new SessionToolSetMap(2);
    maps.push(tools);
    tools.add("s1", "key-a", ["up__echo"]);
    tools.add("s2", "key-a", ["up__other"]);
    tools.add("s3", "key-a", ["up__third"]);
    expect(tools.get("s1", "key-a").size).toBe(0);
    expect(tools.size).toBeLessThanOrEqual(2);

    globalSessionProjects.set("sess-close", project);
    globalSessionToolSets.add("sess-close", "key-a", ["up__echo"]);
    forgetMcpSession("sess-close", "key-a");
    expect(globalSessionProjects.get("sess-close")).toBeNull();
    expect(globalSessionToolSets.get("sess-close", "key-a").size).toBe(0);
    expect(globalSessionToolSets.size).toBe(0);
  });

  it("does not let one key delete another key's session", () => {
    globalSessionProjects.set("sess-owned", project);
    globalSessionToolSets.add("sess-owned", "key-a", ["up__echo"]);

    forgetMcpSession("sess-owned");
    forgetMcpSession("sess-owned", "key-b");
    expect(globalSessionProjects.get("sess-owned")?.keyId).toBe("key-a");
    expect(globalSessionToolSets.get("sess-owned", "key-a")).toEqual(
      new Set(["up__echo"]),
    );

    globalSessionToolSets.add("sess-split", "key-b", ["up__other"]);
    forgetMcpSession("sess-owned", "key-a");
    expect(globalSessionProjects.get("sess-owned")).toBeNull();
    expect(globalSessionToolSets.get("sess-owned", "key-a").size).toBe(0);
    expect(globalSessionToolSets.get("sess-split", "key-b")).toEqual(
      new Set(["up__other"]),
    );

    forgetMcpSession("sess-split", "key-a");
    expect(globalSessionToolSets.get("sess-split", "key-b")).toEqual(
      new Set(["up__other"]),
    );
    forgetMcpSession("sess-split", "key-b");
    expect(globalSessionToolSets.get("sess-split", "key-b").size).toBe(0);
  });
});
