import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import {
  keyMayUseProject,
  toolAllowedByProject,
  toolAllowedByScopes,
} from "../src/types.js";

const master = Buffer.alloc(32, 9).toString("base64");
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function open() {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-proj-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), master);
}

describe("projects", () => {
  it("ensures default project with all backends", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "alpha",
      transport: "stdio",
      command: ["true"],
      placement: { mode: "central-sandbox" },
    });
    store.createBackend(ws.id, {
      slug: "beta",
      transport: "stdio",
      command: ["true"],
      placement: { mode: "central-sandbox" },
    });
    const def = store.getDefaultProject(ws.id)!;
    expect(def.slug).toBe("default");
    expect(def.backendSlugs.sort()).toEqual(["alpha", "beta"]);
    store.close();
  });

  it("filters tools by project membership", () => {
    const project = {
      id: "p1",
      workspaceId: "w",
      slug: "web",
      title: "Web",
      description: null,
      backendSlugs: ["github", "fs"],
      toolPrefixAllowlist: null,
      isDefault: false,
      createdAt: "",
      updatedAt: "",
    };
    expect(toolAllowedByProject("github__list", project)).toBe(true);
    expect(toolAllowedByProject("weather__q", project)).toBe(false);
    expect(toolAllowedByProject("mf_status", project)).toBe(true);
    expect(toolAllowedByScopes("mf_use_project", null)).toBe(true);
  });

  it("mints project session token", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    const key = store.createApiKey(ws.id, "k");
    const web = store.createProject(ws.id, {
      slug: "webdevelopment",
      backendSlugs: ["alpha"],
    });
    const sess = store.createProjectSession(ws.id, key.id, web.id, 60_000);
    expect(sess.token.startsWith("mf_sess_")).toBe(true);
    const auth = store.authenticateProjectSession(sess.token);
    expect(auth?.projectSlug).toBe("webdevelopment");
    expect(auth?.keyId).toBe(key.id);
    expect(keyMayUseProject({ projects: ["webdevelopment"] }, "webdevelopment")).toBe(
      true,
    );
    expect(keyMayUseProject({ projects: ["other"] }, "webdevelopment")).toBe(
      false,
    );
    store.close();
  });
});
