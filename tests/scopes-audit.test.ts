import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import { toolAllowedByScopes } from "../src/types.js";

const master = Buffer.alloc(32, 5).toString("base64");
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function open() {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-sc-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), master);
}

describe("scopes", () => {
  it("toolAllowedByScopes prefix + mf_status always", () => {
    const scopes = { toolPrefixAllowlist: ["yh-finance__", "mf_"] };
    expect(toolAllowedByScopes("yh-finance__quote", scopes)).toBe(true);
    expect(toolAllowedByScopes("other__x", scopes)).toBe(false);
    expect(toolAllowedByScopes("mf_status", scopes)).toBe(true);
    expect(toolAllowedByScopes("mf_list_tools", { toolPrefixAllowlist: ["x__"] })).toBe(
      false,
    );
    expect(toolAllowedByScopes("anything", null)).toBe(true);
  });

  it("stores scopes on keys", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    const created = store.createApiKey(ws.id, "limited", {
      toolPrefixAllowlist: ["a__"],
    });
    expect(created.scopes?.toolPrefixAllowlist).toEqual(["a__"]);
    expect(JSON.stringify(store.listApiKeys(ws.id))).not.toContain(created.token);
    const auth = store.authenticateApiKey(created.token);
    expect(auth?.scopes?.toolPrefixAllowlist).toEqual(["a__"]);
    store.close();
  });
});

describe("audit", () => {
  it("writes and lists events without secrets", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    store.writeAudit({
      workspaceId: ws.id,
      keyId: "key_x",
      action: "tools/call",
      tool: "demo__echo",
      backendSlug: "demo",
      placement: "remote",
      detail: { authorization: "Bearer leak", ok: true },
    });
    const events = store.listAudit(ws.id, { limit: 10 });
    expect(events).toHaveLength(1);
    expect(events[0]!.tool).toBe("demo__echo");
    expect(JSON.stringify(events)).not.toContain("Bearer leak");
    expect(events[0]!.detail?.authorization).toBe("[redacted]");
    store.close();
  });

  it("records deviceId and workspace policy", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    expect(ws.policy.allowEdgeBare).toBe(false);
    const updated = store.updateWorkspacePolicy(ws.id, { allowEdgeBare: true });
    expect(updated?.policy.allowEdgeBare).toBe(true);
    store.writeAudit({
      workspaceId: ws.id,
      action: "bare_exec",
      deviceId: "dev_1",
      placement: "edge-bare",
    });
    const events = store.listAudit(ws.id);
    expect(events[0]!.deviceId).toBe("dev_1");
    const dev = store.enrollDevice(ws.id, { name: "x" });
    expect(dev.token.startsWith("mf_")).toBe(true);
    expect(store.listDevices(ws.id)).toHaveLength(1);
    store.close();
  });
});
