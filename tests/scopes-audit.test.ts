import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import { mergeApiKeyScopes } from "../src/mcp/admin-tools.js";
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
      true,
    );
    expect(toolAllowedByScopes("mf_enable_tools", { toolPrefixAllowlist: ["x__"] })).toBe(
      true,
    );
    expect(toolAllowedByScopes("mf_call_tool", { toolPrefixAllowlist: ["x__"] })).toBe(
      true,
    );
    expect(toolAllowedByScopes("anything", null)).toBe(true);
    expect(toolAllowedByScopes("mf_admin_list_backends", null)).toBe(false);
    expect(
      toolAllowedByScopes("mf_admin_list_backends", { admin: true }),
    ).toBe(true);
    expect(
      toolAllowedByScopes("mf_admin_status", {
        toolPrefixAllowlist: ["x__"],
      }),
    ).toBe(false);
  });

  it("stores admin scope on keys", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    const created = store.createApiKey(ws.id, "ops", { admin: true });
    expect(created.scopes?.admin).toBe(true);
    const auth = store.authenticateApiKey(created.token);
    expect(auth?.scopes?.admin).toBe(true);
    store.close();
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

  it("round-trips dynamicTools-only scopes", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    const created = store.createApiKey(ws.id, "dyn", { dynamicTools: true });
    expect(created.scopes?.dynamicTools).toBe(true);
    const listed = store.listApiKeys(ws.id).find((k) => k.id === created.id);
    expect(listed?.scopes).toEqual({ dynamicTools: true });
    const auth = store.authenticateApiKey(created.token);
    expect(auth?.scopes).toEqual({ dynamicTools: true });
    const hot = store.createApiKey(ws.id, "hot", {
      dynamicTools: true,
      dynamicToolsHot: ["github__"],
    });
    expect(store.listApiKeys(ws.id).find((k) => k.id === hot.id)?.scopes).toEqual({
      dynamicTools: true,
      dynamicToolsHot: ["github__"],
    });
    store.close();
  });
});

describe("mergeApiKeyScopes", () => {
  it("enables and disables dynamicTools without dropping other scopes", () => {
    const prev = {
      admin: true,
      toolPrefixAllowlist: ["demo__"],
      projects: ["web"],
    };
    const on = mergeApiKeyScopes(prev, { dynamicTools: true });
    expect(on).toEqual({
      admin: true,
      toolPrefixAllowlist: ["demo__"],
      projects: ["web"],
      dynamicTools: true,
    });
    const off = mergeApiKeyScopes(on, { dynamicTools: false });
    expect(off).toEqual({
      admin: true,
      toolPrefixAllowlist: ["demo__"],
      projects: ["web"],
    });
    const cleared = mergeApiKeyScopes({ dynamicTools: true }, { dynamicTools: false });
    expect(cleared).toBeNull();
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
    expect(events[0]!.keyId).toBe("key_x");
    expect(events[0]!.keyName).toBeNull();
    expect(events[0]!.keyPrefix).toBeNull();
    store.close();
  });

  it("joins actor key name and prefix onto listed events", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    const created = store.createApiKey(ws.id, "cursor-agent", {
      dynamicTools: true,
    });
    store.writeAudit({
      workspaceId: ws.id,
      keyId: created.id,
      action: "tools/call",
      tool: "mf_list_tools",
    });
    store.writeAudit({
      workspaceId: ws.id,
      action: "workspace.policy",
    });
    const events = store.listAudit(ws.id);
    const call = events.find((e) => e.action === "tools/call");
    expect(call?.keyId).toBe(created.id);
    expect(call?.keyName).toBe("cursor-agent");
    expect(call?.keyPrefix).toBe(created.prefix);
    const policy = events.find((e) => e.action === "workspace.policy");
    expect(policy?.keyId).toBeNull();
    expect(policy?.keyName).toBeNull();
    expect(policy?.keyPrefix).toBeNull();
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
