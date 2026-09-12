import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";

const master = Buffer.alloc(32, 9).toString("base64");
const dirs: string[] = [];

function openStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-az-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), master);
}

afterEach(() => {
  while (dirs.length) {
    rmSync(dirs.pop()!, { recursive: true, force: true });
  }
});

describe("authz store", () => {
  it("rejects empty match and CAS-expires pending approvals", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    expect(() =>
      store.createAuthzRule(ws.id, { name: "empty", match: {} }),
    ).toThrow(/match/);

    const rule = store.createAuthzRule(ws.id, {
      name: "echo",
      match: { tools: ["up__echo"] },
      ttlSeconds: 1,
    });
    const key = store.createApiKey(ws.id, "agent");
    const appr = store.createApproval({
      workspaceId: ws.id,
      ruleId: rule.id,
      keyId: key.id,
      tool: "up__echo",
      arguments: { text: "secret-token-value", password: "hide-me" },
      backendSlug: "up",
      requirement: "notify_approve",
      ttlSeconds: 1,
    });
    const listed = store.listApprovals(ws.id, { status: "pending" });
    expect(listed[0]?.id).toBe(appr.id);
    expect(JSON.stringify(listed[0]?.arguments)).not.toContain("hide-me");

    const raw = store.getApproval(ws.id, appr.id, { redact: false });
    expect(raw?.arguments?.password).toBe("hide-me");

    expect(store.expireApproval(ws.id, appr.id)?.status).toBe("expired");
    expect(
      store.decideApproval(ws.id, appr.id, { status: "approved" }),
    ).toBeNull();
    store.close();
  });
});
