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
    expect(listed[0]?.id).toBe(appr.approval.id);
    expect(JSON.stringify(listed[0]?.arguments)).not.toContain("hide-me");
    expect(appr.decideToken?.startsWith("apd_")).toBe(true);
    const listedJson = JSON.stringify(listed);
    expect(listedJson).not.toContain("apd_");
    expect(listedJson).not.toContain("decideToken");
    expect(listedJson).not.toContain("hide-me");

    const looked = store.lookupPushDecision(appr.approval.id, appr.decideToken!);
    expect(looked.ok).toBe(true);
    expect(store.lookupPushDecision(appr.approval.id, "apd_nope").ok).toBe(
      false,
    );

    const raw = store.getApproval(ws.id, appr.approval.id, { redact: false });
    expect(raw?.arguments?.password).toBe("hide-me");

    expect(store.expireApproval(ws.id, appr.approval.id)?.status).toBe("expired");
    expect(
      store.decideApproval(ws.id, appr.approval.id, { status: "approved" }),
    ).toBeNull();
    expect(store.lookupPushDecision(appr.approval.id, appr.decideToken!)).toEqual(
      { ok: false, error: "not_pending" },
    );

    const sub = store.upsertPushSubscription({
      workspaceId: ws.id,
      operatorKeyId: "",
      endpoint: "https://push.example/abc1234567890",
      p256dh: "p256",
      auth: "auth",
    });
    expect(sub.endpointHint).toContain("push.example");
    expect(sub.endpointHint).not.toContain("abc1234567890");
    const listedSubs = store.listPushSubscriptionsPublic(ws.id);
    expect(JSON.stringify(listedSubs)).not.toContain("p256");
    expect(listedSubs[0]).not.toHaveProperty("auth");
    expect(listedSubs[0]).not.toHaveProperty("p256dh");
    expect(listedSubs[0]).not.toHaveProperty("endpoint");
    expect(store.deletePushSubscription(ws.id, sub.id)).toBe(true);
    store.close();
  });

  it("caps push subscriptions at 20 per workspace", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    for (let i = 0; i < 20; i++) {
      store.upsertPushSubscription({
        workspaceId: ws.id,
        operatorKeyId: "",
        endpoint: `https://push.example/sub-${i}`,
        p256dh: "p",
        auth: "a",
      });
    }
    expect(() =>
      store.upsertPushSubscription({
        workspaceId: ws.id,
        operatorKeyId: "",
        endpoint: "https://push.example/overflow",
        p256dh: "p",
        auth: "a",
      }),
    ).toThrow(/20/);
    store.close();
  });
});
