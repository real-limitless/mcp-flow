import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import webpush from "web-push";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";
import { Store } from "../src/db/store.js";
import { notifyApprovalPush } from "../src/authz/push.js";

const master = Buffer.alloc(32, 7).toString("base64");
const admin = "test-admin-token-please-change";
const dirs: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
const hdr = {
  Authorization: `Bearer ${admin}`,
  "Content-Type": "application/json",
};

afterEach(async () => {
  vi.restoreAllMocks();
  while (cleanups.length) {
    await cleanups.pop()!();
  }
  while (dirs.length) {
    rmSync(dirs.pop()!, { recursive: true, force: true });
  }
});

function openStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-azp-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), master);
}

async function bootGateway(): Promise<RunningServer> {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-azp-g-"));
  dirs.push(dir);
  const cfg = loadConfig({
    dbPath: join(dir, "t.db"),
    masterKeyRaw: master,
    adminToken: admin,
    host: "127.0.0.1",
    port: 0 as unknown as number,
    allowPrivateUrls: true,
    workspaceName: "default",
  });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  const p = (probe.address() as { port: number }).port;
  await new Promise<void>((r, j) => probe.close((e) => (e ? j(e) : r())));
  cfg.port = p;
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

describe("admin PWA + web push", () => {
  it("serves PWA shell and never caches the service worker", async () => {
    const gw = await bootGateway();
    const html = await (await fetch(`${gw.url}/admin/`)).text();
    expect(html).toContain('rel="manifest"');
    expect(html).toContain("apple-mobile-web-app-capable");

    const man = await fetch(`${gw.url}/admin/manifest.webmanifest`);
    expect(man.status).toBe(200);
    expect(await man.text()).toContain('"display": "standalone"');

    const sw = await fetch(`${gw.url}/admin/sw.js`);
    expect(sw.headers.get("cache-control")).toMatch(/no-cache/i);
    expect(sw.headers.get("service-worker-allowed")).toBe("/admin/");
    const swBody = await sw.text();
    expect(swBody).toContain("/v1/approvals/");
    expect(swBody).toContain("push-decision");
  });

  it("exposes VAPID public key only and redacts subscription list", async () => {
    const gw = await bootGateway();
    const denied = await fetch(`${gw.url}/v1/push/vapid`);
    expect(denied.status).toBe(401);

    const vapidRes = await fetch(`${gw.url}/v1/push/vapid`, { headers: hdr });
    expect(vapidRes.status).toBe(200);
    const vapid = (await vapidRes.json()) as Record<string, unknown>;
    expect(typeof vapid.publicKey).toBe("string");
    expect(String(vapid.publicKey).length).toBeGreaterThan(20);
    expect(vapid).not.toHaveProperty("privateKey");
    expect(Object.keys(vapid).sort()).toEqual(["publicKey", "subject"]);

    const created = await fetch(`${gw.url}/v1/push/subscriptions`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({
        endpoint: "https://fcm.googleapis.com/fcm/send/abc-secret-endpoint",
        keys: { p256dh: "p256-secret", auth: "auth-secret" },
      }),
    });
    expect(created.status).toBe(201);
    const createdBody = await created.json();
    expect(JSON.stringify(createdBody)).not.toContain("p256-secret");
    expect(JSON.stringify(createdBody)).not.toContain("auth-secret");
    expect(createdBody.subscription.endpointHint).toContain("fcm.googleapis.com");

    const listed = await fetch(`${gw.url}/v1/push/subscriptions`, {
      headers: hdr,
    });
    const listedBody = (await listed.json()) as {
      subscriptions: Array<{ id: string; endpointHint: string }>;
    };
    expect(listedBody.subscriptions).toHaveLength(1);
    expect(JSON.stringify(listedBody)).not.toContain("p256-secret");
    expect(JSON.stringify(listedBody)).not.toContain("abc-secret-endpoint");

    const del = await fetch(
      `${gw.url}/v1/push/subscriptions/${listedBody.subscriptions[0]!.id}`,
      { method: "DELETE", headers: hdr },
    );
    expect(del.status).toBe(200);
  });

  it("puts decide tokens only on notify_approve push payloads", async () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const rule = store.createAuthzRule(ws.id, {
      name: "echo",
      match: { tools: ["up__echo"] },
    });
    const key = store.createApiKey(ws.id, "agent");
    store.upsertPushSubscription({
      workspaceId: ws.id,
      operatorKeyId: "",
      endpoint: "https://push.example/sub",
      p256dh: "p",
      auth: "a",
    });

    const notify = store.createApproval({
      workspaceId: ws.id,
      ruleId: rule.id,
      keyId: key.id,
      tool: "up__echo",
      arguments: { password: "hide-me" },
      backendSlug: "up",
      requirement: "notify_approve",
      ttlSeconds: 30,
    });
    const sendSpy = vi
      .spyOn(webpush, "sendNotification")
      .mockResolvedValue(undefined as never);
    await notifyApprovalPush({
      store,
      approval: notify.approval,
      decideToken: notify.decideToken,
      ttlSeconds: 30,
      approveBaseUrl: "https://gw.example",
    });
    const payload = JSON.parse(
      String(sendSpy.mock.calls[0]?.[1]),
    ) as Record<string, unknown>;
    expect(payload.token).toBe(notify.decideToken);
    expect(payload.approvalId).toBe(notify.approval.id);
    expect(payload.url).toContain(`/admin/#approvals/${notify.approval.id}`);
    expect(JSON.stringify(payload)).not.toContain("hide-me");

    const mfa = store.createApproval({
      workspaceId: ws.id,
      ruleId: rule.id,
      keyId: key.id,
      tool: "up__echo",
      arguments: { password: "hide-me" },
      backendSlug: "up",
      requirement: "mfa_and_approve",
      ttlSeconds: 30,
    });
    await notifyApprovalPush({
      store,
      approval: mfa.approval,
      decideToken: mfa.decideToken,
      ttlSeconds: 30,
    });
    const mfaPayload = JSON.parse(
      String(sendSpy.mock.calls[1]?.[1]),
    ) as Record<string, unknown>;
    expect(mfaPayload.token).toBeUndefined();
    expect(mfaPayload.requirement).toBe("mfa_and_approve");
    store.close();
  });

  it("drops gone push subscriptions", async () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const rule = store.createAuthzRule(ws.id, {
      name: "echo",
      match: { tools: ["up__echo"] },
    });
    const key = store.createApiKey(ws.id, "agent");
    store.upsertPushSubscription({
      workspaceId: ws.id,
      operatorKeyId: "",
      endpoint: "https://push.example/gone",
      p256dh: "p",
      auth: "a",
    });
    const created = store.createApproval({
      workspaceId: ws.id,
      ruleId: rule.id,
      keyId: key.id,
      tool: "up__echo",
      arguments: {},
      backendSlug: "up",
      requirement: "notify_approve",
      ttlSeconds: 30,
    });
    vi.spyOn(webpush, "sendNotification").mockRejectedValueOnce({
      statusCode: 410,
    });
    const result = await notifyApprovalPush({
      store,
      approval: created.approval,
      decideToken: created.decideToken,
      ttlSeconds: 30,
    });
    expect(result.failed).toBe(1);
    expect(store.listPushSubscriptions(ws.id)).toHaveLength(0);
    store.close();
  });

  it("accepts public push-decision for notify_approve and rejects MFA approve", async () => {
    const gw = await bootGateway();
    const ws = gw.store.ensureWorkspace("default");
    const rule = gw.store.createAuthzRule(ws.id, {
      name: "echo",
      match: { tools: ["up__echo"] },
    });
    const key = gw.store.createApiKey(ws.id, "agent");
    const created = gw.store.createApproval({
      workspaceId: ws.id,
      ruleId: rule.id,
      keyId: key.id,
      tool: "up__echo",
      arguments: { password: "hide-me" },
      backendSlug: "up",
      requirement: "notify_approve",
      ttlSeconds: 30,
    });

    const bad = await fetch(
      `${gw.url}/v1/approvals/${created.approval.id}/push-decision`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision: "approve", token: "apd_nope" }),
      },
    );
    expect(bad.status).toBe(401);

    const ok = await fetch(
      `${gw.url}/v1/approvals/${created.approval.id}/push-decision`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision: "approve",
          token: created.decideToken,
        }),
      },
    );
    expect(ok.status).toBe(200);
    const okBody = await ok.json();
    expect(okBody.approval.status).toBe("approved");
    expect(JSON.stringify(okBody)).not.toContain("apd_");
    expect(JSON.stringify(okBody)).not.toContain("hide-me");

    const replay = await fetch(
      `${gw.url}/v1/approvals/${created.approval.id}/push-decision`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision: "approve",
          token: created.decideToken,
        }),
      },
    );
    expect(replay.status).toBe(401);

    const mfa = gw.store.createApproval({
      workspaceId: ws.id,
      ruleId: rule.id,
      keyId: key.id,
      tool: "up__echo",
      arguments: {},
      backendSlug: "up",
      requirement: "mfa_and_approve",
      ttlSeconds: 30,
    });
    const mfaApprove = await fetch(
      `${gw.url}/v1/approvals/${mfa.approval.id}/push-decision`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision: "approve",
          token: mfa.decideToken,
        }),
      },
    );
    expect(mfaApprove.status).toBe(400);
    const mfaBody = (await mfaApprove.json()) as { error: string; url: string };
    expect(mfaBody.error).toBe("mfa_required");
    expect(mfaBody.url).toContain(`/admin/#approvals/${mfa.approval.id}`);
    expect(gw.store.getApproval(ws.id, mfa.approval.id)?.status).toBe("pending");

    const mfaDeny = await fetch(
      `${gw.url}/v1/approvals/${mfa.approval.id}/push-decision`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision: "deny",
          token: mfa.decideToken,
        }),
      },
    );
    expect(mfaDeny.status).toBe(200);
    expect(gw.store.getApproval(ws.id, mfa.approval.id)?.status).toBe("denied");

    const expired = gw.store.createApproval({
      workspaceId: ws.id,
      ruleId: rule.id,
      keyId: key.id,
      tool: "up__echo",
      arguments: {},
      backendSlug: "up",
      requirement: "notify_approve",
      ttlSeconds: 30,
    });
    gw.store.expireApproval(ws.id, expired.approval.id);
    const late = await fetch(
      `${gw.url}/v1/approvals/${expired.approval.id}/push-decision`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decision: "approve",
          token: expired.decideToken,
        }),
      },
    );
    expect(late.status).toBe(409);
  });
});
