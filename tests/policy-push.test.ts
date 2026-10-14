import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import type { PendingNotice } from "../src/policy/enforcer.js";
import { ARGS_SUMMARY_MAX, createPendingCallNotifier } from "../src/policy/push-notify.js";

const master = Buffer.alloc(32, 13).toString("base64");
const dirs: string[] = [];
let store: Store;
let ws: string;
let chen: string;
let other: string;
let bot: string;

afterEach(() => {
  store?.close();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

beforeEach(() => {
  const d = mkdtempSync(join(tmpdir(), "mcp-flow-push-"));
  dirs.push(d);
  store = new Store(join(d, "t.db"), master, { policyDevKeyRaw: "push-dev-key" });
  ws = store.ensureWorkspace("default").id;
  chen = store.identity.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
  other = store.identity.createAgent({ workspaceId: ws, name: "lead", owner: "chen", kind: "human", projects: [], createdBy: chen });
  bot = store.identity.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["gb_devops"], createdBy: chen });
});

function sub(agentId: string | null, tag = randomBytes(4).toString("hex")) {
  return store.upsertPushSubscription({
    workspaceId: ws, operatorKeyId: "", agentId,
    endpoint: `https://push.example/${tag}`, p256dh: "p", auth: "a",
  });
}

function notice(over: Partial<PendingNotice> = {}): PendingNotice {
  return {
    pendingCallId: `pc_${randomBytes(12).toString("hex")}`, workspaceId: ws, agentId: bot, agentName: "bot",
    projectId: "gb_devops", backendSlug: "gh-repos-shell", tool: "run_command",
    argsRedacted: { command: "git push", token: "[redacted]" }, approvers: [chen],
    expiresAt: new Date(Date.now() + 300_000).toISOString(), reasonToAgent: "Shell needs Chen",
    approveBaseUrl: "https://mcp-flow.example", ...over,
  };
}

function recorder(fail?: (endpoint: string) => number | null) {
  const sent: Array<{ endpoint: string; body: Record<string, unknown>; opts: Record<string, unknown> }> = [];
  const sender = (async (s: { endpoint: string }, body: string, opts: Record<string, unknown>) => {
    const code = fail?.(s.endpoint);
    if (code) throw Object.assign(new Error(`HTTP ${code}`), { statusCode: code });
    sent.push({ endpoint: s.endpoint, body: JSON.parse(body), opts });
    return { statusCode: 201, body: "", headers: {} };
  }) as never;
  return { sent, sender };
}

const notifyAudits = () =>
  store.listAudit(ws, { limit: 50 }).filter((e) => e.action === "policy.notify");

describe("T2.4 Web Push approver notification", () => {
  it("targets only the call's approvers, with agent/project/tool/args summary and no decide token", async () => {
    const mine = sub(chen, "chen");
    sub(other, "lead");
    const r = recorder();
    await createPendingCallNotifier(store, { sender: r.sender, approveBaseUrl: "https://mcp-flow.example" })(notice());
    expect(r.sent.map((s) => s.endpoint)).toEqual(["https://push.example/chen"]);
    const body = r.sent[0]!.body;
    expect(body).toMatchObject({
      kind: "pending_call", agent: "bot", project: "gb_devops", backend: "gh-repos-shell", tool: "run_command",
      audience: "approver", reason: "Shell needs Chen",
    });
    expect(String(body.url)).toBe(`https://mcp-flow.example/admin/#pending/${body.pendingCallId}`);
    expect(body).not.toHaveProperty("token");
    expect(JSON.stringify(body)).not.toMatch(/ghp_|mf_[A-Za-z0-9]{16}/);
    expect(r.sent[0]!.opts).toMatchObject({ urgency: "high" });
    expect(Number(r.sent[0]!.opts.TTL)).toBeLessThanOrEqual(300);
    expect(mine.id).toBeTruthy();
    expect(notifyAudits()[0]!.detail).toMatchObject({ channel: "webpush", audience: "approver", sent: 1, failed: 0 });
  });

  it("args summary is the redacted args, truncated", async () => {
    sub(chen);
    const r = recorder();
    await createPendingCallNotifier(store, { sender: r.sender })(notice({ argsRedacted: { command: "x".repeat(1000) } }));
    const s = String(r.sent[0]!.body.argsSummary);
    expect(s.length).toBeLessThanOrEqual(ARGS_SUMMARY_MAX + 1);
    expect(s.endsWith("…")).toBe(true);
  });

  it("falls back to unlinked workspace devices when no approver has one; never to other humans' devices", async () => {
    sub(other, "lead");
    sub(null, "ops");
    const r = recorder();
    await createPendingCallNotifier(store, { sender: r.sender })(notice());
    expect(r.sent.map((s) => s.endpoint)).toEqual(["https://push.example/ops"]);
    expect(r.sent[0]!.body.audience).toBe("workspace");
  });

  it("no devices at all: audited warning, nothing sent", async () => {
    const r = recorder();
    await createPendingCallNotifier(store, { sender: r.sender })(notice());
    expect(r.sent).toHaveLength(0);
    expect(notifyAudits()[0]!.detail).toMatchObject({ targets: 0, warning: expect.stringMatching(/not notified/) });
  });

  it("failures are audited and gone subscriptions pruned", async () => {
    sub(chen, "gone");
    sub(chen, "flaky");
    const r = recorder((e) => (e.endsWith("gone") ? 410 : e.endsWith("flaky") ? 500 : null));
    await createPendingCallNotifier(store, { sender: r.sender })(notice());
    expect(notifyAudits()[0]!.detail).toMatchObject({ sent: 0, failed: 2 });
    const left = store.listPushSubscriptions(ws).map((s) => s.endpoint);
    expect(left).toEqual(["https://push.example/flaky"]);
  });

  it("only human agents can own a push subscription", () => {
    expect(() => sub(bot)).toThrow(/human/);
    const s = sub(null);
    expect(() => store.setPushSubscriptionAgent(ws, s.id, bot)).toThrow(/human/);
    expect(store.setPushSubscriptionAgent(ws, s.id, chen)).toBe(true);
  });

  it("a failing notifier never approves: the hold still times out as deny", async () => {
    const db = store.db;
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, effect, approval_timeout_s, approvers, created_by) VALUES (?,1,'t','require_approval',1,?,?)`).run(rid, JSON.stringify([chen]), chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    db.exec("COMMIT;");
    store.policy.setNotifier(async () => {
      throw new Error("push service down");
    });
    const key = store.identity.createKey({ agentId: bot, createdBy: chen });
    let dispatched = 0;
    const r = await store.policy.enforce({
      ctx: {
        workspaceId: ws, agentId: bot, agentName: "bot", keyId: key.keyId, keyPrefix: key.prefix, sessionId: null,
        projectId: "gb_devops", backendSlug: "gh-repos-shell", tool: "run_command",
        qualifiedTool: "gh-repos-shell__run_command", placement: "remote", deviceId: null,
      },
      args: {},
      dispatch: async () => {
        dispatched += 1;
        return { content: [] };
      },
    });
    expect(dispatched).toBe(0);
    expect(JSON.parse((r.content[0] as { text: string }).text).reason).toBe("approval_timeout");
  }, 5000);
});
