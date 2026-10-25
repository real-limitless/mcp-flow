// A0: legacy approvals.arguments_json is sealed at rest for new rows and reduced to its
// sanitized form once the approval resolves. Legacy plaintext rows still read and are never
// rewritten. Fake values only.
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import { loadConfig } from "../src/config.js";
import { startServer } from "../src/server.js";

const master = Buffer.alloc(32, 21).toString("base64");
const otherMaster = Buffer.alloc(32, 22).toString("base64");
const SECRET = "hunter2-fake-pw";
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function open(key = master, path?: string): { store: Store; path: string } {
  let p = path;
  if (!p) {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-apr-"));
    dirs.push(dir);
    p = join(dir, "t.db");
  }
  return { store: new Store(p, key), path: p };
}

function setup(store: Store, ttlSeconds = 60) {
  const ws = store.ensureWorkspace("default");
  const rule = store.createAuthzRule(ws.id, { name: "r", match: { tools: ["up__run"] }, ttlSeconds });
  const key = store.createApiKey(ws.id, "agent");
  const make = (args: Record<string, unknown> | null = { cmd: `DB_PASS=${SECRET} ./run`, password: SECRET, n: 1 }) =>
    store.createApproval({
      workspaceId: ws.id, ruleId: rule.id, keyId: key.id, tool: "up__run", arguments: args,
      backendSlug: "up", requirement: "notify_approve", ttlSeconds,
    }).approval;
  return { ws, rule, key, make };
}

function rawArgs(store: Store, id: string): unknown {
  const row = store.db.prepare(`SELECT arguments_json FROM approvals WHERE id = ?`).get(id) as { arguments_json: unknown };
  return row.arguments_json;
}

describe("approvals.arguments_json at rest", () => {
  it("new rows are sealed; raw args read back for the gate, sanitized for listings", () => {
    const { store } = open();
    const { ws, make } = setup(store);
    const a = make();
    const raw = String(rawArgs(store, a.id));
    expect(raw.startsWith("enc:v1:")).toBe(true);
    expect(raw).not.toContain(SECRET);
    expect(raw).not.toContain("DB_PASS");
    expect(store.getApproval(ws.id, a.id, { redact: false })?.arguments).toEqual({ cmd: `DB_PASS=${SECRET} ./run`, password: SECRET, n: 1 });
    expect(JSON.stringify(store.getApproval(ws.id, a.id))).not.toContain(SECRET);
    expect(JSON.stringify(store.listApprovals(ws.id))).not.toContain(SECRET);
    // null arguments stay null
    const b = make(null);
    expect(rawArgs(store, b.id)).toBeNull();
    expect(store.getApproval(ws.id, b.id, { redact: false })?.arguments).toBeNull();
    store.close();
  });

  it("deny and expiry replace the sealed args with the sanitized form", () => {
    const { store } = open();
    const { ws, make } = setup(store);
    const denied = make();
    store.decideApproval(ws.id, denied.id, { status: "denied" });
    const expired = make();
    store.expireApproval(ws.id, expired.id);
    for (const id of [denied.id, expired.id]) {
      const raw = String(rawArgs(store, id));
      expect(raw.startsWith("enc:v1:")).toBe(false);
      expect(raw.startsWith("san:v1:")).toBe(true);
      expect(raw).not.toContain(SECRET);
      expect(JSON.parse(raw.slice("san:v1:".length))).toEqual({ cmd: "DB_PASS=[redacted]", password: "[redacted]", n: 1 });
      expect(store.getApproval(ws.id, id, { redact: false })?.arguments).toEqual({ cmd: "DB_PASS=[redacted]", password: "[redacted]", n: 1 });
    }
    store.close();
  });

  it("overdue expiry retires sealed args too", () => {
    const { store } = open();
    const { ws, make } = setup(store);
    const a = make();
    store.db.prepare(`UPDATE approvals SET expires_at = ? WHERE id = ?`).run("2000-01-01T00:00:00.000Z", a.id);
    expect(store.expireOverdueApprovals(ws.id)).toBe(1);
    expect(String(rawArgs(store, a.id))).not.toContain(SECRET);
    expect(store.getApproval(ws.id, a.id)?.status).toBe("expired");
    store.close();
  });

  it("approved args stay sealed until the gate retires them; pending rows cannot be retired", () => {
    const { store } = open();
    const { ws, make } = setup(store);
    const a = make();
    expect(store.retireApprovalArguments(ws.id, a.id)).toBe(false);
    store.decideApproval(ws.id, a.id, { status: "approved" });
    expect(String(rawArgs(store, a.id)).startsWith("enc:v1:")).toBe(true);
    expect(store.getApproval(ws.id, a.id, { redact: false })?.arguments?.password).toBe(SECRET);
    expect(store.retireApprovalArguments(ws.id, a.id)).toBe(true);
    expect(String(rawArgs(store, a.id))).not.toContain(SECRET);
    expect(store.retireApprovalArguments(ws.id, a.id)).toBe(false);
    store.close();
  });

  it("legacy plaintext rows still read and are never rewritten", () => {
    const { store } = open();
    const { ws, rule, key } = setup(store);
    const legacy = JSON.stringify({ cmd: `DB_PASS=${SECRET}`, password: SECRET });
    const insert = (id: string, expiresAt: string) =>
      store.db.prepare(
        `INSERT INTO approvals (id, workspace_id, rule_id, key_id, tool, arguments_json, backend_slug, status,
           requirement, expires_at, created_at)
         VALUES (?, ?, ?, ?, 'up__run', ?, 'up', 'pending', 'notify_approve', ?, ?)`,
      ).run(id, ws.id, rule.id, key.id, legacy, expiresAt, new Date().toISOString());
    const future = new Date(Date.now() + 60_000).toISOString();
    insert("appr_legacy_1", future);
    insert("appr_legacy_2", future);
    insert("appr_legacy_3", future);
    insert("appr_legacy_4", "2000-01-01T00:00:00.000Z");
    expect(store.getApproval(ws.id, "appr_legacy_1", { redact: false })?.arguments?.password).toBe(SECRET);
    expect(JSON.stringify(store.getApproval(ws.id, "appr_legacy_1"))).not.toContain(SECRET);
    store.decideApproval(ws.id, "appr_legacy_1", { status: "denied" });
    store.decideApproval(ws.id, "appr_legacy_2", { status: "approved" });
    store.expireApproval(ws.id, "appr_legacy_3");
    store.expireOverdueApprovals(ws.id);
    expect(store.retireApprovalArguments(ws.id, "appr_legacy_2")).toBe(false);
    for (const id of ["appr_legacy_1", "appr_legacy_2", "appr_legacy_3", "appr_legacy_4"]) expect(rawArgs(store, id)).toBe(legacy);
    expect(store.getApproval(ws.id, "appr_legacy_2", { redact: false })?.arguments?.password).toBe(SECRET);
    store.close();
  });

  it("the gate's read fails closed: unreadable or already-retired args are never handed out", () => {
    const { store, path } = open();
    const { ws, make } = setup(store);
    const a = make();
    const b = make();
    const c = make();
    store.decideApproval(ws.id, a.id, { status: "approved" });
    store.decideApproval(ws.id, b.id, { status: "approved" });
    // c stays pending: not approved
    expect(store.consumeApprovedArguments(ws.id, c.id)).toEqual({ ok: false, reason: "not_approved" });
    // first read gets the raw args and retires them in the same transaction; a second read fails
    expect(store.consumeApprovedArguments(ws.id, a.id)).toEqual({ ok: true, args: { cmd: `DB_PASS=${SECRET} ./run`, password: SECRET, n: 1 } });
    expect(String(rawArgs(store, a.id)).startsWith("san:v1:")).toBe(true);
    expect(store.consumeApprovedArguments(ws.id, a.id)).toEqual({ ok: false, reason: "retired" });
    store.close();
    // b sealed under a different master key: unreadable, and the blob is left as is
    const { store: other } = open(otherMaster, path);
    const before = rawArgs(other, b.id);
    expect(other.consumeApprovedArguments(ws.id, b.id)).toEqual({ ok: false, reason: "unreadable" });
    expect(other.retireApprovalArguments(ws.id, b.id)).toBe(false);
    expect(rawArgs(other, b.id)).toBe(before);
    other.close();
  });

  it("legacy plaintext approved rows still dispatch through the gate read, unchanged at rest", () => {
    const { store } = open();
    const { ws, rule, key } = setup(store);
    const legacy = JSON.stringify({ cmd: "echo hi" });
    store.db.prepare(
      `INSERT INTO approvals (id, workspace_id, rule_id, key_id, tool, arguments_json, backend_slug, status,
         requirement, expires_at, created_at)
       VALUES ('appr_legacy_ok', ?, ?, ?, 'up__run', ?, 'up', 'approved', 'notify_approve', ?, ?)`,
    ).run(ws.id, rule.id, key.id, legacy, new Date(Date.now() + 60_000).toISOString(), new Date().toISOString());
    expect(store.consumeApprovedArguments(ws.id, "appr_legacy_ok")).toEqual({ ok: true, args: { cmd: "echo hi" } });
    expect(rawArgs(store, "appr_legacy_ok")).toBe(legacy);
    // corrupt legacy JSON fails closed too
    store.db.prepare(`UPDATE approvals SET arguments_json = '{not json' WHERE id = 'appr_legacy_ok'`).run();
    expect(store.consumeApprovedArguments(ws.id, "appr_legacy_ok")).toEqual({ ok: false, reason: "unreadable" });
    store.close();
  });

  it("status change and retire commit together: a failed retire rolls the decision back", () => {
    const { store } = open();
    const { ws, make } = setup(store);
    const a = make();
    store.db.exec(`CREATE TRIGGER no_retire BEFORE UPDATE OF arguments_json ON approvals
      BEGIN SELECT RAISE(ABORT, 'retire blocked'); END`);
    expect(() => store.decideApproval(ws.id, a.id, { status: "denied" })).toThrow(/retire blocked/);
    expect(store.getApproval(ws.id, a.id)?.status).toBe("pending");
    expect(() => store.expireApproval(ws.id, a.id)).toThrow(/retire blocked/);
    expect(store.getApproval(ws.id, a.id)?.status).toBe("pending");
    store.db.exec(`DROP TRIGGER no_retire`);
    expect(store.decideApproval(ws.id, a.id, { status: "denied" })?.status).toBe("denied");
    expect(String(rawArgs(store, a.id)).startsWith("san:v1:")).toBe(true);
    store.close();
  });

  it("startup sweep retires sealed args on resolved rows only; legacy and pending rows untouched", () => {
    const { store, path } = open();
    const { ws, rule, key, make } = setup(store);
    const approved = make();
    const pending = make();
    store.decideApproval(ws.id, approved.id, { status: "approved" });
    const legacy = JSON.stringify({ password: SECRET });
    store.db.prepare(
      `INSERT INTO approvals (id, workspace_id, rule_id, key_id, tool, arguments_json, backend_slug, status,
         requirement, expires_at, created_at)
       VALUES ('appr_legacy_sw', ?, ?, ?, 'up__run', ?, 'up', 'denied', 'notify_approve', ?, ?)`,
    ).run(ws.id, rule.id, key.id, legacy, new Date().toISOString(), new Date().toISOString());
    const pendingBefore = rawArgs(store, pending.id);
    expect(store.sweepResolvedSealedApprovalArgs()).toBe(1);
    expect(String(rawArgs(store, approved.id)).startsWith("san:v1:")).toBe(true);
    expect(String(rawArgs(store, approved.id))).not.toContain(SECRET);
    expect(rawArgs(store, pending.id)).toBe(pendingBefore);
    expect(rawArgs(store, "appr_legacy_sw")).toBe(legacy);
    expect(store.sweepResolvedSealedApprovalArgs()).toBe(0);
    store.close();
    void path;
  });

  it("a wrong master key yields no arguments, never ciphertext", () => {
    const { store, path } = open();
    const { ws, make } = setup(store);
    const a = make();
    store.close();
    const { store: other } = open(otherMaster, path);
    const got = other.getApproval(ws.id, a.id, { redact: false });
    expect(got?.arguments).toBeNull();
    expect(JSON.stringify(other.listApprovals(ws.id))).not.toContain("enc:v1:");
    other.close();
  });

  it("the gateway runs the sweep at startup", async () => {
    const { store, path } = open();
    const { ws, make } = setup(store);
    const a = make();
    store.decideApproval(ws.id, a.id, { status: "approved" });
    store.close();
    const cfg = loadConfig({
      dbPath: path, masterKeyRaw: master, adminToken: "test-admin-token-please-change",
      host: "127.0.0.1", port: 0 as unknown as number, allowPrivateUrls: true, workspaceName: "default",
    });
    const running = await startServer(cfg);
    try {
      expect(String(rawArgs(running.store, a.id)).startsWith("san:v1:")).toBe(true);
    } finally {
      await running.close();
    }
  });

  it("redacts ordinary admin secrets for pending, approved, denied, and expired rows", () => {
    const stripe = "stripe-placeholder-value";
    const sig = "sig-placeholder-value";
    const key = "key-placeholder-value";
    const nested = "nested-stripe-placeholder";
    const caseEnv = "case-env-placeholder";
    const caseHeader = "case-header-placeholder";
    const secrets = [stripe, sig, key, nested, caseEnv, caseHeader];
    const args = {
      idOrSlug: "remote",
      env: { STRIPE_SK: stripe },
      headers: { "X-Upstream-Sig": sig },
      apiKey: key,
      Env: { SLACK_BOT: caseEnv },
      HEADERS: { "X-Case": caseHeader },
      placement: { mode: "remote", env: { STRIPE_SK: nested } },
      sandbox: { memory: "512m", headers: { "X-Upstream-Sig": sig } },
    };
    const { store, path } = open();
    const ws = store.ensureWorkspace("default");
    const rule = store.createAuthzRule(ws.id, {
      name: "admin-update",
      match: { tools: ["mf_admin_update_backend"] },
      ttlSeconds: 60,
    });
    const agent = store.createApiKey(ws.id, "ops");
    const make = () =>
      store.createApproval({
        workspaceId: ws.id,
        ruleId: rule.id,
        keyId: agent.id,
        tool: "mf_admin_update_backend",
        arguments: args,
        backendSlug: "remote",
        requirement: "notify_approve",
        ttlSeconds: 60,
      }).approval;
    const bytes = () =>
      Buffer.concat(
        [path, `${path}-wal`, `${path}-shm`]
          .filter((file) => existsSync(file))
          .map((file) => readFileSync(file)),
      ).toString("utf8");
    const noSecrets = (text: string) => {
      for (const secret of secrets) expect(text).not.toContain(secret);
    };

    const pending = make();
    expect(String(rawArgs(store, pending.id)).startsWith("enc:v1:")).toBe(true);
    noSecrets(bytes());
    noSecrets(JSON.stringify(store.listApprovals(ws.id, { status: "pending" })));
    noSecrets(JSON.stringify(store.getApproval(ws.id, pending.id)));
    const pendingView = JSON.stringify(store.listApprovals(ws.id, { status: "all" }));
    expect(pendingView).toContain("STRIPE_SK");
    expect(pendingView).toContain("X-Upstream-Sig");
    expect(pendingView).toContain("[redacted]");
    expect(store.getApproval(ws.id, pending.id, { redact: false })?.arguments).toEqual(args);

    const denied = make();
    store.decideApproval(ws.id, denied.id, { status: "denied" });
    const expired = make();
    store.expireApproval(ws.id, expired.id);
    const approved = make();
    store.decideApproval(ws.id, approved.id, { status: "approved" });
    noSecrets(JSON.stringify(store.getApproval(ws.id, approved.id)));
    expect(String(rawArgs(store, approved.id)).startsWith("enc:v1:")).toBe(true);
    expect(store.consumeApprovedArguments(ws.id, approved.id)).toEqual({
      ok: true,
      args,
    });

    for (const id of [denied.id, expired.id, approved.id]) {
      const raw = String(rawArgs(store, id));
      expect(raw.startsWith("san:v1:")).toBe(true);
      expect(raw).toContain("STRIPE_SK");
      expect(raw).toContain("X-Upstream-Sig");
      expect(raw).not.toContain("SLACK_BOT");
      expect(raw).not.toContain("X-Case");
      expect(raw).toContain("[redacted]");
      noSecrets(raw);
    }
    noSecrets(bytes());
    noSecrets(JSON.stringify(store.listApprovals(ws.id, { status: "all" })));
    store.close();
  });
});
