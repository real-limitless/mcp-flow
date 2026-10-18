// A0: legacy approvals.arguments_json is sealed at rest for new rows and reduced to its
// sanitized form once the approval resolves. Legacy plaintext rows still read and are never
// rewritten. Fake values only.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";

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
      expect(raw).not.toContain(SECRET);
      expect(JSON.parse(raw)).toEqual({ cmd: "DB_PASS=[redacted]", password: "[redacted]", n: 1 });
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
});
