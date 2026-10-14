import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer } from "../src/policy/enforcer.js";
import type { CallContext } from "../src/policy/engine.js";
import { exportCallAudit, queryCallAudit, runAuditRetention } from "../src/audit/call-audit.js";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";

const WS = "ws_" + "c".repeat(24);
const keys = derivePolicyKeys("audit-dev-key");
let db: DatabaseSync;
let dir: AgentDirectory;
let pe: PolicyEnforcer;
let chen: string;
let bot: string;
let botKey: string;
const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

function setup() {
  db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  dir = new AgentDirectory(db, keys);
  chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
  bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["gb_devops"], createdBy: chen });
  botKey = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
  pe = new PolicyEnforcer({ db, keys });
}

function rule(effect: string, tools: string[]) {
  const id = `rule_${randomBytes(12).toString("hex")}`;
  db.exec("BEGIN IMMEDIATE;");
  db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, WS, chen);
  db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, created_by) VALUES (?,1,'t',?,?,?)`).run(id, JSON.stringify(tools), effect, chen);
  db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(id);
  db.exec("COMMIT;");
}

const ctx = (tool: string): CallContext => ({
  workspaceId: WS, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null,
  projectId: "gb_devops", backendSlug: "gh", tool, qualifiedTool: `gh__${tool}`, placement: "remote", deviceId: null,
});
const ok = async () => ({ content: [{ type: "text" as const, text: "ok" }] });

describe("T3.1 write path", () => {
  beforeEach(setup);

  it("each call writes exactly one decision and one completion row, linked by call_id", async () => {
    rule("allow", ["read"]);
    rule("deny", ["delete"]);
    await pe.enforce({ ctx: ctx("read"), args: { path: "a" }, dispatch: ok });
    await pe.enforce({ ctx: ctx("delete"), args: { path: "a" }, dispatch: ok });
    await pe.enforce({ ctx: ctx("unknown"), args: {}, dispatch: ok });
    await pe.enforce({ ctx: ctx("read"), args: {}, dispatch: async () => { throw new Error("x"); } });
    const rows = db.prepare(`SELECT call_id, event_type FROM mcpflow_call_audit WHERE event_type <> 'lifecycle'`).all() as Array<{ call_id: string; event_type: string }>;
    const byCall = new Map<string, string[]>();
    for (const r of rows) byCall.set(r.call_id, [...(byCall.get(r.call_id) ?? []), r.event_type]);
    expect(byCall.size).toBe(4);
    for (const v of byCall.values()) expect(v).toEqual(["decision", "completion"]);
  });

  it("args are stored redacted, never raw secrets", async () => {
    rule("allow", ["read"]);
    await pe.enforce({ ctx: ctx("read"), args: { token: "ghp_" + "a".repeat(36), path: "x" }, dispatch: ok });
    const all = JSON.stringify(db.prepare(`SELECT * FROM mcpflow_call_audit`).all());
    expect(all).not.toContain("ghp_" + "a".repeat(36));
  });
});

describe("T3.3 query and export", () => {
  beforeEach(setup);

  it("filters and cursor pagination", async () => {
    rule("allow", ["read"]);
    rule("deny", ["delete"]);
    for (let i = 0; i < 5; i++) await pe.enforce({ ctx: ctx("read"), args: { i }, dispatch: ok });
    await pe.enforce({ ctx: ctx("delete"), args: {}, dispatch: ok });
    const denies = queryCallAudit(db, WS, { policyDecision: "deny" });
    expect(denies.rows).toHaveLength(1);
    expect(denies.rows[0]!.tool).toBe("delete");
    const p1 = queryCallAudit(db, WS, { agentId: bot, eventType: "completion" }, { limit: 4 });
    expect(p1.rows).toHaveLength(4);
    expect(p1.nextCursor).not.toBeNull();
    const p2 = queryCallAudit(db, WS, { agentId: bot, eventType: "completion" }, { limit: 4, cursor: p1.nextCursor! });
    expect(p2.rows).toHaveLength(2);
    expect(p2.nextCursor).toBeNull();
    expect(new Set([...p1.rows, ...p2.rows].map((r) => r.audit_id)).size).toBe(6);
    expect(queryCallAudit(db, "ws_" + "d".repeat(24), {}).rows).toHaveLength(0); // workspace-scoped
    expect(queryCallAudit(db, WS, {}, { limit: 10_000 }).rows.length).toBeLessThanOrEqual(500);
  });

  it("CSV escapes quotes/commas/newlines and neutralises formulas; JSON round-trips; cap reported", async () => {
    rule("allow", ["read"]);
    await pe.enforce({ ctx: ctx("read"), args: { note: 'a,"b"\nc', f: "=HYPERLINK(1)" }, dispatch: ok });
    const csv = exportCallAudit(db, WS, { eventType: "decision" }, "csv");
    const lines = csv.body.split("\r\n");
    expect(lines[0]!.startsWith("audit_id,ts,event_type")).toBe(true);
    expect(csv.body).toContain('\\""b\\""');
    expect(csv.rows).toBe(1);
    const json = JSON.parse(exportCallAudit(db, WS, {}, "json").body) as { rows: Array<Record<string, unknown>> };
    expect(json.rows.some((r) => (r.args_redacted as Record<string, unknown>)?.f === "=HYPERLINK(1)")).toBe(true);
    const capped = exportCallAudit(db, WS, {}, "csv", 1);
    expect(capped.truncated).toBe(true);
    // formula guard on a lifecycle row whose agent_name-like text starts with '='
    db.prepare(`INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, lifecycle_action, actor) VALUES ('lifecycle', '=cmd', ?, 'x', ?)`).run(WS, chen);
    expect(exportCallAudit(db, WS, { eventType: "lifecycle" }, "csv").body).toContain("'=cmd");
  });
});

describe("T3.1 retention maintenance path", () => {
  beforeEach(setup);

  function old(ts: string) {
    db.prepare(`INSERT INTO mcpflow_call_audit (ts, event_type, call_id, workspace_id, agent_id, policy_decision) VALUES (?, 'decision', ?, ?, ?, 'allow')`)
      .run(ts, `call_${randomBytes(6).toString("hex")}`, WS, bot);
  }

  it("archives per month, deletes in one txn, restores the trigger and logs a lifecycle row", () => {
    old("2025-08-15T00:00:00.000Z");
    old("2025-09-02T00:00:00.000Z");
    old("2025-09-30T23:59:59.999Z");
    old("2025-10-01T00:00:00.000Z"); // kept
    const archive = mkdtempSync(join(tmpdir(), "mcpflow-arch-"));
    tmp.push(archive);
    const out = runAuditRetention(db, { workspaceId: WS, before: "2025-10-01T00:00:00.000Z", archiveDir: archive, actor: chen });
    expect(out.deleted).toBe(3);
    expect(out.archived).toEqual({ "2025-08": 1, "2025-09": 2 });
    expect(readFileSync(out.files[1]!, "utf8").trim().split("\n")).toHaveLength(2);
    expect(() => db.prepare(`DELETE FROM mcpflow_call_audit`).run()).toThrow(/append-only/);
    const lc = queryCallAudit(db, WS, { eventType: "lifecycle" }).rows.find((r) => r.lifecycle_action === "audit_retention");
    expect(lc).toBeTruthy();
    expect(queryCallAudit(db, WS, { to: "2025-10-01T00:00:00.000Z" }).rows).toHaveLength(0);
    // never overwrites an existing archive
    old("2025-09-03T00:00:00.000Z");
    expect(() => runAuditRetention(db, { workspaceId: WS, before: "2025-10-01T00:00:00.000Z", archiveDir: archive, actor: chen })).toThrow(/EEXIST/);
    expect(queryCallAudit(db, WS, { to: "2025-10-01T00:00:00.000Z" }).rows).toHaveLength(1);
  });

  it("a failure inside the txn rolls back and keeps the trigger", () => {
    old("2025-08-15T00:00:00.000Z");
    const archive = mkdtempSync(join(tmpdir(), "mcpflow-arch-"));
    tmp.push(archive);
    expect(() => runAuditRetention(db, { workspaceId: WS, before: "2025-09-01T00:00:00.000Z", archiveDir: archive, actor: "not-an-agent" })).toThrow();
    expect(() => db.prepare(`DELETE FROM mcpflow_call_audit`).run()).toThrow(/append-only/);
    expect(queryCallAudit(db, WS, {}).rows.length).toBeGreaterThan(0);
    expect(existsSync(archive)).toBe(true);
  });

  it("rejects a non-month boundary", () => {
    expect(() => runAuditRetention(db, { workspaceId: WS, before: "2025-09-15T00:00:00.000Z", archiveDir: "/tmp/x", actor: chen })).toThrow(/first instant/);
  });
});

// ---------------- REST + MCP access control ----------------
const master = Buffer.alloc(32, 17).toString("base64");
const admin = "test-admin-token-audit";
async function boot(): Promise<RunningServer> {
  const d = mkdtempSync(join(tmpdir(), "mcp-flow-aud-"));
  tmp.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: master, adminToken: admin, host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default" });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

describe("T3.3 access: admin only", () => {
  it("REST /v1/audit/calls: human admin agent and env admin ok; non-admin agent refused", async () => {
    const gw = await boot();
    const ws = gw.store.ensureWorkspace("default");
    const id = gw.store.identity;
    const human = id.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
    const hk = id.createKey({ agentId: human, createdBy: human });
    // human admin needs ≥1 project to resolve
    gw.store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'default')`).run(human);
    const b = id.createAgent({ workspaceId: ws.id, name: "bot", owner: "chen", kind: "grokbot", projects: ["default"], createdBy: human });
    const bk = id.createKey({ agentId: b, createdBy: human });
    const get = (tok: string, q = "") => fetch(`${gw.url}/v1/audit/calls${q}`, { headers: { Authorization: `Bearer ${tok}` } });
    expect((await get(bk.token)).status).toBe(401);
    const r = await get(hk.token);
    expect(r.status).toBe(200);
    const body = (await r.json()) as { rows: unknown[] };
    expect(body.rows.length).toBeGreaterThan(0); // lifecycle rows from bootstrap
    const csv = await get(admin, "?format=csv&event_type=lifecycle");
    expect(csv.headers.get("content-type")).toMatch(/text\/csv/);
    expect((await csv.text()).split("\r\n")[0]).toMatch(/^audit_id,/);
    const exports = gw.store.listAudit(ws.id, { limit: 20 }).filter((e) => e.action === "audit.export");
    expect(exports).toHaveLength(1);
  });
});
