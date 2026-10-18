/** SecOPS item 7: mcpflow_call_audit text columns sanitized on write (fake secrets only). */
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it } from "vitest";
import {
  auditActor, auditIdCol, auditText, CALL_AUDIT_INVALID, CALL_AUDIT_NOTE_MAX, CALL_AUDIT_TEXT_MAX, sanitizeCallAuditCols,
} from "../src/audit/call-audit-cols.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer } from "../src/policy/enforcer.js";
import type { CallContext } from "../src/policy/engine.js";

const WS = "ws_" + "7".repeat(24);
const keys = derivePolicyKeys("call-audit-cols-dev");
const SECRETS = ["FAKEDBPASS1", "FAKEB3ARERVALUE123", "FAKEQS0TOKEN9", "FAKEAPIKEY77"];
let db: DatabaseSync;
let chen: string, bot: string, botKey: string;

beforeEach(() => {
  db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  const dir = new AgentDirectory(db, keys);
  chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
  bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  botKey = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
});
const allAudit = () => JSON.stringify(db.prepare(`SELECT * FROM mcpflow_call_audit`).all());
const noSecrets = () => {
  const all = allAudit();
  for (const s of SECRETS) expect(all).not.toContain(s);
};

describe("auditText / auditActor", () => {
  it("redacts embedded secrets, replaces control characters, caps at 256, is idempotent", () => {
    expect(auditText("gh__x?token=FAKEQS0TOKEN9")).not.toContain("FAKEQS0TOKEN9");
    expect(auditText("Bearer FAKEB3ARERVALUE123")).toBe("Bearer [redacted]");
    expect(auditText("a\nb\u0000c\u001bd\u0085e\u2028f")).toBe("a?b?c?d?e?f");
    const long = auditText("x".repeat(5000))!;
    expect(long).toBe(`${"x".repeat(CALL_AUDIT_TEXT_MAX)}…`);
    expect(auditText(long)).toBe(long);
    expect(auditText(null)).toBeNull();
    expect(auditText("plain_tool")).toBe("plain_tool");
  });

  it("actor is shape-checked; a bad value is refused without being echoed", () => {
    expect(auditActor(null)).toBeNull();
    expect(auditActor(`agt_${"a".repeat(24)}`)).toBe(`agt_${"a".repeat(24)}`);
    expect(auditActor("system:sweeper")).toBe("system:sweeper");
    for (const bad of ["Bearer FAKEB3ARERVALUE123", `agt_${"A".repeat(24)}`, "system:root", `agt_${"a".repeat(24)}\n`, 42]) {
      let msg = "";
      try {
        auditActor(bad);
      } catch (e) {
        msg = (e as Error).message;
      }
      expect(msg).toMatch(/shape check/);
      expect(msg).not.toContain("FAKE");
    }
  });

  it("sanitizeCallAuditCols touches only qualified_tool/tool/agent_name/error_code/actor", () => {
    const out = sanitizeCallAuditCols({ qualified_tool: "a\nb", args_redacted: "{\"x\":\"a\\nb\"}", call_id: "call_x" });
    expect(out).toEqual({ qualified_tool: "a?b", args_redacted: "{\"x\":\"a\\nb\"}", call_id: "call_x" });
    expect("actor" in out).toBe(false);
  });
});

describe("enforcer writes (enforcer.ts refuse / decision / completion / purge)", () => {
  const ctx = (over: Partial<CallContext> = {}): CallContext => ({
    workspaceId: WS, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null,
    projectId: "p1", backendSlug: "gh", tool: "echo", qualifiedTool: "gh__echo", placement: "remote", deviceId: null, ...over,
  });

  it("refuseBeforePolicy (unknown_tool / backend_unavailable): requested tool, agent_name sanitized; args redacted", () => {
    const pe = new PolicyEnforcer({ db, keys });
    pe.refuseBeforePolicy(ctx({ agentName: "bot\u001b[31m Bearer FAKEB3ARERVALUE123" }), "unknown_tool", `gh__x?token=FAKEQS0TOKEN9&${"y".repeat(600)}`, {});
    pe.refuseBeforePolicy(ctx(), "backend_unavailable", "s2__echo", { cmd: "DB_PASS=FAKEDBPASS1 ./run", note: "API_KEY=FAKEAPIKEY77" });
    const rows = db.prepare(`SELECT event_type, tool, agent_name, error_code, args_redacted FROM mcpflow_call_audit WHERE event_type <> 'lifecycle' ORDER BY audit_id`).all() as Array<Record<string, string>>;
    expect(rows).toHaveLength(4);
    expect(rows[0]!.tool.length).toBeLessThanOrEqual(CALL_AUDIT_TEXT_MAX + 1);
    expect(rows[0]!.agent_name).not.toMatch(/[\u0000-\u001f]/);
    expect(rows[2]!.error_code).toBe("backend_unavailable");
    noSecrets();
  });

  it("decision + completion rows from enforce(): qualified_tool sanitized and capped", async () => {
    const id = `rule_${randomBytes(12).toString("hex")}`;
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, WS, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, created_by) VALUES (?,1,'t','["*"]','allow',?)`).run(id, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(id);
    db.exec("COMMIT;");
    const pe = new PolicyEnforcer({ db, keys });
    const q = `gh__echo?api_key=FAKEAPIKEY77\n${"z".repeat(400)}`;
    await pe.enforce({ ctx: ctx({ qualifiedTool: q }), args: {}, dispatch: async () => ({ content: [{ type: "text", text: "ok" }] }) });
    const rows = db.prepare(`SELECT event_type, qualified_tool FROM mcpflow_call_audit WHERE event_type <> 'lifecycle' ORDER BY audit_id`).all() as Array<{ event_type: string; qualified_tool: string }>;
    expect(rows.map((r) => r.event_type)).toEqual(["decision", "completion"]);
    for (const r of rows) {
      expect(r.qualified_tool.length).toBe(CALL_AUDIT_TEXT_MAX + 1);
      expect(r.qualified_tool).not.toContain("\n");
    }
    noSecrets();
  });

  it("result_purge rows: agent name and qualified tool read from other tables are sanitized too", async () => {
    const id = `rule_${randomBytes(12).toString("hex")}`;
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, WS, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, approvers, approval_timeout_s, created_by)
                VALUES (?,1,'t','["merge"]','require_approval',?,30,?)`).run(id, JSON.stringify([chen]), chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(id);
    db.exec("COMMIT;");
    const pe = new PolicyEnforcer({ db, keys, resultTtlMs: 50 });
    const r = await pe.enforce({
      ctx: ctx({ tool: "merge", qualifiedTool: "gh__merge\u0007?token=FAKEQS0TOKEN9" }), args: {}, asyncApproval: true,
      dispatch: async () => ({ content: [{ type: "text", text: "ok" }] }),
    });
    const pc = JSON.parse((r as { content: Array<{ text: string }> }).content[0]!.text).pending_call_id as string;
    pe.decide(pc, chen, "approved");
    const stored = () => (db.prepare(`SELECT result_stored_at FROM mcpflow_call_outcome WHERE pending_call_id = ?`).get(pc) as { result_stored_at: string | null }).result_stored_at != null;
    for (let i = 0; i < 300 && !stored(); i++) await new Promise((res) => setTimeout(res, 10));
    expect(stored()).toBe(true);
    db.prepare(`UPDATE mcpflow_agent SET name = ? WHERE id = ?`).run("bot Bearer FAKEB3ARERVALUE123", bot);
    await new Promise((res) => setTimeout(res, 100));
    expect(pe.purgeResults()).toBe(1);
    const p = db.prepare(`SELECT actor, error_code, agent_name, qualified_tool FROM mcpflow_call_audit WHERE event_type = 'result_purge'`).get() as Record<string, string>;
    expect(p).toMatchObject({ actor: "system:sweeper", error_code: "purged:expired", agent_name: "bot Bearer [redacted]" });
    expect(p.qualified_tool).toMatch(/^gh__merge\?/);
    noSecrets();
  });
});

describe("SecOPS afcbc646 SHOULD 3/4: approver_note text column, identifier shape checks", () => {
  it("identifier columns keep minted shapes and turn anything else into [invalid] without echo", () => {
    const good = {
      key_prefix: "Ab3_-xYz09Qw", placement: "edge-bare", device_id: `dev_${"0".repeat(24)}`,
      backend_slug: "gh-repos_shell", project_id: "gb_devops",
    };
    expect(sanitizeCallAuditCols(good)).toEqual(good);
    const bad = sanitizeCallAuditCols({
      key_prefix: "Bearer FAKEB3ARERVALUE123", placement: "remote\nGH_TOKEN=FAKEAPIKEY77", device_id: "dev Bearer FAKEB3ARERVALUE123",
      backend_slug: "gh?token=FAKEQS0TOKEN9", project_id: "P1;DB_PASS=FAKEDBPASS1",
    });
    expect(Object.values(bad)).toEqual(Array(5).fill(CALL_AUDIT_INVALID));
    expect(sanitizeCallAuditCols({ key_prefix: null, device_id: "", project_id: undefined })).toEqual({ key_prefix: null, device_id: null, project_id: null });
    expect(auditIdCol("placement", 42)).toBe(CALL_AUDIT_INVALID);
  });

  it("approver_note: redacted, control characters replaced, capped at 2048", () => {
    const out = sanitizeCallAuditCols({ approver_note: `no, DB_PASS=FAKEDBPASS1\n${"n".repeat(5000)}` });
    expect(out.approver_note).not.toContain("FAKEDBPASS1");
    expect(out.approver_note!.length).toBe(CALL_AUDIT_NOTE_MAX + 1);
    expect(sanitizeCallAuditCols({ approver_note: "short\u0007note" }).approver_note).toBe("short?note");
  });

  it("enforcer writes: refused call with malformed ids, and a denied approval with a secret in the note", async () => {
    const pe = new PolicyEnforcer({ db, keys });
    const ctx = (over: Partial<CallContext> = {}): CallContext => ({
      workspaceId: WS, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: "Bearer FAKEB3ARERVALUE123", sessionId: null,
      projectId: "p1", backendSlug: "gh?token=FAKEQS0TOKEN9", tool: "echo", qualifiedTool: "gh__echo", placement: "remote", deviceId: null, ...over,
    });
    pe.refuseBeforePolicy(ctx(), "unknown_backend", "x__echo", {});
    const r0 = db.prepare(`SELECT key_prefix, backend_slug, project_id, placement FROM mcpflow_call_audit WHERE event_type='decision'`).get() as Record<string, string>;
    expect(r0).toMatchObject({ key_prefix: CALL_AUDIT_INVALID, backend_slug: CALL_AUDIT_INVALID, project_id: "p1" });

    const id = `rule_${randomBytes(12).toString("hex")}`;
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, WS, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, approvers, approval_timeout_s, created_by)
                VALUES (?,1,'t','["merge"]','require_approval',?,30,?)`).run(id, JSON.stringify([chen]), chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(id);
    db.exec("COMMIT;");
    const p = pe.enforce({
      ctx: ctx({ tool: "merge", qualifiedTool: "gh__merge", keyPrefix: "Ab3_-xYz09Qw", backendSlug: "gh" }), args: {},
      dispatch: async () => ({ content: [{ type: "text", text: "ok" }] }),
    });
    let pc: { id: string } | undefined;
    for (let i = 0; i < 300 && !pc; i++) {
      pc = db.prepare(`SELECT id FROM mcpflow_pending_call WHERE status='pending'`).get() as { id: string } | undefined;
      if (!pc) await new Promise((res) => setTimeout(res, 10));
    }
    expect(pc).toBeDefined();
    pe.decide(pc!.id, chen, "denied", `denied, API_KEY=FAKEAPIKEY77\n${"w".repeat(3000)}`);
    await p;
    const c = db.prepare(`SELECT approver_note, key_prefix, backend_slug FROM mcpflow_call_audit WHERE event_type='completion' ORDER BY audit_id DESC LIMIT 1`).get() as Record<string, string>;
    expect(c.key_prefix).toBe("Ab3_-xYz09Qw");
    expect(c.backend_slug).toBe("gh");
    // the note was already sanitized in mcpflow_pending_call (ed022746); the second pass (\n now "?")
    // redacts to the end, so the copy is shorter: over-redaction, never a leak
    expect(c.approver_note).toBe("denied, API_KEY=[redacted]");
    expect(c.approver_note.length).toBeLessThanOrEqual(CALL_AUDIT_NOTE_MAX + 1);
    expect(c.approver_note).not.toContain("\n");
    // the audit table never carries the fake values (mcpflow_pending_call.note is the decision record)
    noSecrets();
  });
});

