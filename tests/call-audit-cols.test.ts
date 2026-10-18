/** SecOPS item 7: mcpflow_call_audit text columns sanitized on write (fake secrets only). */
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it } from "vitest";
import { auditActor, auditText, CALL_AUDIT_TEXT_MAX, sanitizeCallAuditCols } from "../src/audit/call-audit-cols.js";
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
