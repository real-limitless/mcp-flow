/** T2.1 §10/§11: rule versions store agt_ ids or ["*"]; names resolve at save time; min_approvals must be 1. */
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it } from "vitest";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { RuleInputError, checkMinApprovals, resolveAgentMatchers, saveRuleVersion } from "../src/policy/rule-input.js";
import { loadActiveRules } from "../src/policy/engine.js";

const WS = "ws_" + "c".repeat(24);
const rid = () => `rule_${randomBytes(12).toString("hex")}`;
let db: DatabaseSync;
let chen: string;
let bot: string;

beforeEach(() => {
  db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  const dir = new AgentDirectory(db, derivePolicyKeys("rule-input-dev"));
  chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
  bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["gb_devops"], createdBy: chen });
});

describe("resolveAgentMatchers", () => {
  it("names -> agt_ ids; ids kept; '*' alone; dedupes", () => {
    expect(resolveAgentMatchers(db, WS, ["bot", bot, "chen"])).toEqual([bot, chen]);
    expect(resolveAgentMatchers(db, WS, ["*"])).toEqual(["*"]);
    expect(resolveAgentMatchers(db, WS, undefined)).toEqual(["*"]);
  });
  it("rejects unknown names, other-workspace ids, globs, '*' mixed in, empty", () => {
    expect(() => resolveAgentMatchers(db, WS, ["nobody"])).toThrow(RuleInputError);
    expect(() => resolveAgentMatchers(db, "ws_" + "d".repeat(24), [bot])).toThrow(/unknown agent/);
    expect(() => resolveAgentMatchers(db, WS, ["bo*"])).toThrow(/globs/);
    expect(() => resolveAgentMatchers(db, WS, ["*", "bot"])).toThrow(/cannot be combined/);
    expect(() => resolveAgentMatchers(db, WS, [])).toThrow(RuleInputError);
  });
});

describe("saveRuleVersion", () => {
  it("stores ids, not names, and the engine matches the agent", () => {
    const id = rid();
    expect(saveRuleVersion(db, { ruleId: id, workspaceId: WS, createdBy: chen, description: "bot only", effect: "allow", matchAgents: ["bot"] })).toBe(1);
    expect(db.prepare(`SELECT match_agents, min_approvals FROM mcpflow_policy_rule_version WHERE rule_id = ?`).get(id))
      .toEqual({ match_agents: JSON.stringify([bot]), min_approvals: 1 });
    expect(loadActiveRules(db, WS).find((r) => r.ruleId === id)!.matchAgents).toEqual([bot]);
    expect(saveRuleVersion(db, { ruleId: id, workspaceId: WS, createdBy: chen, description: "all", effect: "allow" })).toBe(2);
  });
  it("approver names resolve to ids", () => {
    const id = rid();
    saveRuleVersion(db, { ruleId: id, workspaceId: WS, createdBy: chen, description: "ra", effect: "require_approval", approvalTimeoutS: 60, approvers: ["chen"] });
    expect(db.prepare(`SELECT approvers FROM mcpflow_policy_rule_version WHERE rule_id = ?`).get(id)).toEqual({ approvers: JSON.stringify([chen]) });
  });
  it("rejects min_approvals != 1 and writes nothing", () => {
    for (const v of [0, 2, "1", 1.5]) {
      const id = rid();
      expect(() => saveRuleVersion(db, { ruleId: id, workspaceId: WS, createdBy: chen, description: "x", effect: "allow", minApprovals: v })).toThrow(/min_approvals must be 1/);
      expect(db.prepare(`SELECT count(*) n FROM mcpflow_policy_rule WHERE id = ?`).get(id)).toEqual({ n: 0 });
    }
    expect(checkMinApprovals(1)).toBe(1);
    expect(checkMinApprovals(undefined)).toBe(1);
  });
});

describe("policy-starter.sql", () => {
  it("applies on a migrated DB with ids substituted; every match_agents is ['*']", () => {
    const ruleIds: Record<string, string> = {};
    const sql = readFileSync(new URL("../src/db/seeds/policy-starter.sql", import.meta.url), "utf8")
      .split("\n")
      .filter((l) => /^-- (BEGIN|INSERT|UPDATE|COMMIT|  )/.test(l))
      .map((l) => l.slice(3))
      .join("\n")
      .replace(/:ws\b/g, `'${WS}'`)
      .replace(/:chen\b/g, `'${chen}'`)
      .replace(/:(rule_\w+)/g, (_m, n: string) => `'${ruleIds[n] ??= rid()}'`);
    db.exec(sql);
    const rows = db.prepare(`SELECT match_agents FROM mcpflow_policy_rule_version`).all() as Array<{ match_agents: string }>;
    expect(rows.length).toBe(4);
    expect(rows.every((r) => r.match_agents === '["*"]')).toBe(true);
  });
});
