/**
 * T2.1 §10 / §11 rule-version input (0011): the single write path for per-call policy rule versions.
 * - match_agents are stored as agt_ ids or ["*"] only; agent NAMES given by an admin are resolved to the
 *   ids of agents in the same workspace at save time (names are mutable; ids are not).
 * - min_approvals is reserved: anything other than 1 is rejected until two-person approval is enforced.
 * The 0011 triggers enforce the same shape in the DB; this gives readable errors first.
 * No HTTP endpoint writes rules yet (GAP-2); any future admin route or ops script must go through here.
 */
import type { DatabaseSync } from "node:sqlite";

export class RuleInputError extends Error {}

const AGT_ID = /^agt_[0-9a-f]{24}$/;

/** Map ["*"] / agt_ ids / agent names to the stored form. Throws RuleInputError on unknown, mixed or empty input. */
export function resolveAgentMatchers(db: DatabaseSync, workspaceId: string, input: unknown): string[] {
  const list = input == null ? ["*"] : input;
  if (!Array.isArray(list) || list.length === 0 || !list.every((x) => typeof x === "string" && x.length > 0)) {
    throw new RuleInputError("match_agents must be a non-empty array of agent ids, agent names, or [\"*\"]");
  }
  if (list.includes("*")) {
    if (list.length > 1) throw new RuleInputError("match_agents: \"*\" cannot be combined with specific agents");
    return ["*"];
  }
  const byId = db.prepare(`SELECT id FROM mcpflow_agent WHERE workspace_id = ? AND id = ?`);
  const byName = db.prepare(`SELECT id FROM mcpflow_agent WHERE workspace_id = ? AND name = ?`);
  const out: string[] = [];
  for (const raw of list as string[]) {
    if (/[*?[\]]/.test(raw)) throw new RuleInputError(`match_agents: globs are not allowed (${JSON.stringify(raw)}); use agent ids or ["*"]`);
    const hit = (AGT_ID.test(raw) ? byId.get(workspaceId, raw) : byName.get(workspaceId, raw)) as { id: string } | undefined;
    if (!hit) throw new RuleInputError(`match_agents: unknown agent ${JSON.stringify(raw)} in this workspace`);
    if (!out.includes(hit.id)) out.push(hit.id);
  }
  return out;
}

/** §11: min_approvals is reserved; only 1 (or absent) is accepted. */
export function checkMinApprovals(v: unknown): 1 {
  if (v === undefined || v === null || v === 1) return 1;
  throw new RuleInputError("min_approvals must be 1 (two-person approval is not enforced yet)");
}

export interface RuleVersionInput {
  ruleId: string;
  workspaceId: string;
  createdBy: string;
  description: string;
  effect: "allow" | "deny" | "require_approval";
  priority?: number;
  matchAgents?: unknown;
  matchProjects?: string[];
  matchBackends?: string[];
  matchTools?: string[];
  matchArgs?: unknown[];
  approvalTimeoutS?: number | null;
  approvers?: string[] | null;
  reasonToAgent?: string | null;
  minApprovals?: unknown;
}

/**
 * Insert the next version of a rule (creating the rule on version 1) and point current_version at it,
 * in one transaction. Returns the new version number.
 */
export function saveRuleVersion(db: DatabaseSync, r: RuleVersionInput): number {
  const minApprovals = checkMinApprovals(r.minApprovals);
  const agents = resolveAgentMatchers(db, r.workspaceId, r.matchAgents);
  const approvers = r.approvers == null ? null : resolveApprovers(db, r.workspaceId, r.approvers);
  db.exec("BEGIN IMMEDIATE;");
  try {
    const cur = db.prepare(`SELECT workspace_id, current_version FROM mcpflow_policy_rule WHERE id = ?`).get(r.ruleId) as
      | { workspace_id: string; current_version: number | null } | undefined;
    if (cur && cur.workspace_id !== r.workspaceId) throw new RuleInputError("rule belongs to another workspace");
    if (!cur) db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?, ?, ?)`).run(r.ruleId, r.workspaceId, r.createdBy);
    const max = (db.prepare(`SELECT max(version) v FROM mcpflow_policy_rule_version WHERE rule_id = ?`).get(r.ruleId) as { v: number | null }).v ?? 0;
    const version = max + 1;
    db.prepare(
      `INSERT INTO mcpflow_policy_rule_version (rule_id, version, priority, description, match_agents, match_projects,
         match_backends, match_tools, match_args, effect, approval_timeout_s, approvers, reason_to_agent, created_by, min_approvals)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      r.ruleId, version, r.priority ?? 100, r.description, JSON.stringify(agents), JSON.stringify(r.matchProjects ?? ["*"]),
      JSON.stringify(r.matchBackends ?? ["*"]), JSON.stringify(r.matchTools ?? ["*"]), JSON.stringify(r.matchArgs ?? []),
      r.effect, r.approvalTimeoutS ?? null, approvers ? JSON.stringify(approvers) : null, r.reasonToAgent ?? null, r.createdBy, minApprovals,
    );
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version = ? WHERE id = ?`).run(version, r.ruleId);
    db.exec("COMMIT;");
    return version;
  } catch (err) {
    db.exec("ROLLBACK;");
    throw err;
  }
}

/** Approvers are human agents; names resolve to ids the same way as matchers ("*" is not allowed). */
function resolveApprovers(db: DatabaseSync, workspaceId: string, list: string[]): string[] {
  if (list.includes("*")) throw new RuleInputError("approvers must name agents, not \"*\"");
  return resolveAgentMatchers(db, workspaceId, list);
}
