/**
 * T2.1 §3 resolution: deny > require_approval > allow; nothing matched -> project default deny.
 * Priority (lower first) only picks which rule is reported, never weakens a deny.
 */
import type { DatabaseSync } from "node:sqlite";
import { allArgsMatch, anyGlob, type ArgMatcher } from "./matchers.js";

export type Effect = "allow" | "deny" | "require_approval";

export interface PolicyRule {
  ruleId: string;
  version: number;
  priority: number;
  description: string;
  matchAgents: string[];
  matchProjects: string[];
  matchBackends: string[];
  matchTools: string[];
  matchArgs: ArgMatcher[];
  effect: Effect;
  approvalTimeoutS: number | null;
  approvers: string[];
  reasonToAgent: string | null;
}

/** What policy sees. backendSlug/tool come from the gateway's routing table, never the caller. */
export interface CallContext {
  workspaceId: string;
  agentId: string;
  agentName: string;
  keyId: string;
  keyPrefix: string | null;
  sessionId: string | null;
  projectId: string;
  backendSlug: string;
  tool: string;
  qualifiedTool: string;
  placement: string | null;
  deviceId: string | null;
}

export interface Decision {
  decision: Effect;
  /** Winning rule (null when the project default applied) */
  rule: PolicyRule | null;
  matched: PolicyRule[];
  reason: string;
  /** require_approval only */
  timeoutS?: number;
  approvers?: string[];
}

export const DEFAULT_APPROVAL_TIMEOUT_S = 300;

export function loadActiveRules(db: DatabaseSync, workspaceId: string): PolicyRule[] {
  const rows = db
    .prepare(`SELECT * FROM mcpflow_active_policy_rule WHERE workspace_id = ? ORDER BY priority, rule_id`)
    .all(workspaceId) as Record<string, unknown>[];
  return rows.map((r) => ({
    ruleId: String(r.rule_id),
    version: Number(r.version),
    priority: Number(r.priority),
    description: String(r.description),
    matchAgents: JSON.parse(String(r.match_agents)) as string[],
    matchProjects: JSON.parse(String(r.match_projects)) as string[],
    matchBackends: JSON.parse(String(r.match_backends)) as string[],
    matchTools: JSON.parse(String(r.match_tools)) as string[],
    matchArgs: JSON.parse(String(r.match_args)) as ArgMatcher[],
    effect: String(r.effect) as Effect,
    approvalTimeoutS: r.approval_timeout_s == null ? null : Number(r.approval_timeout_s),
    approvers: r.approvers == null ? [] : (JSON.parse(String(r.approvers)) as string[]),
    reasonToAgent: r.reason_to_agent == null ? null : String(r.reason_to_agent),
  }));
}

export function ruleMatches(rule: PolicyRule, ctx: CallContext, args: unknown): boolean {
  return (
    anyGlob(rule.matchAgents, ctx.agentId) && // agt_ ids only (0003 Q6 default)
    anyGlob(rule.matchProjects, ctx.projectId) &&
    anyGlob(rule.matchBackends, ctx.backendSlug) &&
    anyGlob(rule.matchTools, ctx.tool) &&
    allArgsMatch(rule.matchArgs, args)
  );
}

const byPriority = (a: PolicyRule, b: PolicyRule) => a.priority - b.priority || a.ruleId.localeCompare(b.ruleId);

/**
 * True when policy denies this agent/project/backend/tool for EVERY possible args:
 * an unconditional deny rule matches, or no allow/require_approval rule can ever match
 * (project default deny). Used only to hide tools from listings, never to allow anything.
 */
export function alwaysDenied(
  rules: PolicyRule[],
  scope: { agentId: string; projectId: string; backendSlug: string; tool: string },
): boolean {
  const inScope = rules.filter(
    (r) =>
      anyGlob(r.matchAgents, scope.agentId) &&
      anyGlob(r.matchProjects, scope.projectId) &&
      anyGlob(r.matchBackends, scope.backendSlug) &&
      anyGlob(r.matchTools, scope.tool),
  );
  if (inScope.some((r) => r.effect === "deny" && r.matchArgs.length === 0)) return true;
  return !inScope.some((r) => r.effect !== "deny");
}

/** Throws on a malformed rule; the enforcer turns any throw into deny (fail closed). */
export function evaluate(rules: PolicyRule[], ctx: CallContext, args: unknown): Decision {
  const matched = rules.filter((r) => ruleMatches(r, ctx, args)).sort(byPriority);
  if (!matched.length) {
    return { decision: "deny", rule: null, matched, reason: "no_matching_rule" };
  }
  const deny = matched.find((r) => r.effect === "deny");
  if (deny) return { decision: "deny", rule: deny, matched, reason: "rule_deny" };
  const appr = matched.filter((r) => r.effect === "require_approval");
  if (appr.length) {
    const timeoutS = Math.min(...appr.map((r) => r.approvalTimeoutS ?? DEFAULT_APPROVAL_TIMEOUT_S));
    const approvers = [...new Set(appr.flatMap((r) => r.approvers))];
    return { decision: "require_approval", rule: appr[0]!, matched, reason: "approval_required", timeoutS, approvers };
  }
  return { decision: "allow", rule: matched[0]!, matched, reason: "rule_allow" };
}
