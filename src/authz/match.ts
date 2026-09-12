import type { PlacementMode } from "../types.js";
import {
  isAuthzExemptTool,
  requirementRank,
  type AuthzMatch,
  type AuthzRule,
} from "./types.js";

export interface AuthzEvalContext {
  tool: string;
  keyId: string | null | undefined;
  backendSlug: string | null;
  placement: PlacementMode | null;
}

export function ruleMatches(rule: AuthzRule, ctx: AuthzEvalContext): boolean {
  if (!rule.enabled) return false;
  const m = rule.match ?? {};
  if (m.keyIds?.length) {
    if (!ctx.keyId || !m.keyIds.includes(ctx.keyId)) return false;
  }
  if (m.placements?.length) {
    if (!ctx.placement || !m.placements.includes(ctx.placement)) return false;
  }
  if (m.backends?.length) {
    if (!ctx.backendSlug || !m.backends.includes(ctx.backendSlug)) return false;
  }
  if (m.tools?.length || m.prefixes?.length) {
    const exact = Boolean(m.tools?.includes(ctx.tool));
    const prefix = Boolean(
      m.prefixes?.some((p) => p && ctx.tool.startsWith(p)),
    );
    if (!exact && !prefix) return false;
  }
  return true;
}

/** Strictest matching enabled rule, or null. */
export function evaluateAuthzRules(
  rules: AuthzRule[],
  ctx: AuthzEvalContext,
): AuthzRule | null {
  if (isAuthzExemptTool(ctx.tool)) return null;
  const hits = rules.filter((r) => ruleMatches(r, ctx));
  if (!hits.length) return null;
  hits.sort(compareAuthzRules);
  return hits[0] ?? null;
}

/** Strictest hit across several contexts (e.g. mf_call_tool + inner name). */
export function evaluateAuthzRulesForContexts(
  rules: AuthzRule[],
  ctxs: AuthzEvalContext[],
): AuthzRule | null {
  let best: AuthzRule | null = null;
  for (const ctx of ctxs) {
    const hit = evaluateAuthzRules(rules, ctx);
    if (!hit) continue;
    if (!best || compareAuthzRules(hit, best) < 0) best = hit;
  }
  return best;
}

function compareAuthzRules(a: AuthzRule, b: AuthzRule): number {
  const d = requirementRank(b.requirement) - requirementRank(a.requirement);
  if (d !== 0) return d;
  return b.priority - a.priority;
}

export function normalizeMatch(raw: unknown): AuthzMatch {
  if (!raw || typeof raw !== "object") return {};
  const o = raw as Record<string, unknown>;
  const strList = (v: unknown): string[] | undefined => {
    if (!Array.isArray(v)) return undefined;
    const out = v.map((x) => String(x).trim()).filter(Boolean);
    return out.length ? out : undefined;
  };
  const placements = Array.isArray(o.placements)
    ? (o.placements
        .map(String)
        .filter((p) =>
          ["remote", "central-sandbox", "edge-sandbox", "edge-bare"].includes(p),
        ) as PlacementMode[])
    : undefined;
  return {
    tools: strList(o.tools),
    prefixes: strList(o.prefixes),
    backends: strList(o.backends),
    placements: placements?.length ? placements : undefined,
    keyIds: strList(o.keyIds),
  };
}
