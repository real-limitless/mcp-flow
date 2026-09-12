import type { PlacementMode } from "../types.js";

export type AuthzRequirement = "notify_approve" | "mfa" | "mfa_and_approve";

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export const AUTHZ_DEFAULT_TTL_SECONDS = 180;
export const AUTHZ_MIN_TTL_SECONDS = 1;
export const AUTHZ_MAX_TTL_SECONDS = 600;
export const AUTHZ_MAX_CONCURRENT_WAITS = 32;

/** Discovery / session metas must never wait (deadlock). */
export const AUTHZ_EXEMPT_TOOLS = new Set([
  "mf_status",
  "mf_list_projects",
  "mf_use_project",
  "mf_current_project",
  "mf_list_backends",
  "mf_list_tools",
  "mf_get_tool_schema",
  "mf_enable_tools",
  "mf_disable_tools",
]);

export interface AuthzMatch {
  tools?: string[];
  prefixes?: string[];
  backends?: string[];
  placements?: PlacementMode[];
  keyIds?: string[];
}

export interface AuthzRule {
  id: string;
  workspaceId: string;
  name: string;
  enabled: boolean;
  priority: number;
  match: AuthzMatch;
  requirement: AuthzRequirement;
  ttlSeconds: number;
  mfaReuseSeconds: number;
  createdAt: string;
  updatedAt: string;
}

export interface Approval {
  id: string;
  workspaceId: string;
  ruleId: string;
  keyId: string;
  keyName: string | null;
  keyPrefix: string | null;
  tool: string;
  arguments: Record<string, unknown> | null;
  backendSlug: string | null;
  status: ApprovalStatus;
  requirement: AuthzRequirement;
  mfaSatisfiedAt: string | null;
  decidedByKeyId: string | null;
  expiresAt: string;
  createdAt: string;
  decidedAt: string | null;
}

export interface CreateAuthzRuleInput {
  name: string;
  enabled?: boolean;
  priority?: number;
  match: AuthzMatch | unknown;
  requirement?: AuthzRequirement;
  ttlSeconds?: number;
  mfaReuseSeconds?: number;
}

export interface UpdateAuthzRuleInput {
  name?: string;
  enabled?: boolean;
  priority?: number;
  match?: AuthzMatch | unknown;
  requirement?: AuthzRequirement;
  ttlSeconds?: number;
  mfaReuseSeconds?: number;
}

export function clampAuthzTtl(raw: unknown): number {
  const n = Number(raw ?? AUTHZ_DEFAULT_TTL_SECONDS);
  if (!Number.isFinite(n)) return AUTHZ_DEFAULT_TTL_SECONDS;
  return Math.min(
    AUTHZ_MAX_TTL_SECONDS,
    Math.max(AUTHZ_MIN_TTL_SECONDS, Math.floor(n)),
  );
}

export function requirementRank(req: AuthzRequirement): number {
  if (req === "mfa_and_approve") return 3;
  if (req === "mfa") return 2;
  return 1;
}

export function requirementNeedsMfa(req: AuthzRequirement): boolean {
  return req === "mfa" || req === "mfa_and_approve";
}

export function parseAuthzRequirement(raw: unknown): AuthzRequirement | null {
  if (raw === "notify_approve" || raw === "mfa" || raw === "mfa_and_approve") {
    return raw;
  }
  return null;
}

export function isAuthzExemptTool(name: string): boolean {
  return AUTHZ_EXEMPT_TOOLS.has(name);
}

export function authzMatchHasConstraint(match: AuthzMatch): boolean {
  return Boolean(
    match.tools?.length ||
      match.prefixes?.length ||
      match.backends?.length ||
      match.placements?.length ||
      match.keyIds?.length,
  );
}
