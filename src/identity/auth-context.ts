import { randomBytes } from "node:crypto";
import type { AuthContext } from "../types.js";
import type { ResolvedAgent } from "./agents.js";

/**
 * Fresh sticky-session id for an agent whose client sent no MCP session id (T1.1 §3.5):
 * agent:<agt>:<key_id>:<128-bit random>. Never deterministic, never shared across clients.
 * Returned in the Mcp-Session-Id response header; clients that echo it keep their project binding.
 */
export function newAgentSessionId(agent: Pick<ResolvedAgent, "agentId" | "keyId">): string {
  return `agent:${agent.agentId}:${agent.keyId}:${randomBytes(16).toString("hex")}`;
}

/**
 * A client-supplied session id is accepted only if it is not an agent: id at all,
 * or an agent: id minted for this exact agent+key (so one key can't ride another's binding).
 */
export function acceptClientSessionId(
  agent: Pick<ResolvedAgent, "agentId" | "keyId">,
  sid: string | null,
): boolean {
  if (!sid) return false;
  if (!sid.startsWith("agent:")) return true;
  return new RegExp(`^agent:${agent.agentId}:${agent.keyId}:[0-9a-f]{32}$`).test(sid);
}

/**
 * Build the per-request AuthContext for a resolved agent (T1.1 §3 step 5).
 * scopes.projects = effective projects so every existing project check applies;
 * scopes.admin mirrors agent.is_admin (only kind=human may hold it).
 */
export function agentAuthContext(
  agent: ResolvedAgent,
  opts: {
    mcpSessionId: string | null;
    projectId?: string | null;
    projectSlug?: string | null;
  },
): AuthContext {
  return {
    kind: agent.sessionId ? "project_session" : "api_key",
    workspaceId: agent.workspaceId,
    keyId: agent.keyId,
    keyName: agent.agentName,
    scopes: {
      projects: [...agent.effectiveProjects],
      ...(agent.isAdmin ? { admin: true } : {}),
    },
    projectId: opts.projectId ?? null,
    projectSlug: opts.projectSlug ?? null,
    mcpSessionId: opts.mcpSessionId || newAgentSessionId(agent),
    projectSessionId: agent.sessionId ?? null,
    agentId: agent.agentId,
    agentName: agent.agentName,
    agentOwner: agent.owner,
    agentKind: agent.kind,
    keyPrefix: agent.keyPrefix,
    keyExpiresAt: agent.keyExpiresAt,
    effectiveProjects: [...agent.effectiveProjects],
  };
}
