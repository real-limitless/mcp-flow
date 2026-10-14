import type { AuthContext } from "../types.js";
import type { ResolvedAgent } from "./agents.js";

/** Stable sticky-session id for an agent when the client sends no MCP session id. */
export function agentSessionKey(agent: Pick<ResolvedAgent, "agentId" | "keyId">): string {
  return `agent:${agent.agentId}:${agent.keyId}`;
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
    mcpSessionId: opts.mcpSessionId || agentSessionKey(agent),
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
