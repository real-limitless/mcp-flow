/**
 * Read endpoints for the admin UI (Frontend GAP-1..4). Admin-only (mounted on the admin router).
 * Never returns secrets or key material: no key secret/hash, no lookup prefix, no session tokens
 * or token hashes, no backend credentials/headers.
 */
import type { Hono } from "hono";
import type { Store } from "../db/store.js";
import type { UpstreamPool } from "../mcp/upstream.js";
import { alwaysDenied, loadActiveRules, ruleMatches, type CallContext, type PolicyRule } from "../policy/engine.js";
import { toolAllowedByProject, type Project } from "../types.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AdminRouter = Hono<any>;

export function agentRow(store: Store, a: Record<string, unknown>) {
  const db = store.db;
  const projects = (db.prepare(`SELECT project_id FROM mcpflow_agent_project WHERE agent_id = ? ORDER BY project_id`).all(String(a.id)) as Array<{ project_id: string }>).map((r) => r.project_id);
  const keys = (db.prepare(
    `SELECT id, status, valid_from, expires_at, last_used_at, created_at, revoked_at, predecessor_key_id
       FROM mcpflow_api_key WHERE agent_id = ? ORDER BY created_at`,
  ).all(String(a.id)) as Array<Record<string, unknown>>).map((k) => ({
    id: k.id, status: k.status, valid_from: k.valid_from, expires_at: k.expires_at, last_used_at: k.last_used_at,
    created_at: k.created_at, revoked_at: k.revoked_at, predecessor_key_id: k.predecessor_key_id,
    projects: (db.prepare(`SELECT project_id FROM mcpflow_api_key_project WHERE key_id = ? ORDER BY project_id`).all(String(k.id)) as Array<{ project_id: string }>).map((r) => r.project_id),
  }));
  return {
    id: a.id, name: a.name, owner: a.owner, kind: a.kind, is_admin: Number(a.is_admin) === 1, status: a.status,
    created_at: a.created_at, updated_at: a.updated_at, revoked_at: a.revoked_at, created_by: a.created_by,
    projects, keys,
  };
}

/** Rules with all versions (new engine). `current` = the active version or null. */
export function listPolicyRules(store: Store, workspaceId: string, onlyApprover?: string) {
  const db = store.db;
  const rules = db.prepare(`SELECT * FROM mcpflow_policy_rule WHERE workspace_id = ? ORDER BY created_at, id`).all(workspaceId) as Array<Record<string, unknown>>;
  const out = [];
  for (const r of rules) {
    const versions = (db.prepare(`SELECT * FROM mcpflow_policy_rule_version WHERE rule_id = ? ORDER BY version`).all(String(r.id)) as Array<Record<string, unknown>>).map((v) => ({
      version: v.version, priority: v.priority, description: v.description,
      match_agents: JSON.parse(String(v.match_agents)), match_projects: JSON.parse(String(v.match_projects)),
      match_backends: JSON.parse(String(v.match_backends)), match_tools: JSON.parse(String(v.match_tools)),
      match_args: JSON.parse(String(v.match_args)), effect: v.effect,
      approval_timeout_s: v.approval_timeout_s, approvers: v.approvers == null ? [] : JSON.parse(String(v.approvers)),
      reason_to_agent: v.reason_to_agent, created_at: v.created_at, created_by: v.created_by,
    }));
    const current = versions.find((v) => v.version === r.current_version) ?? null;
    if (onlyApprover && !versions.some((v) => (v.approvers as string[]).includes(onlyApprover))) continue;
    out.push({
      id: r.id, enabled: Number(r.enabled) === 1, retired_at: r.retired_at, current_version: r.current_version,
      active: Number(r.enabled) === 1 && r.retired_at == null && current != null,
      created_at: r.created_at, created_by: r.created_by, current, versions,
    });
  }
  return out;
}

type Effect = "allow" | "require_approval" | "conditional" | "denied";

/** Static per-tool reach for agent+project (ignores args; "conditional" = some arg-dependent rule decides). */
export function toolEffect(rules: PolicyRule[], scope: { agentId: string; projectId: string; backendSlug: string; tool: string }): Effect {
  if (alwaysDenied(rules, scope)) return "denied";
  const ctx = { ...scope, workspaceId: "", agentName: "", keyId: "", keyPrefix: null, sessionId: null, qualifiedTool: "", placement: null, deviceId: null } as unknown as CallContext;
  const inScope = rules.filter((r) => ruleMatches({ ...r, matchArgs: [] }, ctx, {}));
  if (inScope.some((r) => r.matchArgs.length > 0 && r.effect !== "allow")) return "conditional";
  if (inScope.some((r) => r.effect === "require_approval")) return "require_approval";
  if (inScope.some((r) => r.effect === "allow" && r.matchArgs.length === 0)) return "allow";
  return "conditional";
}

export function registerReadEndpoints(admin: AdminRouter, store: Store, pool: UpstreamPool) {
  // GAP-1
  admin.get("/agents", (c) => {
    const ws = c.get("auth").workspaceId as string;
    const rows = store.db.prepare(`SELECT * FROM mcpflow_agent WHERE workspace_id = ? ORDER BY name`).all(ws) as Array<Record<string, unknown>>;
    return c.json({ agents: rows.map((a) => agentRow(store, a)) });
  });
  admin.get("/agents/:id", (c) => {
    const ws = c.get("auth").workspaceId as string;
    const a = store.db.prepare(`SELECT * FROM mcpflow_agent WHERE workspace_id = ? AND id = ?`).get(ws, c.req.param("id")) as Record<string, unknown> | undefined;
    if (!a) return c.json({ error: "not found" }, 404);
    return c.json({ agent: agentRow(store, a) });
  });

  // GAP-2
  admin.get("/policy/rules", (c) => {
    const ws = c.get("auth").workspaceId as string;
    return c.json({ rules: listPolicyRules(store, ws) });
  });

  // GAP-3
  admin.get("/backends/:id/tools", async (c) => {
    const ws = c.get("auth").workspaceId as string;
    const b = store.getBackend(ws, c.req.param("id"));
    if (!b) return c.json({ error: "not found" }, 404);
    try {
      const all = await pool.listNamespacedTools(ws);
      const tools = all
        .filter((t) => t.backendSlug === b.slug)
        .map((t) => ({ name: t.name, upstream_name: t.upstreamName, description: t.description ?? null, input_schema: t.inputSchema ?? null }))
        .sort((x, y) => x.name.localeCompare(y.name));
      return c.json({ backend: { id: b.id, slug: b.slug, enabled: b.enabled }, tools });
    } catch {
      return c.json({ error: "backend tools unavailable" }, 502);
    }
  });

  // GAP-4: per-agent, per-project reach, plus live project sessions (ids only)
  admin.get("/agents/:id/reach", async (c) => {
    const ws = c.get("auth").workspaceId as string;
    const db = store.db;
    const a = db.prepare(`SELECT * FROM mcpflow_agent WHERE workspace_id = ? AND id = ?`).get(ws, c.req.param("id")) as Record<string, unknown> | undefined;
    if (!a) return c.json({ error: "not found" }, 404);
    const agentId = String(a.id);
    const agentProjects = agentRow(store, a).projects as string[];
    const want = c.req.query("project");
    const slugs = want ? agentProjects.filter((p) => p === want) : agentProjects;
    let catalog: Awaited<ReturnType<UpstreamPool["listNamespacedTools"]>> = [];
    let catalogError: string | null = null;
    try {
      catalog = await pool.listNamespacedTools(ws);
    } catch {
      catalogError = "backend tools unavailable";
    }
    const rules = loadActiveRules(db, ws);
    const now = new Date().toISOString();
    const sessions = db.prepare(
      `SELECT id, key_id, project_id, created_at, expires_at FROM mcpflow_session
        WHERE agent_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY created_at`,
    ).all(agentId, now) as Array<Record<string, unknown>>;
    const projects = slugs.map((slug) => {
      const p: Project | null = store.getProject(ws, slug);
      const tools = p
        ? catalog.filter((t) => toolAllowedByProject(t.name, p)).map((t) => ({
            name: t.name,
            effect: a.status === "active" ? toolEffect(rules, { agentId, projectId: slug, backendSlug: t.backendSlug, tool: t.upstreamName }) : "denied",
          }))
        : [];
      return {
        project: slug, exists: Boolean(p), tools,
        sessions: sessions.filter((s) => s.project_id === slug).map((s) => ({
          session_id: s.id, key_id: s.key_id, created_at: s.created_at, expires_at: s.expires_at,
        })),
      };
    });
    return c.json({ agent: { id: agentId, name: a.name, kind: a.kind, status: a.status }, catalog_error: catalogError, projects });
  });
}
