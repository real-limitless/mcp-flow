/**
 * Mint a project-scoped agent key into mcpflow_api_key.
 * The token is returned once. Callers must not write it to the audit log.
 */
import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Store } from "../db/store.js";
import type { AgentKind } from "./agents.js";

const KINDS = new Set<AgentKind>(["grokbot", "cloud_agent", "human", "service"]);
const SLUG = /^[a-z][a-z0-9_-]{0,63}$/;
const NAME_MAX = 128;

export class MintAgentError extends Error {
  constructor(
    readonly status: 400 | 404 | 409,
    message: string,
  ) {
    super(message);
    this.name = "MintAgentError";
  }
}

export interface MintAgentRequest {
  /** Omitted: a generated name. Required when creating an agent unless you pass agentId. */
  name?: string;
  owner?: string;
  kind?: AgentKind;
  /** Human admin agent. Implies kind human. */
  admin?: boolean;
  /**
   * Project slugs. Omitted or empty binds every project that exists now.
   * A project created later is not added.
   */
  projects?: string[];
  toolPrefixAllowlist?: string[];
  ttlDays?: number;
  /** Mint another key for this agent instead of creating one. */
  agentId?: string;
  /** Legacy-only. Present and set → 400, nothing is written. */
  dynamicTools?: boolean;
  dynamicToolsHot?: string[];
  defaultProject?: string | null;
  scopes?: {
    dynamicTools?: boolean;
    dynamicToolsHot?: string[];
    defaultProject?: string | null;
  } | null;
}

export interface MintedAgentKey {
  agent: {
    id: string;
    name: string;
    kind: AgentKind;
    owner: string;
    isAdmin: boolean;
    projects: string[];
  };
  key: {
    id: string;
    workspaceId: string;
    name: string;
    /** Short display prefix of the token. Not the lookup prefix. */
    prefix: string;
    token: string;
    scopes: {
      projects: string[];
      toolPrefixAllowlist?: string[];
      admin?: boolean;
    };
    createdAt: string;
    revokedAt: null;
    expiresAt: string;
    agentId: string;
  };
}

export function mintAgentKey(
  store: Store,
  input: { workspaceId: string; createdByAgentId: string | null; body: MintAgentRequest },
): MintedAgentKey {
  const body = input.body;
  const legacyOnly = legacyOnlyField(body as MintAgentRequest & Record<string, unknown>);
  if (legacyOnly) throw new MintAgentError(400, legacyOnly);

  const admin = body.admin === true;
  const kind = resolveKind(body.kind, admin);
  const allow = normalizePrefixes(body.toolPrefixAllowlist);
  const ttlDays = normalizeTtl(body.ttlDays);
  const owner = normalizeLabel(body.owner, "admin");
  const createdBy =
    input.createdByAgentId ??
    store.identity.ensureBootstrapAdmin(input.workspaceId, {
      name: "bootstrap-admin",
      owner: "admin",
    });

  return inTransaction(store.db, () => {
    if (body.agentId) {
      return mintForExisting(store, input.workspaceId, createdBy, body.agentId, body.projects, allow, ttlDays);
    }
    const name = body.name?.trim() ? normalizeLabel(body.name, "") : `agent-${randomBytes(4).toString("hex")}`;
    if (!name) throw new MintAgentError(400, "name is required");
    const projects = resolveProjects(store, input.workspaceId, body.projects);
    let agentId: string;
    try {
      agentId = store.identity.createAgent({
        workspaceId: input.workspaceId,
        name,
        owner,
        kind,
        isAdmin: admin,
        projects,
        createdBy,
      });
    } catch (err) {
      if (isUnique(err)) throw new MintAgentError(409, `an agent named ${name} already exists`);
      throw err;
    }
    const key = issueKey(store, agentId, createdBy, projects, allow, ttlDays);
    return assemble(store, input.workspaceId, agentId, key, projects, allow, admin);
  });
}

function mintForExisting(
  store: Store,
  workspaceId: string,
  createdBy: string,
  agentId: string,
  requested: string[] | undefined,
  allow: string[],
  ttlDays: number | undefined,
): MintedAgentKey {
  const row = store.db
    .prepare(
      `SELECT id, name, owner, kind, is_admin, status FROM mcpflow_agent WHERE id = ? AND workspace_id = ?`,
    )
    .get(agentId, workspaceId) as
    | { id: string; name: string; owner: string; kind: AgentKind; is_admin: number; status: string }
    | undefined;
  if (!row) throw new MintAgentError(404, "agent not found");
  if (row.status !== "active") throw new MintAgentError(409, "agent is not active");
  const owned = (
    store.db.prepare(`SELECT project_id FROM mcpflow_agent_project WHERE agent_id = ? ORDER BY project_id`).all(agentId) as Array<{
      project_id: string;
    }>
  ).map((r) => r.project_id);
  const projects = requested?.length ? resolveProjects(store, workspaceId, requested) : owned;
  if (!projects.length) throw new MintAgentError(400, "at least one project is required");
  for (const slug of projects) {
    if (!owned.includes(slug)) throw new MintAgentError(400, `project is not on this agent: ${slug}`);
  }
  const key = issueKey(store, agentId, createdBy, projects, allow, ttlDays);
  return assemble(store, workspaceId, agentId, key, projects, allow, row.is_admin === 1);
}

function issueKey(
  store: Store,
  agentId: string,
  createdBy: string,
  projects: string[],
  allow: string[],
  ttlDays: number | undefined,
): { keyId: string; token: string; expiresAt: string } {
  try {
    return store.identity.createKey({
      agentId,
      createdBy,
      projects,
      toolPrefixAllowlist: allow,
      ttlDays,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("2 live keys")) {
      throw new MintAgentError(409, "agent already has 2 live keys; revoke one before minting another");
    }
    throw err;
  }
}

function assemble(
  store: Store,
  workspaceId: string,
  agentId: string,
  key: { keyId: string; token: string; expiresAt: string },
  projects: string[],
  allow: string[],
  isAdmin: boolean,
): MintedAgentKey {
  const row = store.db
    .prepare(`SELECT name, owner, kind, is_admin FROM mcpflow_agent WHERE id = ?`)
    .get(agentId) as { name: string; owner: string; kind: AgentKind; is_admin: number };
  const createdAt = new Date().toISOString();
  return {
    agent: {
      id: agentId,
      name: row.name,
      kind: row.kind,
      owner: row.owner,
      isAdmin: row.is_admin === 1,
      projects: (
        store.db.prepare(`SELECT project_id FROM mcpflow_agent_project WHERE agent_id = ? ORDER BY project_id`).all(agentId) as Array<{
          project_id: string;
        }>
      ).map((r) => r.project_id),
    },
    key: {
      id: key.keyId,
      workspaceId,
      name: row.name,
      prefix: key.token.slice(0, 10),
      token: key.token,
      scopes: {
        projects,
        ...(allow.length ? { toolPrefixAllowlist: allow } : {}),
        ...(isAdmin ? { admin: true } : {}),
      },
      createdAt,
      revokedAt: null,
      expiresAt: key.expiresAt,
      agentId,
    },
  };
}

/** Fields that exist on legacy keys and must not be silently dropped. */
function legacyOnlyField(body: Record<string, unknown>): string | null {
  if (body.dynamicTools === true) {
    return "dynamicTools is not stored on an agent key. Omit it. The key is limited by projects and toolPrefixAllowlist.";
  }
  if (Array.isArray(body.dynamicToolsHot) && body.dynamicToolsHot.length) {
    return "dynamicToolsHot is not stored on an agent key. Omit it.";
  }
  if (typeof body.defaultProject === "string" && body.defaultProject.trim()) {
    return "defaultProject is not stored on an agent key. Pass projects with only the project this key may use.";
  }
  const scopes = body.scopes;
  if (scopes && typeof scopes === "object") {
    const s = scopes as { dynamicTools?: boolean; dynamicToolsHot?: string[]; defaultProject?: string };
    if (s.dynamicTools) return legacyOnlyField({ dynamicTools: true });
    if (s.dynamicToolsHot?.length) return legacyOnlyField({ dynamicToolsHot: s.dynamicToolsHot });
    if (s.defaultProject) return legacyOnlyField({ defaultProject: s.defaultProject });
  }
  return null;
}

function resolveKind(kind: AgentKind | undefined, admin: boolean): AgentKind {
  const resolved = kind ?? (admin ? "human" : "service");
  if (!KINDS.has(resolved)) throw new MintAgentError(400, "kind must be grokbot, cloud_agent, human, or service");
  if (admin && resolved !== "human") throw new MintAgentError(400, "admin agents must use kind human");
  return resolved;
}

function normalizeTtl(ttlDays: number | undefined): number | undefined {
  if (ttlDays === undefined) return undefined;
  if (!Number.isInteger(ttlDays) || ttlDays < 1 || ttlDays > 365) {
    throw new MintAgentError(400, "ttlDays must be an integer from 1 to 365");
  }
  return ttlDays;
}

function normalizeLabel(value: string | undefined, fallback: string): string {
  const text = (value ?? "").trim();
  const out = text || fallback;
  if (!out || out.length > NAME_MAX || /[\r\n]/.test(out)) {
    throw new MintAgentError(400, "name must be 1–128 characters on one line");
  }
  return out;
}

function normalizePrefixes(raw: string[] | undefined): string[] {
  if (raw == null) return [];
  if (!Array.isArray(raw)) throw new MintAgentError(400, "toolPrefixAllowlist must be an array of strings");
  if (raw.length > 64) throw new MintAgentError(400, "toolPrefixAllowlist has too many entries");
  const out: string[] = [];
  for (const item of raw) {
    if (typeof item !== "string") throw new MintAgentError(400, "toolPrefixAllowlist must be an array of strings");
    const prefix = item.trim();
    if (!prefix || prefix.length > 128 || /\s/.test(prefix)) {
      throw new MintAgentError(400, "each tool prefix must be 1–128 characters without whitespace");
    }
    out.push(prefix);
  }
  return [...new Set(out)];
}

function resolveProjects(store: Store, workspaceId: string, requested: string[] | undefined): string[] {
  store.ensureDefaultProject(workspaceId);
  const source = requested?.length
    ? requested
    : store.listProjects(workspaceId).map((project) => project.slug);
  const slugs: string[] = [];
  for (const raw of source) {
    if (typeof raw !== "string") throw new MintAgentError(400, "projects must be an array of slugs");
    const slug = raw.trim().toLowerCase();
    if (!slug) continue;
    if (!SLUG.test(slug)) {
      throw new MintAgentError(400, "project slug must be lowercase alphanumeric, underscore, or hyphen");
    }
    if (!store.getProjectBySlug(workspaceId, slug)) throw new MintAgentError(400, `unknown project: ${slug}`);
    if (!slugs.includes(slug)) slugs.push(slug);
  }
  if (!slugs.length) throw new MintAgentError(400, "at least one project is required");
  return slugs;
}

function isUnique(err: unknown): boolean {
  return /UNIQUE constraint failed/.test(String((err as Error)?.message ?? err));
}

function inTransaction<T>(db: DatabaseSync, fn: () => T): T {
  if (db.isTransaction) return fn();
  db.exec("BEGIN IMMEDIATE;");
  try {
    const out = fn();
    db.exec("COMMIT;");
    return out;
  } catch (err) {
    try {
      db.exec("ROLLBACK;");
    } catch {
      /* already rolled back */
    }
    throw err;
  }
}
