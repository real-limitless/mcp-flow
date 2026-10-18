/**
 * T1.3 — per-agent identity on the mcpflow_* tables (T1.1 §3, §8; db-t1.2).
 * Resolves an mf_ key or mf_sess_ token to {agent, key, effective projects}.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { PolicyKeys } from "./dev-keys.js";
import { auditActor, auditText } from "../audit/call-audit-cols.js";

export type AgentKind = "grokbot" | "cloud_agent" | "human" | "service";

export interface ResolvedAgent {
  agentId: string;
  agentName: string;
  owner: string;
  kind: AgentKind;
  isAdmin: boolean;
  workspaceId: string;
  keyId: string;
  keyPrefix: string;
  keyExpiresAt: string;
  effectiveProjects: string[];
  /** Set when resolved from an mf_sess_ token */
  sessionId?: string;
  sessionProject?: string;
}

export type ResolveResult =
  | { status: "ok"; agent: ResolvedAgent }
  /** Token is ours but not usable: inactive/expired/revoked key or agent, bad secret */
  | { status: "unauthorized" }
  /** Valid identity but no project in key ∩ agent */
  | { status: "forbidden"; reason: "no_projects"; agent: ResolvedAgent }
  /** Not an agent-directory token: caller may try the legacy key path */
  | { status: "unknown" };

export const KEY_TOKEN_PREFIX = "mf_";
export const SESSION_TOKEN_PREFIX = "mf_sess_";
/** Security I-3: session ids are not bearer tokens; a distinct prefix avoids confusing the two. */
export const SESSION_ID_PREFIX = "sess_";
export const LOOKUP_PREFIX_LEN = 12;
export const DEFAULT_KEY_TTL_DAYS = 90;
export const MAX_KEY_TTL_DAYS = 365;
export const ROTATING_FORCED_EXPIRY_DAYS = 7;
/** Short so a revoke made by another process applies within seconds (Security T2.5 L-5). */
export const RESOLVE_CACHE_MS = 5_000;
const HASH_SCHEME = "sha256-pepper$v1$";
const DAY_MS = 86_400_000;

const newId = (p: string) => `${p}_${randomBytes(12).toString("hex")}`;
const nowIso = () => new Date().toISOString();

function isUniqueViolation(err: unknown): boolean {
  return /UNIQUE constraint failed/.test(String((err as Error)?.message ?? err));
}

export class AgentDirectory {
  private cache = new Map<string, { at: number; version: number; epoch: number; result: ResolveResult }>();

  /** DB-side identity epoch (0006): changes made by any process invalidate every cache (Security T2.5 L-5). */
  private dbEpoch(): number {
    try {
      return Number((this.db.prepare(`SELECT epoch FROM mcpflow_identity_epoch WHERE id = 1`).get() as { epoch: number } | undefined)?.epoch ?? -1);
    } catch {
      return -1;
    }
  }
  private version = 0;

  constructor(
    private readonly db: DatabaseSync,
    private readonly keys: PolicyKeys,
    private readonly clock: () => number = Date.now,
  ) {}

  hashSecret(token: string): string {
    return HASH_SCHEME + createHmac("sha256", this.keys.pepper).update(token, "utf8").digest("hex");
  }

  /** Drop every cached resolution (called on any revoke/suspend). */
  bumpVersion(): void {
    this.version += 1;
    this.cache.clear();
  }

  // ---------- bootstrap / admin ----------

  hasWorkspace(workspaceId: string): boolean {
    return Boolean(this.db.prepare(`SELECT 1 FROM mcpflow_workspace WHERE id = ?`).get(workspaceId));
  }

  /** Workspace + its owning human agent in one transaction (deferred owner FK). */
  bootstrapWorkspace(workspaceId: string, owner: { name: string; owner: string }): string {
    const agentId = newId("agt");
    this.tx(() => {
      this.db
        .prepare(`INSERT INTO mcpflow_workspace (id, owner_principal_id) VALUES (?, ?)`)
        .run(workspaceId, agentId);
      this.db
        .prepare(
          `INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by)
           VALUES (?, ?, ?, ?, 'human', 1, NULL)`,
        )
        .run(agentId, workspaceId, owner.name, owner.owner);
      this.lifecycle(workspaceId, agentId, "workspace_bootstrap", { agentId });
    });
    return agentId;
  }

  createAgent(input: {
    workspaceId: string;
    name: string;
    owner: string;
    kind: AgentKind;
    isAdmin?: boolean;
    projects: string[];
    createdBy: string;
  }): string {
    const agentId = newId("agt");
    this.tx(() => {
      this.db
        .prepare(
          `INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(agentId, input.workspaceId, input.name, input.owner, input.kind, input.isAdmin ? 1 : 0, input.createdBy);
      const ins = this.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, ?)`);
      for (const p of new Set(input.projects)) ins.run(agentId, p);
      this.lifecycle(input.workspaceId, input.createdBy, "agent_create", { agentId, name: input.name });
    });
    return agentId;
  }

  /**
   * Issue a key. Secret returned once; only its peppered hash is stored.
   * Lookup prefix = 12 chars after "mf_" (UNIQUE); on collision regenerate, max 3 tries (T1.1 §8.7).
   */
  createKey(input: {
    agentId: string;
    createdBy: string;
    projects?: string[];
    ttlDays?: number;
    predecessorKeyId?: string;
  }): { keyId: string; token: string; prefix: string; expiresAt: string } {
    const ttl = Math.min(Math.max(input.ttlDays ?? DEFAULT_KEY_TTL_DAYS, 1), MAX_KEY_TTL_DAYS);
    const ws = this.agentWorkspace(input.agentId);
    for (let attempt = 1; attempt <= 3; attempt++) {
      const token = KEY_TOKEN_PREFIX + randomBytes(32).toString("base64url");
      if (token.startsWith(SESSION_TOKEN_PREFIX)) continue; // never mint a key that looks like a session
      const prefix = token.slice(KEY_TOKEN_PREFIX.length, KEY_TOKEN_PREFIX.length + LOOKUP_PREFIX_LEN);
      const keyId = newId("key");
      const now = this.clock();
      const createdAt = new Date(now).toISOString();
      const expiresAt = new Date(now + ttl * DAY_MS).toISOString();
      try {
        this.tx(() => {
          this.db
            .prepare(
              `INSERT INTO mcpflow_api_key (id, agent_id, prefix, secret_hash, predecessor_key_id,
                 valid_from, expires_at, created_at, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            )
            .run(keyId, input.agentId, prefix, this.hashSecret(token), input.predecessorKeyId ?? null,
              createdAt, expiresAt, createdAt, input.createdBy);
          const ins = this.db.prepare(
            `INSERT INTO mcpflow_api_key_project (key_id, agent_id, project_id) VALUES (?, ?, ?)`,
          );
          for (const p of new Set(input.projects ?? [])) ins.run(keyId, input.agentId, p);
          this.lifecycle(ws, input.createdBy, "key_create", { keyId, agentId: input.agentId, prefix });
        });
        return { keyId, token, prefix, expiresAt };
      } catch (err) {
        if (isUniqueViolation(err) && attempt < 3) continue;
        if (isUniqueViolation(err)) throw new Error("could not mint a unique key after 3 attempts");
        throw err;
      }
    }
    throw new Error("could not mint a unique key after 3 attempts");
  }

  /** Rotate: issue B (predecessor A), mark A rotating with a forced expiry ≤ 7 days. */
  rotateKey(keyId: string, by: string): { keyId: string; token: string; prefix: string; expiresAt: string } {
    const old = this.db.prepare(`SELECT agent_id, expires_at FROM mcpflow_api_key WHERE id = ?`).get(keyId) as
      | { agent_id: string; expires_at: string }
      | undefined;
    if (!old) throw new Error("key not found");
    const forced = new Date(this.clock() + ROTATING_FORCED_EXPIRY_DAYS * DAY_MS).toISOString();
    const next = this.createKey({ agentId: old.agent_id, createdBy: by, predecessorKeyId: keyId });
    this.db
      .prepare(`UPDATE mcpflow_api_key SET status = 'rotating', expires_at = min(expires_at, ?) WHERE id = ?`)
      .run(forced, keyId);
    this.bumpVersion();
    return next;
  }

  revokeKey(keyId: string, by: string, reason: string): boolean {
    let changed = false;
    this.tx(() => {
      const res = this.db
        .prepare(
          `UPDATE mcpflow_api_key SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = ?
           WHERE id = ? AND status <> 'revoked'`,
        )
        .run(nowIso(), by, reason, keyId);
      changed = Number(res.changes) === 1;
      if (changed) this.lifecycle(this.keyWorkspace(keyId), by, "key_revoke", { keyId, reason });
    });
    this.bumpVersion();
    return changed;
  }

  suspendAgent(agentId: string, by: string): boolean {
    let changed = false;
    this.tx(() => {
      const res = this.db
        .prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ? AND status = 'active'`)
        .run(agentId);
      changed = Number(res.changes) === 1;
      if (changed) this.lifecycle(this.agentWorkspace(agentId), by, "agent_suspend", { agentId });
    });
    this.bumpVersion();
    return changed;
  }

  revokeAgent(agentId: string, by: string, reason: string): boolean {
    let changed = false;
    this.tx(() => {
      const res = this.db
        .prepare(
          `UPDATE mcpflow_agent SET status = 'revoked', revoked_at = ?, revoked_by = ?, revoked_reason = ?
           WHERE id = ? AND status <> 'revoked'`,
        )
        .run(nowIso(), by, reason, agentId);
      changed = Number(res.changes) === 1;
      if (changed) this.lifecycle(this.agentWorkspace(agentId), by, "agent_revoke", { agentId, reason });
    });
    this.bumpVersion();
    return changed;
  }

  // ---------- resolution (every request) ----------

  /** Resolve an `mf_` API key. Sessions go through resolveSession. */
  resolveKey(token: string, ip?: string | null): ResolveResult {
    if (!token.startsWith(KEY_TOKEN_PREFIX) || token.startsWith(SESSION_TOKEN_PREFIX)) {
      return { status: "unknown" };
    }
    const prefix = token.slice(KEY_TOKEN_PREFIX.length, KEY_TOKEN_PREFIX.length + LOOKUP_PREFIX_LEN);
    if (prefix.length !== LOOKUP_PREFIX_LEN) return { status: "unknown" };
    const hash = this.hashSecret(token);

    const cached = this.cache.get(hash);
    if (cached && cached.version === this.version && this.clock() - cached.at < RESOLVE_CACHE_MS && cached.epoch === this.dbEpoch() && cached.epoch !== -1) {
      return this.recheckExpiry(cached.result);
    }

    const epochAtLookup = this.dbEpoch(); // read before the rows, so a concurrent change is never cached
    const known = this.db.prepare(`SELECT secret_hash FROM mcpflow_api_key WHERE prefix = ?`).get(prefix) as
      | { secret_hash: string }
      | undefined;
    if (!known) return { status: "unknown" }; // legacy key path may still accept it
    // mismatch: not this key (a legacy key could share 12 chars); let the legacy path decide
    if (!safeEqual(known.secret_hash, hash)) return { status: "unknown" };

    const row = this.db
      .prepare(`SELECT * FROM mcpflow_resolvable_key WHERE prefix = ?`)
      .get(prefix) as Record<string, unknown> | undefined;
    if (!row) {
      this.cache.set(hash, { at: this.clock(), version: this.version, epoch: epochAtLookup, result: { status: "unauthorized" } });
      return { status: "unauthorized" };
    }
    const result = this.recheckExpiry(this.toResult(row));
    this.cache.set(hash, { at: this.clock(), version: this.version, epoch: epochAtLookup, result });
    if (result.status === "ok") {
      this.db
        .prepare(`UPDATE mcpflow_api_key SET last_used_at = ?, last_used_ip = ? WHERE id = ?`)
        .run(nowIso(), ip ?? null, result.agent.keyId);
    }
    return result;
  }

  /** Mint an mf_sess_ token bound to agent+key+project; expiry ≤ key expiry (DB clamps too). */
  createSession(
    agent: Pick<ResolvedAgent, "agentId" | "keyId" | "keyExpiresAt" | "effectiveProjects">,
    projectId: string,
    ttlMs = 12 * 60 * 60 * 1000,
  ): { sessionId: string; token: string; expiresAt: string } {
    if (!agent.effectiveProjects.includes(projectId)) {
      throw new Error(`project not permitted for agent: ${projectId}`);
    }
    const token = SESSION_TOKEN_PREFIX + randomBytes(32).toString("base64url");
    const sessionId = SESSION_ID_PREFIX + randomBytes(12).toString("hex");
    const now = this.clock();
    const expiresAt = new Date(Math.min(now + ttlMs, Date.parse(agent.keyExpiresAt))).toISOString();
    this.db
      .prepare(
        `INSERT INTO mcpflow_session (id, token_hash, agent_id, key_id, project_id, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(sessionId, this.hashSecret(token), agent.agentId, agent.keyId, projectId, new Date(now).toISOString(), expiresAt);
    return { sessionId, token, expiresAt };
  }

  resolveSession(token: string): ResolveResult {
    if (!token.startsWith(SESSION_TOKEN_PREFIX)) return { status: "unknown" };
    const hash = this.hashSecret(token);
    const sess = this.db
      .prepare(`SELECT * FROM mcpflow_resolvable_session WHERE token_hash = ?`)
      .get(hash) as Record<string, unknown> | undefined;
    if (!sess) {
      const exists = this.db.prepare(`SELECT 1 FROM mcpflow_session WHERE token_hash = ?`).get(hash);
      return exists ? { status: "unauthorized" } : { status: "unknown" };
    }
    const row = this.db
      .prepare(`SELECT * FROM mcpflow_resolvable_key WHERE key_id = ?`)
      .get(String(sess.key_id)) as Record<string, unknown> | undefined;
    if (!row) return { status: "unauthorized" };
    const result = this.toResult(row);
    if (result.status !== "ok") return result;
    const project = String(sess.project_id);
    if (!result.agent.effectiveProjects.includes(project)) return { status: "unauthorized" };
    return {
      status: "ok",
      agent: { ...result.agent, sessionId: String(sess.session_id), sessionProject: project },
    };
  }

  effectiveProjects(keyId: string, agentId: string): string[] {
    const keyProjects = this.db
      .prepare(`SELECT project_id FROM mcpflow_api_key_project WHERE key_id = ? ORDER BY project_id`)
      .all(keyId) as Array<{ project_id: string }>;
    const agentProjects = this.db
      .prepare(`SELECT project_id FROM mcpflow_agent_project WHERE agent_id = ? ORDER BY project_id`)
      .all(agentId) as Array<{ project_id: string }>;
    const agentSet = new Set(agentProjects.map((r) => r.project_id));
    // key ∩ agent; key projects are FK-bound to agent projects, intersect anyway (defence in depth)
    const source = keyProjects.length ? keyProjects.map((r) => r.project_id) : [...agentSet];
    return source.filter((p) => agentSet.has(p));
  }

  // ---------- internals ----------

  private toResult(row: Record<string, unknown>): ResolveResult {
    const keyId = String(row.key_id);
    const agentId = String(row.agent_id);
    const effectiveProjects = this.effectiveProjects(keyId, agentId);
    const agent: ResolvedAgent = {
      agentId,
      agentName: String(row.agent_name),
      owner: String(row.owner),
      kind: String(row.kind) as AgentKind,
      isAdmin: Number(row.is_admin) === 1,
      workspaceId: String(row.workspace_id),
      keyId,
      keyPrefix: String(row.prefix),
      keyExpiresAt: String(row.expires_at),
      effectiveProjects,
    };
    // forbidden still carries the identity: the gateway refuses it, but non-project
    // surfaces (approvals, admin) may accept e.g. a human approver with no projects.
    if (!effectiveProjects.length) return { status: "forbidden", reason: "no_projects", agent };
    return { status: "ok", agent };
  }

  private recheckExpiry(result: ResolveResult): ResolveResult {
    if (result.status === "ok" && Date.parse(result.agent.keyExpiresAt) <= this.clock()) {
      return { status: "unauthorized" };
    }
    return result;
  }

  private agentWorkspace(agentId: string): string {
    const r = this.db.prepare(`SELECT workspace_id FROM mcpflow_agent WHERE id = ?`).get(agentId) as
      | { workspace_id: string }
      | undefined;
    if (!r) throw new Error("agent not found");
    return r.workspace_id;
  }

  private keyWorkspace(keyId: string): string {
    const r = this.db
      .prepare(`SELECT a.workspace_id FROM mcpflow_api_key k JOIN mcpflow_agent a ON a.id = k.agent_id WHERE k.id = ?`)
      .get(keyId) as { workspace_id: string } | undefined;
    if (!r) throw new Error("key not found");
    return r.workspace_id;
  }

  /** Lifecycle audit row in the append-only call log (T1.1 §4). */
  private lifecycle(workspaceId: string, actor: string, action: string, detail: Record<string, unknown>): void {
    this.db
      .prepare(
        `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, key_id,
           lifecycle_action, actor, args_redacted)
         VALUES ('lifecycle', ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        newId("lc"),
        workspaceId,
        (detail.agentId as string | undefined) ?? null,
        (detail.keyId as string | undefined) ?? null,
        auditText(action),
        auditActor(actor), // SecOPS 7: shape-checked on write
        JSON.stringify(detail),
      );
  }

  private tx(fn: () => void): void {
    if (this.db.isTransaction) {
      fn();
      return;
    }
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      fn();
      this.db.exec("COMMIT;");
    } catch (err) {
      try {
        this.db.exec("ROLLBACK;");
      } catch {
        /* already rolled back */
      }
      throw err;
    }
  }
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
