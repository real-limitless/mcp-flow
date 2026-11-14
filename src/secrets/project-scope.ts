/**
 * Project-scoped secret self-service (issue #74).
 * A key with secrets_project_write may generate, rotate, and bind secrets
 * for its own projects. The flag is off until a human admin sets it.
 * Upload tickets store a token hash only. Approvals store refs only.
 * No method returns a secret value.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { newId } from "../crypto.js";
import type { SecretActor, SecretCreated, SecretDirectory, SecretListItem } from "./directory.js";
import { parseSecretRef, SecretError } from "./directory.js";
import { ProtectedTargetError, type ProtectedTargets } from "./protected.js";

const NAME = /^[a-z0-9_-]{1,128}$/;
const SLUG = /^[A-Za-z0-9_.:-]{1,64}$/;
const COMPOSE = /^[A-Za-z0-9_.:-]{1,128}$/;
const APPROVAL_TTL_MS = 24 * 60 * 60 * 1000;
const MIN_IMPORT_CHARS = 12;
const MIN_IMPORT_BITS = 64;

export interface ProjectCaller {
  workspaceId: string;
  keyId: string;
  agentId: string;
  allowedProjects: readonly string[] | null;
}

export interface ProjectSecretOptions {
  quota: number;
  uploadTtlSec: number;
  productionApproval: boolean;
  publicUrl: string;
}

export interface RegisteredTarget {
  id: string;
  project: string;
  backend: string;
  compose_id: string;
  tier: "DEVELOPMENT" | "PRODUCTION";
  revoked_at: string | null;
}

export interface UploadIssued {
  ticket_id: string;
  project: string;
  name: string;
  expires_at: string;
  upload_path: string;
  upload_url: string;
  /** Present when MCP_FLOW_PUBLIC_URL is unset, so the link is a path on this gateway. */
  hint?: string;
}

interface AuditFn {
  (event: { workspaceId: string; keyId: string | null; action: string; detail: Record<string, unknown> }): void;
}

function sha256(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function tokensEqual(storedHex: string, token: string): boolean {
  const a = Buffer.from(storedHex, "utf8");
  const b = Buffer.from(sha256(token), "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Shannon bits, capped by a character-class bound. */
export function estimateImportBits(value: string): number {
  if (value.length === 0) return 0;
  const freq = new Map<string, number>();
  let classes = 0;
  let lower = false;
  let upper = false;
  let digit = false;
  let other = false;
  for (const ch of value) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
    if (/[a-z]/.test(ch)) lower = true;
    else if (/[A-Z]/.test(ch)) upper = true;
    else if (/[0-9]/.test(ch)) digit = true;
    else other = true;
  }
  classes = Number(lower) + Number(upper) + Number(digit) + Number(other);
  const alphabet = classes <= 1 ? 26 : classes === 2 ? 36 : classes === 3 ? 62 : 95;
  let shannon = 0;
  for (const n of freq.values()) {
    const p = n / value.length;
    shannon -= p * Math.log2(p);
  }
  return Math.min(shannon * value.length, value.length * Math.log2(alphabet));
}

export function assertImportEntropy(value: string): void {
  if (value.length < MIN_IMPORT_CHARS || estimateImportBits(value) < MIN_IMPORT_BITS) {
    throw new SecretError("import is below the entropy floor");
  }
  if (/[\r\n\0]/.test(value)) throw new SecretError("import contains a forbidden character");
}

export class ProjectSecretDirectory {
  constructor(
    private readonly db: DatabaseSync,
    private readonly secrets: SecretDirectory,
    private readonly protectedTargets: ProtectedTargets,
    private readonly options: ProjectSecretOptions,
    private readonly audit: AuditFn,
  ) {}

  productionApproval(): boolean {
    return this.options.productionApproval;
  }

  private auditOf(caller: { workspaceId: string; keyId: string }, action: string, detail: Record<string, unknown>): void {
    this.audit({ workspaceId: caller.workspaceId, keyId: caller.keyId, action, detail });
  }

  private humanAdmin(input: SecretActor): void {
    const row = this.db
      .prepare(
        `SELECT a.kind, a.is_admin, k.status, a.status AS agent_status
           FROM mcpflow_api_key k JOIN mcpflow_agent a ON a.id = k.agent_id
          WHERE k.id = ? AND k.agent_id = ? AND a.workspace_id = ?`,
      )
      .get(input.keyId, input.agentId, input.workspaceId) as
      | { kind: string; is_admin: number; status: string; agent_status: string }
      | undefined;
    if (!row || row.agent_status !== "active" || (row.status !== "active" && row.status !== "rotating")) {
      throw new SecretError("human admin required", 403);
    }
    if (row.kind !== "human" || row.is_admin !== 1) throw new SecretError("human admin required", 403);
  }

  private scopeOn(keyId: string): boolean {
    const row = this.db
      .prepare(`SELECT secrets_project_write AS n FROM mcpflow_api_key WHERE id = ?`)
      .get(keyId) as { n: number } | undefined;
    return row?.n === 1;
  }

  private requireScope(caller: ProjectCaller): void {
    if (!this.scopeOn(caller.keyId)) {
      this.auditOf(caller, "project_secret.denied", { reason: "scope" });
      throw new SecretError("secrets:project:write is not enabled for this key", 403);
    }
  }

  private projectOf(caller: ProjectCaller, requested: string | null): string {
    const projects = caller.allowedProjects ?? [];
    if (projects.length === 0) {
      this.auditOf(caller, "project_secret.denied", { reason: "cross_project" });
      throw new SecretError("project is not permitted", 403);
    }
    if (requested) {
      if (!NAME.test(requested) || !projects.includes(requested)) {
        this.auditOf(caller, "project_secret.denied", { reason: "cross_project", project: requested });
        throw new SecretError("project is not permitted", 403);
      }
      return requested;
    }
    if (projects.length === 1) return projects[0]!;
    throw new SecretError("project is required");
  }

  private countTowardQuota(workspaceId: string, project: string): number {
    const secrets = this.db
      .prepare(
        `SELECT count(*) AS n FROM mcpflow_secret
          WHERE workspace_id = ? AND project_id = ? AND deleted_at IS NULL`,
      )
      .get(workspaceId, project) as { n: number };
    const now = new Date().toISOString();
    const pending = this.db
      .prepare(
        `SELECT count(*) AS n FROM mcpflow_secret_upload
          WHERE workspace_id = ? AND project_id = ? AND consumed_at IS NULL AND expires_at > ?`,
      )
      .get(workspaceId, project, now) as { n: number };
    return Number(secrets.n) + Number(pending.n);
  }

  private assertQuota(caller: ProjectCaller, project: string): void {
    if (this.countTowardQuota(caller.workspaceId, project) >= this.options.quota) {
      this.auditOf(caller, "project_secret.denied", { reason: "quota", project });
      throw new SecretError("project secret quota exceeded", 403);
    }
  }

  private actor(caller: ProjectCaller): SecretActor {
    return {
      workspaceId: caller.workspaceId,
      keyId: caller.keyId,
      agentId: caller.agentId,
      allowedProjects: caller.allowedProjects,
      humanAdmin: false,
    };
  }

  create(caller: ProjectCaller, input: {
    project: string | null;
    name: string;
    type: string;
    params?: unknown;
    description?: string | null;
  }): SecretCreated & { name: string; project: string; type: string } {
    this.requireScope(caller);
    const project = this.projectOf(caller, input.project);
    if (!NAME.test(input.name)) throw new SecretError("invalid name");
    this.assertQuota(caller, project);
    const created = this.secrets.createForProjectKey({
      ...this.actor(caller),
      project,
      name: input.name,
      type: input.type,
      params: input.params,
      description: input.description ?? null,
    });
    this.auditOf(caller, "project_secret.create", {
      ref: created.ref,
      version: created.version,
      project,
      name: input.name,
      type: input.type,
    });
    return { ...created, name: input.name, project, type: input.type };
  }

  rotate(caller: ProjectCaller, ref: string): SecretCreated {
    this.requireScope(caller);
    let project = "";
    try {
      project = parseSecretRef(ref.trim().split("@")[0]!.split("#")[0]!).project;
    } catch {
      throw new SecretError("invalid ref");
    }
    this.projectOf(caller, project);
    const created = this.secrets.rotateForProjectKey({ ...this.actor(caller), ref });
    this.auditOf(caller, "project_secret.rotate", { ref: created.ref, version: created.version });
    return created;
  }

  list(caller: ProjectCaller, project: string | null, q: string | null): { secrets: SecretListItem[] } {
    this.requireScope(caller);
    const projects = caller.allowedProjects ?? [];
    if (project) this.projectOf(caller, project);
    const out = this.secrets.listForProjects({
      workspaceId: caller.workspaceId,
      keyId: caller.keyId,
      project,
      q,
      allowedProjects: projects,
    });
    return out;
  }

  issueUpload(caller: ProjectCaller, input: {
    project: string | null;
    name: string;
    description?: string | null;
  }): UploadIssued {
    this.requireScope(caller);
    const project = this.projectOf(caller, input.project);
    if (!NAME.test(input.name)) throw new SecretError("invalid name");
    const description = input.description ?? null;
    if (description != null && (description.length > 512 || /[\r\n\0]/.test(description))) {
      throw new SecretError("invalid description");
    }
    this.assertQuota(caller, project);
    const token = randomBytes(32).toString("base64url");
    const id = newId("upl");
    const now = new Date();
    const expires = new Date(now.getTime() + this.options.uploadTtlSec * 1000).toISOString();
    this.db
      .prepare(
        `INSERT INTO mcpflow_secret_upload (
           id, workspace_id, project_id, name, description, token_hash,
           created_by_key, created_by_agent, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        caller.workspaceId,
        project,
        input.name,
        description,
        sha256(token),
        caller.keyId,
        caller.agentId,
        now.toISOString(),
        expires,
      );
    const uploadPath = `/secret-uploads/${id}`;
    const origin = this.options.publicUrl.replace(/\/$/, "");
    const uploadUrl = `${origin}${uploadPath}#${encodeURIComponent(token)}`;
    this.auditOf(caller, "project_secret.upload_issued", {
      ticket_id: id,
      project,
      name: input.name,
      expires_at: expires,
    });
    const issued: UploadIssued = {
      ticket_id: id,
      project,
      name: input.name,
      expires_at: expires,
      upload_path: uploadPath,
      upload_url: uploadUrl,
    };
    if (!origin) {
      issued.hint = "Open upload_url on this gateway's origin. Set MCP_FLOW_PUBLIC_URL to mint an absolute link.";
    }
    return issued;
  }

  uploadPage(id: string): { project: string; name: string; expires_at: string } | null {
    if (!/^upl_[0-9a-f]{24}$/.test(id)) return null;
    const row = this.db
      .prepare(
        `SELECT project_id, name, expires_at, consumed_at FROM mcpflow_secret_upload WHERE id = ?`,
      )
      .get(id) as { project_id: string; name: string; expires_at: string; consumed_at: string | null } | undefined;
    if (!row || row.consumed_at) return null;
    if (row.expires_at <= new Date().toISOString()) return null;
    return { project: row.project_id, name: row.name, expires_at: row.expires_at };
  }

  consumeUpload(id: string, token: string, value: string): { ref: string; version: number; name: string; project: string } {
    if (!/^upl_[0-9a-f]{24}$/.test(id) || typeof token !== "string" || token.length < 20 || token.length > 128) {
      throw new SecretError("upload link not found", 404);
    }
    assertImportEntropy(value);
    const buf = Buffer.from(value, "utf8");
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      const row = this.db
        .prepare(
          `SELECT workspace_id, project_id, name, description, token_hash, created_by_key, created_by_agent,
                  expires_at, consumed_at
             FROM mcpflow_secret_upload WHERE id = ?`,
        )
        .get(id) as
        | {
            workspace_id: string;
            project_id: string;
            name: string;
            description: string | null;
            token_hash: string;
            created_by_key: string;
            created_by_agent: string;
            expires_at: string;
            consumed_at: string | null;
          }
        | undefined;
      if (!row || !tokensEqual(row.token_hash, token)) {
        throw new SecretError("upload link not found", 404);
      }
      if (row.consumed_at) throw new SecretError("upload link already used", 409);
      if (row.expires_at <= new Date().toISOString()) throw new SecretError("upload link expired", 400);
      const created = this.secrets.storeImported({
        workspaceId: row.workspace_id,
        keyId: row.created_by_key,
        agentId: row.created_by_agent,
        allowedProjects: [row.project_id],
        humanAdmin: false,
        project: row.project_id,
        name: row.name,
        description: row.description,
        value: buf,
      });
      const now = new Date().toISOString();
      const secretRowId = this.secretId(row.workspace_id, row.project_id, row.name);
      const updated = this.db
        .prepare(
          `UPDATE mcpflow_secret_upload
              SET consumed_at = ?, secret_id = ?
            WHERE id = ? AND consumed_at IS NULL`,
        )
        .run(now, secretRowId, id);
      if (Number(updated.changes ?? 0) !== 1) throw new SecretError("upload link already used", 409);
      this.db.exec("COMMIT;");
      this.auditOf(
        { workspaceId: row.workspace_id, keyId: row.created_by_key },
        "project_secret.upload_consumed",
        { ticket_id: id, ref: created.ref, version: created.version, project: row.project_id, name: row.name },
      );
      return { ref: created.ref, version: created.version, name: row.name, project: row.project_id };
    } catch (err) {
      if (this.db.isTransaction) this.db.exec("ROLLBACK;");
      throw err;
    } finally {
      buf.fill(0);
    }
  }

  private secretId(workspaceId: string, project: string, name: string): string | null {
    const row = this.db
      .prepare(`SELECT id FROM mcpflow_secret WHERE workspace_id = ? AND project_id = ? AND name = ?`)
      .get(workspaceId, project, name) as { id: string } | undefined;
    return row?.id ?? null;
  }

  setScope(actor: SecretActor, keyId: string, enabled: boolean): { key_id: string; secrets_project_write: boolean } {
    this.humanAdmin(actor);
    if (!/^key_[0-9a-f]{24}$/.test(keyId)) throw new SecretError("key not found", 404);
    const row = this.db
      .prepare(
        `SELECT k.id FROM mcpflow_api_key k JOIN mcpflow_agent a ON a.id = k.agent_id
          WHERE k.id = ? AND a.workspace_id = ?`,
      )
      .get(keyId, actor.workspaceId) as { id: string } | undefined;
    if (!row) throw new SecretError("key not found", 404);
    this.db.prepare(`UPDATE mcpflow_api_key SET secrets_project_write = ? WHERE id = ?`).run(enabled ? 1 : 0, keyId);
    this.auditOf(actor, "project_secret.scope", { key_id: keyId, enabled });
    return { key_id: keyId, secrets_project_write: enabled };
  }

  registerTarget(actor: SecretActor, input: {
    project: string;
    backend: string;
    composeId: string;
    tier: string;
  }): { target_id: string; tier: "DEVELOPMENT" | "PRODUCTION" } {
    this.humanAdmin(actor);
    if (!NAME.test(input.project)) throw new SecretError("invalid project");
    if (!SLUG.test(input.backend)) throw new SecretError("invalid backend");
    if (!COMPOSE.test(input.composeId)) throw new SecretError("invalid compose_id");
    if (input.tier !== "DEVELOPMENT" && input.tier !== "PRODUCTION") throw new SecretError("tier must be DEVELOPMENT or PRODUCTION");
    if (this.protectedTargets.invalid || this.protectedTargets.ids.has(input.composeId)) {
      this.auditOf(actor, "project_secret.denied", { reason: "protected", compose_id: input.composeId });
      throw new ProtectedTargetError();
    }
    const existing = this.db
      .prepare(
        `SELECT id FROM mcpflow_project_env_target
          WHERE workspace_id = ? AND project_id = ? AND backend_slug = ? AND compose_id = ?`,
      )
      .get(actor.workspaceId, input.project, input.backend, input.composeId) as { id: string } | undefined;
    const now = new Date().toISOString();
    let id = existing?.id;
    if (id) {
      this.db
        .prepare(`UPDATE mcpflow_project_env_target SET tier = ?, revoked_at = NULL WHERE id = ?`)
        .run(input.tier, id);
    } else {
      id = newId("etg");
      this.db
        .prepare(
          `INSERT INTO mcpflow_project_env_target (
             id, workspace_id, project_id, backend_slug, compose_id, tier, created_by_key, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(id, actor.workspaceId, input.project, input.backend, input.composeId, input.tier, actor.keyId, now);
    }
    this.auditOf(actor, "project_secret.target_register", {
      target_id: id,
      project: input.project,
      backend: input.backend,
      compose_id: input.composeId,
      tier: input.tier,
    });
    return { target_id: id, tier: input.tier };
  }

  listTargets(actor: SecretActor, project: string | null): { targets: RegisteredTarget[] } {
    this.humanAdmin(actor);
    const params: string[] = [actor.workspaceId];
    let sql = `SELECT id, project_id, backend_slug, compose_id, tier, revoked_at
                 FROM mcpflow_project_env_target WHERE workspace_id = ?`;
    if (project) {
      if (!NAME.test(project)) throw new SecretError("invalid project");
      sql += ` AND project_id = ?`;
      params.push(project);
    }
    sql += ` ORDER BY project_id, backend_slug, compose_id`;
    const rows = this.db.prepare(sql).all(...params) as Array<{
      id: string;
      project_id: string;
      backend_slug: string;
      compose_id: string;
      tier: "DEVELOPMENT" | "PRODUCTION";
      revoked_at: string | null;
    }>;
    return {
      targets: rows.map((row) => ({
        id: row.id,
        project: row.project_id,
        backend: row.backend_slug,
        compose_id: row.compose_id,
        tier: row.tier,
        revoked_at: row.revoked_at,
      })),
    };
  }

  revokeTarget(actor: SecretActor, targetId: string): { revoked: true } {
    this.humanAdmin(actor);
    const now = new Date().toISOString();
    const res = this.db
      .prepare(
        `UPDATE mcpflow_project_env_target SET revoked_at = ?
          WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL`,
      )
      .run(now, targetId, actor.workspaceId);
    if (Number(res.changes ?? 0) !== 1) throw new SecretError("target not found", 404);
    this.auditOf(actor, "project_secret.target_revoke", { target_id: targetId });
    return { revoked: true };
  }

  /** Registration row only. Does not check the key scope. */
  activeTarget(input: {
    workspaceId: string;
    project: string;
    backend: string;
    composeId: string;
  }): { tier: "DEVELOPMENT" | "PRODUCTION" } | null {
    if (this.protectedTargets.invalid || this.protectedTargets.ids.has(input.composeId)) return null;
    const row = this.db
      .prepare(
        `SELECT tier FROM mcpflow_project_env_target
          WHERE workspace_id = ? AND project_id = ? AND backend_slug = ? AND compose_id = ?
            AND revoked_at IS NULL`,
      )
      .get(input.workspaceId, input.project, input.backend, input.composeId) as
      | { tier: "DEVELOPMENT" | "PRODUCTION" }
      | undefined;
    return row ?? null;
  }

  /** Active registration for a key that holds secrets:project:write. Null when either is missing. */
  registeredTarget(input: {
    workspaceId: string;
    keyId: string;
    project: string;
    backend: string;
    composeId: string;
  }): { tier: "DEVELOPMENT" | "PRODUCTION" } | null {
    if (!this.scopeOn(input.keyId)) return null;
    return this.activeTarget(input);
  }

  queueApproval(input: {
    caller: ProjectCaller;
    project: string;
    backend: string;
    composeId: string;
    envKey: string;
    action: "set" | "unset" | "resync";
    ref: string;
    version: number;
    privateRef: boolean;
  }): { approval_id: string; expires_at: string } {
    const id = newId("psa");
    const now = new Date();
    const expires = new Date(now.getTime() + APPROVAL_TTL_MS).toISOString();
    this.db
      .prepare(
        `INSERT INTO mcpflow_project_secret_approval (
           id, workspace_id, project_id, key_id, agent_id, backend_slug, compose_id, env_key,
           action, ref, version, private, state, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      )
      .run(
        id,
        input.caller.workspaceId,
        input.project,
        input.caller.keyId,
        input.caller.agentId,
        input.backend,
        input.composeId,
        input.envKey,
        input.action,
        input.action === "unset" ? "" : input.ref,
        input.version,
        input.privateRef ? 1 : 0,
        now.toISOString(),
        expires,
      );
    this.auditOf(input.caller, "project_secret.approval_requested", {
      approval_id: id,
      project: input.project,
      backend: input.backend,
      compose_id: input.composeId,
      env_key: input.envKey,
      action: input.action,
      ref: input.action === "unset" ? null : input.ref,
      version: input.version,
      expires_at: expires,
    });
    return { approval_id: id, expires_at: expires };
  }

  loadApproval(workspaceId: string, approvalId: string): {
    id: string;
    project: string;
    backend: string;
    compose_id: string;
    env_key: string;
    action: "set" | "unset" | "resync";
    ref: string;
    version: number;
    private: boolean;
    state: string;
    expires_at: string;
  } {
    const row = this.db
      .prepare(
        `SELECT id, project_id, backend_slug, compose_id, env_key, action, ref, version, private, state, expires_at
           FROM mcpflow_project_secret_approval WHERE id = ? AND workspace_id = ?`,
      )
      .get(approvalId, workspaceId) as
      | {
          id: string;
          project_id: string;
          backend_slug: string;
          compose_id: string;
          env_key: string;
          action: "set" | "unset" | "resync";
          ref: string;
          version: number;
          private: number;
          state: string;
          expires_at: string;
        }
      | undefined;
    if (!row) throw new SecretError("approval not found", 404);
    return {
      id: row.id,
      project: row.project_id,
      backend: row.backend_slug,
      compose_id: row.compose_id,
      env_key: row.env_key,
      action: row.action,
      ref: row.ref,
      version: row.version,
      private: row.private === 1,
      state: row.state,
      expires_at: row.expires_at,
    };
  }

  markApproval(actor: SecretActor, approvalId: string, state: "approved" | "denied" | "expired"): void {
    const now = new Date().toISOString();
    const res = this.db
      .prepare(
        `UPDATE mcpflow_project_secret_approval
            SET state = ?, decided_at = ?, decided_by_key = ?
          WHERE id = ? AND workspace_id = ? AND state = 'pending'`,
      )
      .run(state, now, actor.keyId, approvalId, actor.workspaceId);
    if (Number(res.changes ?? 0) !== 1) throw new SecretError("approval not found", 404);
    this.auditOf(actor, "project_secret.approval_decided", { approval_id: approvalId, state });
  }
}
