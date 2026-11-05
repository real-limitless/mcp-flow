/**
 * Built-in secrets store (Secrets B).
 * Create, list, rotate, and delete return refs and metadata. Plaintext is sealed and wiped.
 * Secret rows are not bound to an upstream URL. Origin-tied credential clears stay on
 * urlOriginChanged in the backend update path. This store does not compare origins.
 */

import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { newId } from "../crypto.js";
import type { KekProvider } from "../crypto/kek.js";
import type { PolicyKeys } from "../identity/dev-keys.js";
import { openSecretValue, sealSecretValue } from "./envelope.js";
import { generateSecret, GeneratorError, type SecretType } from "./generate.js";
import { assertSecretTargetAllowed, ProtectedTargetError, type ProtectedTargets } from "./protected.js";
import { assertSecureDelete, secureReclaim } from "./purge.js";

const NAME = /^[a-z0-9_-]{1,128}$/;
const MAX_GRACE_SECONDS = 30 * 24 * 60 * 60;

export class SecretError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 403 | 404 | 409 = 400,
  ) {
    super(message);
    this.name = "SecretError";
  }
}

export interface SecretActor {
  workspaceId: string;
  keyId: string;
  agentId: string;
  /** null means every project in the workspace (human admin REST). */
  allowedProjects: readonly string[] | null;
  humanAdmin: boolean;
}

export interface SecretCreated {
  ref: string;
  version: number;
  public_part?: string;
}

export interface SecretListItem {
  ref: string;
  name: string;
  project: string;
  type: string;
  imported: boolean;
  current_version: number;
  created_at: string;
  grants: number;
  public_part: string | null;
  versions: Array<{ version: number; state: string; created_at: string }>;
}

interface ActorRow {
  agent_id: string;
  status: string;
  workspace_id: string;
  kind: string;
  is_admin: number;
  agent_status: string;
}

function refOf(project: string, name: string): string {
  return `secret://${project}/${name}`;
}

export function parseSecretRef(ref: string): { project: string; name: string } {
  const text = ref.trim();
  if (!text.startsWith("secret://") || text.includes("@") || text.includes("#")) {
    throw new SecretError("invalid ref");
  }
  const rest = text.slice("secret://".length);
  const slash = rest.indexOf("/");
  if (slash <= 0 || rest.indexOf("/", slash + 1) !== -1) throw new SecretError("invalid ref");
  const project = rest.slice(0, slash);
  const name = rest.slice(slash + 1);
  if (!NAME.test(project) || !NAME.test(name)) throw new SecretError("invalid ref");
  return { project, name };
}

function created(ref: string, version: number, publicPart: string | null): SecretCreated {
  const out: SecretCreated = { ref, version };
  if (publicPart) out.public_part = publicPart;
  return out;
}

export class SecretDirectory {
  constructor(
    private readonly db: DatabaseSync,
    private readonly keys: PolicyKeys,
    private readonly kek: KekProvider | null,
    private readonly protectedTargets: ProtectedTargets,
    private readonly audit?: (event: {
      workspaceId: string;
      keyId: string | null;
      action: string;
      detail: Record<string, unknown>;
    }) => void,
  ) {}

  private kekOrThrow(): KekProvider {
    if (!this.kek) throw new SecretError("KEK provider is not configured", 403);
    return this.kek;
  }

  private actor(input: SecretActor): ActorRow {
    assertSecureDelete(this.db);
    if (this.protectedTargets.invalid) throw new ProtectedTargetError();
    const row = this.db
      .prepare(
        `SELECT k.agent_id, k.status, a.workspace_id, a.kind, a.is_admin, a.status AS agent_status
           FROM mcpflow_api_key k JOIN mcpflow_agent a ON a.id = k.agent_id
          WHERE k.id = ?`,
      )
      .get(input.keyId) as ActorRow | undefined;
    if (!row || row.agent_id !== input.agentId || row.workspace_id !== input.workspaceId) {
      throw new SecretError("secret tools require an agent key", 403);
    }
    if (row.agent_status !== "active" || (row.status !== "active" && row.status !== "rotating")) {
      throw new SecretError("secret tools require an agent key", 403);
    }
    return row;
  }

  /** Create, rotate, and delete are human-admin writes. The row is the check, not the caller flag. */
  private requireHumanAdmin(row: ActorRow): void {
    if (row.kind !== "human" || row.is_admin !== 1) {
      throw new SecretError("human admin required", 403);
    }
  }

  private allowProject(input: SecretActor, project: string): void {
    if (!NAME.test(project)) throw new SecretError("invalid project");
    if (input.allowedProjects && !input.allowedProjects.includes(project)) {
      throw new SecretError("project is not permitted", 403);
    }
  }

  private guardInputs(value: unknown): void {
    try {
      assertSecretTargetAllowed(this.protectedTargets, value);
    } catch (err) {
      if (err instanceof ProtectedTargetError) throw err;
      throw new ProtectedTargetError();
    }
  }

  private writeAudit(input: SecretActor, action: string, detail: Record<string, unknown>): void {
    this.audit?.({ workspaceId: input.workspaceId, keyId: input.keyId, action, detail });
  }

  create(input: SecretActor & {
    project: string;
    name: string;
    type: string;
    params?: unknown;
    description?: string | null;
  }): SecretCreated {
    const actor = this.actor(input);
    this.requireHumanAdmin(actor);
    if (input.type === "import") throw new SecretError("import is not available");
    if (!NAME.test(input.name)) throw new SecretError("invalid name");
    this.allowProject(input, input.project);
    const description = input.description ?? null;
    if (description != null && (typeof description !== "string" || description.length > 512 || /[\r\n\0]/.test(description))) {
      throw new SecretError("invalid description");
    }
    this.guardInputs({ project: input.project, name: input.name, type: input.type, params: input.params ?? {}, description });
    let generated;
    try {
      generated = generateSecret(input.type, input.params ?? {});
    } catch (err) {
      if (err instanceof GeneratorError) throw new SecretError(err.message);
      throw new SecretError("secret operation failed");
    }
    if (generated.value.length > 64 * 1024) {
      generated.value.fill(0);
      throw new SecretError("secret exceeds 64KiB");
    }
    const exact = this.protectedTargets.ids.has(generated.value.toString("utf8"));
    if (exact) {
      generated.value.fill(0);
      throw new SecretError("secret operation failed");
    }
    const secretId = newId("sec");
    const kek = this.kekOrThrow();
    let sealed;
    try {
      sealed = sealSecretValue(kek, this.keys.secretsIndex, {
        workspaceId: input.workspaceId,
        projectId: input.project,
        secretId,
        version: 1,
        value: generated.value,
      });
    } catch {
      throw new SecretError("KEK provider is not configured", 403);
    }
    const now = new Date().toISOString();
    try {
      this.db.exec("BEGIN IMMEDIATE;");
      this.db
        .prepare(
          `INSERT INTO mcpflow_secret (
             id, workspace_id, project_id, name, type, imported, generator_json, current_version,
             description, created_by_key, created_by_agent, created_at
           ) VALUES (?, ?, ?, ?, ?, 0, ?, 1, ?, ?, ?, ?)`,
        )
        .run(
          secretId,
          input.workspaceId,
          input.project,
          input.name,
          generated.type,
          generated.generatorJson,
          description,
          input.keyId,
          input.agentId,
          now,
        );
      this.db
        .prepare(
          `INSERT INTO mcpflow_secret_version (
             secret_id, version, state, ciphertext, wrapped_dek, kek_id, value_hmac, public_part,
             created_at, created_by_key
           ) VALUES (?, 1, 'active', ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          secretId,
          sealed.ciphertext,
          sealed.wrappedDek,
          sealed.kekId,
          sealed.valueHmac,
          generated.publicPart,
          now,
          input.keyId,
        );
      this.db.exec("COMMIT;");
    } catch (err) {
      if (this.db.isTransaction) this.db.exec("ROLLBACK;");
      const message = err instanceof Error ? err.message : "";
      if (/UNIQUE/i.test(message)) throw new SecretError("secret name already exists", 409);
      throw new SecretError("secret operation failed");
    }
    const out = created(refOf(input.project, input.name), 1, generated.publicPart);
    this.writeAudit(input, "secret.create", { ref: out.ref, version: 1, type: generated.type, actor: actor.kind });
    return out;
  }

  list(input: SecretActor & { project?: string | null; q?: string | null }): { secrets: SecretListItem[] } {
    this.actor(input);
    const project = input.project ?? null;
    if (project != null) this.allowProject(input, project);
    const q = input.q ?? null;
    if (q != null && (typeof q !== "string" || q.length > 128)) throw new SecretError("invalid query");
    this.guardInputs({ project, q });
    const projects = input.allowedProjects;
    if (projects && projects.length === 0) return { secrets: [] };
    const params: SQLInputValue[] = [input.workspaceId];
    let sql = `SELECT id, project_id, name, type, imported, current_version, created_at
                 FROM mcpflow_secret
                WHERE workspace_id = ? AND deleted_at IS NULL`;
    if (project) {
      sql += ` AND project_id = ?`;
      params.push(project);
    }
    if (projects) {
      sql += ` AND project_id IN (${projects.map(() => "?").join(",")})`;
      params.push(...projects);
    }
    if (q) {
      sql += ` AND instr(name, ?) > 0`;
      params.push(q);
    }
    sql += ` ORDER BY project_id, name LIMIT 200`;
    const rows = this.db.prepare(sql).all(...params) as Array<{
      id: string;
      project_id: string;
      name: string;
      type: string;
      imported: number;
      current_version: number;
      created_at: string;
    }>;
    const versions = this.db.prepare(
      `SELECT version, state, created_at, public_part FROM mcpflow_secret_version
        WHERE secret_id = ? ORDER BY version`,
    );
    const grants = this.db.prepare(
      `SELECT count(*) AS n FROM mcpflow_secret_grant
        WHERE workspace_id = ? AND revoked_at IS NULL AND (ref_pattern = ? OR ref_pattern = ?)`,
    );
    const secrets: SecretListItem[] = rows.map((row) => {
      const vers = versions.all(row.id) as Array<{ version: number; state: string; created_at: string; public_part: string | null }>;
      const active = vers.find((item) => item.state === "active");
      const ref = refOf(row.project_id, row.name);
      const grantRow = grants.get(input.workspaceId, ref, `secret://${row.project_id}/*`) as { n: number };
      return {
        ref,
        name: row.name,
        project: row.project_id,
        type: row.type,
        imported: row.imported === 1,
        current_version: row.current_version,
        created_at: row.created_at,
        grants: Number(grantRow.n),
        public_part: active?.public_part ?? null,
        versions: vers.map((item) => ({ version: item.version, state: item.state, created_at: item.created_at })),
      };
    });
    this.writeAudit(input, "secret.list", { count: secrets.length, project });
    return { secrets };
  }

  rotate(input: SecretActor & { ref: string; graceSeconds?: number | null; resync?: boolean }): SecretCreated {
    this.requireHumanAdmin(this.actor(input));
    if (input.resync) throw new SecretError("resync is not available");
    if (input.graceSeconds != null) {
      if (!Number.isInteger(input.graceSeconds) || input.graceSeconds < 0 || input.graceSeconds > MAX_GRACE_SECONDS) {
        throw new SecretError("grace_seconds is invalid");
      }
    }
    this.guardInputs({ ref: input.ref });
    const parsed = parseSecretRef(input.ref);
    this.allowProject(input, parsed.project);
    const secret = this.liveSecret(input.workspaceId, parsed.project, parsed.name);
    const params = JSON.parse(String(secret.generator_json)) as unknown;
    let generated;
    try {
      generated = generateSecret(secret.type as SecretType, params);
    } catch (err) {
      if (err instanceof GeneratorError) throw new SecretError(err.message);
      throw new SecretError("secret operation failed");
    }
    const version = Number(secret.current_version) + 1;
    const kek = this.kekOrThrow();
    let sealed;
    try {
      sealed = sealSecretValue(kek, this.keys.secretsIndex, {
        workspaceId: input.workspaceId,
        projectId: parsed.project,
        secretId: String(secret.id),
        version,
        value: generated.value,
      });
    } catch {
      throw new SecretError("KEK provider is not configured", 403);
    }
    const now = new Date().toISOString();
    try {
      this.db.exec("BEGIN IMMEDIATE;");
      this.db
        .prepare(`UPDATE mcpflow_secret_version SET state = 'previous' WHERE secret_id = ? AND state = 'active'`)
        .run(secret.id);
      this.db
        .prepare(
          `INSERT INTO mcpflow_secret_version (
             secret_id, version, state, ciphertext, wrapped_dek, kek_id, value_hmac, public_part,
             created_at, created_by_key
           ) VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          secret.id,
          version,
          sealed.ciphertext,
          sealed.wrappedDek,
          sealed.kekId,
          sealed.valueHmac,
          generated.publicPart,
          now,
          input.keyId,
        );
      this.db.prepare(`UPDATE mcpflow_secret SET current_version = ? WHERE id = ?`).run(version, secret.id);
      this.db.exec("COMMIT;");
    } catch {
      if (this.db.isTransaction) this.db.exec("ROLLBACK;");
      throw new SecretError("secret operation failed");
    }
    const out = created(refOf(parsed.project, parsed.name), version, generated.publicPart);
    this.writeAudit(input, "secret.rotate", { ref: out.ref, version });
    return out;
  }

  delete(input: SecretActor & { ref: string; purge?: boolean }): { ref: string; deleted: true; purged?: true } {
    this.requireHumanAdmin(this.actor(input));
    this.guardInputs({ ref: input.ref, purge: input.purge === true });
    const parsed = parseSecretRef(input.ref);
    this.allowProject(input, parsed.project);
    const secret = this.liveSecret(input.workspaceId, parsed.project, parsed.name);
    const purge = input.purge === true;
    const now = new Date().toISOString();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      if (purge) {
        this.db
          .prepare(
            `UPDATE mcpflow_secret_version
                SET state = 'destroyed', ciphertext = NULL, wrapped_dek = NULL, destroyed_at = ?
              WHERE secret_id = ? AND state <> 'destroyed'`,
          )
          .run(now, secret.id);
      }
      this.db
        .prepare(`UPDATE mcpflow_secret SET deleted_at = ? WHERE id = ? AND deleted_at IS NULL`)
        .run(now, secret.id);
      this.db.exec("COMMIT;");
    } catch {
      if (this.db.isTransaction) this.db.exec("ROLLBACK;");
      throw new SecretError("secret operation failed");
    }
    if (purge) secureReclaim(this.db);
    const ref = refOf(parsed.project, parsed.name);
    this.writeAudit(input, purge ? "secret.purge" : "secret.delete", { ref });
    return purge ? { ref, deleted: true, purged: true } : { ref, deleted: true };
  }

  /** Round-trip used by tests. Not exposed as a tool. */
  openForTest(input: { workspaceId: string; project: string; name: string; version: number }): Buffer {
    const secret = this.db
      .prepare(
        `SELECT id FROM mcpflow_secret WHERE workspace_id = ? AND project_id = ? AND name = ?`,
      )
      .get(input.workspaceId, input.project, input.name) as { id: string } | undefined;
    if (!secret) throw new SecretError("secret not found", 404);
    const row = this.db
      .prepare(
        `SELECT ciphertext, wrapped_dek, kek_id FROM mcpflow_secret_version WHERE secret_id = ? AND version = ?`,
      )
      .get(secret.id, input.version) as { ciphertext: Buffer | null; wrapped_dek: Buffer | null; kek_id: string } | undefined;
    if (!row?.ciphertext || !row.wrapped_dek) throw new SecretError("secret not found", 404);
    return openSecretValue(this.kekOrThrow(), {
      workspaceId: input.workspaceId,
      projectId: input.project,
      secretId: secret.id,
      version: input.version,
      ciphertext: Buffer.from(row.ciphertext),
      wrappedDek: Buffer.from(row.wrapped_dek),
      kekId: row.kek_id,
    });
  }

  private liveSecret(workspaceId: string, project: string, name: string): {
    id: string;
    type: string;
    generator_json: string;
    current_version: number;
    deleted_at: string | null;
  } {
    const row = this.db
      .prepare(
        `SELECT id, type, generator_json, current_version, deleted_at
           FROM mcpflow_secret WHERE workspace_id = ? AND project_id = ? AND name = ?`,
      )
      .get(workspaceId, project, name) as {
        id: string;
        type: string;
        generator_json: string;
        current_version: number;
        deleted_at: string | null;
      } | undefined;
    if (!row || row.deleted_at) throw new SecretError("secret not found", 404);
    return row;
  }
}
