import type { DatabaseSync } from "node:sqlite";
import { newId } from "../crypto.js";
import type { SecretActor } from "./directory.js";
import { ProtectedTargetError, type ProtectedTargets } from "./protected.js";

export class EnvGrantError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 403 | 404 = 400,
  ) {
    super(message);
    this.name = "EnvGrantError";
  }
}

export interface EnvGrant {
  id: string;
  project: string;
  backend: string;
  targets: string[];
  created_at: string;
  revoked_at: string | null;
}

export class EnvGrantDirectory {
  constructor(
    private readonly db: DatabaseSync,
    private readonly protectedTargets: ProtectedTargets,
  ) {}

  private actor(row: { kind: string; is_admin: number; status: string; agent_status: string } | undefined): void {
    if (!row || row.agent_status !== "active" || (row.status !== "active" && row.status !== "rotating")) {
      throw new EnvGrantError("env grant tools require an agent key", 403);
    }
    if (row.kind !== "human" || row.is_admin !== 1) {
      throw new EnvGrantError("human admin required", 403);
    }
  }

  private loadActor(input: SecretActor): { kind: string; is_admin: number; status: string; agent_status: string } {
    const row = this.db
      .prepare(
        `SELECT a.kind, a.is_admin, k.status, a.status AS agent_status
           FROM mcpflow_api_key k JOIN mcpflow_agent a ON a.id = k.agent_id
          WHERE k.id = ? AND k.agent_id = ? AND a.workspace_id = ?`,
      )
      .get(input.keyId, input.agentId, input.workspaceId) as
      | { kind: string; is_admin: number; status: string; agent_status: string }
      | undefined;
    return row as { kind: string; is_admin: number; status: string; agent_status: string };
  }

  private guardProtected(ids: string[]): void {
    if (this.protectedTargets.invalid) throw new ProtectedTargetError();
    for (const id of ids) {
      if (this.protectedTargets.ids.has(id)) throw new ProtectedTargetError();
    }
  }

  create(input: {
    actor: SecretActor;
    keyId?: string | null;
    agentId?: string | null;
    project: string;
    backend: string;
    composeIds: string[];
  }): { sinkId: string; grantId: string } {
    const actorRow = this.loadActor(input.actor);
    this.actor(actorRow);
    if (input.actor.allowedProjects && !input.actor.allowedProjects.includes(input.project)) {
      throw new EnvGrantError("project is not permitted", 403);
    }
    if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(input.backend)) throw new EnvGrantError("invalid backend");
    if (!Array.isArray(input.composeIds) || input.composeIds.length === 0) {
      throw new EnvGrantError("compose_ids is required");
    }
    this.guardProtected(input.composeIds);
    const granteeKey = input.keyId ?? null;
    const granteeAgent = input.agentId ?? null;
    if ((granteeKey == null) === (granteeAgent == null)) {
      throw new EnvGrantError("exactly one of key_id or agent_id is required");
    }
    const sinkId = newId("snk");
    const grantId = newId("sgr");
    const refPattern = `secret://${input.project}/*`;
    const now = new Date().toISOString();
    this.db.exec("BEGIN IMMEDIATE;");
    try {
      this.db
        .prepare(
          `INSERT INTO mcpflow_secret_sink (
             id, workspace_id, backend_slug, tool, field_path, target_field, targets_json, encoding, created_by_key, created_at
           ) VALUES (?, ?, ?, 'compose-saveEnvironment', 'env', 'composeId', ?, 'env-text', ?, ?)`,
        )
        .run(
          sinkId,
          input.actor.workspaceId,
          input.backend,
          JSON.stringify(input.composeIds),
          input.actor.keyId,
          now,
        );
      this.db
        .prepare(
          `INSERT INTO mcpflow_secret_grant (
             id, workspace_id, key_id, agent_id, ref_pattern, sink_id, created_by_key, created_at
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          grantId,
          input.actor.workspaceId,
          granteeKey,
          granteeAgent,
          refPattern,
          sinkId,
          input.actor.keyId,
          now,
        );
      this.db.exec("COMMIT;");
    } catch (err) {
      if (this.db.isTransaction) this.db.exec("ROLLBACK;");
      throw new EnvGrantError("grant operation failed");
    }
    return { sinkId, grantId };
  }

  list(input: { actor: SecretActor; project?: string | null }): EnvGrant[] {
    const actorRow = this.loadActor(input.actor);
    this.actor(actorRow);
    let sql = `SELECT s.id AS sink_id, s.backend_slug, s.targets_json, s.created_at AS sink_created,
                      g.id AS grant_id, g.ref_pattern, g.created_at AS grant_created, g.revoked_at
                 FROM mcpflow_secret_grant g JOIN mcpflow_secret_sink s ON s.id = g.sink_id
                WHERE g.workspace_id = ?`;
    const params: (string | null)[] = [input.actor.workspaceId];
    if (input.project) {
      sql += ` AND g.ref_pattern = ?`;
      params.push(`secret://${input.project}/*`);
    }
    sql += ` ORDER BY g.created_at DESC`;
    const rows = this.db.prepare(sql).all(...params) as Array<{
      sink_id: string;
      backend_slug: string;
      targets_json: string;
      grant_created: string;
      grant_id: string;
      ref_pattern: string;
      revoked_at: string | null;
    }>;
    return rows.map((r) => {
      let targets: string[] = [];
      try {
        targets = JSON.parse(r.targets_json) as string[];
      } catch {
        targets = [];
      }
      const project = r.ref_pattern.slice("secret://".length, -2); // strip trailing /*
      return {
        id: r.grant_id,
        project,
        backend: r.backend_slug,
        targets,
        created_at: r.grant_created,
        revoked_at: r.revoked_at,
      };
    });
  }

  revoke(input: { actor: SecretActor; grantId: string }): { revoked: true } {
    const actorRow = this.loadActor(input.actor);
    this.actor(actorRow);
    const now = new Date().toISOString();
    const res = this.db
      .prepare(`UPDATE mcpflow_secret_grant SET revoked_at = ? WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL`)
      .run(now, input.grantId, input.actor.workspaceId);
    if (Number(res.changes ?? 0) === 0) throw new EnvGrantError("grant not found", 404);
    return { revoked: true };
  }

  check(input: {
    workspaceId: string;
    keyId: string;
    agentId: string;
    project: string;
    backend: string;
    composeId: string;
  }): boolean {
    if (this.protectedTargets.invalid) return false;
    if (this.protectedTargets.ids.has(input.composeId)) return false;
    // Human admin passes without a grant.
    const row = this.db
      .prepare(
        `SELECT a.kind, a.is_admin, k.status, a.status AS agent_status
           FROM mcpflow_api_key k JOIN mcpflow_agent a ON a.id = k.agent_id
          WHERE k.id = ? AND k.agent_id = ? AND a.workspace_id = ?`,
      )
      .get(input.keyId, input.agentId, input.workspaceId) as
      | { kind: string; is_admin: number; status: string; agent_status: string }
      | undefined;
    if (row && row.agent_status === "active" && (row.status === "active" || row.status === "rotating")) {
      if (row.kind === "human" && row.is_admin === 1) return true;
    }
    const refPattern = `secret://${input.project}/*`;
    const rows = this.db
      .prepare(
        `SELECT g.key_id, g.agent_id, g.ref_pattern, s.backend_slug, s.targets_json, g.revoked_at
           FROM mcpflow_secret_grant g JOIN mcpflow_secret_sink s ON s.id = g.sink_id
          WHERE g.workspace_id = ? AND g.revoked_at IS NULL
            AND (g.key_id = ? OR g.agent_id = ?)
            AND g.ref_pattern = ? AND s.backend_slug = ?`,
      )
      .all(input.workspaceId, input.keyId, input.agentId, refPattern, input.backend) as Array<{
      key_id: string | null;
      agent_id: string | null;
      ref_pattern: string;
      backend_slug: string;
      targets_json: string;
      revoked_at: string | null;
    }>;
    for (const r of rows) {
      let targets: string[] = [];
      try {
        targets = JSON.parse(r.targets_json) as string[];
      } catch {
        continue;
      }
      if (targets.includes(input.composeId)) return true;
    }
    return false;
  }
}
