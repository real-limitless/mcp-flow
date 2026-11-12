import type { DatabaseSync } from "node:sqlite";

export interface EnvTemplateRow {
  workspaceId: string;
  backendSlug: string;
  composeId: string;
  envKey: string;
  ref: string;
  version: number;
  updatedAt: string;
}

export class EnvTemplateDirectory {
  constructor(private readonly db: DatabaseSync) {}

  upsert(row: Omit<EnvTemplateRow, "updatedAt"> & { updatedAt?: string }): void {
    const now = row.updatedAt ?? new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO mcpflow_env_template (workspace_id, backend_slug, compose_id, env_key, ref, version, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(workspace_id, backend_slug, compose_id, env_key) DO UPDATE SET
           ref = excluded.ref,
           version = excluded.version,
           updated_at = excluded.updated_at`,
      )
      .run(row.workspaceId, row.backendSlug, row.composeId, row.envKey, row.ref, row.version, now);
  }

  delete(workspaceId: string, backendSlug: string, composeId: string, envKey: string): void {
    this.db
      .prepare(
        `DELETE FROM mcpflow_env_template
          WHERE workspace_id = ? AND backend_slug = ? AND compose_id = ? AND env_key = ?`,
      )
      .run(workspaceId, backendSlug, composeId, envKey);
  }

  deleteForKeys(workspaceId: string, backendSlug: string, composeId: string, keys: string[]): void {
    for (const key of keys) this.delete(workspaceId, backendSlug, composeId, key);
  }

  get(workspaceId: string, backendSlug: string, composeId: string, envKey: string): EnvTemplateRow | null {
    const r = this.db
      .prepare(
        `SELECT workspace_id, backend_slug, compose_id, env_key, ref, version, updated_at
           FROM mcpflow_env_template
          WHERE workspace_id = ? AND backend_slug = ? AND compose_id = ? AND env_key = ?`,
      )
      .get(workspaceId, backendSlug, composeId, envKey) as
      | {
          workspace_id: string;
          backend_slug: string;
          compose_id: string;
          env_key: string;
          ref: string;
          version: number;
          updated_at: string;
        }
      | undefined;
    if (!r) return null;
    return {
      workspaceId: r.workspace_id,
      backendSlug: r.backend_slug,
      composeId: r.compose_id,
      envKey: r.env_key,
      ref: r.ref,
      version: Number(r.version),
      updatedAt: r.updated_at,
    };
  }

  list(filter: { workspaceId: string; backendSlug?: string; composeId?: string; ref?: string }): EnvTemplateRow[] {
    const params: (string | null)[] = [filter.workspaceId];
    let sql = `SELECT workspace_id, backend_slug, compose_id, env_key, ref, version, updated_at
                 FROM mcpflow_env_template WHERE workspace_id = ?`;
    if (filter.backendSlug) {
      sql += ` AND backend_slug = ?`;
      params.push(filter.backendSlug);
    }
    if (filter.composeId) {
      sql += ` AND compose_id = ?`;
      params.push(filter.composeId);
    }
    if (filter.ref) {
      sql += ` AND ref = ?`;
      params.push(filter.ref);
    }
    const rows = this.db.prepare(sql).all(...params) as Array<{
      workspace_id: string;
      backend_slug: string;
      compose_id: string;
      env_key: string;
      ref: string;
      version: number;
      updated_at: string;
    }>;
    return rows.map((r) => ({
      workspaceId: r.workspace_id,
      backendSlug: r.backend_slug,
      composeId: r.compose_id,
      envKey: r.env_key,
      ref: r.ref,
      version: Number(r.version),
      updatedAt: r.updated_at,
    }));
  }
}
