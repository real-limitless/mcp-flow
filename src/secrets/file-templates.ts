import type { DatabaseSync } from "node:sqlite";

export interface FileTemplateRow {
  workspaceId: string;
  backendSlug: string;
  composeId: string;
  mountPath: string;
  mountId: string;
  ref: string;
  version: number;
  envKey: string | null;
  updatedAt: string;
}

export class FileTemplateDirectory {
  constructor(private readonly db: DatabaseSync) {}

  upsert(row: Omit<FileTemplateRow, "updatedAt" | "envKey"> & { envKey?: string | null; updatedAt?: string }): void {
    const now = row.updatedAt ?? new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO mcpflow_file_template (
           workspace_id, backend_slug, compose_id, mount_path, mount_id, ref, version, env_key, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(workspace_id, backend_slug, compose_id, mount_path) DO UPDATE SET
           mount_id = excluded.mount_id,
           ref = excluded.ref,
           version = excluded.version,
           env_key = excluded.env_key,
           updated_at = excluded.updated_at`,
      )
      .run(
        row.workspaceId,
        row.backendSlug,
        row.composeId,
        row.mountPath,
        row.mountId,
        row.ref,
        row.version,
        row.envKey ?? null,
        now,
      );
  }

  delete(workspaceId: string, backendSlug: string, composeId: string, mountPath: string): void {
    this.db
      .prepare(
        `DELETE FROM mcpflow_file_template
          WHERE workspace_id = ? AND backend_slug = ? AND compose_id = ? AND mount_path = ?`,
      )
      .run(workspaceId, backendSlug, composeId, mountPath);
  }

  get(workspaceId: string, backendSlug: string, composeId: string, mountPath: string): FileTemplateRow | null {
    const row = this.db
      .prepare(
        `SELECT workspace_id, backend_slug, compose_id, mount_path, mount_id, ref, version, env_key, updated_at
           FROM mcpflow_file_template
          WHERE workspace_id = ? AND backend_slug = ? AND compose_id = ? AND mount_path = ?`,
      )
      .get(workspaceId, backendSlug, composeId, mountPath) as Raw | undefined;
    return row ? mapRow(row) : null;
  }

  list(filter: { workspaceId: string; backendSlug?: string; composeId?: string; ref?: string }): FileTemplateRow[] {
    const params: string[] = [filter.workspaceId];
    let sql = `SELECT workspace_id, backend_slug, compose_id, mount_path, mount_id, ref, version, env_key, updated_at
                 FROM mcpflow_file_template WHERE workspace_id = ?`;
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
    const rows = this.db.prepare(sql).all(...params) as unknown as Raw[];
    return rows.map(mapRow);
  }
}

interface Raw {
  workspace_id: string;
  backend_slug: string;
  compose_id: string;
  mount_path: string;
  mount_id: string;
  ref: string;
  version: number;
  env_key: string | null;
  updated_at: string;
}

function mapRow(row: Raw): FileTemplateRow {
  return {
    workspaceId: row.workspace_id,
    backendSlug: row.backend_slug,
    composeId: row.compose_id,
    mountPath: row.mount_path,
    mountId: row.mount_id,
    ref: row.ref,
    version: Number(row.version),
    envKey: row.env_key,
    updatedAt: row.updated_at,
  };
}
