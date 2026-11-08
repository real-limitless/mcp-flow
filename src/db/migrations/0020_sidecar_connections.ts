import type { DatabaseSync } from "node:sqlite";

/**
 * 0020_sidecar_connections. Named VPN/sidecar endpoints and an optional
 * backends.connection_id. Null means the backend keeps the normal network path.
 * 0016–0019 stay reserved. The column add is conditional: migration-only
 * databases (no legacy `backends` table) still apply this id.
 */
export const MIGRATION_0020 = `
-- 0020_sidecar_connections: operator-named sidecar/VPN egress endpoints
CREATE TABLE sidecar_connections (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  slug TEXT NOT NULL,
  display_name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('tailscale', 'generic')),
  http_proxy_url TEXT,
  socks_proxy_url TEXT,
  scope TEXT NOT NULL CHECK (scope IN ('gateway', 'device')),
  device_id TEXT,
  enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, slug),
  CHECK (http_proxy_url IS NOT NULL OR socks_proxy_url IS NOT NULL)
);

CREATE INDEX idx_sidecar_workspace ON sidecar_connections(workspace_id);
`;

export function applySidecarConnectionColumn(db: DatabaseSync): void {
  const backends = db
    .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'backends'`)
    .get();
  if (!backends) return;
  const cols = db.prepare(`PRAGMA table_info(backends)`).all() as Array<{ name: string }>;
  if (!cols.some((col) => col.name === "connection_id")) {
    db.exec(
      `ALTER TABLE backends ADD COLUMN connection_id TEXT REFERENCES sidecar_connections(id)`,
    );
  }
  db.exec(`CREATE INDEX IF NOT EXISTS idx_backends_connection ON backends(connection_id)`);
}

/** Manual rollback. Drops the catalog and the backend column. */
export const MIGRATION_0020_DOWN = `
DROP INDEX IF EXISTS idx_backends_connection;
ALTER TABLE backends DROP COLUMN connection_id;
DROP TABLE IF EXISTS sidecar_connections;
`;
