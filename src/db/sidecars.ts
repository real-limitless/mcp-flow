import type { DatabaseSync } from "node:sqlite";
import { newId } from "../crypto.js";
import {
  assertEgressPlacement,
  parseProxyUrl,
  SidecarError,
  SidecarUnavailableError,
  type EgressProxy,
} from "../egress/sidecar.js";
import type {
  BackendRecord,
  CreateSidecarInput,
  Placement,
  SidecarConnectionKind,
  SidecarConnectionPublic,
  SidecarConnectionScope,
  SidecarConnectionSummary,
  UpdateSidecarInput,
} from "../types.js";

function nowIso(): string {
  return new Date().toISOString();
}

const SLUG = /^[a-z][a-z0-9_-]{0,63}$/;

interface SidecarStored {
  id: string;
  workspaceId: string;
  slug: string;
  displayName: string;
  kind: SidecarConnectionKind;
  httpProxy: string | null;
  socksProxy: string | null;
  scope: SidecarConnectionScope;
  deviceId: string | null;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

function asKind(value: string): SidecarConnectionKind {
  if (value === "tailscale" || value === "generic") return value;
  throw new SidecarError("kind must be tailscale or generic");
}

function asScope(value: string): SidecarConnectionScope {
  if (value === "gateway" || value === "device") return value;
  throw new SidecarError("scope must be gateway or device");
}

function rowSidecar(r: Record<string, unknown>): SidecarStored {
  return {
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    slug: String(r.slug),
    displayName: String(r.display_name),
    kind: asKind(String(r.kind)),
    httpProxy: r.http_proxy_url == null ? null : String(r.http_proxy_url),
    socksProxy: r.socks_proxy_url == null ? null : String(r.socks_proxy_url),
    scope: asScope(String(r.scope)),
    deviceId: r.device_id == null || r.device_id === "" ? null : String(r.device_id),
    enabled: Number(r.enabled) === 1,
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
}

function toPublic(row: SidecarStored): SidecarConnectionPublic {
  return { ...row, health: "unknown" };
}

function toSummary(row: SidecarStored): SidecarConnectionSummary {
  return {
    id: row.id,
    slug: row.slug,
    displayName: row.displayName,
    kind: row.kind,
    scope: row.scope,
  };
}

function toEgress(row: SidecarStored): EgressProxy {
  return {
    connectionId: row.id,
    slug: row.slug,
    displayName: row.displayName,
    kind: row.kind,
    httpProxyUrl: row.httpProxy,
    socksProxyUrl: row.socksProxy,
    scope: row.scope,
    deviceId: row.deviceId,
  };
}

function displayNameOf(raw: string): string {
  const name = raw.trim();
  if (!name) throw new SidecarError("display name is required");
  if (name.length > 80) throw new SidecarError("display name must be 80 characters or fewer");
  if (/[\u0000-\u001f\u007f]/.test(name)) {
    throw new SidecarError("display name cannot include control characters");
  }
  return name;
}

function slugOf(raw: string): string {
  const slug = raw.trim().toLowerCase();
  if (!SLUG.test(slug)) {
    throw new SidecarError(
      "slug must be lowercase alphanumeric/underscore/hyphen, start with a letter",
    );
  }
  return slug;
}

function optionalProxy(
  value: string | null | undefined,
  role: "http" | "socks",
): string | null | undefined {
  if (value === undefined) return undefined;
  if (value === null) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return parseProxyUrl(trimmed, role);
}

function deviceExists(db: DatabaseSync, workspaceId: string, deviceId: string): boolean {
  const row = db
    .prepare(`SELECT id FROM devices WHERE workspace_id = ? AND id = ?`)
    .get(workspaceId, deviceId);
  return Boolean(row);
}

function assertScope(
  db: DatabaseSync,
  workspaceId: string,
  scope: SidecarConnectionScope,
  deviceId: string | null,
): void {
  if (scope === "gateway") {
    if (deviceId) throw new SidecarError("gateway scope cannot set a device");
    return;
  }
  if (!deviceId) throw new SidecarError("device scope requires a device on this workspace");
  if (!deviceExists(db, workspaceId, deviceId)) {
    throw new SidecarError("device scope requires a device on this workspace");
  }
}

function requireProxy(httpProxy: string | null, socksProxy: string | null): void {
  if (!httpProxy && !socksProxy) {
    throw new SidecarError("set an HTTP proxy, a SOCKS proxy, or both");
  }
}

function loadRow(
  db: DatabaseSync,
  workspaceId: string,
  idOrSlug: string,
): SidecarStored | null {
  const row = db
    .prepare(
      `SELECT * FROM sidecar_connections
       WHERE workspace_id = ? AND (id = ? OR slug = ?)`,
    )
    .get(workspaceId, idOrSlug, idOrSlug) as Record<string, unknown> | undefined;
  return row ? rowSidecar(row) : null;
}

export function listSidecars(
  db: DatabaseSync,
  workspaceId: string,
): SidecarConnectionPublic[] {
  const rows = db
    .prepare(
      `SELECT * FROM sidecar_connections WHERE workspace_id = ? ORDER BY slug ASC`,
    )
    .all(workspaceId) as Record<string, unknown>[];
  return rows.map((row) => toPublic(rowSidecar(row)));
}

export function getSidecar(
  db: DatabaseSync,
  workspaceId: string,
  idOrSlug: string,
): SidecarConnectionPublic | null {
  const row = loadRow(db, workspaceId, idOrSlug);
  return row ? toPublic(row) : null;
}

export function sidecarSummary(
  db: DatabaseSync,
  workspaceId: string,
  connectionId: string | null,
): SidecarConnectionSummary | null {
  if (!connectionId) return null;
  const row = loadRow(db, workspaceId, connectionId);
  return row ? toSummary(row) : null;
}

export function createSidecar(
  db: DatabaseSync,
  workspaceId: string,
  input: CreateSidecarInput,
): SidecarConnectionPublic {
  const slug = slugOf(input.slug);
  const displayName = displayNameOf(input.displayName);
  const kind = asKind(input.kind ?? "generic");
  const scope = asScope(input.scope ?? "gateway");
  const deviceId = input.deviceId?.trim() ? input.deviceId.trim() : null;
  assertScope(db, workspaceId, scope, deviceId);
  const httpProxy = optionalProxy(input.httpProxy, "http") ?? null;
  const socksProxy = optionalProxy(input.socksProxy, "socks") ?? null;
  requireProxy(httpProxy, socksProxy);
  const ts = nowIso();
  const id = newId("sc");
  db.prepare(
    `INSERT INTO sidecar_connections (
      id, workspace_id, slug, display_name, kind, http_proxy_url, socks_proxy_url,
      scope, device_id, enabled, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    id,
    workspaceId,
    slug,
    displayName,
    kind,
    httpProxy,
    socksProxy,
    scope,
    deviceId,
    input.enabled === false ? 0 : 1,
    ts,
    ts,
  );
  const created = loadRow(db, workspaceId, id);
  if (!created) throw new SidecarError("sidecar connection was not stored");
  return toPublic(created);
}

function assignedCount(db: DatabaseSync, workspaceId: string, id: string): number {
  const row = db
    .prepare(
      `SELECT count(*) AS n FROM backends WHERE workspace_id = ? AND connection_id = ?`,
    )
    .get(workspaceId, id) as { n: number };
  return Number(row.n);
}

export function updateSidecar(
  db: DatabaseSync,
  workspaceId: string,
  idOrSlug: string,
  input: UpdateSidecarInput,
): SidecarConnectionPublic | null {
  const existing = loadRow(db, workspaceId, idOrSlug);
  if (!existing) return null;
  const displayName =
    input.displayName !== undefined ? displayNameOf(input.displayName) : existing.displayName;
  const kind = input.kind !== undefined ? asKind(input.kind) : existing.kind;
  const scope = input.scope !== undefined ? asScope(input.scope) : existing.scope;
  let deviceId = existing.deviceId;
  if (input.deviceId !== undefined) {
    deviceId = input.deviceId?.trim() ? input.deviceId.trim() : null;
  }
  if (scope === "gateway") deviceId = null;
  assertScope(db, workspaceId, scope, deviceId);
  const httpProxy =
    input.httpProxy !== undefined
      ? (optionalProxy(input.httpProxy, "http") ?? null)
      : existing.httpProxy;
  const socksProxy =
    input.socksProxy !== undefined
      ? (optionalProxy(input.socksProxy, "socks") ?? null)
      : existing.socksProxy;
  requireProxy(httpProxy, socksProxy);
  const scopeChanged = scope !== existing.scope || deviceId !== existing.deviceId;
  if (scopeChanged && assignedCount(db, workspaceId, existing.id) > 0) {
    throw new SidecarError(
      "connection is assigned; unassign backends before changing where it is reachable",
    );
  }
  const enabled = input.enabled !== undefined ? input.enabled : existing.enabled;
  db.prepare(
    `UPDATE sidecar_connections SET
      display_name = ?, kind = ?, http_proxy_url = ?, socks_proxy_url = ?,
      scope = ?, device_id = ?, enabled = ?, updated_at = ?
     WHERE id = ?`,
  ).run(
    displayName,
    kind,
    httpProxy,
    socksProxy,
    scope,
    deviceId,
    enabled ? 1 : 0,
    nowIso(),
    existing.id,
  );
  const next = loadRow(db, workspaceId, existing.id);
  return next ? toPublic(next) : null;
}

export function deleteSidecar(
  db: DatabaseSync,
  workspaceId: string,
  idOrSlug: string,
): boolean {
  const existing = loadRow(db, workspaceId, idOrSlug);
  if (!existing) return false;
  const n = assignedCount(db, workspaceId, existing.id);
  if (n > 0) {
    throw new SidecarError(
      `sidecar connection is assigned to ${n} backend${n === 1 ? "" : "s"}`,
    );
  }
  const res = db
    .prepare(`DELETE FROM sidecar_connections WHERE id = ? AND workspace_id = ?`)
    .run(existing.id, workspaceId);
  return Number(res.changes) > 0;
}

export function resolveConnectionId(
  db: DatabaseSync,
  workspaceId: string,
  idOrSlug: string | null | undefined,
): string | null {
  if (idOrSlug == null) return null;
  const key = idOrSlug.trim();
  if (!key) return null;
  const row = loadRow(db, workspaceId, key);
  if (!row) throw new SidecarError("sidecar connection not found");
  if (!row.enabled) throw new SidecarError("sidecar connection is disabled");
  return row.id;
}

function placementOf(backend: BackendRecord): Placement {
  try {
    const parsed = JSON.parse(backend.placementJson) as Placement;
    if (parsed && typeof parsed.mode === "string") return parsed;
  } catch {
    /* use remote */
  }
  return { mode: "remote" };
}

/** Null when the backend has no connection. Throws when the selection cannot be used. */
export function egressForBackend(db: DatabaseSync, backend: BackendRecord): EgressProxy | null {
  if (!backend.connectionId) return null;
  const row = loadRow(db, backend.workspaceId, backend.connectionId);
  if (!row) {
    throw new SidecarUnavailableError(
      `backend ${backend.slug} sidecar connection is missing`,
    );
  }
  if (!row.enabled) {
    throw new SidecarUnavailableError(
      `backend ${backend.slug} sidecar connection is disabled`,
    );
  }
  const egress = toEgress(row);
  assertEgressPlacement(egress, placementOf(backend), backend.slug);
  return egress;
}

export function assertConnectionForPlacement(
  db: DatabaseSync,
  workspaceId: string,
  connectionId: string | null,
  placement: Placement,
  backendSlug: string,
): void {
  if (!connectionId) return;
  const row = loadRow(db, workspaceId, connectionId);
  if (!row) throw new SidecarError("sidecar connection not found");
  if (!row.enabled) throw new SidecarError("sidecar connection is disabled");
  assertEgressPlacement(toEgress(row), placement, backendSlug);
}

export interface SidecarSeedItem {
  slug: string;
  displayName?: string;
  kind?: SidecarConnectionKind;
  httpProxy?: string | null;
  socksProxy?: string | null;
  scope?: SidecarConnectionScope;
  deviceId?: string | null;
}

export interface SidecarSeedResult {
  created: string[];
  refreshed: string[];
}

function seedItem(raw: unknown, index: number): SidecarSeedItem {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new SidecarError(`MCP_FLOW_SIDECARS[${index}] must be an object`);
  }
  const item = raw as Record<string, unknown>;
  if (typeof item.slug !== "string") {
    throw new SidecarError(`MCP_FLOW_SIDECARS[${index}] needs a slug`);
  }
  const readUrl = (key: "httpProxy" | "socksProxy"): string | null | undefined => {
    if (!(key in item)) return undefined;
    const value = item[key];
    if (value == null) return null;
    if (typeof value !== "string") {
      throw new SidecarError(`MCP_FLOW_SIDECARS[${index}].${key} must be a string`);
    }
    return value;
  };
  return {
    slug: item.slug,
    displayName: typeof item.displayName === "string" ? item.displayName : undefined,
    kind:
      item.kind === undefined
        ? undefined
        : asKind(typeof item.kind === "string" ? item.kind : ""),
    httpProxy: readUrl("httpProxy"),
    socksProxy: readUrl("socksProxy"),
    scope:
      item.scope === undefined
        ? undefined
        : asScope(typeof item.scope === "string" ? item.scope : ""),
    deviceId: typeof item.deviceId === "string" ? item.deviceId : undefined,
  };
}

/**
 * Register connections from MCP_FLOW_SIDECARS. Existing display names are kept.
 * Proxy endpoints are refreshed so compose stays the source of those URLs.
 * Does not assign any backend.
 */
export function seedSidecarConnections(
  db: DatabaseSync,
  workspaceId: string,
  raw: string | undefined,
): SidecarSeedResult {
  const text = raw?.trim();
  if (!text) return { created: [], refreshed: [] };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new SidecarError("MCP_FLOW_SIDECARS must be a JSON array");
  }
  if (!Array.isArray(parsed)) throw new SidecarError("MCP_FLOW_SIDECARS must be a JSON array");
  const items = parsed.map((item, index) => seedItem(item, index));
  const created: string[] = [];
  const refreshed: string[] = [];
  db.exec("BEGIN");
  try {
    for (const item of items) {
      const slug = slugOf(item.slug);
      const existing = loadRow(db, workspaceId, slug);
      if (!existing) {
        createSidecar(db, workspaceId, {
          slug,
          displayName: item.displayName?.trim() || slug,
          kind: item.kind ?? "generic",
          httpProxy: item.httpProxy,
          socksProxy: item.socksProxy,
          scope: item.scope,
          deviceId: item.deviceId,
        });
        created.push(slug);
        continue;
      }
      const httpProxy = item.httpProxy !== undefined ? item.httpProxy : existing.httpProxy;
      const socksProxy = item.socksProxy !== undefined ? item.socksProxy : existing.socksProxy;
      updateSidecar(db, workspaceId, existing.id, {
        kind: item.kind,
        httpProxy,
        socksProxy,
      });
      refreshed.push(slug);
    }
    db.exec("COMMIT");
  } catch (err) {
    if (db.isTransaction) db.exec("ROLLBACK");
    throw err;
  }
  return { created, refreshed };
}
