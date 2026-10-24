import { createHash } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { hashToken, mintApiToken, newId } from "../crypto.js";
import type { ApiKeyScopes } from "../types.js";

export const ACCESS_TTL_SECONDS = 60 * 60;
export const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
export const CODE_TTL_SECONDS = 5 * 60;

export interface OauthClientRow {
  id: string;
  workspaceId: string | null;
  name: string;
  secretHash: string | null;
  redirectUris: string[];
  revokedAt: string | null;
}

export interface OauthGrantPublic {
  id: string;
  workspaceId: string;
  clientId: string;
  name: string;
  accessPrefix: string;
  scope: string;
  scopes: ApiKeyScopes | null;
  expiresAt: string;
  createdAt: string;
  revokedAt: string | null;
}

function nowIso(): string {
  return new Date().toISOString();
}

function parseScopes(raw: string | null): ApiKeyScopes | null {
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as ApiKeyScopes;
    if (!s || typeof s !== "object") return null;
    return s.admin ? { admin: true } : null;
  } catch {
    return null;
  }
}

function rowClient(r: Record<string, unknown>): OauthClientRow {
  let redirectUris: string[] = [];
  try {
    const parsed = JSON.parse(String(r.redirect_uris_json)) as unknown;
    if (Array.isArray(parsed)) redirectUris = parsed.map(String);
  } catch {
    redirectUris = [];
  }
  return {
    id: String(r.id),
    workspaceId: r.workspace_id == null ? null : String(r.workspace_id),
    name: String(r.name),
    secretHash: r.secret_hash == null ? null : String(r.secret_hash),
    redirectUris,
    revokedAt: r.revoked_at == null ? null : String(r.revoked_at),
  };
}

export function publicClientId(workspaceId: string): string {
  const hex = createHash("sha256").update(workspaceId).digest("hex").slice(0, 24);
  return `mfc_${hex}`;
}

export function ensurePublicClient(
  db: DatabaseSync,
  workspaceId: string,
): OauthClientRow {
  const id = publicClientId(workspaceId);
  const existing = db
    .prepare(`SELECT * FROM oauth_clients WHERE id = ?`)
    .get(id) as Record<string, unknown> | undefined;
  if (existing) return rowClient(existing);
  db.prepare(
    `INSERT INTO oauth_clients (
      id, workspace_id, name, secret_hash, redirect_uris_json, created_at, revoked_at
    ) VALUES (?, ?, 'mcp-flow', NULL, '["*"]', ?, NULL)`,
  ).run(id, workspaceId, nowIso());
  return getClient(db, id)!;
}

export function getClient(db: DatabaseSync, id: string): OauthClientRow | null {
  const row = db
    .prepare(`SELECT * FROM oauth_clients WHERE id = ?`)
    .get(id) as Record<string, unknown> | undefined;
  if (!row || row.revoked_at != null) return null;
  return rowClient(row);
}

export function insertClient(
  db: DatabaseSync,
  input: {
    workspaceId: string | null;
    name: string;
    secretHash: string | null;
    redirectUris: string[];
  },
): OauthClientRow {
  const id = newId("mfc");
  db.prepare(
    `INSERT INTO oauth_clients (
      id, workspace_id, name, secret_hash, redirect_uris_json, created_at, revoked_at
    ) VALUES (?, ?, ?, ?, ?, ?, NULL)`,
  ).run(
    id,
    input.workspaceId,
    input.name,
    input.secretHash,
    JSON.stringify(input.redirectUris),
    nowIso(),
  );
  return getClient(db, id)!;
}

export function saveAuthCode(
  db: DatabaseSync,
  input: {
    codeHash: string;
    clientId: string;
    workspaceId: string;
    redirectUri: string;
    codeChallenge: string;
    scope: string;
    scopes: ApiKeyScopes | null;
    expiresAt: string;
  },
): void {
  db.prepare(
    `INSERT INTO oauth_codes (
      code_hash, client_id, workspace_id, redirect_uri, code_challenge,
      scope, scopes_json, expires_at, used_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
  ).run(
    input.codeHash,
    input.clientId,
    input.workspaceId,
    input.redirectUri,
    input.codeChallenge,
    input.scope,
    input.scopes ? JSON.stringify(input.scopes) : null,
    input.expiresAt,
  );
}

export function consumeAuthCode(
  db: DatabaseSync,
  codeHash: string,
): {
  clientId: string;
  workspaceId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  scopes: ApiKeyScopes | null;
} | null {
  const now = nowIso();
  const row = db
    .prepare(
      `SELECT * FROM oauth_codes WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?`,
    )
    .get(codeHash, now) as Record<string, unknown> | undefined;
  if (!row) return null;
  const res = db
    .prepare(
      `UPDATE oauth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL`,
    )
    .run(now, codeHash);
  if (Number(res.changes) !== 1) return null;
  return {
    clientId: String(row.client_id),
    workspaceId: String(row.workspace_id),
    redirectUri: String(row.redirect_uri),
    codeChallenge: String(row.code_challenge),
    scope: String(row.scope),
    scopes: parseScopes(row.scopes_json == null ? null : String(row.scopes_json)),
  };
}

export function insertGrant(
  db: DatabaseSync,
  input: {
    workspaceId: string;
    clientId: string;
    name: string;
    scope: string;
    scopes: ApiKeyScopes | null;
  },
): { id: string; accessToken: string; refreshToken: string; expiresIn: number } {
  const access = mintApiToken("mfo_");
  const refresh = mintApiToken("mfor_");
  const id = newId("og");
  const created = nowIso();
  const expiresAt = new Date(Date.now() + ACCESS_TTL_SECONDS * 1000).toISOString();
  const refreshExpiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
  db.prepare(
    `INSERT INTO oauth_grants (
      id, workspace_id, client_id, name, access_hash, refresh_hash, access_prefix,
      scope, scopes_json, expires_at, refresh_expires_at, created_at, revoked_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
  ).run(
    id,
    input.workspaceId,
    input.clientId,
    input.name,
    access.hash,
    refresh.hash,
    access.prefix,
    input.scope,
    input.scopes ? JSON.stringify(input.scopes) : null,
    expiresAt,
    refreshExpiresAt,
    created,
  );
  return {
    id,
    accessToken: access.token,
    refreshToken: refresh.token,
    expiresIn: ACCESS_TTL_SECONDS,
  };
}

export function rotateGrant(
  db: DatabaseSync,
  refreshToken: string,
): {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  scope: string;
} | null {
  const hash = hashToken(refreshToken);
  const now = nowIso();
  const row = db
    .prepare(
      `SELECT * FROM oauth_grants
       WHERE refresh_hash = ? AND revoked_at IS NULL AND refresh_expires_at > ?`,
    )
    .get(hash, now) as Record<string, unknown> | undefined;
  if (!row) return null;
  const access = mintApiToken("mfo_");
  const refresh = mintApiToken("mfor_");
  const expiresAt = new Date(Date.now() + ACCESS_TTL_SECONDS * 1000).toISOString();
  const refreshExpiresAt = new Date(Date.now() + REFRESH_TTL_SECONDS * 1000).toISOString();
  const res = db
    .prepare(
      `UPDATE oauth_grants SET
        access_hash = ?, refresh_hash = ?, access_prefix = ?,
        expires_at = ?, refresh_expires_at = ?
       WHERE id = ? AND refresh_hash = ? AND revoked_at IS NULL`,
    )
    .run(
      access.hash,
      refresh.hash,
      access.prefix,
      expiresAt,
      refreshExpiresAt,
      String(row.id),
      hash,
    );
  if (Number(res.changes) !== 1) return null;
  return {
    accessToken: access.token,
    refreshToken: refresh.token,
    expiresIn: ACCESS_TTL_SECONDS,
    scope: String(row.scope),
  };
}

export function authenticateAccess(
  db: DatabaseSync,
  token: string,
): {
  workspaceId: string;
  keyId: string;
  keyName: string;
  scopes: ApiKeyScopes | null;
} | null {
  const row = db
    .prepare(
      `SELECT * FROM oauth_grants WHERE access_hash = ? AND revoked_at IS NULL`,
    )
    .get(hashToken(token)) as Record<string, unknown> | undefined;
  if (!row) return null;
  if (String(row.expires_at) <= nowIso()) return null;
  return {
    workspaceId: String(row.workspace_id),
    keyId: String(row.id),
    keyName: String(row.name),
    scopes: parseScopes(row.scopes_json == null ? null : String(row.scopes_json)),
  };
}

export function listGrants(db: DatabaseSync, workspaceId: string): OauthGrantPublic[] {
  const rows = db
    .prepare(
      `SELECT * FROM oauth_grants WHERE workspace_id = ? ORDER BY created_at DESC`,
    )
    .all(workspaceId) as Record<string, unknown>[];
  return rows.map((r) => ({
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    clientId: String(r.client_id),
    name: String(r.name),
    accessPrefix: String(r.access_prefix),
    scope: String(r.scope),
    scopes: parseScopes(r.scopes_json == null ? null : String(r.scopes_json)),
    expiresAt: String(r.expires_at),
    createdAt: String(r.created_at),
    revokedAt: r.revoked_at == null ? null : String(r.revoked_at),
  }));
}

export function revokeGrant(
  db: DatabaseSync,
  workspaceId: string,
  id: string,
): boolean {
  const res = db
    .prepare(
      `UPDATE oauth_grants SET revoked_at = ?
       WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL`,
    )
    .run(nowIso(), id, workspaceId);
  return Number(res.changes) > 0;
}
