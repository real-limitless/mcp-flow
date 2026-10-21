import type { DatabaseSync } from "node:sqlite";
import { seal, unseal } from "../crypto.js";
import type {
  BackendAuthPublic,
  BackendOauthInput,
  OauthAuthStatus,
} from "../types.js";
import { EXPIRING_WINDOW_MS } from "../oauth/time.js";
import { scopeString } from "../oauth/policy.js";

/** Sealed at rest. Never returned by the API, UI, or audit log. */
export interface OauthSecrets {
  clientSecret?: string;
  /** True when client_id was issued by dynamic client registration. */
  dynamicClient?: boolean;
  /** Redirect URIs actually registered for this client. Not the public gateway URL when that was rejected. */
  registeredRedirectUris?: string[];
  tokens?: {
    access_token: string;
    token_type: string;
    expires_in?: number;
    refresh_token?: string;
    scope?: string;
    id_token?: string;
  };
  codeVerifier?: string;
  /** RFC 8628 device grant. deviceCode is a secret. userCode is safe to display. */
  device?: {
    deviceCode: string;
    intervalSeconds: number;
    userCode: string;
    verificationUri: string;
    verificationUriComplete?: string;
    expiresAt: string;
  };
  discovery?: {
    authorizationServerUrl: string;
    resourceMetadataUrl?: string;
    authorizationServerMetadata?: Record<string, unknown>;
    resourceMetadata?: Record<string, unknown>;
  };
}

export interface OauthRow {
  backendId: string;
  status: OauthAuthStatus;
  clientId: string | null;
  scope: string | null;
  issuer: string | null;
  redirectUri: string;
  tokenExpiresAt: string | null;
  pendingStateHash: string | null;
  pendingExpiresAt: string | null;
  lastError: string | null;
  updatedAt: string;
}

export interface OauthDb {
  db: DatabaseSync;
  masterKey: Buffer;
}

function nowIso(): string {
  return new Date().toISOString();
}

function parseRow(r: Record<string, unknown>): OauthRow {
  const status = String(r.status);
  return {
    backendId: String(r.backend_id),
    status:
      status === "connected" || status === "expiring" ? status : "needs_reauth",
    clientId: r.client_id == null ? null : String(r.client_id),
    scope: r.scope == null ? null : String(r.scope),
    issuer: r.issuer == null ? null : String(r.issuer),
    redirectUri: r.redirect_uri == null ? "" : String(r.redirect_uri),
    tokenExpiresAt:
      r.token_expires_at == null ? null : String(r.token_expires_at),
    pendingStateHash:
      r.pending_state_hash == null ? null : String(r.pending_state_hash),
    pendingExpiresAt:
      r.pending_expires_at == null ? null : String(r.pending_expires_at),
    lastError: r.last_error == null ? null : String(r.last_error),
    updatedAt: String(r.updated_at),
  };
}

export function getOauthRow(db: DatabaseSync, backendId: string): OauthRow | null {
  const row = db
    .prepare(`SELECT * FROM backend_oauth WHERE backend_id = ?`)
    .get(backendId) as Record<string, unknown> | undefined;
  return row ? parseRow(row) : null;
}

export function readOauthSecrets(
  db: DatabaseSync,
  masterKey: Buffer,
  backendId: string,
): OauthSecrets | null {
  const row = db
    .prepare(`SELECT secrets_enc FROM backend_oauth WHERE backend_id = ?`)
    .get(backendId) as { secrets_enc: string | null } | undefined;
  if (!row?.secrets_enc) return null;
  return unseal<OauthSecrets>(masterKey, row.secrets_enc);
}

function writeSecrets(
  db: DatabaseSync,
  masterKey: Buffer,
  backendId: string,
  secrets: OauthSecrets,
): void {
  const empty =
    !secrets.clientSecret &&
    !secrets.dynamicClient &&
    !secrets.registeredRedirectUris?.length &&
    !secrets.tokens &&
    !secrets.codeVerifier &&
    !secrets.device &&
    !secrets.discovery;
  db.prepare(
    `UPDATE backend_oauth SET secrets_enc = ?, updated_at = ? WHERE backend_id = ?`,
  ).run(
    empty ? null : seal(masterKey, secrets),
    nowIso(),
    backendId,
  );
}

export function oauthStatusFrom(
  row: OauthRow,
  secrets: OauthSecrets | null,
  now = Date.now(),
): OauthAuthStatus {
  if (row.status === "needs_reauth") return "needs_reauth";
  if (!secrets?.tokens?.access_token) return "needs_reauth";
  if (!row.tokenExpiresAt) return "connected";
  const remaining = Date.parse(row.tokenExpiresAt) - now;
  if (Number.isNaN(remaining)) return "connected";
  if (remaining <= 0 && !secrets.tokens.refresh_token) return "needs_reauth";
  if (remaining <= EXPIRING_WINDOW_MS) return "expiring";
  return "connected";
}

export function toAuthPublic(
  row: OauthRow | null,
  secrets: OauthSecrets | null,
): BackendAuthPublic {
  if (!row) return { type: "static" };
  return {
    type: "oauth",
    status: oauthStatusFrom(row, secrets),
    clientId: row.clientId,
    hasClientSecret: Boolean(secrets?.clientSecret),
    scope: row.scope,
    issuer: row.issuer,
    redirectUri: row.redirectUri || null,
    expiresAt: row.tokenExpiresAt,
    lastError: row.lastError,
    device: secrets?.device?.userCode
      ? {
          userCode: secrets.device.userCode,
          verificationUri: secrets.device.verificationUri,
          verificationUriComplete: secrets.device.verificationUriComplete ?? null,
          expiresAt: secrets.device.expiresAt,
        }
      : null,
  };
}

export function authPublicForBackend(
  conn: OauthDb,
  backendId: string,
): BackendAuthPublic {
  const row = getOauthRow(conn.db, backendId);
  if (!row) return { type: "static" };
  return toAuthPublic(row, readOauthSecrets(conn.db, conn.masterKey, backendId));
}

export function authPublicByWorkspace(
  conn: OauthDb,
  workspaceId: string,
): Map<string, BackendAuthPublic> {
  const rows = conn.db
    .prepare(
      `SELECT o.* FROM backend_oauth o
       JOIN backends b ON b.id = o.backend_id
       WHERE b.workspace_id = ?`,
    )
    .all(workspaceId) as Record<string, unknown>[];
  const map = new Map<string, BackendAuthPublic>();
  for (const raw of rows) {
    const row = parseRow(raw);
    const secrets =
      raw.secrets_enc == null
        ? null
        : unseal<OauthSecrets>(conn.masterKey, String(raw.secrets_enc));
    map.set(row.backendId, toAuthPublic(row, secrets));
  }
  return map;
}

export function insertOauthBackend(
  conn: OauthDb,
  backendId: string,
  auth: BackendOauthInput,
): void {
  const ts = nowIso();
  const secrets: OauthSecrets = {};
  if (auth.clientSecret) secrets.clientSecret = auth.clientSecret;
  conn.db
    .prepare(
      `INSERT INTO backend_oauth (
        backend_id, status, client_id, scope, issuer, redirect_uri,
        token_expires_at, pending_state_hash, pending_expires_at, last_error,
        secrets_enc, updated_at
      ) VALUES (?, 'needs_reauth', ?, ?, NULL, '', NULL, NULL, NULL, NULL, ?, ?)`,
    )
    .run(
      backendId,
      auth.clientId?.trim() || null,
      scopeString(auth.scopes),
      secrets.clientSecret ? seal(conn.masterKey, secrets) : null,
      ts,
    );
}

export function deleteOauthBackend(db: DatabaseSync, backendId: string): void {
  db.prepare(`DELETE FROM backend_oauth WHERE backend_id = ?`).run(backendId);
}

export function upsertOauthSettings(
  conn: OauthDb,
  backendId: string,
  auth: BackendOauthInput,
): void {
  const existing = getOauthRow(conn.db, backendId);
  if (!existing) {
    insertOauthBackend(conn, backendId, auth);
    return;
  }
  const secrets = readOauthSecrets(conn.db, conn.masterKey, backendId) ?? {};
  const nextId =
    auth.clientId !== undefined ? auth.clientId.trim() || null : existing.clientId;
  const idChanged = nextId !== existing.clientId;
  if (auth.clientSecret !== undefined) {
    if (auth.clientSecret) secrets.clientSecret = auth.clientSecret;
    else delete secrets.clientSecret;
  }
  if (idChanged) {
    delete secrets.tokens;
    delete secrets.codeVerifier;
    secrets.dynamicClient = false;
  }
  const scope =
    auth.scopes !== undefined ? scopeString(auth.scopes) : existing.scope;
  conn.db
    .prepare(
      `UPDATE backend_oauth SET
        client_id = ?,
        scope = ?,
        status = ?,
        token_expires_at = ?,
        pending_state_hash = NULL,
        pending_expires_at = NULL,
        secrets_enc = ?,
        updated_at = ?
       WHERE backend_id = ?`,
    )
    .run(
      nextId,
      scope,
      idChanged ? "needs_reauth" : existing.status,
      idChanged ? null : existing.tokenExpiresAt,
      seal(conn.masterKey, secrets),
      nowIso(),
      backendId,
    );
}

export function setOauthRedirect(
  db: DatabaseSync,
  backendId: string,
  redirectUri: string,
): void {
  db.prepare(
    `UPDATE backend_oauth SET redirect_uri = ?, updated_at = ? WHERE backend_id = ?`,
  ).run(redirectUri, nowIso(), backendId);
}

export function setOauthLastError(
  db: DatabaseSync,
  backendId: string,
  lastError: string | null,
): void {
  db.prepare(
    `UPDATE backend_oauth SET last_error = ?, updated_at = ? WHERE backend_id = ?`,
  ).run(lastError, nowIso(), backendId);
}

export function saveOauthPendingState(
  db: DatabaseSync,
  backendId: string,
  stateHash: string,
  expiresAt: string,
): void {
  db.prepare(
    `UPDATE backend_oauth SET
      pending_state_hash = ?, pending_expires_at = ?, updated_at = ?
     WHERE backend_id = ?`,
  ).run(stateHash, expiresAt, nowIso(), backendId);
}

/** One-time consume. Returns the backend id, or null if missing, expired, or replayed. */
export function consumeOauthPendingState(
  db: DatabaseSync,
  stateHash: string,
  now = new Date().toISOString(),
): string | null {
  const row = db
    .prepare(
      `SELECT backend_id, pending_expires_at FROM backend_oauth WHERE pending_state_hash = ?`,
    )
    .get(stateHash) as
    | { backend_id: string; pending_expires_at: string | null }
    | undefined;
  if (!row?.pending_expires_at || row.pending_expires_at <= now) {
    if (row) {
      db.prepare(
        `UPDATE backend_oauth SET pending_state_hash = NULL, pending_expires_at = NULL, updated_at = ?
         WHERE pending_state_hash = ?`,
      ).run(nowIso(), stateHash);
    }
    return null;
  }
  const res = db
    .prepare(
      `UPDATE backend_oauth SET
        pending_state_hash = NULL, pending_expires_at = NULL, updated_at = ?
       WHERE pending_state_hash = ? AND pending_expires_at > ?`,
    )
    .run(nowIso(), stateHash, now);
  return Number(res.changes) === 1 ? row.backend_id : null;
}

export function mergeOauthSecrets(
  conn: OauthDb,
  backendId: string,
  mutate: (secrets: OauthSecrets) => void,
): OauthSecrets {
  const secrets = readOauthSecrets(conn.db, conn.masterKey, backendId) ?? {};
  mutate(secrets);
  writeSecrets(conn.db, conn.masterKey, backendId, secrets);
  return secrets;
}

export function saveOauthTokens(
  conn: OauthDb,
  backendId: string,
  tokens: NonNullable<OauthSecrets["tokens"]>,
  expiresAt: string | null,
): void {
  const secrets = readOauthSecrets(conn.db, conn.masterKey, backendId) ?? {};
  const refresh = tokens.refresh_token ?? secrets.tokens?.refresh_token;
  secrets.tokens = {
    access_token: tokens.access_token,
    token_type: tokens.token_type || "Bearer",
    ...(tokens.expires_in != null ? { expires_in: tokens.expires_in } : {}),
    ...(refresh ? { refresh_token: refresh } : {}),
    ...(tokens.scope ? { scope: tokens.scope } : {}),
    ...(tokens.id_token ? { id_token: tokens.id_token } : {}),
  };
  delete secrets.codeVerifier;
  delete secrets.device;
  conn.db
    .prepare(
      `UPDATE backend_oauth SET
        status = 'connected',
        token_expires_at = ?,
        last_error = NULL,
        pending_state_hash = NULL,
        pending_expires_at = NULL,
        secrets_enc = ?,
        updated_at = ?
       WHERE backend_id = ?`,
    )
    .run(
      expiresAt,
      seal(conn.masterKey, secrets),
      nowIso(),
      backendId,
    );
}

export function clearOauthTokens(
  conn: OauthDb,
  backendId: string,
  lastError: string | null,
): void {
  const secrets = readOauthSecrets(conn.db, conn.masterKey, backendId) ?? {};
  delete secrets.tokens;
  delete secrets.codeVerifier;
  delete secrets.device;
  conn.db
    .prepare(
      `UPDATE backend_oauth SET
        status = 'needs_reauth',
        token_expires_at = NULL,
        pending_state_hash = NULL,
        pending_expires_at = NULL,
        last_error = ?,
        secrets_enc = ?,
        updated_at = ?
       WHERE backend_id = ?`,
    )
    .run(
      lastError,
      seal(conn.masterKey, secrets),
      nowIso(),
      backendId,
    );
}

/** Drop a dynamic client so the next start registers again. Keeps nothing usable. */
export function clearOauthClient(conn: OauthDb, backendId: string): void {
  const secrets = readOauthSecrets(conn.db, conn.masterKey, backendId) ?? {};
  delete secrets.clientSecret;
  delete secrets.dynamicClient;
  delete secrets.registeredRedirectUris;
  delete secrets.tokens;
  delete secrets.codeVerifier;
  delete secrets.device;
  conn.db
    .prepare(
      `UPDATE backend_oauth SET
        client_id = NULL,
        status = 'needs_reauth',
        token_expires_at = NULL,
        pending_state_hash = NULL,
        pending_expires_at = NULL,
        secrets_enc = ?,
        updated_at = ?
       WHERE backend_id = ?`,
    )
    .run(seal(conn.masterKey, secrets), nowIso(), backendId);
}

export function clearOauthVerifier(conn: OauthDb, backendId: string): void {
  mergeOauthSecrets(conn, backendId, (secrets) => {
    delete secrets.codeVerifier;
  });
}

export function clearOauthDiscovery(conn: OauthDb, backendId: string): void {
  mergeOauthSecrets(conn, backendId, (secrets) => {
    delete secrets.discovery;
  });
  conn.db
    .prepare(`UPDATE backend_oauth SET issuer = NULL, updated_at = ? WHERE backend_id = ?`)
    .run(nowIso(), backendId);
}

export function saveOauthDiscovery(
  conn: OauthDb,
  backendId: string,
  discovery: NonNullable<OauthSecrets["discovery"]>,
): void {
  mergeOauthSecrets(conn, backendId, (secrets) => {
    secrets.discovery = discovery;
  });
  conn.db
    .prepare(`UPDATE backend_oauth SET issuer = ?, updated_at = ? WHERE backend_id = ?`)
    .run(discovery.authorizationServerUrl, nowIso(), backendId);
}

export function saveOauthClient(
  conn: OauthDb,
  backendId: string,
  client: {
    clientId: string;
    clientSecret?: string;
    dynamicClient: boolean;
    registeredRedirectUris?: string[];
  },
): void {
  mergeOauthSecrets(conn, backendId, (secrets) => {
    if (client.clientSecret) secrets.clientSecret = client.clientSecret;
    secrets.dynamicClient = client.dynamicClient;
    if (client.registeredRedirectUris?.length) {
      const prev = secrets.registeredRedirectUris ?? [];
      secrets.registeredRedirectUris = [
        ...new Set([...prev, ...client.registeredRedirectUris]),
      ];
    }
  });
  conn.db
    .prepare(
      `UPDATE backend_oauth SET client_id = ?, updated_at = ? WHERE backend_id = ?`,
    )
    .run(client.clientId, nowIso(), backendId);
}

export function saveOauthDevice(
  conn: OauthDb,
  backendId: string,
  device: NonNullable<OauthSecrets["device"]>,
): void {
  mergeOauthSecrets(conn, backendId, (secrets) => {
    secrets.device = device;
  });
  conn.db
    .prepare(
      `UPDATE backend_oauth SET last_error = NULL, updated_at = ? WHERE backend_id = ?`,
    )
    .run(nowIso(), backendId);
}
