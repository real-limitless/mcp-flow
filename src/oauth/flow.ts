import {
  auth,
  discoverOAuthServerInfo,
  registerClient,
} from "@modelcontextprotocol/sdk/client/auth.js";
import { redactSecrets } from "../audit/sanitize.js";
import { hashToken } from "../crypto.js";
import type { Store } from "../db/store.js";
import type { BackendRecord } from "../types.js";
import {
  clearOauthClient,
  clearOauthTokens,
  getOauthRow,
  readOauthSecrets,
  saveOauthClient,
  saveOauthDevice,
  saveOauthDiscovery,
  saveOauthTokens,
  setOauthLastError,
  setOauthRedirect,
  consumeOauthPendingState,
  type OauthSecrets,
} from "../db/oauth-store.js";
import { createSafeFetch } from "./fetch.js";
import { StoreOauthProvider, oauthErrorCode } from "./provider.js";

const SETUP_HINT =
  "This server does not offer dynamic client registration. Enter a client id and, if the provider uses a confidential client, a client secret.";

export function safeOauthMessage(err: unknown): string {
  const code = oauthErrorCode(err);
  const raw = err instanceof Error ? err.message : String(err);
  const safe = redactSecrets(raw).replace(/\s+/g, " ").trim().slice(0, 400);
  if (!safe) {
    return code === "refresh_failed" ? "OAuth request failed" : `OAuth error: ${code}`;
  }
  // The SDK maps unrecognized OAuth errors (including invalid_redirect_uri) onto
  // ServerError, whose code is server_error. Keep the description.
  if (code === "refresh_failed" || code === "server_error") return safe;
  if (safe.toLowerCase().includes(code)) return safe;
  return `${code}: ${safe}`;
}

export interface OauthStartResult {
  mode: "authorization_code" | "device";
  redirectUri: string;
  authorizationUrl?: string;
  userCode?: string;
  verificationUri?: string;
  verificationUriComplete?: string | null;
  expiresAt?: string;
  intervalSeconds?: number;
}

/**
 * Discover the authorization server, register or reuse the client, and return
 * the provider consent URL. Does not complete consent.
 */
export async function startOauthAuthorization(opts: {
  store: Store;
  backend: BackendRecord;
  redirectUri: string;
  allowPrivateUrls: boolean;
  keyId?: string | null;
  ip?: string | null;
}): Promise<OauthStartResult> {
  const row = getOauthRow(opts.store.db, opts.backend.id);
  if (!row) throw new Error("backend is not configured for OAuth");
  if (!opts.backend.url) throw new Error("backend has no url");

  const fetchFn = createSafeFetch(opts.allowPrivateUrls);
  let info;
  try {
    info = await discoverOAuthServerInfo(opts.backend.url, { fetchFn });
  } catch (err) {
    const message = safeOauthMessage(err);
    setOauthLastError(opts.store.db, opts.backend.id, message);
    throw new Error(message);
  }

  const secrets = readOauthSecrets(
    opts.store.db,
    opts.store.masterKey,
    opts.backend.id,
  );
  const clientId = row.clientId?.trim() || "";
  const registration = info.authorizationServerMetadata?.registration_endpoint;
  if (!clientId && !registration) {
    const message = `${SETUP_HINT} Register this redirect URL with the provider: ${opts.redirectUri}`;
    setOauthLastError(opts.store.db, opts.backend.id, message);
    throw new Error(message);
  }

  const methods = info.authorizationServerMetadata?.token_endpoint_auth_methods_supported;
  if (
    clientId &&
    !secrets?.clientSecret &&
    Array.isArray(methods) &&
    methods.length > 0 &&
    !methods.includes("none")
  ) {
    const message = "This authorization server requires a client secret.";
    setOauthLastError(opts.store.db, opts.backend.id, message);
    throw new Error(message);
  }

  if (row.redirectUri && row.redirectUri !== opts.redirectUri) {
    if (clientId && !secrets?.dynamicClient) {
      const message = `Redirect URI changed. Add ${opts.redirectUri} at the provider for client ${clientId}.`;
      setOauthLastError(opts.store.db, opts.backend.id, message);
      throw new Error(message);
    }
    if (secrets?.dynamicClient) {
      clearOauthClient(
        { db: opts.store.db, masterKey: opts.store.masterKey },
        opts.backend.id,
      );
    }
  }

  setOauthRedirect(opts.store.db, opts.backend.id, opts.redirectUri);
  const conn = { db: opts.store.db, masterKey: opts.store.masterKey };
  saveOauthDiscovery(conn, opts.backend.id, {
    authorizationServerUrl: String(info.authorizationServerUrl),
    ...(info.authorizationServerMetadata
      ? {
          authorizationServerMetadata: info.authorizationServerMetadata as Record<
            string,
            unknown
          >,
        }
      : {}),
    ...(info.resourceMetadata
      ? { resourceMetadata: info.resourceMetadata as Record<string, unknown> }
      : {}),
  });

  const hadTokens = Boolean(secrets?.tokens?.access_token || secrets?.tokens?.refresh_token);
  const fresh = getOauthRow(opts.store.db, opts.backend.id);
  const provider = new StoreOauthProvider({
    store: opts.store,
    backendId: opts.backend.id,
    workspaceId: opts.backend.workspaceId,
    slug: opts.backend.slug,
    redirectUri: opts.redirectUri,
    interactive: true,
    allowPrivateUrls: opts.allowPrivateUrls,
  });

  try {
    const result = await auth(provider, {
      serverUrl: opts.backend.url,
      fetchFn,
      ...(fresh?.scope ? { scope: fresh.scope } : {}),
    });
    if (result !== "REDIRECT" || !provider.authorizationUrl) {
      throw new Error("authorization server did not return a consent URL");
    }
  } catch (err) {
    if (redirectRejected(err) && deviceGrantSupported(info.authorizationServerMetadata)) {
      return beginDeviceGrant({
        store: opts.store,
        backend: opts.backend,
        redirectUri: opts.redirectUri,
        allowPrivateUrls: opts.allowPrivateUrls,
        info,
        scope: fresh?.scope ?? row.scope,
        fetchFn,
      });
    }
    const message = safeOauthMessage(err);
    setOauthLastError(opts.store.db, opts.backend.id, message);
    throw new Error(message);
  }

  if (hadTokens) {
    opts.store.writeAudit({
      workspaceId: opts.backend.workspaceId,
      keyId: opts.keyId,
      action: "oauth.reauth",
      backendSlug: opts.backend.slug,
      detail: { phase: "started" },
      ip: opts.ip,
    });
  }

  return {
    mode: "authorization_code",
    authorizationUrl: provider.authorizationUrl.href,
    redirectUri: opts.redirectUri,
  };
}

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const LOOPBACK_DCR_REDIRECT = "http://127.0.0.1/oauth/callback";

function redirectRejected(err: unknown): boolean {
  const raw = err instanceof Error ? err.message : String(err);
  return /invalid_redirect_uri|redirect_uri not allowed|redirect_uris is required/i.test(raw);
}

function deviceGrantSupported(metadata: Record<string, unknown> | undefined): boolean {
  if (!metadata || typeof metadata.device_authorization_endpoint !== "string") return false;
  const grants = metadata.grant_types_supported;
  if (!Array.isArray(grants)) return true;
  return grants.some((grant) => String(grant).includes("device_code"));
}

function grantScope(
  rowScope: string | null,
  info: {
    resourceMetadata?: { scopes_supported?: string[] };
    authorizationServerMetadata?: { scopes_supported?: string[] };
  },
): string | undefined {
  if (rowScope?.trim()) return rowScope.trim();
  const resource = info.resourceMetadata?.scopes_supported;
  if (Array.isArray(resource) && resource.length) return resource.join(" ");
  const server = info.authorizationServerMetadata?.scopes_supported;
  if (Array.isArray(server) && server.length) return server.join(" ");
  return undefined;
}

async function beginDeviceGrant(opts: {
  store: Store;
  backend: BackendRecord;
  redirectUri: string;
  allowPrivateUrls: boolean;
  info: {
    authorizationServerUrl: string | URL;
    authorizationServerMetadata?: Record<string, unknown>;
    resourceMetadata?: { scopes_supported?: string[] };
  };
  scope: string | null;
  fetchFn: ReturnType<typeof createSafeFetch>;
}): Promise<OauthStartResult> {
  const metadata = opts.info.authorizationServerMetadata;
  const endpoint = metadata?.device_authorization_endpoint;
  if (typeof endpoint !== "string") {
    throw new Error("this authorization server does not offer device login");
  }
  const conn = { db: opts.store.db, masterKey: opts.store.masterKey };
  let clientId = getOauthRow(opts.store.db, opts.backend.id)?.clientId ?? "";
  if (!clientId) {
    const scope = grantScope(opts.scope, opts.info);
    const registered = await registerClient(opts.info.authorizationServerUrl, {
      metadata: metadata as never,
      clientMetadata: {
        client_name: "mcp-flow",
        redirect_uris: [LOOPBACK_DCR_REDIRECT],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      },
      ...(scope ? { scope } : {}),
      fetchFn: opts.fetchFn,
    });
    saveOauthClient(conn, opts.backend.id, {
      clientId: registered.client_id,
      ...(registered.client_secret ? { clientSecret: registered.client_secret } : {}),
      dynamicClient: true,
    });
    clientId = registered.client_id;
  }
  const scope = grantScope(opts.scope, opts.info);
  const body = new URLSearchParams({ client_id: clientId });
  if (scope) body.set("scope", scope);
  const response = await opts.fetchFn(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
  });
  if (!response.ok) {
    const failed = await readOauthError(response);
    const message = failed.description
      ? `${failed.error}: ${failed.description}`
      : `OAuth error: ${failed.error}`;
    setOauthLastError(opts.store.db, opts.backend.id, message);
    throw new Error(message);
  }
  const payload = (await response.json()) as Record<string, unknown>;
  const deviceCode = stringField(payload, "device_code");
  const userCode = stringField(payload, "user_code");
  const verificationUri = stringField(payload, "verification_uri");
  if (!deviceCode || !userCode || !verificationUri) {
    throw new Error("device authorization response was missing user_code");
  }
  const intervalSeconds = Math.max(
    5,
    numberField(payload, "interval") ?? 5,
  );
  const expiresIn = numberField(payload, "expires_in") ?? 600;
  const expiresAt = new Date(Date.now() + expiresIn * 1000).toISOString();
  const verificationUriComplete = stringField(payload, "verification_uri_complete");
  saveOauthDevice(conn, opts.backend.id, {
    deviceCode,
    intervalSeconds,
    userCode,
    verificationUri,
    ...(verificationUriComplete ? { verificationUriComplete } : {}),
    expiresAt,
  });
  return {
    mode: "device",
    redirectUri: opts.redirectUri,
    userCode,
    verificationUri,
    verificationUriComplete,
    expiresAt,
    intervalSeconds,
  };
}

export async function pollOauthDevice(opts: {
  store: Store;
  backend: BackendRecord;
  allowPrivateUrls: boolean;
  keyId?: string | null;
  ip?: string | null;
}): Promise<
  | { status: "pending"; intervalSeconds: number }
  | { status: "connected" }
  | { status: "expired" | "error"; error: string }
> {
  const conn = { db: opts.store.db, masterKey: opts.store.masterKey };
  const row = getOauthRow(opts.store.db, opts.backend.id);
  const secrets = readOauthSecrets(opts.store.db, opts.store.masterKey, opts.backend.id);
  const device = secrets?.device;
  if (!row || !device?.deviceCode) {
    return { status: "error", error: "no device authorization in progress" };
  }
  if (Date.parse(device.expiresAt) <= Date.now()) {
    clearOauthTokens(conn, opts.backend.id, "device code expired");
    return { status: "expired", error: "device code expired" };
  }
  const tokenEndpoint = secrets?.discovery?.authorizationServerMetadata?.token_endpoint;
  if (typeof tokenEndpoint !== "string" || !row.clientId) {
    return { status: "error", error: "token endpoint is not known" };
  }
  const body = new URLSearchParams({
    grant_type: DEVICE_GRANT,
    device_code: device.deviceCode,
    client_id: row.clientId,
  });
  const response = await createSafeFetch(opts.allowPrivateUrls)(tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body,
  });
  if (response.ok) {
    const tokens = readTokenFields((await response.json()) as Record<string, unknown>);
    const expiresAt =
      tokens.expires_in != null
        ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
        : null;
    saveOauthTokens(conn, opts.backend.id, tokens, expiresAt);
    opts.store.writeAudit({
      workspaceId: opts.backend.workspaceId,
      keyId: opts.keyId,
      action: "oauth.authorize",
      backendSlug: opts.backend.slug,
      detail: { phase: "device" },
      ip: opts.ip,
    });
    return { status: "connected" };
  }
  const failed = await readOauthError(response);
  if (failed.error === "authorization_pending") {
    return { status: "pending", intervalSeconds: device.intervalSeconds };
  }
  if (failed.error === "slow_down") {
    const intervalSeconds = device.intervalSeconds + 5;
    saveOauthDevice(conn, opts.backend.id, { ...device, intervalSeconds });
    return { status: "pending", intervalSeconds };
  }
  const message = failed.description
    ? `${failed.error}: ${failed.description}`
    : failed.error;
  clearOauthTokens(conn, opts.backend.id, message);
  return { status: "error", error: message };
}

function stringField(obj: Record<string, unknown>, key: string): string | null {
  const value = obj[key];
  return typeof value === "string" && value.trim() ? value : null;
}

function numberField(obj: Record<string, unknown>, key: string): number | null {
  const value = obj[key];
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function readTokenFields(payload: Record<string, unknown>): NonNullable<OauthSecrets["tokens"]> {
  const access = stringField(payload, "access_token");
  if (!access) throw new Error("token response missing access_token");
  const expires = numberField(payload, "expires_in");
  const refresh = stringField(payload, "refresh_token");
  const scope = stringField(payload, "scope");
  return {
    access_token: access,
    token_type: stringField(payload, "token_type") ?? "Bearer",
    ...(expires != null ? { expires_in: expires } : {}),
    ...(refresh ? { refresh_token: refresh } : {}),
    ...(scope ? { scope } : {}),
  };
}

async function readOauthError(
  response: Response,
): Promise<{ error: string; description: string }> {
  const text = await response.text();
  try {
    const json = JSON.parse(text) as { error?: unknown; error_description?: unknown };
    const error = typeof json.error === "string" && json.error ? json.error : "server_error";
    const description =
      typeof json.error_description === "string"
        ? redactSecrets(json.error_description).slice(0, 300)
        : "";
    return { error, description };
  } catch {
    return { error: "server_error", description: redactSecrets(text).slice(0, 200) };
  }
}

export async function completeOauthCallback(opts: {
  store: Store;
  code?: string;
  state?: string;
  oauthError?: string;
  allowPrivateUrls: boolean;
}): Promise<{ ok: true; slug: string } | { ok: false }> {
  if (!opts.state) return { ok: false };
  const backendId = consumeOauthPendingState(opts.store.db, hashToken(opts.state));
  if (!backendId) return { ok: false };
  const backend = opts.store.getBackendById(backendId);
  const row = getOauthRow(opts.store.db, backendId);
  if (!backend?.url || !row?.redirectUri) return { ok: false };

  if (opts.oauthError || !opts.code) {
    const code = sanitizeOauthErrorCode(opts.oauthError);
    setOauthLastError(opts.store.db, backendId, `authorization ${code}`);
    return { ok: false };
  }

  const before = readOauthSecrets(opts.store.db, opts.store.masterKey, backendId);
  const replacing = Boolean(before?.tokens?.access_token || before?.tokens?.refresh_token);
  const provider = new StoreOauthProvider({
    store: opts.store,
    backendId,
    workspaceId: backend.workspaceId,
    slug: backend.slug,
    redirectUri: row.redirectUri,
    interactive: true,
    allowPrivateUrls: opts.allowPrivateUrls,
  });
  try {
    const result = await auth(provider, {
      serverUrl: backend.url,
      authorizationCode: opts.code,
      fetchFn: createSafeFetch(opts.allowPrivateUrls),
      ...(row.scope ? { scope: row.scope } : {}),
    });
    if (result !== "AUTHORIZED") {
      throw new Error("authorization did not complete");
    }
  } catch (err) {
    setOauthLastError(opts.store.db, backendId, safeOauthMessage(err));
    return { ok: false };
  }

  opts.store.writeAudit({
    workspaceId: backend.workspaceId,
    action: replacing ? "oauth.reauth" : "oauth.authorize",
    backendSlug: backend.slug,
    detail: replacing ? { phase: "completed" } : { phase: "authorized" },
  });
  return { ok: true, slug: backend.slug };
}

export async function revokeOauthGrant(opts: {
  store: Store;
  backend: BackendRecord;
  allowPrivateUrls: boolean;
  keyId?: string | null;
  ip?: string | null;
}): Promise<void> {
  const row = getOauthRow(opts.store.db, opts.backend.id);
  if (!row) throw new Error("backend is not configured for OAuth");
  const secrets = readOauthSecrets(
    opts.store.db,
    opts.store.masterKey,
    opts.backend.id,
  );
  const endpoint = secrets?.discovery?.authorizationServerMetadata?.revocation_endpoint;
  const token = secrets?.tokens?.refresh_token || secrets?.tokens?.access_token;
  if (typeof endpoint === "string" && token) {
    try {
      const headers = new Headers({
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      });
      if (row.clientId && secrets?.clientSecret) {
        const basic = Buffer.from(`${row.clientId}:${secrets.clientSecret}`).toString(
          "base64",
        );
        headers.set("Authorization", `Basic ${basic}`);
      }
      await createSafeFetch(opts.allowPrivateUrls)(endpoint, {
        method: "POST",
        headers,
        body: new URLSearchParams({
          token,
          token_type_hint: secrets?.tokens?.refresh_token
            ? "refresh_token"
            : "access_token",
        }),
      });
    } catch {
      /* Local grant is cleared even when the provider cannot be reached. */
    }
  }
  clearOauthTokens(
    { db: opts.store.db, masterKey: opts.store.masterKey },
    opts.backend.id,
    null,
  );
  opts.store.writeAudit({
    workspaceId: opts.backend.workspaceId,
    keyId: opts.keyId,
    action: "oauth.revoke",
    backendSlug: opts.backend.slug,
    detail: { phase: "revoked" },
    ip: opts.ip,
  });
}

function sanitizeOauthErrorCode(code: string | undefined): string {
  if (code && /^[a-z0-9_]{1,64}$/i.test(code)) return code;
  return "access_denied";
}
