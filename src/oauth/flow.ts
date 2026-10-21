import {
  auth,
  discoverOAuthServerInfo,
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
  saveOauthDiscovery,
  setOauthLastError,
  setOauthRedirect,
  consumeOauthPendingState,
} from "../db/oauth-store.js";
import { createSafeFetch } from "./fetch.js";
import { StoreOauthProvider, oauthErrorCode } from "./provider.js";

const SETUP_HINT =
  "This server does not offer dynamic client registration. Enter a client id and, if the provider uses a confidential client, a client secret.";

export function safeOauthMessage(err: unknown): string {
  const code = oauthErrorCode(err);
  if (code !== "refresh_failed") return `OAuth error: ${code}`;
  const raw = err instanceof Error ? err.message : String(err);
  return redactSecrets(raw).slice(0, 300);
}

export interface OauthStartResult {
  authorizationUrl: string;
  redirectUri: string;
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
    authorizationUrl: provider.authorizationUrl.href,
    redirectUri: opts.redirectUri,
  };
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
