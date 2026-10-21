import { randomBytes } from "node:crypto";
import { refreshAuthorization } from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthClientProvider,
  OAuthDiscoveryState,
} from "@modelcontextprotocol/sdk/client/auth.js";
import type {
  OAuthClientInformationMixed,
  OAuthClientMetadata,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthorizationServerMetadata } from "@modelcontextprotocol/sdk/shared/auth.js";
import { hashToken } from "../crypto.js";
import type { Store } from "../db/store.js";
import {
  clearOauthClient,
  clearOauthDiscovery,
  clearOauthTokens,
  clearOauthVerifier,
  getOauthRow,
  mergeOauthSecrets,
  readOauthSecrets,
  saveOauthClient,
  saveOauthDiscovery,
  saveOauthPendingState,
  saveOauthTokens,
  type OauthSecrets,
} from "../db/oauth-store.js";
import { createSafeFetch } from "./fetch.js";
import { PENDING_STATE_MS, REFRESH_SKEW_MS } from "./time.js";

const refreshInflight = new Map<string, Promise<OAuthTokens>>();

export class NeedsReauthError extends Error {
  readonly backendSlug: string;

  constructor(slug: string) {
    super(
      `Backend "${slug}" needs re-authorization. An admin can reconnect it in place with \`mcp-flow backend oauth login ${slug}\`.`,
    );
    this.name = "NeedsReauthError";
    this.backendSlug = slug;
  }
}

export function oauthErrorCode(err: unknown): string {
  if (err && typeof err === "object" && "errorCode" in err) {
    const code = (err as { errorCode?: unknown }).errorCode;
    if (typeof code === "string" && /^[a-z0-9_]{1,64}$/i.test(code)) return code;
  }
  return "refresh_failed";
}

export interface StoreOauthProviderOptions {
  store: Store;
  backendId: string;
  workspaceId: string;
  slug: string;
  redirectUri: string;
  /**
   * Admin consent start and the callback exchange.
   * tokens() stays empty so the SDK builds a consent URL instead of refreshing.
   */
  interactive: boolean;
  allowPrivateUrls: boolean;
  /** Set when an agent call is what discovered the grant is dead. */
  onRefreshFailure?: (code: string) => void;
}

/**
 * OAuth client backed by the sealed backend_oauth row.
 * The SDK calls this during discovery, registration, code exchange, and requests.
 */
export class StoreOauthProvider implements OAuthClientProvider {
  /** Captured during an interactive start. Not followed by the gateway. */
  authorizationUrl: URL | null = null;
  private stateValue: string | null = null;
  private hadGrant = false;

  constructor(private readonly opts: StoreOauthProviderOptions) {}

  get redirectUrl(): string {
    return this.opts.redirectUri;
  }

  get clientMetadata(): OAuthClientMetadata {
    const row = getOauthRow(this.opts.store.db, this.opts.backendId);
    const secrets = this.secrets();
    const metadata: OAuthClientMetadata = {
      client_name: "mcp-flow",
      redirect_uris: [this.opts.redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      token_endpoint_auth_method: secrets?.clientSecret
        ? "client_secret_basic"
        : "none",
    };
    if (row?.scope) metadata.scope = row.scope;
    return metadata;
  }

  async state(): Promise<string> {
    if (this.stateValue) return this.stateValue;
    this.stateValue = randomBytes(32).toString("base64url");
    saveOauthPendingState(
      this.opts.store.db,
      this.opts.backendId,
      hashToken(this.stateValue),
      new Date(Date.now() + PENDING_STATE_MS).toISOString(),
    );
    return this.stateValue;
  }

  async clientInformation(): Promise<OAuthClientInformationMixed | undefined> {
    const row = getOauthRow(this.opts.store.db, this.opts.backendId);
    if (!row?.clientId) return undefined;
    const secrets = this.secrets();
    return secrets?.clientSecret
      ? { client_id: row.clientId, client_secret: secrets.clientSecret }
      : { client_id: row.clientId };
  }

  async saveClientInformation(info: OAuthClientInformationMixed): Promise<void> {
    const clientId = info.client_id?.trim();
    if (!clientId) return;
    const existing = getOauthRow(this.opts.store.db, this.opts.backendId);
    const dynamic = !existing?.clientId || Boolean(this.secrets()?.dynamicClient);
    saveOauthClient(this.conn(), this.opts.backendId, {
      clientId,
      ...(info.client_secret ? { clientSecret: info.client_secret } : {}),
      dynamicClient: dynamic,
      registeredRedirectUris: [this.opts.redirectUri],
    });
  }

  async tokens(): Promise<OAuthTokens | undefined> {
    if (this.opts.interactive) return undefined;
    const secrets = this.secrets();
    if (!secrets?.tokens?.access_token) return undefined;
    const tokens = secrets.tokens;
    this.hadGrant = true;
    const row = getOauthRow(this.opts.store.db, this.opts.backendId);
    if (tokens.refresh_token && row?.tokenExpiresAt) {
      const exp = Date.parse(row.tokenExpiresAt);
      if (!Number.isNaN(exp) && exp - Date.now() <= REFRESH_SKEW_MS) {
        return this.refreshSingleFlight(secrets);
      }
    }
    return toSdkTokens(tokens);
  }

  async saveTokens(tokens: OAuthTokens): Promise<void> {
    const prev = this.secrets();
    const refresh = tokens.refresh_token ?? prev?.tokens?.refresh_token;
    const expiresAt =
      tokens.expires_in != null
        ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
        : null;
    saveOauthTokens(this.conn(), this.opts.backendId, {
      access_token: tokens.access_token,
      token_type: tokens.token_type || "Bearer",
      ...(tokens.expires_in != null ? { expires_in: tokens.expires_in } : {}),
      ...(refresh ? { refresh_token: refresh } : {}),
      ...(tokens.scope ? { scope: tokens.scope } : {}),
      ...(tokens.id_token ? { id_token: tokens.id_token } : {}),
    }, expiresAt);
  }

  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    if (this.opts.interactive) {
      this.authorizationUrl = authorizationUrl;
      return;
    }
    clearOauthTokens(this.conn(), this.opts.backendId, "authorization required");
    if (this.hadGrant) this.opts.onRefreshFailure?.("authorization_required");
    throw new NeedsReauthError(this.opts.slug);
  }

  async saveCodeVerifier(codeVerifier: string): Promise<void> {
    mergeOauthSecrets(this.conn(), this.opts.backendId, (secrets) => {
      secrets.codeVerifier = codeVerifier;
    });
  }

  async codeVerifier(): Promise<string> {
    const verifier = this.secrets()?.codeVerifier;
    if (!verifier) throw new Error("missing PKCE code verifier");
    return verifier;
  }

  async saveDiscoveryState(state: OAuthDiscoveryState): Promise<void> {
    saveOauthDiscovery(this.conn(), this.opts.backendId, {
      authorizationServerUrl: String(state.authorizationServerUrl),
      ...(state.resourceMetadataUrl
        ? { resourceMetadataUrl: String(state.resourceMetadataUrl) }
        : {}),
      ...(state.authorizationServerMetadata
        ? {
            authorizationServerMetadata: state.authorizationServerMetadata as Record<
              string,
              unknown
            >,
          }
        : {}),
      ...(state.resourceMetadata
        ? { resourceMetadata: state.resourceMetadata as Record<string, unknown> }
        : {}),
    });
  }

  async discoveryState(): Promise<OAuthDiscoveryState | undefined> {
    const discovery = this.secrets()?.discovery;
    if (!discovery?.authorizationServerUrl) return undefined;
    return {
      authorizationServerUrl: discovery.authorizationServerUrl,
      ...(discovery.resourceMetadataUrl
        ? { resourceMetadataUrl: discovery.resourceMetadataUrl }
        : {}),
      ...(discovery.authorizationServerMetadata
        ? {
            authorizationServerMetadata:
              discovery.authorizationServerMetadata as unknown as OAuthDiscoveryState["authorizationServerMetadata"],
          }
        : {}),
      ...(discovery.resourceMetadata
        ? {
            resourceMetadata:
              discovery.resourceMetadata as unknown as OAuthDiscoveryState["resourceMetadata"],
          }
        : {}),
    };
  }

  async invalidateCredentials(
    scope: "all" | "client" | "tokens" | "verifier" | "discovery",
  ): Promise<void> {
    const conn = this.conn();
    if (scope === "all" || scope === "tokens") {
      clearOauthTokens(conn, this.opts.backendId, "credentials invalidated");
    }
    if (scope === "all" || scope === "verifier") {
      clearOauthVerifier(conn, this.opts.backendId);
    }
    if (scope === "all" || scope === "discovery") {
      clearOauthDiscovery(conn, this.opts.backendId);
    }
    if ((scope === "all" || scope === "client") && this.secrets()?.dynamicClient) {
      clearOauthClient(conn, this.opts.backendId);
    }
  }

  /** Fail closed before opening a connection when the grant cannot be used. */
  async prepareForConnect(): Promise<void> {
    const row = getOauthRow(this.opts.store.db, this.opts.backendId);
    const secrets = this.secrets();
    if (!row || !secrets?.tokens?.access_token || row.status === "needs_reauth") {
      throw new NeedsReauthError(this.opts.slug);
    }
    if (row.tokenExpiresAt) {
      const remaining = Date.parse(row.tokenExpiresAt) - Date.now();
      if (remaining <= 0 && !secrets.tokens.refresh_token) {
        clearOauthTokens(this.conn(), this.opts.backendId, "access token expired");
        throw new NeedsReauthError(this.opts.slug);
      }
    }
    await this.tokens();
  }

  private conn() {
    return { db: this.opts.store.db, masterKey: this.opts.store.masterKey };
  }

  private secrets(): OauthSecrets | null {
    return readOauthSecrets(
      this.opts.store.db,
      this.opts.store.masterKey,
      this.opts.backendId,
    );
  }

  private refreshSingleFlight(secrets: OauthSecrets): Promise<OAuthTokens> {
    const existing = refreshInflight.get(this.opts.backendId);
    if (existing) return existing;
    const job = this.doRefresh(secrets).finally(() => {
      if (refreshInflight.get(this.opts.backendId) === job) {
        refreshInflight.delete(this.opts.backendId);
      }
    });
    refreshInflight.set(this.opts.backendId, job);
    return job;
  }

  private async doRefresh(secrets: OauthSecrets): Promise<OAuthTokens> {
    const row = getOauthRow(this.opts.store.db, this.opts.backendId);
    const refreshToken = secrets.tokens?.refresh_token;
    const issuer = secrets.discovery?.authorizationServerUrl;
    if (!row?.clientId || !refreshToken || !issuer) {
      this.failRefresh("refresh_failed");
      throw new NeedsReauthError(this.opts.slug);
    }
    const resourceValue = secrets.discovery?.resourceMetadata?.resource;
    const resource =
      typeof resourceValue === "string" ? new URL(resourceValue) : undefined;
    try {
      const next = await refreshAuthorization(issuer, {
        metadata: secrets.discovery?.authorizationServerMetadata as
          | AuthorizationServerMetadata
          | undefined,
        clientInformation: secrets.clientSecret
          ? { client_id: row.clientId, client_secret: secrets.clientSecret }
          : { client_id: row.clientId },
        refreshToken,
        ...(resource ? { resource } : {}),
        fetchFn: createSafeFetch(this.opts.allowPrivateUrls),
      });
      await this.saveTokens(next);
      return next;
    } catch (err) {
      if (err instanceof NeedsReauthError) throw err;
      const code = oauthErrorCode(err);
      this.failRefresh(code);
      throw new NeedsReauthError(this.opts.slug);
    }
  }

  private failRefresh(code: string): void {
    clearOauthTokens(
      this.conn(),
      this.opts.backendId,
      `refresh failed: ${code}`,
    );
    this.opts.onRefreshFailure?.(code);
  }
}

function toSdkTokens(tokens: NonNullable<OauthSecrets["tokens"]>): OAuthTokens {
  return {
    access_token: tokens.access_token,
    token_type: tokens.token_type || "Bearer",
    ...(tokens.expires_in != null ? { expires_in: tokens.expires_in } : {}),
    ...(tokens.refresh_token ? { refresh_token: tokens.refresh_token } : {}),
    ...(tokens.scope ? { scope: tokens.scope } : {}),
    ...(tokens.id_token ? { id_token: tokens.id_token } : {}),
  };
}
