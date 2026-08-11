export type PlacementMode =
  | "remote"
  | "central-sandbox"
  | "edge-sandbox"
  | "edge-bare";

export type TransportKind =
  | "streamable-http"
  | "sse"
  | "stdio"
  | "oci";

export type Affinity = "harness-local" | "pinned" | "any-online";

export interface Placement {
  mode: PlacementMode;
  deviceId?: string;
  deviceTags?: string[];
  affinity?: Affinity;
}

export interface Workspace {
  id: string;
  name: string;
  createdAt: string;
}

/** null/undefined scopes = full workspace tool access */
export interface ApiKeyScopes {
  /** Match tool names by prefix, e.g. "yh-finance__", "mf_" */
  toolPrefixAllowlist?: string[];
}

export interface ApiKeyRecord {
  id: string;
  workspaceId: string;
  name: string;
  tokenHash: string;
  prefix: string;
  scopes: ApiKeyScopes | null;
  createdAt: string;
  revokedAt: string | null;
}

export interface ApiKeyPublic {
  id: string;
  workspaceId: string;
  name: string;
  prefix: string;
  scopes: ApiKeyScopes | null;
  createdAt: string;
  revokedAt: string | null;
}

export interface ApiKeyCreated extends ApiKeyPublic {
  /** Shown once at creation — never stored plaintext */
  token: string;
}

export interface BackendRecord {
  id: string;
  workspaceId: string;
  slug: string;
  title: string;
  transport: TransportKind;
  url: string | null;
  image: string | null;
  commandJson: string | null;
  headersEnc: string | null;
  envEnc: string | null;
  enabled: boolean;
  toolAllowlistJson: string | null;
  placementJson: string;
  createdAt: string;
  updatedAt: string;
}

export interface BackendPublic {
  id: string;
  workspaceId: string;
  slug: string;
  title: string;
  transport: TransportKind;
  url: string | null;
  image: string | null;
  command: string[] | null;
  /** True when sealed headers exist — values never returned */
  hasHeaders: boolean;
  /** True when sealed env exists — values never returned */
  hasEnv: boolean;
  enabled: boolean;
  toolAllowlist: string[] | null;
  placement: Placement;
  createdAt: string;
  updatedAt: string;
}

export interface CreateBackendInput {
  slug: string;
  title?: string;
  transport?: TransportKind;
  url?: string;
  image?: string;
  command?: string[];
  headers?: Record<string, string>;
  env?: Record<string, string>;
  enabled?: boolean;
  toolAllowlist?: string[];
  placement?: Placement;
}

export interface UpdateBackendInput {
  title?: string;
  transport?: TransportKind;
  url?: string | null;
  image?: string | null;
  command?: string[] | null;
  headers?: Record<string, string> | null;
  env?: Record<string, string> | null;
  enabled?: boolean;
  toolAllowlist?: string[] | null;
  placement?: Placement;
}

export interface AuthContext {
  kind: "admin" | "api_key";
  workspaceId: string;
  keyId?: string;
  keyName?: string;
  scopes?: ApiKeyScopes | null;
}

export type AuditAction =
  | "tools/call"
  | "tools/list"
  | "backend.create"
  | "backend.update"
  | "backend.delete"
  | "backend.test"
  | "key.create"
  | "key.revoke"
  | "key.update"
  | "catalog.install"
  | "catalog.sync";

export interface AuditEvent {
  id: string;
  ts: string;
  workspaceId: string;
  keyId: string | null;
  action: AuditAction | string;
  backendSlug: string | null;
  tool: string | null;
  placement: string | null;
  detail: Record<string, unknown> | null;
  ip: string | null;
}

export const DEFAULT_PLACEMENT: Placement = { mode: "remote" };

/** Always allowed even when scopes restrict tools */
export const ALWAYS_ALLOWED_META_TOOLS = new Set(["mf_status"]);

export function toolAllowedByScopes(
  toolName: string,
  scopes: ApiKeyScopes | null | undefined,
): boolean {
  if (!scopes?.toolPrefixAllowlist?.length) return true;
  if (ALWAYS_ALLOWED_META_TOOLS.has(toolName)) return true;
  return scopes.toolPrefixAllowlist.some((p) => toolName.startsWith(p));
}
