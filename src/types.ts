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

export interface WorkspacePolicy {
  /** Enterprise default false — host process on edge devices */
  allowEdgeBare?: boolean;
}

export const DEFAULT_WORKSPACE_POLICY: WorkspacePolicy = {
  allowEdgeBare: false,
};

export interface Workspace {
  id: string;
  name: string;
  createdAt: string;
  policy: WorkspacePolicy;
}

export type DeviceSandboxCap = "docker" | "podman" | "none";

export interface DeviceCapabilities {
  sandbox: DeviceSandboxCap;
  bare: boolean;
}

export type DeviceStatus = "online" | "offline";

export interface Device {
  id: string;
  workspaceId: string;
  name: string;
  tags: string[];
  capabilities: DeviceCapabilities;
  status: DeviceStatus;
  lastSeen: string | null;
  createdAt: string;
  /** Hashed device credential — never returned on public list as hash */
  tokenHash?: string;
}

export interface DevicePublic {
  id: string;
  workspaceId: string;
  name: string;
  tags: string[];
  capabilities: DeviceCapabilities;
  status: DeviceStatus;
  lastSeen: string | null;
  createdAt: string;
}

export interface DeviceEnrolled extends DevicePublic {
  /** Shown once at enrollment */
  token: string;
}

/** Optional runtime limits for central/edge sandbox */
export interface SandboxConfig {
  /** e.g. "512m" */
  memory?: string;
  /** e.g. "1.0" */
  cpus?: string;
  /** docker/podman network mode; default bridge */
  networkMode?: string;
}

/** null/undefined scopes = full workspace tool access (non-admin) */
export interface ApiKeyScopes {
  /** Match tool names by prefix, e.g. "yh-finance__", "mf_" */
  toolPrefixAllowlist?: string[];
  /**
   * Operator key: may call mf_admin_* tools and (when dual-auth is on) /v1/* REST.
   * Only mintable by env admin token or another admin key.
   */
  admin?: boolean;
}

export function isAdminScopes(
  scopes: ApiKeyScopes | null | undefined,
): boolean {
  return Boolean(scopes?.admin);
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
  sandboxJson: string | null;
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
  sandbox: SandboxConfig | null;
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
  sandbox?: SandboxConfig | null;
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
  sandbox?: SandboxConfig | null;
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
  | "catalog.sync"
  | "device.enroll"
  | "device.revoke"
  | "device.connect"
  | "bare_exec"
  | "workspace.policy";

export interface AuditEvent {
  id: string;
  ts: string;
  workspaceId: string;
  keyId: string | null;
  action: AuditAction | string;
  backendSlug: string | null;
  tool: string | null;
  placement: string | null;
  deviceId: string | null;
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
  // Admin tools only for operator keys
  if (toolName.startsWith("mf_admin_")) {
    return isAdminScopes(scopes);
  }
  if (!scopes?.toolPrefixAllowlist?.length) return true;
  if (ALWAYS_ALLOWED_META_TOOLS.has(toolName)) return true;
  // Admin keys may still use other mf_* metas when prefixes are set
  if (isAdminScopes(scopes) && toolName.startsWith("mf_")) return true;
  return scopes.toolPrefixAllowlist.some((p) => toolName.startsWith(p));
}
