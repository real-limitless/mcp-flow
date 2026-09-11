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
  /**
   * Project slugs this key may activate. Empty/undefined = all projects.
   */
  projects?: string[];
  /** Default project slug when no session has selected one */
  defaultProject?: string;
  /**
   * Opt-in: hide namespaced upstream tools from tools/list. The agent
   * searches with mf_list_tools, then mf_enable_tools / mf_call_tool.
   */
  dynamicTools?: boolean;
  /**
   * Prefixes always treated as enabled when dynamicTools is on
   * (e.g. "github__") — Anthropic-style hot tools.
   */
  dynamicToolsHot?: string[];
}

export function isAdminScopes(
  scopes: ApiKeyScopes | null | undefined,
): boolean {
  return Boolean(scopes?.admin);
}

/** Working-set listing / enable cap (stay under typical 200-tool harness limits). */
export const DYNAMIC_TOOLS_LIST_CAP = 32;
/** Absolute ceiling; listing/enable never exceed this. */
export const DYNAMIC_TOOLS_HARD_CAP = 128;
/**
 * mf_list_tools page size when `limit` is omitted: the full in-scope catalog
 * (names + descriptions, not schemas). Native tools/list stays at LIST_CAP.
 */
export const DYNAMIC_LIST_DEFAULT_LIMIT = 5000;
/** Hard cap per mf_list_tools call. Page with `offset` if the catalog is larger. */
export const DYNAMIC_LIST_MAX_LIMIT = 5000;

export function isDynamicTools(
  scopes: ApiKeyScopes | null | undefined,
): boolean {
  return Boolean(scopes?.dynamicTools);
}

export function scopesHasFields(
  scopes: ApiKeyScopes | null | undefined,
): boolean {
  if (!scopes) return false;
  return Boolean(
    scopes.admin ||
      scopes.dynamicTools ||
      scopes.toolPrefixAllowlist?.length ||
      scopes.projects?.length ||
      scopes.defaultProject ||
      scopes.dynamicToolsHot?.length,
  );
}

export function toolMatchesHotPrefix(
  toolName: string,
  scopes: ApiKeyScopes | null | undefined,
): boolean {
  const hot = scopes?.dynamicToolsHot;
  if (!hot?.length) return false;
  return hot.some((p) => toolName.startsWith(p));
}

/**
 * Visibility/invoke gate for namespaced tools when dynamicTools is on.
 * Meta tools always pass. When the flag is off, every in-scope tool is enabled.
 */
export function toolEnabledInWorkingSet(
  toolName: string,
  working: ReadonlySet<string>,
  scopes: ApiKeyScopes | null | undefined,
): boolean {
  if (toolName.startsWith("mf_")) return true;
  if (!isDynamicTools(scopes)) return true;
  if (working.has(toolName)) return true;
  return toolMatchesHotPrefix(toolName, scopes);
}

export function dynamicToolsCap(): number {
  return Math.min(DYNAMIC_TOOLS_LIST_CAP, DYNAMIC_TOOLS_HARD_CAP);
}

export function clampToolSearchLimit(raw: unknown): number {
  if (raw == null || raw === "" || raw === true || raw === "all") {
    return DYNAMIC_LIST_MAX_LIMIT;
  }
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 1) return DYNAMIC_LIST_MAX_LIMIT;
  return Math.min(Math.floor(n), DYNAMIC_LIST_MAX_LIMIT);
}

export function clampToolSearchOffset(raw: unknown): number {
  const n = Number(raw ?? 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(Math.floor(n), 1_000_000);
}

/** Named collection of backends for multi-project tool views */
export interface Project {
  id: string;
  workspaceId: string;
  slug: string;
  title: string;
  description: string | null;
  /** Backend slugs included in this project */
  backendSlugs: string[];
  /** Extra tool prefixes (optional fine filter) */
  toolPrefixAllowlist: string[] | null;
  isDefault: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateProjectInput {
  slug: string;
  title?: string;
  description?: string | null;
  backendSlugs?: string[];
  toolPrefixAllowlist?: string[] | null;
  isDefault?: boolean;
}

export interface UpdateProjectInput {
  title?: string;
  description?: string | null;
  backendSlugs?: string[];
  toolPrefixAllowlist?: string[] | null;
  isDefault?: boolean;
}

/** Short-lived project session (mf_sess_*) */
export interface ProjectSessionPublic {
  id: string;
  keyId: string;
  projectId: string;
  projectSlug: string;
  expiresAt: string;
  createdAt: string;
}

export interface ProjectSessionCreated extends ProjectSessionPublic {
  /** Shown once */
  token: string;
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
  kind: "admin" | "api_key" | "project_session";
  workspaceId: string;
  keyId?: string;
  keyName?: string;
  scopes?: ApiKeyScopes | null;
  /** Active project when bound via session token or MCP session sticky */
  projectId?: string | null;
  projectSlug?: string | null;
  /** MCP transport session id when present */
  mcpSessionId?: string | null;
  /** Project session row id when auth is mf_sess_* */
  projectSessionId?: string | null;
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
  | "workspace.policy"
  | "project.create"
  | "project.update"
  | "project.delete"
  | "project.use";

export interface AuditEvent {
  id: string;
  ts: string;
  workspaceId: string;
  /** Actor that performed the action (`audit_events.key_id`). */
  keyId: string | null;
  /** Joined from `api_keys` at list time; null if env/system or key missing. */
  keyName: string | null;
  /** Joined token prefix (e.g. `mf_ab12`); never the secret. */
  keyPrefix: string | null;
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
export const ALWAYS_ALLOWED_META_TOOLS = new Set([
  "mf_status",
  "mf_list_projects",
  "mf_use_project",
  "mf_current_project",
  "mf_list_backends",
  "mf_list_tools",
  "mf_get_tool_schema",
  "mf_enable_tools",
  "mf_disable_tools",
  "mf_call_tool",
]);

export function toolAllowedByScopes(
  toolName: string,
  scopes: ApiKeyScopes | null | undefined,
): boolean {
  // Admin tools only for operator keys
  if (toolName.startsWith("mf_admin_")) {
    return isAdminScopes(scopes);
  }
  if (ALWAYS_ALLOWED_META_TOOLS.has(toolName)) return true;
  if (!scopes?.toolPrefixAllowlist?.length) return true;
  // Admin keys may still use other mf_* metas when prefixes are set
  if (isAdminScopes(scopes) && toolName.startsWith("mf_")) return true;
  return scopes.toolPrefixAllowlist.some((p) => toolName.startsWith(p));
}

/**
 * Filter upstream tools by active project (backend membership).
 * Meta tools (mf_*) always pass here — scopes handle admin.
 */
export function toolAllowedByProject(
  toolName: string,
  project: Project | null | undefined,
): boolean {
  if (toolName.startsWith("mf_")) return true;
  if (!project) return true;
  const slug = toolName.split("__")[0] ?? "";
  if (!project.backendSlugs.length) return false;
  if (!project.backendSlugs.includes(slug)) return false;
  if (project.toolPrefixAllowlist?.length) {
    return project.toolPrefixAllowlist.some((p) => toolName.startsWith(p));
  }
  return true;
}

/** Whether a key may activate a project slug */
export function keyMayUseProject(
  scopes: ApiKeyScopes | null | undefined,
  projectSlug: string,
): boolean {
  if (isAdminScopes(scopes)) return true;
  const allowed = scopes?.projects;
  if (!allowed?.length) return true;
  return allowed.includes(projectSlug);
}

export function resolveDefaultProjectSlug(
  scopes: ApiKeyScopes | null | undefined,
  workspaceDefaultSlug: string | null,
): string | null {
  if (scopes?.defaultProject) return scopes.defaultProject;
  return workspaceDefaultSlug;
}
