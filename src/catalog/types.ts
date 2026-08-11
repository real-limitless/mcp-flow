export const CATALOG_SCHEMA_VERSION = "1.2.0";

export type GalleryTransport =
  | "streamable-http"
  | "sse"
  | "stdio"
  | "unknown";

export type GalleryFlag =
  | "remote"
  | "stdio"
  | "incomplete"
  /** Source GitHub/GitLab repo returned 404/410 */
  | "repo-offline";

export type GalleryProvenance = "official-registry" | "manual";

/** registry status + catalog-derived inactive (dead source repo) */
export type GalleryStatus =
  | "active"
  | "deprecated"
  | "deleted"
  | "inactive"
  | "unknown";

export type GalleryPackageKind = "npm" | "pypi" | "oci" | "binary" | "unknown";

/** Env/header variable docs — names + descriptions only, never secret values */
export interface GallerySecretFieldDoc {
  name: string;
  description?: string;
  /** True when registry marks isSecret */
  secret?: boolean;
  /** True only when registry marks required / isRequired */
  required?: boolean;
  /** Default non-secret value from registry if any (rare) */
  default?: string;
}

export interface GalleryHeaderDoc extends GallerySecretFieldDoc {
  /**
   * Registry header value *template* only, e.g. `Bearer {api_key}`.
   * Never a resolved credential.
   */
  valueTemplate?: string;
  /** Placeholder variables inside the template */
  variables?: GallerySecretFieldDoc[];
}

export interface GalleryRemote {
  type: "streamable-http" | "sse" | "unknown";
  url: string;
  headers?: GalleryHeaderDoc[];
}

export interface GalleryInstall {
  kind: GalleryPackageKind;
  package?: string;
  version?: string;
  transport?: GalleryTransport;
  command?: string[];
  environmentVariables?: GallerySecretFieldDoc[];
}

/** Full package list from registry (stdio npm/pypi/oci, etc.) */
export interface GalleryPackage extends GalleryInstall {}

export interface GalleryRepository {
  url?: string;
  source?: string;
  /** Registry/GitHub numeric or string id when present */
  id?: string;
  subfolder?: string;
}

export interface GalleryReadme {
  source: "github" | "gitlab" | "url" | "none";
  url?: string;
  markdown?: string;
  fetchedAt?: string;
  truncated?: boolean;
  error?: string;
}

export type ToolsPreviewStatus =
  | "ok"
  | "auth_required"
  | "unreachable"
  | "unsupported"
  | "skipped";

export interface GalleryToolPreview {
  name: string;
  description?: string;
}

export type SourceRepoStatus =
  | "ok"
  | "not_found"
  | "unreachable"
  | "skipped"
  | "unsupported";

export interface GallerySourceRepoCheck {
  status: SourceRepoStatus;
  url?: string;
  checkedAt?: string;
  httpStatus?: number;
  error?: string;
  host?: "github" | "gitlab";
}

export interface GalleryEnrichment {
  normalizedAt?: string;
  readmeAt?: string;
  toolsAt?: string;
  sourceRepoAt?: string;
  /** All configured stages finished (may include soft-fails) */
  complete?: boolean;
}

export interface McpGalleryEntry {
  id: string;
  title: string;
  /** Full registry description — what the server claims to do */
  description: string;
  /** Short blurb for indexes / TUI lists (derived from description if omitted) */
  summary?: string;
  version?: string;
  status?: GalleryStatus;
  transport: GalleryTransport;
  endpointUrl?: string;
  remotes?: GalleryRemote[];
  install?: GalleryInstall;
  flags?: GalleryFlag[];
  homepage?: string;
  sourceUrl?: string;
  repository?: GalleryRepository;
  /** All registry packages (npm/pypi/…); `install` is the preferred primary */
  packages?: GalleryPackage[];
  /** Aggregated env var docs across packages (names only) */
  environmentVariables?: GallerySecretFieldDoc[];
  categories?: string[];
  updatedAt?: string;
  publishedAt?: string;
  provenance: GalleryProvenance;
  /** Header names marked required — never values */
  requiresHeaders?: string[];
  /** Header docs from registry (names + templates + variable docs; never secrets) */
  headerDocs?: GalleryHeaderDoc[];
  /**
   * Human-oriented capabilities hint from registry text (not live tools/list).
   */
  offersHint?: string;
  /** Cached README from public repo */
  readme?: GalleryReadme;
  /**
   * Live check of sourceUrl / repository.url (GitHub/GitLab).
   * `not_found` → status inactive + flag repo-offline.
   */
  sourceRepo?: GallerySourceRepoCheck;
  /** Live tools/list preview (names + descriptions) */
  toolsPreview?: GalleryToolPreview[];
  toolsPreviewAt?: string;
  toolsPreviewError?: string;
  toolsPreviewStatus?: ToolsPreviewStatus;
  enrichment?: GalleryEnrichment;
}

export interface CatalogMeta {
  schemaVersion: string;
  syncedAt: string | null;
  source: string;
  apiVersion: string;
  /** sharded = entries/*.json + index.json; monolith = gallery.json array */
  storage?: "sharded" | "monolith";
  counts: {
    total: number;
    remote: number;
    stdio: number;
    incomplete: number;
    withReadme?: number;
    withTools?: number;
    inactive?: number;
  };
  note?: string;
}

export const DEFAULT_REGISTRY_URL =
  "https://registry.modelcontextprotocol.io/v0.1/servers";
