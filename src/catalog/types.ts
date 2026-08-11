export const CATALOG_SCHEMA_VERSION = "1.1.0";

export type GalleryTransport =
  | "streamable-http"
  | "sse"
  | "stdio"
  | "unknown";

export type GalleryFlag = "remote" | "stdio" | "incomplete";

export type GalleryProvenance = "official-registry" | "manual";

export type GalleryStatus = "active" | "deprecated" | "deleted" | "unknown";

export interface GalleryRemote {
  type: "streamable-http" | "sse" | "unknown";
  url: string;
}

export interface GalleryInstall {
  kind: "npm" | "pypi" | "oci" | "binary" | "unknown";
  package?: string;
  command?: string[];
}

export interface GalleryHeaderDoc {
  name: string;
  description?: string;
  required?: boolean;
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

export interface GalleryEnrichment {
  normalizedAt?: string;
  readmeAt?: string;
  toolsAt?: string;
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
  categories?: string[];
  updatedAt?: string;
  provenance: GalleryProvenance;
  /** Header *names* only — never values */
  requiresHeaders?: string[];
  /** Header docs from registry (names + descriptions, never secret values) */
  headerDocs?: GalleryHeaderDoc[];
  /**
   * Human-oriented capabilities hint from registry text (not live tools/list).
   */
  offersHint?: string;
  /** Cached README from public repo */
  readme?: GalleryReadme;
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
  };
  note?: string;
}

export const DEFAULT_REGISTRY_URL =
  "https://registry.modelcontextprotocol.io/v0.1/servers";
