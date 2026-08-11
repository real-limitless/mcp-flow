import type {
  GalleryFlag,
  GalleryHeaderDoc,
  GalleryInstall,
  GalleryRemote,
  GalleryStatus,
  GalleryTransport,
  McpGalleryEntry,
} from "./types.js";
import { summaryFromDescription } from "./shard.js";

/** Loose registry API shapes (v0.1). */
export interface RegistryRemote {
  type?: string;
  url?: string;
  headers?: Array<{
    name?: string;
    description?: string;
    isSecret?: boolean;
    isRequired?: boolean;
  }>;
}

export interface RegistryPackage {
  registryType?: string;
  identifier?: string;
  transport?: { type?: string };
}

export interface RegistryServer {
  name?: string;
  title?: string;
  description?: string;
  version?: string;
  websiteUrl?: string;
  repository?: { url?: string; source?: string };
  remotes?: RegistryRemote[];
  packages?: RegistryPackage[];
}

export interface RegistryOfficialMeta {
  status?: string;
  updatedAt?: string;
  isLatest?: boolean;
}

export interface RegistryListItem {
  server?: RegistryServer;
  _meta?: {
    "io.modelcontextprotocol.registry/official"?: RegistryOfficialMeta;
  };
}

function mapRemoteType(t?: string): GalleryRemote["type"] {
  if (t === "streamable-http" || t === "http") return "streamable-http";
  if (t === "sse") return "sse";
  return "unknown";
}

function mapStatus(s?: string): GalleryStatus {
  if (s === "active" || s === "deprecated" || s === "deleted") return s;
  return "unknown";
}

function mapInstall(pkg: RegistryPackage): GalleryInstall | undefined {
  const id = pkg.identifier?.trim();
  if (!id && !pkg.registryType) return undefined;
  const rt = (pkg.registryType ?? "").toLowerCase();
  let kind: GalleryInstall["kind"] = "unknown";
  if (rt.includes("npm") || rt === "node") kind = "npm";
  else if (rt.includes("pypi") || rt === "python") kind = "pypi";
  else if (rt.includes("oci") || rt.includes("docker")) kind = "oci";
  return {
    kind,
    package: id,
  };
}

/**
 * Normalize one registry list item → McpGalleryEntry.
 * Never copies secret header values into the gallery.
 */
export function normalizeRegistryItem(
  item: RegistryListItem,
): McpGalleryEntry | null {
  const server = item.server;
  if (!server?.name?.trim()) return null;

  const official = item._meta?.["io.modelcontextprotocol.registry/official"];
  const remotes: GalleryRemote[] = [];
  const requiresHeaders = new Set<string>();
  const headerDocsMap = new Map<string, GalleryHeaderDoc>();

  for (const r of server.remotes ?? []) {
    if (!r.url?.trim()) continue;
    remotes.push({
      type: mapRemoteType(r.type),
      url: r.url.trim(),
    });
    for (const h of r.headers ?? []) {
      const name = h.name?.trim();
      if (!name) continue;
      if (h.isRequired || h.isSecret) requiresHeaders.add(name);
      const prev = headerDocsMap.get(name);
      headerDocsMap.set(name, {
        name,
        description: h.description?.trim() || prev?.description,
        required: Boolean(h.isRequired || prev?.required),
      });
    }
  }

  const flags: GalleryFlag[] = [];
  let transport: GalleryTransport = "unknown";
  let endpointUrl: string | undefined;
  let install: GalleryInstall | undefined;

  const httpRemote = remotes.find((r) => r.type === "streamable-http");
  const sseRemote = remotes.find((r) => r.type === "sse");
  const anyRemote = httpRemote ?? sseRemote ?? remotes[0];

  if (anyRemote) {
    flags.push("remote");
    transport = anyRemote.type === "unknown" ? "streamable-http" : anyRemote.type;
    endpointUrl = anyRemote.url;
  }

  const pkgs = server.packages ?? [];
  if (pkgs.length) {
    flags.push("stdio");
    install = mapInstall(pkgs[0]!);
    if (!anyRemote) {
      transport = "stdio";
    }
  }

  if (!anyRemote && !pkgs.length) {
    flags.push("incomplete");
  } else if (anyRemote && !endpointUrl) {
    flags.push("incomplete");
  }

  const title =
    server.title?.trim() ||
    server.name.split("/").pop() ||
    server.name;
  const description = server.description?.trim() || "";
  const summary = summaryFromDescription(description || title);

  const offerBits: string[] = [];
  if (description) offerBits.push(description);
  if (anyRemote) offerBits.push(`Remote MCP (${transport}) at ${endpointUrl}`);
  if (install?.package)
    offerBits.push(`Installable package (${install.kind}): ${install.package}`);
  if (requiresHeaders.size)
    offerBits.push(
      `Requires headers (set at install): ${[...requiresHeaders].join(", ")}`,
    );

  const now = new Date().toISOString();
  return {
    id: server.name.trim(),
    title,
    description,
    summary,
    offersHint: offerBits.join(" · ") || undefined,
    version: server.version,
    status: mapStatus(official?.status),
    transport,
    endpointUrl,
    remotes: remotes.length ? remotes : undefined,
    install,
    flags: flags.length ? [...new Set(flags)] : undefined,
    homepage: server.websiteUrl?.trim() || undefined,
    sourceUrl: server.repository?.url?.trim() || undefined,
    updatedAt: official?.updatedAt,
    provenance: "official-registry",
    requiresHeaders: requiresHeaders.size
      ? [...requiresHeaders].sort()
      : undefined,
    headerDocs: headerDocsMap.size
      ? [...headerDocsMap.values()].sort((a, b) => a.name.localeCompare(b.name))
      : undefined,
    enrichment: { normalizedAt: now },
  };
}

export function slugFromGalleryId(id: string): string {
  const base = id.includes("/") ? id.split("/").pop()! : id;
  let s = base
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-");
  if (!s || !/^[a-z]/.test(s)) s = `m-${s || "server"}`;
  return s.slice(0, 64);
}
