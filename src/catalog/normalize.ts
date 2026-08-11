import type {
  GalleryFlag,
  GalleryHeaderDoc,
  GalleryInstall,
  GalleryPackage,
  GalleryPackageKind,
  GalleryRemote,
  GalleryRepository,
  GallerySecretFieldDoc,
  GalleryStatus,
  GalleryTransport,
  McpGalleryEntry,
} from "./types.js";
import { summaryFromDescription } from "./shard.js";

/** Loose registry API shapes (v0.1 / server.schema). */
export interface RegistryHeaderVariable {
  description?: string;
  isSecret?: boolean;
  isRequired?: boolean;
  default?: string;
}

export interface RegistryRemote {
  type?: string;
  url?: string;
  headers?: Array<{
    name?: string;
    description?: string;
    isSecret?: boolean;
    isRequired?: boolean;
    /** May be a template like `Bearer {api_key}` — never store resolved secrets */
    value?: string;
    variables?: Record<string, RegistryHeaderVariable>;
  }>;
}

export interface RegistryPackage {
  registryType?: string;
  identifier?: string;
  version?: string;
  transport?: { type?: string };
  environmentVariables?: Array<{
    name?: string;
    description?: string;
    isSecret?: boolean;
    isRequired?: boolean;
    default?: string;
  }>;
}

export interface RegistryServer {
  name?: string;
  title?: string;
  description?: string;
  version?: string;
  websiteUrl?: string;
  repository?: {
    url?: string;
    source?: string;
    id?: string | number;
    subfolder?: string;
  };
  remotes?: RegistryRemote[];
  packages?: RegistryPackage[];
}

export interface RegistryOfficialMeta {
  status?: string;
  updatedAt?: string;
  publishedAt?: string;
  statusChangedAt?: string;
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

function mapPkgTransport(t?: string): GalleryTransport | undefined {
  if (!t) return undefined;
  if (t === "streamable-http" || t === "http") return "streamable-http";
  if (t === "sse") return "sse";
  if (t === "stdio") return "stdio";
  return "unknown";
}

function mapStatus(s?: string): GalleryStatus {
  if (s === "active" || s === "deprecated" || s === "deleted") return s;
  return "unknown";
}

function mapPackageKind(registryType?: string): GalleryPackageKind {
  const rt = (registryType ?? "").toLowerCase();
  if (rt.includes("npm") || rt === "node") return "npm";
  if (rt.includes("pypi") || rt === "python") return "pypi";
  if (rt.includes("oci") || rt.includes("docker")) return "oci";
  if (rt.includes("binary") || rt.includes("nuget") || rt.includes("mcpb"))
    return "binary";
  return "unknown";
}

function mapEnvVar(ev: {
  name?: string;
  description?: string;
  isSecret?: boolean;
  isRequired?: boolean;
  default?: string;
}): GallerySecretFieldDoc | null {
  const name = ev.name?.trim();
  if (!name) return null;
  const doc: GallerySecretFieldDoc = { name };
  if (ev.description?.trim()) doc.description = ev.description.trim();
  if (ev.isSecret) doc.secret = true;
  if (ev.isRequired) doc.required = true;
  // only keep default when not secret
  if (ev.default != null && ev.default !== "" && !ev.isSecret) {
    doc.default = String(ev.default);
  }
  return doc;
}

/**
 * Keep header value only if it looks like a template / placeholder, not a live secret.
 * Allows: `Bearer {api_key}`, `{token}`, empty.
 * Rejects: long opaque tokens, sk-*, etc.
 */
export function sanitizeValueTemplate(value?: string): string | undefined {
  if (value == null) return undefined;
  const v = value.trim();
  if (!v) return undefined;
  // placeholders
  if (/\{[a-zA-Z0-9_.-]+\}/.test(v)) return v;
  // obvious non-secret literals
  if (/^(Bearer|Basic|Token)\s*$/i.test(v)) return v;
  // reject anything that looks like a credential
  if (v.length > 80) return undefined;
  if (/^(sk|pk|ghp|gho|xox[baprs])-[A-Za-z0-9_-]+/i.test(v)) return undefined;
  if (/^[A-Za-z0-9+/=_-]{32,}$/.test(v) && !/\s/.test(v)) return undefined;
  // short fixed scheme prefixes without token are ok
  if (/^(Bearer|Basic|Token)\s+/i.test(v) && v.length < 40 && /\{/.test(v))
    return v;
  // plain short non-base64 labels
  if (v.length <= 24 && !/^[A-Za-z0-9+/=]{20,}$/.test(v)) return v;
  return undefined;
}

function mapHeader(h: NonNullable<RegistryRemote["headers"]>[number]): GalleryHeaderDoc | null {
  const name = h.name?.trim();
  if (!name) return null;

  const variables: GallerySecretFieldDoc[] = [];
  let anyVarSecret = false;
  let anyVarRequired = false;
  if (h.variables && typeof h.variables === "object") {
    for (const [varName, meta] of Object.entries(h.variables)) {
      const vd = mapEnvVar({
        name: varName,
        description: meta?.description,
        isSecret: meta?.isSecret,
        isRequired: meta?.isRequired,
        default: meta?.default,
      });
      if (vd) {
        variables.push(vd);
        if (vd.secret) anyVarSecret = true;
        if (vd.required) anyVarRequired = true;
      }
    }
  }

  const doc: GalleryHeaderDoc = { name };
  if (h.description?.trim()) doc.description = h.description.trim();
  if (h.isSecret || anyVarSecret) doc.secret = true;
  if (h.isRequired || anyVarRequired) doc.required = true;
  const tmpl = sanitizeValueTemplate(h.value);
  if (tmpl) doc.valueTemplate = tmpl;
  if (variables.length) doc.variables = variables;
  return doc;
}

function mapPackage(pkg: RegistryPackage): GalleryPackage | null {
  const id = pkg.identifier?.trim();
  if (!id && !pkg.registryType) return null;
  const env =
    pkg.environmentVariables
      ?.map(mapEnvVar)
      .filter((x): x is GallerySecretFieldDoc => Boolean(x)) ?? [];
  const out: GalleryPackage = {
    kind: mapPackageKind(pkg.registryType),
    package: id,
    version: pkg.version?.trim() || undefined,
    transport: mapPkgTransport(pkg.transport?.type),
  };
  if (env.length) out.environmentVariables = env;
  return out;
}

/**
 * Normalize one registry list item → McpGalleryEntry.
 * Captures packages, env vars, remote header templates/variables.
 * Never copies resolved secret values into the gallery.
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
    const headers: GalleryHeaderDoc[] = [];
    for (const h of r.headers ?? []) {
      const doc = mapHeader(h);
      if (!doc) continue;
      headers.push(doc);
      if (doc.required) requiresHeaders.add(doc.name);
      const prev = headerDocsMap.get(doc.name);
      headerDocsMap.set(doc.name, mergeHeaderDocs(prev, doc));
    }
    remotes.push({
      type: mapRemoteType(r.type),
      url: r.url.trim(),
      headers: headers.length ? headers : undefined,
    });
  }

  const flags: GalleryFlag[] = [];
  let transport: GalleryTransport = "unknown";
  let endpointUrl: string | undefined;

  const httpRemote = remotes.find((r) => r.type === "streamable-http");
  const sseRemote = remotes.find((r) => r.type === "sse");
  const anyRemote = httpRemote ?? sseRemote ?? remotes[0];

  if (anyRemote) {
    flags.push("remote");
    transport =
      anyRemote.type === "unknown" ? "streamable-http" : anyRemote.type;
    endpointUrl = anyRemote.url;
  }

  const packages: GalleryPackage[] = [];
  for (const p of server.packages ?? []) {
    const m = mapPackage(p);
    if (m) packages.push(m);
  }

  let install: GalleryInstall | undefined;
  if (packages.length) {
    flags.push("stdio");
    // Prefer npm, then pypi, then first
    install =
      packages.find((p) => p.kind === "npm") ??
      packages.find((p) => p.kind === "pypi") ??
      packages[0];
    if (!anyRemote) {
      transport = "stdio";
    }
  }

  const envMap = new Map<string, GallerySecretFieldDoc>();
  for (const p of packages) {
    for (const ev of p.environmentVariables ?? []) {
      const prev = envMap.get(ev.name);
      envMap.set(ev.name, {
        name: ev.name,
        description: ev.description || prev?.description,
        secret: ev.secret || prev?.secret,
        required: ev.required || prev?.required,
        default: ev.default ?? prev?.default,
      });
    }
  }

  if (!anyRemote && !packages.length) {
    flags.push("incomplete");
  } else if (anyRemote && !endpointUrl) {
    flags.push("incomplete");
  }

  const title =
    server.title?.trim() || server.name.split("/").pop() || server.name;
  const description = server.description?.trim() || "";
  const summary = summaryFromDescription(description || title);

  const offerBits: string[] = [];
  if (description) offerBits.push(description);
  if (anyRemote) offerBits.push(`Remote MCP (${transport}) at ${endpointUrl}`);
  if (packages.length) {
    offerBits.push(
      `Packages: ${packages.map((p) => `${p.kind}:${p.package}`).join(", ")}`,
    );
  }
  if (requiresHeaders.size) {
    offerBits.push(
      `Requires headers: ${[...requiresHeaders].join(", ")}`,
    );
  } else if (headerDocsMap.size) {
    offerBits.push(
      `Optional headers: ${[...headerDocsMap.keys()].sort().join(", ")}`,
    );
  }
  if (envMap.size) {
    offerBits.push(
      `Env vars: ${[...envMap.keys()].sort().join(", ")}`,
    );
  }

  let repository: GalleryRepository | undefined;
  if (
    server.repository?.url ||
    server.repository?.source ||
    server.repository?.id != null ||
    server.repository?.subfolder
  ) {
    repository = {
      url: server.repository.url?.trim() || undefined,
      source: server.repository.source?.trim() || undefined,
      id:
        server.repository.id != null
          ? String(server.repository.id)
          : undefined,
      subfolder: server.repository.subfolder?.trim() || undefined,
    };
  }

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
    packages: packages.length ? packages : undefined,
    environmentVariables: envMap.size
      ? [...envMap.values()].sort((a, b) => a.name.localeCompare(b.name))
      : undefined,
    flags: flags.length ? [...new Set(flags)] : undefined,
    homepage: server.websiteUrl?.trim() || undefined,
    sourceUrl: server.repository?.url?.trim() || undefined,
    repository,
    updatedAt: official?.updatedAt,
    publishedAt: official?.publishedAt,
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

function mergeHeaderDocs(
  a: GalleryHeaderDoc | undefined,
  b: GalleryHeaderDoc,
): GalleryHeaderDoc {
  if (!a) return b;
  const vars = new Map<string, GallerySecretFieldDoc>();
  for (const v of [...(a.variables ?? []), ...(b.variables ?? [])]) {
    const prev = vars.get(v.name);
    vars.set(v.name, {
      name: v.name,
      description: v.description || prev?.description,
      secret: v.secret || prev?.secret,
      required: v.required || prev?.required,
      default: v.default ?? prev?.default,
    });
  }
  return {
    name: b.name,
    description: b.description || a.description,
    secret: b.secret || a.secret,
    required: b.required || a.required,
    valueTemplate: b.valueTemplate || a.valueTemplate,
    variables: vars.size
      ? [...vars.values()].sort((x, y) => x.name.localeCompare(y.name))
      : undefined,
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
