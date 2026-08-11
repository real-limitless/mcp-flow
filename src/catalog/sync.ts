import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { normalizeRegistryItem, type RegistryListItem } from "./normalize.js";
import {
  loadAllEntries,
  loadIndex,
  upsertShardedEntries,
  type GalleryIndexRow,
} from "./shard.js";
import {
  DEFAULT_REGISTRY_URL,
  type CatalogMeta,
  type McpGalleryEntry,
} from "./types.js";

export interface SyncOptions {
  registryUrl?: string;
  catalogDir: string;
  /** Max pages (each page ~registry limit). 0 = unlimited */
  maxPages?: number;
  pageLimit?: number;
  /** Prefer isLatest-only when present */
  latestOnly?: boolean;
  fetchImpl?: typeof fetch;
}

export interface SyncResult {
  entries: McpGalleryEntry[];
  meta: CatalogMeta;
  galleryPath: string;
  metaPath: string;
  indexPath: string;
  storage: "sharded";
}

function loadBlocklist(catalogDir: string): Set<string> {
  const path = join(catalogDir, "blocklist.txt");
  if (!existsSync(path)) return new Set();
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const set = new Set<string>();
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    set.add(t);
  }
  return set;
}

export async function fetchRegistryPage(
  baseUrl: string,
  opts: { cursor?: string; limit?: number; search?: string },
  fetchImpl: typeof fetch = fetch,
): Promise<{ items: RegistryListItem[]; nextCursor?: string }> {
  const u = new URL(baseUrl);
  u.searchParams.set("limit", String(opts.limit ?? 100));
  if (opts.cursor) u.searchParams.set("cursor", opts.cursor);
  if (opts.search) u.searchParams.set("search", opts.search);

  const res = await fetchImpl(u.toString(), {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    throw new Error(`registry HTTP ${res.status}: ${u.toString()}`);
  }
  const body = (await res.json()) as {
    servers?: RegistryListItem[];
    metadata?: { nextCursor?: string };
  };
  return {
    items: body.servers ?? [],
    nextCursor: body.metadata?.nextCursor,
  };
}

export async function searchRegistryLive(
  query: string,
  opts: {
    registryUrl?: string;
    limit?: number;
    fetchImpl?: typeof fetch;
  } = {},
): Promise<McpGalleryEntry[]> {
  const registryUrl = opts.registryUrl ?? DEFAULT_REGISTRY_URL;
  const { items } = await fetchRegistryPage(
    registryUrl,
    { search: query, limit: opts.limit ?? 25 },
    opts.fetchImpl,
  );
  const out: McpGalleryEntry[] = [];
  for (const item of items) {
    const e = normalizeRegistryItem(item);
    if (e) out.push(e);
  }
  return out;
}

export function loadLocalGallery(catalogDir: string): McpGalleryEntry[] {
  return loadAllEntries(catalogDir);
}

/** Prefer slim index for search (fast); hydrate full entry when needed. */
export function loadLocalIndex(catalogDir: string): GalleryIndexRow[] {
  return loadIndex(catalogDir)?.entries ?? [];
}

export function filterLocalGallery(
  entries: McpGalleryEntry[],
  query: string,
): McpGalleryEntry[] {
  const q = query.trim().toLowerCase();
  if (!q) return entries.slice(0, 50);
  return entries
    .filter((e) => {
      const hay =
        `${e.id} ${e.title} ${e.summary ?? ""} ${e.description} ${e.offersHint ?? ""}`.toLowerCase();
      return hay.includes(q);
    })
    .slice(0, 50);
}

export function filterLocalIndex(
  rows: GalleryIndexRow[],
  query: string,
): GalleryIndexRow[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows.slice(0, 50);
  return rows
    .filter((e) => {
      const hay = `${e.id} ${e.title} ${e.summary}`.toLowerCase();
      return hay.includes(q);
    })
    .slice(0, 50);
}

export async function syncCatalog(opts: SyncOptions): Promise<SyncResult> {
  const registryUrl = opts.registryUrl ?? DEFAULT_REGISTRY_URL;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const maxPages = opts.maxPages ?? 0;
  const pageLimit = opts.pageLimit ?? 100;
  const blocklist = loadBlocklist(opts.catalogDir);

  const byId = new Map<string, McpGalleryEntry>();
  let cursor: string | undefined;
  let pages = 0;

  for (;;) {
    if (maxPages > 0 && pages >= maxPages) break;
    const { items, nextCursor } = await fetchRegistryPage(
      registryUrl,
      { cursor, limit: pageLimit },
      fetchImpl,
    );
    pages++;
    for (const item of items) {
      const official =
        item._meta?.["io.modelcontextprotocol.registry/official"];
      if (opts.latestOnly !== false && official && official.isLatest === false) {
        continue;
      }
      const entry = normalizeRegistryItem(item);
      if (!entry) continue;
      if (blocklist.has(entry.id)) continue;
      const prev = byId.get(entry.id);
      if (!prev) {
        byId.set(entry.id, entry);
        continue;
      }
      // Keep newer version string if both present (simple replace)
      if (entry.version && entry.version !== prev.version) {
        byId.set(entry.id, entry);
      }
    }
    if (!nextCursor || items.length === 0) break;
    cursor = nextCursor;
  }

  const entries = [...byId.values()].sort((a, b) =>
    a.id.localeCompare(b.id),
  );
  mkdirSync(opts.catalogDir, { recursive: true });
  const { meta } = await upsertShardedEntries(
    opts.catalogDir,
    entries,
    registryUrl,
  );

  return {
    entries,
    meta,
    galleryPath: join(opts.catalogDir, "entries"),
    metaPath: join(opts.catalogDir, "meta.json"),
    indexPath: join(opts.catalogDir, "index.json"),
    storage: "sharded",
  };
}

export function defaultCatalogDir(fromCwd = process.cwd()): string {
  // Prefer package-relative catalog/ when running from repo
  const candidates = [
    join(fromCwd, "catalog"),
    join(dirname(fromCwd), "catalog"),
  ];
  for (const c of candidates) {
    if (existsSync(join(c, "meta.json")) || existsSync(c)) return c;
  }
  return join(fromCwd, "catalog");
}
