import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
  openSync,
  closeSync,
} from "node:fs";
import { join } from "node:path";
import {
  CATALOG_SCHEMA_VERSION,
  type CatalogMeta,
  type McpGalleryEntry,
} from "./types.js";

export interface GalleryIndexRow {
  id: string;
  title: string;
  /** Short blurb for browse UI (full description lives in entry file) */
  summary: string;
  transport: McpGalleryEntry["transport"];
  flags?: McpGalleryEntry["flags"];
  version?: string;
  status?: McpGalleryEntry["status"];
  endpointUrl?: string;
  hasReadme?: boolean;
  hasToolsPreview?: boolean;
  toolsCount?: number;
  toolsPreviewStatus?: McpGalleryEntry["toolsPreviewStatus"];
  sourceRepoStatus?: McpGalleryEntry["sourceRepo"] extends
    | { status: infer S }
    | undefined
    ? S
    : never;
  /** Relative path under catalog/ */
  file: string;
}

export interface GalleryIndex {
  schemaVersion: string;
  storage: "sharded";
  updatedAt: string;
  entries: GalleryIndexRow[];
}

/** Filesystem-safe filename for a registry id (keeps readability). */
export function entryFilename(id: string): string {
  // io.github.foo/bar → io.github.foo--bar.json
  const base = id
    .trim()
    .replace(/\//g, "--")
    .replace(/[^a-zA-Z0-9._@+-]/g, "_");
  return `${base || "unknown"}.json`;
}

export function entryRelPath(id: string): string {
  return join("entries", entryFilename(id));
}

export function entriesDir(catalogDir: string): string {
  return join(catalogDir, "entries");
}

export function indexPath(catalogDir: string): string {
  return join(catalogDir, "index.json");
}

export function galleryMonolithPath(catalogDir: string): string {
  return join(catalogDir, "gallery.json");
}

export function summaryFromDescription(description: string, max = 160): string {
  const one = description.replace(/\s+/g, " ").trim();
  if (one.length <= max) return one;
  return `${one.slice(0, max - 1)}…`;
}

export function toIndexRow(e: McpGalleryEntry): GalleryIndexRow {
  const summary =
    e.summary?.trim() ||
    summaryFromDescription(e.description || e.title || e.id);
  return {
    id: e.id,
    title: e.title,
    summary,
    transport: e.transport,
    flags: e.flags,
    version: e.version,
    status: e.status,
    endpointUrl: e.endpointUrl,
    hasReadme: Boolean(e.readme?.markdown),
    hasToolsPreview: Boolean(e.toolsPreview?.length),
    toolsCount: e.toolsPreview?.length,
    toolsPreviewStatus: e.toolsPreviewStatus,
    sourceRepoStatus: e.sourceRepo?.status,
    file: entryRelPath(e.id).replace(/\\/g, "/"),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export async function withCatalogLock<T>(
  catalogDir: string,
  fn: () => T | Promise<T>,
): Promise<T> {
  const lock = join(catalogDir, ".gallery.lock");
  mkdirSync(catalogDir, { recursive: true });
  for (let i = 0; i < 50; i++) {
    try {
      const fd = openSync(lock, "wx");
      closeSync(fd);
      try {
        return await fn();
      } finally {
        try {
          unlinkSync(lock);
        } catch {
          /* ignore */
        }
      }
    } catch {
      await sleep(40 + Math.random() * 40);
    }
  }
  throw new Error("could not acquire catalog lock");
}

export function writeEntryFile(
  catalogDir: string,
  entry: McpGalleryEntry,
): string {
  const dir = entriesDir(catalogDir);
  mkdirSync(dir, { recursive: true });
  const rel = entryRelPath(entry.id);
  const abs = join(catalogDir, rel);
  const enriched: McpGalleryEntry = {
    ...entry,
    summary:
      entry.summary?.trim() ||
      summaryFromDescription(entry.description || entry.title || entry.id),
  };
  const tmp = `${abs}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(enriched, null, 2)}\n`, "utf8");
  renameSync(tmp, abs);
  return rel.replace(/\\/g, "/");
}

export function readEntryFile(
  catalogDir: string,
  id: string,
): McpGalleryEntry | null {
  const abs = join(catalogDir, entryRelPath(id));
  if (!existsSync(abs)) return null;
  try {
    return JSON.parse(readFileSync(abs, "utf8")) as McpGalleryEntry;
  } catch {
    return null;
  }
}

export function loadIndex(catalogDir: string): GalleryIndex | null {
  const p = indexPath(catalogDir);
  if (!existsSync(p)) return null;
  try {
    return JSON.parse(readFileSync(p, "utf8")) as GalleryIndex;
  } catch {
    return null;
  }
}

export function writeIndex(catalogDir: string, rows: GalleryIndexRow[]): void {
  const index: GalleryIndex = {
    schemaVersion: CATALOG_SCHEMA_VERSION,
    storage: "sharded",
    updatedAt: new Date().toISOString(),
    entries: [...rows].sort((a, b) => a.id.localeCompare(b.id)),
  };
  const p = indexPath(catalogDir);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(index, null, 2)}\n`, "utf8");
  renameSync(tmp, p);
}

function countFlags(
  entries: Iterable<McpGalleryEntry | GalleryIndexRow>,
): CatalogMeta["counts"] {
  let total = 0;
  let remote = 0;
  let stdio = 0;
  let incomplete = 0;
  let withReadme = 0;
  let withTools = 0;
  let inactive = 0;
  for (const e of entries) {
    total++;
    const f = new Set(e.flags ?? []);
    if (f.has("remote")) remote++;
    if (f.has("stdio")) stdio++;
    if (f.has("incomplete")) incomplete++;
    if (f.has("repo-offline") || e.status === "inactive") inactive++;
    if ("file" in e) {
      // index row
      if (e.hasReadme) withReadme++;
      if (e.hasToolsPreview) withTools++;
    } else {
      const full = e as McpGalleryEntry;
      if (full.readme?.markdown) withReadme++;
      if (full.toolsPreview?.length) withTools++;
    }
  }
  return { total, remote, stdio, incomplete, withReadme, withTools, inactive };
}

export function writeMetaFile(
  catalogDir: string,
  counts: CatalogMeta["counts"],
  source: string,
  extra?: Partial<CatalogMeta>,
): CatalogMeta {
  const meta: CatalogMeta = {
    schemaVersion: CATALOG_SCHEMA_VERSION,
    syncedAt: new Date().toISOString(),
    source,
    apiVersion: "v0.1",
    counts,
    storage: "sharded",
    ...extra,
  };
  writeFileSync(
    join(catalogDir, "meta.json"),
    `${JSON.stringify(meta, null, 2)}\n`,
    "utf8",
  );
  return meta;
}

/** Load all full entries: prefer shards; fall back to monolith gallery.json. */
export function loadAllEntries(catalogDir: string): McpGalleryEntry[] {
  const dir = entriesDir(catalogDir);
  if (existsSync(dir)) {
    const files = readdirSync(dir).filter((f) => f.endsWith(".json"));
    if (files.length) {
      const out: McpGalleryEntry[] = [];
      for (const f of files) {
        try {
          const e = JSON.parse(
            readFileSync(join(dir, f), "utf8"),
          ) as McpGalleryEntry;
          if (e?.id) out.push(e);
        } catch {
          /* skip */
        }
      }
      return out.sort((a, b) => a.id.localeCompare(b.id));
    }
  }
  const mono = galleryMonolithPath(catalogDir);
  if (existsSync(mono)) {
    try {
      const raw = JSON.parse(readFileSync(mono, "utf8")) as unknown;
      if (Array.isArray(raw)) return raw as McpGalleryEntry[];
    } catch {
      /* ignore */
    }
  }
  return [];
}

export function loadEntryIds(catalogDir: string): Set<string> {
  const idx = loadIndex(catalogDir);
  if (idx?.entries?.length) return new Set(idx.entries.map((e) => e.id));
  return new Set(loadAllEntries(catalogDir).map((e) => e.id));
}

/**
 * Upsert full entry files + rebuild slim index + meta.
 * Does not rewrite a monolith gallery.json (optional export separate).
 */
export async function upsertShardedEntries(
  catalogDir: string,
  incoming: McpGalleryEntry[],
  source: string,
): Promise<{ upserted: number; total: number; meta: CatalogMeta }> {
  return withCatalogLock(catalogDir, () => {
    mkdirSync(entriesDir(catalogDir), { recursive: true });

    // seed index from disk (empty index array must still scan entry files)
    const byId = new Map<string, GalleryIndexRow>();
    const existingIndex = loadIndex(catalogDir);
    if (existingIndex?.entries?.length) {
      for (const r of existingIndex.entries) byId.set(r.id, r);
    } else {
      for (const e of loadAllEntries(catalogDir)) {
        byId.set(e.id, toIndexRow(e));
      }
    }

    let upserted = 0;
    for (const e of incoming) {
      if (!e.id) continue;
      writeEntryFile(catalogDir, e);
      byId.set(e.id, toIndexRow(e));
      upserted++;
    }

    const rows = [...byId.values()];
    writeIndex(catalogDir, rows);
    const meta = writeMetaFile(catalogDir, countFlags(rows), source);
    return { upserted, total: rows.length, meta };
  });
}

/** Split monolith gallery.json → entries/*.json + index.json */
export async function migrateMonolithToShards(
  catalogDir: string,
): Promise<{ migrated: number; meta: CatalogMeta }> {
  return withCatalogLock(catalogDir, () => {
    const mono = galleryMonolithPath(catalogDir);
    let entries: McpGalleryEntry[] = [];
    if (existsSync(mono)) {
      try {
        const raw = JSON.parse(readFileSync(mono, "utf8")) as unknown;
        if (Array.isArray(raw)) entries = raw as McpGalleryEntry[];
      } catch {
        /* ignore */
      }
    }
    // If monolith is already a pointer / empty, rebuild index from existing shards
    if (!entries.length) {
      entries = loadAllEntries(catalogDir);
    }
    mkdirSync(entriesDir(catalogDir), { recursive: true });
    const rows: GalleryIndexRow[] = [];
    for (const e of entries) {
      if (!e?.id) continue;
      writeEntryFile(catalogDir, e);
      rows.push(toIndexRow(e));
    }
    writeIndex(catalogDir, rows);
    const meta = writeMetaFile(
      catalogDir,
      countFlags(rows),
      entries.length ? "migrate-monolith" : "rebuild-index",
      {
        note: "Sharded storage: catalog/entries/<id>.json + index.json. gallery.json is legacy optional export.",
      },
    );
    // Replace monolith with tiny pointer so tools don't load 13MB
    writeFileSync(
      mono,
      `${JSON.stringify(
        {
          deprecated: true,
          message:
            "Use catalog/index.json + catalog/entries/*.json. Run: npx tsx scripts/factory/export-gallery.ts",
          storage: "sharded",
          count: rows.length,
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
    return { migrated: rows.length, meta };
  });
}

/** Optional: rebuild single gallery.json array (for consumers that need one file). */
export function exportMonolithGallery(catalogDir: string): number {
  const entries = loadAllEntries(catalogDir);
  const p = galleryMonolithPath(catalogDir);
  const tmp = `${p}.${process.pid}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(entries, null, 2)}\n`, "utf8");
  renameSync(tmp, p);
  return entries.length;
}

export function rebuildIndexFromEntries(catalogDir: string): number {
  const entries = loadAllEntries(catalogDir);
  writeIndex(catalogDir, entries.map(toIndexRow));
  writeMetaFile(
    catalogDir,
    countFlags(entries),
    "rebuild-index",
  );
  return entries.length;
}
