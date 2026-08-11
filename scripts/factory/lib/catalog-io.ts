import {
  loadAllEntries,
  loadEntryIds,
  loadIndex,
  migrateMonolithToShards,
  readEntryFile,
  rebuildIndexFromEntries,
  upsertShardedEntries,
  exportMonolithGallery,
  type GalleryIndexRow,
} from "../../../src/catalog/shard.js";
import type { CatalogMeta, McpGalleryEntry } from "../../../src/catalog/types.js";
import { CATALOG_DIR } from "./paths.js";

export type { GalleryIndexRow };

export function loadGallery(): McpGalleryEntry[] {
  return loadAllEntries(CATALOG_DIR);
}

export function galleryIds(): Set<string> {
  return loadEntryIds(CATALOG_DIR);
}

export function getEntry(id: string): McpGalleryEntry | null {
  return readEntryFile(CATALOG_DIR, id);
}

export function loadSlimIndex(): GalleryIndexRow[] {
  return loadIndex(CATALOG_DIR)?.entries ?? [];
}

/** Upsert sharded entry files + index.json + meta.json */
export async function upsertEntries(
  incoming: McpGalleryEntry[],
  source: string,
): Promise<{ upserted: number; total: number; meta: CatalogMeta }> {
  return upsertShardedEntries(CATALOG_DIR, incoming, source);
}

export async function repairGallery(): Promise<number> {
  // Rebuild index from entry files; drop corrupt
  const before = loadAllEntries(CATALOG_DIR).length;
  const n = rebuildIndexFromEntries(CATALOG_DIR);
  return Math.max(0, before - n);
}

export async function migrateToShards(): Promise<{
  migrated: number;
  meta: CatalogMeta;
}> {
  return migrateMonolithToShards(CATALOG_DIR);
}

export function exportGalleryJson(): number {
  return exportMonolithGallery(CATALOG_DIR);
}
