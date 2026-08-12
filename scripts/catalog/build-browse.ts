#!/usr/bin/env tsx
/**
 * Build chunked browse shards for the static site (lazy load + worker search).
 *
 *   npx tsx scripts/catalog/build-browse.ts
 *   CATALOG_DIR=./catalog SHARD_SIZE=800 npx tsx scripts/catalog/build-browse.ts
 *
 * Writes catalog/browse/manifest.json + shard-NNN.json (slim rows).
 */
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  readdirSync,
} from "node:fs";
import { join } from "node:path";

const catalogDir = process.env.CATALOG_DIR || join(process.cwd(), "catalog");
const shardSize = Math.max(200, Number(process.env.SHARD_SIZE || 800));
const browseDir = join(catalogDir, "browse");

export interface BrowseRow {
  id: string;
  title: string;
  summary: string;
  transport: string;
  status?: string;
  flags?: string[];
  toolsCount?: number;
  toolsPreviewStatus?: string;
  hasReadme?: boolean;
  sourceRepoStatus?: string;
  /** true if remote endpoint exists */
  remote?: boolean;
}

export interface BrowseManifest {
  version: 1;
  updatedAt: string;
  shardSize: number;
  shardCount: number;
  total: number;
  inactive: number;
  shards: string[];
  fields: string[];
}

function slimSummary(s: string | undefined, max = 100): string {
  const one = (s || "").replace(/\s+/g, " ").trim();
  if (one.length <= max) return one;
  return `${one.slice(0, max - 1)}…`;
}

function toBrowseRow(raw: Record<string, unknown>): BrowseRow {
  const flags = Array.isArray(raw.flags)
    ? (raw.flags as string[]).filter((f) => typeof f === "string")
    : undefined;
  const endpointUrl =
    typeof raw.endpointUrl === "string" ? raw.endpointUrl : undefined;
  return {
    id: String(raw.id || ""),
    title: String(raw.title || raw.id || ""),
    summary: slimSummary(
      typeof raw.summary === "string" ? raw.summary : undefined,
    ),
    transport: String(raw.transport || "unknown"),
    status: typeof raw.status === "string" ? raw.status : undefined,
    flags: flags?.length ? flags : undefined,
    toolsCount:
      typeof raw.toolsCount === "number"
        ? raw.toolsCount
        : typeof raw.hasToolsPreview === "boolean" && raw.hasToolsPreview
          ? 1
          : undefined,
    toolsPreviewStatus:
      typeof raw.toolsPreviewStatus === "string"
        ? raw.toolsPreviewStatus
        : undefined,
    hasReadme: Boolean(raw.hasReadme),
    sourceRepoStatus:
      typeof raw.sourceRepoStatus === "string"
        ? raw.sourceRepoStatus
        : undefined,
    remote: Boolean(endpointUrl) || flags?.includes("remote"),
  };
}

function isInactive(r: BrowseRow): boolean {
  if (r.status === "inactive" || r.status === "deleted") return true;
  if (r.sourceRepoStatus === "not_found") return true;
  if (r.flags?.includes("repo-offline")) return true;
  return false;
}

export function buildBrowse(dir = catalogDir, size = shardSize): BrowseManifest {
  const indexPath = join(dir, "index.json");
  if (!existsSync(indexPath)) {
    throw new Error(`missing ${indexPath}`);
  }
  const index = JSON.parse(readFileSync(indexPath, "utf8")) as {
    entries?: Record<string, unknown>[];
    updatedAt?: string;
  };
  const rows = (index.entries || [])
    .map(toBrowseRow)
    .filter((r) => r.id)
    .sort((a, b) => a.id.localeCompare(b.id));

  const out = join(dir, "browse");
  if (existsSync(out)) rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });

  const shards: string[] = [];
  for (let i = 0; i < rows.length; i += size) {
    const chunk = rows.slice(i, i + size);
    const name = `shard-${String(shards.length).padStart(3, "0")}.json`;
    writeFileSync(join(out, name), `${JSON.stringify(chunk)}\n`, "utf8");
    shards.push(name);
  }

  // empty catalog still gets empty shard list
  if (!shards.length) {
    writeFileSync(join(out, "shard-000.json"), "[]\n", "utf8");
    shards.push("shard-000.json");
  }

  const inactive = rows.filter(isInactive).length;
  const manifest: BrowseManifest = {
    version: 1,
    updatedAt: index.updatedAt || new Date().toISOString(),
    shardSize: size,
    shardCount: shards.length,
    total: rows.length,
    inactive,
    shards,
    fields: [
      "id",
      "title",
      "summary",
      "transport",
      "status",
      "flags",
      "toolsCount",
      "toolsPreviewStatus",
      "hasReadme",
      "sourceRepoStatus",
      "remote",
    ],
  };
  writeFileSync(
    join(out, "manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  return manifest;
}

// Always runnable as CLI via package script
try {
  // Only auto-run when executed directly (not imported)
  const entry = process.argv[1] || "";
  if (entry.includes("build-browse")) {
    const m = buildBrowse();
    console.log(
      JSON.stringify(
        {
          browseDir,
          total: m.total,
          inactive: m.inactive,
          shards: m.shardCount,
          shardSize: m.shardSize,
        },
        null,
        2,
      ),
    );
  }
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
}
