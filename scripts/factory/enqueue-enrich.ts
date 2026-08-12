#!/usr/bin/env node
/**
 * Enqueue enrich jobs for existing catalog entries or by id.
 *
 *   npx tsx scripts/factory/enqueue-enrich.ts --id 'ai.foo/bar'
 *   npx tsx scripts/factory/enqueue-enrich.ts --missing-readme
 *   npx tsx scripts/factory/enqueue-enrich.ts --missing-tools
 *   npx tsx scripts/factory/enqueue-enrich.ts --missing-source-repo
 *   npx tsx scripts/factory/enqueue-enrich.ts --all --limit 50
 *   npx tsx scripts/factory/enqueue-enrich.ts --all --force   # even if already complete
 */
import { parseArgs } from "node:util";
import { loadAllEntries, loadIndex } from "../../src/catalog/shard.js";
import type { McpGalleryEntry } from "../../src/catalog/types.js";
import { enqueueEnrich } from "./lib/job-store.js";
import { CATALOG_DIR, ensureJobsDirs } from "./lib/paths.js";

function isEnrichComplete(e: McpGalleryEntry): boolean {
  return (
    e.enrichment?.complete === true &&
    Boolean(e.toolsPreviewStatus) &&
    Boolean(e.sourceRepo?.status)
  );
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      id: { type: "string", multiple: true },
      "missing-readme": { type: "boolean", default: false },
      "missing-tools": { type: "boolean", default: false },
      "missing-source-repo": { type: "boolean", default: false },
      all: { type: "boolean", default: false },
      /** Re-enqueue even when entry is already fully enriched */
      force: { type: "boolean", default: false },
      limit: { type: "string", default: "100" },
      help: { type: "boolean", default: false },
    },
  });

  if (values.help) {
    console.log(
      `Usage: enqueue-enrich [--id ID]... [--missing-readme] [--missing-tools] [--missing-source-repo] [--all] [--force] [--limit N]
  Default skips entries already enrich-complete (unless --force or explicit --id).
  --missing-tools only queues entries with no toolsPreviewStatus yet (not auth_required retries).`,
    );
    process.exit(0);
  }

  ensureJobsDirs();
  const limit = Number(values.limit ?? "100");
  const force = Boolean(values.force);
  const ids = new Set<string>();

  for (const id of values.id ?? []) {
    if (id) ids.add(id);
  }

  const needScan =
    values.all ||
    values["missing-readme"] ||
    values["missing-tools"] ||
    values["missing-source-repo"];

  if (needScan) {
    const entries = loadAllEntries(CATALOG_DIR);
    const index = loadIndex(CATALOG_DIR)?.entries ?? [];

    if (values.all) {
      const pool = entries.length ? entries : null;
      if (pool) {
        for (const e of pool) {
          if (!force && isEnrichComplete(e)) continue;
          ids.add(e.id);
          if (ids.size >= limit) break;
        }
      } else {
        for (const r of index) {
          ids.add(r.id);
          if (ids.size >= limit) break;
        }
      }
    }

    if (values["missing-readme"]) {
      for (const e of entries) {
        if (!e.readme?.markdown && !e.readme?.error) ids.add(e.id);
        else if (!e.readme?.markdown && force) ids.add(e.id);
        if (ids.size >= limit) break;
      }
    }

    if (values["missing-tools"]) {
      for (const e of entries) {
        // only never-probed; do not re-queue auth_required / unreachable forever
        if (!e.toolsPreviewStatus) ids.add(e.id);
        else if (force && e.toolsPreviewStatus !== "ok") ids.add(e.id);
        if (ids.size >= limit) break;
      }
    }

    if (values["missing-source-repo"]) {
      for (const e of entries) {
        if (!e.sourceRepo?.status) ids.add(e.id);
        else if (force && e.sourceRepo.status === "unreachable") ids.add(e.id);
        if (ids.size >= limit) break;
      }
    }
  }

  if (!ids.size) {
    console.error(
      "no ids to enqueue (already complete, or pass --id / --missing-* / --all --force)",
    );
    process.exit(1);
  }

  let enqueued = 0;
  let skippedQueued = 0;
  for (const id of ids) {
    const job = enqueueEnrich({ galleryId: id, skipIfQueued: true });
    if (job) enqueued++;
    else skippedQueued++;
  }
  console.log(
    JSON.stringify(
      {
        enqueued,
        skippedAlreadyQueued: skippedQueued,
        requested: ids.size,
        ids: [...ids].slice(0, 20),
      },
      null,
      2,
    ),
  );
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
