#!/usr/bin/env node
/**
 * Enqueue enrich jobs for existing catalog entries or by id.
 *
 *   npx tsx scripts/factory/enqueue-enrich.ts --id 'ai.foo/bar'
 *   npx tsx scripts/factory/enqueue-enrich.ts --missing-readme
 *   npx tsx scripts/factory/enqueue-enrich.ts --missing-tools
 *   npx tsx scripts/factory/enqueue-enrich.ts --all --limit 50
 */
import { parseArgs } from "node:util";
import { loadAllEntries, loadIndex } from "../../src/catalog/shard.js";
import { enqueueEnrich } from "./lib/job-store.js";
import { CATALOG_DIR, ensureJobsDirs } from "./lib/paths.js";

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      id: { type: "string", multiple: true },
      "missing-readme": { type: "boolean", default: false },
      "missing-tools": { type: "boolean", default: false },
      all: { type: "boolean", default: false },
      limit: { type: "string", default: "100" },
      help: { type: "boolean", default: false },
    },
  });

  if (values.help) {
    console.log(`Usage: enqueue-enrich [--id ID]... [--missing-readme] [--missing-tools] [--all] [--limit N]`);
    process.exit(0);
  }

  ensureJobsDirs();
  const limit = Number(values.limit ?? "100");
  const ids = new Set<string>();

  for (const id of values.id ?? []) {
    if (id) ids.add(id);
  }

  if (values.all || values["missing-readme"] || values["missing-tools"]) {
    const index = loadIndex(CATALOG_DIR)?.entries ?? [];
    const entries =
      values["missing-readme"] || values["missing-tools"]
        ? loadAllEntries(CATALOG_DIR)
        : [];

    if (values.all) {
      for (const r of index.slice(0, limit)) ids.add(r.id);
    }
    if (values["missing-readme"]) {
      for (const e of entries) {
        if (!e.readme?.markdown) ids.add(e.id);
        if (ids.size >= limit) break;
      }
    }
    if (values["missing-tools"]) {
      for (const e of entries) {
        if (e.toolsPreviewStatus !== "ok" || !e.toolsPreview?.length) {
          ids.add(e.id);
        }
        if (ids.size >= limit) break;
      }
    }
  }

  if (!ids.size) {
    console.error("no ids to enqueue (pass --id, --all, --missing-readme, or --missing-tools)");
    process.exit(1);
  }

  let n = 0;
  for (const id of ids) {
    enqueueEnrich({ galleryId: id });
    n++;
  }
  console.log(JSON.stringify({ enqueued: n, ids: [...ids].slice(0, 20) }, null, 2));
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
