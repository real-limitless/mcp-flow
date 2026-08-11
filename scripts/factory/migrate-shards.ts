#!/usr/bin/env node
/**
 * Split catalog/gallery.json → catalog/entries/*.json + index.json
 *
 *   npx tsx scripts/factory/migrate-shards.ts
 */
import { migrateToShards } from "./lib/catalog-io.js";

async function main(): Promise<void> {
  const result = await migrateToShards();
  console.log(
    JSON.stringify(
      {
        migrated: result.migrated,
        meta: result.meta,
        layout: {
          entries: "catalog/entries/<id>.json",
          index: "catalog/index.json",
          meta: "catalog/meta.json",
          gallery: "catalog/gallery.json (pointer only)",
        },
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
