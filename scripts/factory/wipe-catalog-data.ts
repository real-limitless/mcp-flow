#!/usr/bin/env node
/**
 * Wipe local catalog data for a clean enrich rebuild (keeps schema/blocklist).
 *
 *   npx tsx scripts/factory/wipe-catalog-data.ts --yes
 */
import { existsSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { CATALOG_DIR, JOBS, REPO_ROOT } from "./lib/paths.js";

const { values } = parseArgs({
  options: {
    yes: { type: "boolean", default: false },
    "keep-jobs": { type: "boolean", default: false },
  },
});

if (!values.yes) {
  console.error("Refusing to wipe without --yes");
  console.error(`Would remove: ${join(CATALOG_DIR, "entries")}, index.json, gallery.json, meta.json`);
  if (!values["keep-jobs"]) console.error(`And: ${JOBS}`);
  process.exit(1);
}

const targets = [
  join(CATALOG_DIR, "entries"),
  join(CATALOG_DIR, "index.json"),
  join(CATALOG_DIR, "gallery.json"),
  join(CATALOG_DIR, "meta.json"),
];
if (!values["keep-jobs"]) targets.push(JOBS);

for (const t of targets) {
  if (existsSync(t)) {
    rmSync(t, { recursive: true, force: true });
    console.error(`removed ${t}`);
  }
}

writeFileSync(
  join(CATALOG_DIR, "meta.json"),
  `${JSON.stringify(
    {
      schemaVersion: "1.1.0",
      syncedAt: null,
      source: "https://registry.modelcontextprotocol.io/v0.1/servers",
      apiVersion: "v0.1",
      storage: "sharded",
      counts: {
        total: 0,
        remote: 0,
        stdio: 0,
        incomplete: 0,
        withReadme: 0,
        withTools: 0,
      },
      note: "Wiped — run factory scrape + worker to rebuild",
    },
    null,
    2,
  )}\n`,
);

console.log(
  JSON.stringify(
    {
      ok: true,
      catalogDir: CATALOG_DIR,
      repo: REPO_ROOT,
      next: [
        "npm run factory:scrape -- --max-pages 3 --enqueue",
        "npm run factory:worker -- --once",
      ],
    },
    null,
    2,
  ),
);
