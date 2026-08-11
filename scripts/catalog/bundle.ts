#!/usr/bin/env tsx
/** Pack catalog shards into a tarball for releases / transfer. */
import { existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const root = process.cwd();
const catalogDir = process.env.CATALOG_DIR || join(root, "catalog");
const out =
  process.env.BUNDLE_OUT || join(root, "dist/catalog-bundle.tgz");

if (!existsSync(join(catalogDir, "index.json"))) {
  console.error("missing catalog/index.json — run catalog sync first");
  process.exit(1);
}

mkdirSync(join(root, "dist"), { recursive: true });
const r = spawnSync(
  "tar",
  [
    "-czf",
    out,
    "-C",
    catalogDir,
    "index.json",
    "meta.json",
    "entries",
  ],
  { stdio: "inherit" },
);
if (r.status !== 0) process.exit(r.status ?? 1);
console.log(JSON.stringify({ ok: true, out }, null, 2));
