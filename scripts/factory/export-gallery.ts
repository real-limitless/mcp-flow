#!/usr/bin/env node
/**
 * Rebuild optional monolith catalog/gallery.json from shards.
 *
 *   npx tsx scripts/factory/export-gallery.ts
 */
import { exportGalleryJson } from "./lib/catalog-io.js";

const n = exportGalleryJson();
console.log(JSON.stringify({ exported: n, path: "catalog/gallery.json" }, null, 2));
