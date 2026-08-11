#!/usr/bin/env node
/**
 * Headless registry scan → optional enqueue for factory worker.
 *
 *   npx tsx scripts/factory/scrape-registry.ts --max-pages 5 --enqueue
 *   npx tsx scripts/factory/scrape-registry.ts --use-proxy --proxy socks5h://127.0.0.1:1080
 */
import { parseArgs } from "node:util";
import type { RegistryListItem } from "../../src/catalog/normalize.js";
import { enqueue, newId, saveScan, appendLog } from "./lib/job-store.js";
import { ensureJobsDirs } from "./lib/paths.js";
import { ProxyPool } from "./lib/proxy-pool.js";
import { RegistryClient } from "./lib/registry-client.js";
import { loadSettings, saveSettings } from "./lib/settings.js";
import { galleryIds } from "./lib/catalog-io.js";

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      "max-pages": { type: "string" },
      search: { type: "string" },
      enqueue: { type: "boolean", default: false },
      "skip-known": { type: "boolean", default: true },
      "use-proxy": { type: "boolean", default: false },
      proxy: { type: "string" },
      "prefer-remote": { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
  });

  if (values.help) {
    console.log(`Usage: scrape-registry [--max-pages N] [--search Q] [--enqueue]
  --use-proxy --proxy URL   SOCKS/HTTP proxy
  --skip-known              skip ids already in gallery (default true)
  --prefer-remote           only enqueue items with remote URLs`);
    process.exit(0);
  }

  ensureJobsDirs();
  const settings = loadSettings();
  if (values["max-pages"] != null) settings.maxPages = Number(values["max-pages"]);
  if (values.search) settings.search = values.search;
  if (values["use-proxy"]) settings.useProxy = true;
  if (values.proxy) settings.proxy = values.proxy;
  if (values["prefer-remote"]) settings.preferRemoteOnly = true;
  saveSettings(settings);

  const pool = settings.useProxy ? new ProxyPool() : undefined;
  const client = new RegistryClient(settings, pool);
  const known = values["skip-known"] ? galleryIds() : new Set<string>();

  const items: RegistryListItem[] = [];
  const seen = new Set<string>();

  console.error("scanning registry…");
  for await (const page of client.paginate({
    maxPages: settings.maxPages,
    search: settings.search || undefined,
    onPage: (n, c) => console.error(`  page ${n}: ${c} items`),
  })) {
    for (const item of page) {
      const name = item.server?.name;
      if (!name || seen.has(name)) continue;
      const official =
        item._meta?.["io.modelcontextprotocol.registry/official"];
      if (settings.latestOnly && official && official.isLatest === false) {
        continue;
      }
      if (known.has(name)) continue;
      if (settings.preferRemoteOnly) {
        const remotes = item.server?.remotes ?? [];
        if (!remotes.some((r) => r.url)) continue;
      }
      seen.add(name);
      items.push(item);
    }
  }

  const scanId = newId("scan");
  saveScan(
    scanId,
    {
      id: scanId,
      createdAt: new Date().toISOString(),
      source: settings.registryUrl,
      counts: { items: items.length },
    },
    items,
  );
  appendLog(`scan ${scanId}: ${items.length} items`);

  let enqueued = 0;
  if (values.enqueue) {
    for (const item of items) {
      enqueue(item);
      enqueued++;
    }
    appendLog(`scan ${scanId}: enqueued ${enqueued}`);
  }

  console.log(
    JSON.stringify(
      {
        scanId,
        items: items.length,
        enqueued,
        useProxy: settings.useProxy,
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
