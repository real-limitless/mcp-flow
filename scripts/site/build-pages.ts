#!/usr/bin/env tsx
/**
 * Assemble static GitHub Pages publish tree:
 *   site/*  +  catalog/{index,meta,entries}  →  site/out/
 *
 * No per-server HTML generation — the browser fetches entry JSON.
 *
 *   npm run site:build
 *   SITE_BASE=/mcp-flow CATALOG_DIR=./catalog OUT_DIR=./site/out npm run site:build
 */
import {
  cpSync,
  existsSync,
  mkdirSync,
  rmSync,
  writeFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { buildBrowse } from "../catalog/build-browse.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "../..");

const siteSrc = process.env.SITE_SRC || join(ROOT, "site");
const catalogDir = process.env.CATALOG_DIR || join(ROOT, "catalog");
const outDir = process.env.OUT_DIR || join(ROOT, "site/out");
const base = normalizeBase(process.env.SITE_BASE ?? "/mcp-flow");
const repoUrl =
  process.env.SITE_REPO || "https://github.com/real-limitless/mcp-flow";
const origin = process.env.SITE_ORIGIN || "https://real-limitless.github.io";

function normalizeBase(b: string): string {
  if (!b || b === "/") return "";
  return b.endsWith("/") ? b.slice(0, -1) : b;
}

function copyDir(src: string, dest: string): void {
  mkdirSync(dest, { recursive: true });
  for (const name of readdirSync(src)) {
    if (name === "out") continue;
    const s = join(src, name);
    const d = join(dest, name);
    if (statSync(s).isDirectory()) copyDir(s, d);
    else cpSync(s, d);
  }
}

function main(): void {
  if (!existsSync(siteSrc)) {
    throw new Error(`site source missing: ${siteSrc}`);
  }

  if (existsSync(outDir)) rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  // Copy site shell (html/js/css)
  for (const name of readdirSync(siteSrc)) {
    if (name === "out") continue;
    const s = join(siteSrc, name);
    const d = join(outDir, name);
    if (statSync(s).isDirectory()) copyDir(s, d);
    else cpSync(s, d);
  }

  // Catalog data next to shell
  const catOut = join(outDir, "catalog");
  mkdirSync(catOut, { recursive: true });

  let entryCount = 0;
  let browseShards = 0;
  const indexPath = join(catalogDir, "index.json");
  const metaPath = join(catalogDir, "meta.json");
  const entriesPath = join(catalogDir, "entries");
  const browsePath = join(catalogDir, "browse");

  // Ensure browse shards exist for lazy site load
  if (existsSync(indexPath)) {
    try {
      const m = buildBrowse(catalogDir);
      browseShards = m.shardCount;
      console.error(
        `browse shards: ${m.shardCount} · rows ${m.total} · inactive ${m.inactive}`,
      );
    } catch (err) {
      console.error(
        "browse build failed (site will fall back if possible):",
        err instanceof Error ? err.message : err,
      );
    }
  }

  // Slim pointer only — full index.json is huge; site uses browse/*
  writeFileSync(
    join(catOut, "index.json"),
    JSON.stringify(
      {
        schemaVersion: "1.2.0",
        storage: "sharded",
        browse: "browse/manifest.json",
        updatedAt: new Date().toISOString(),
        note: "Full entry list is in browse/shards; dossier data in entries/*",
      },
      null,
      2,
    ) + "\n",
  );

  if (existsSync(metaPath)) {
    cpSync(metaPath, join(catOut, "meta.json"));
  } else {
    writeFileSync(
      join(catOut, "meta.json"),
      JSON.stringify(
        {
          schemaVersion: "1.2.0",
          syncedAt: null,
          source: "none",
          apiVersion: "v0.1",
          storage: "sharded",
          counts: { total: 0, remote: 0, stdio: 0, incomplete: 0 },
        },
        null,
        2,
      ) + "\n",
    );
  }

  if (existsSync(browsePath)) {
    mkdirSync(join(catOut, "browse"), { recursive: true });
    for (const f of readdirSync(browsePath)) {
      cpSync(join(browsePath, f), join(catOut, "browse", f));
    }
    browseShards = readdirSync(join(catOut, "browse")).filter((f) =>
      f.startsWith("shard-"),
    ).length;
  }

  if (existsSync(entriesPath)) {
    mkdirSync(join(catOut, "entries"), { recursive: true });
    // Prefer system cp for 20k files
    const r = spawnSync(
      "cp",
      ["-a", `${entriesPath}/.`, join(catOut, "entries")],
      { encoding: "utf8" },
    );
    if (r.status !== 0) {
      for (const f of readdirSync(entriesPath)) {
        if (!f.endsWith(".json")) continue;
        cpSync(join(entriesPath, f), join(catOut, "entries", f));
        entryCount++;
      }
    } else {
      entryCount = readdirSync(join(catOut, "entries")).filter((f) =>
        f.endsWith(".json"),
      ).length;
    }
  } else {
    mkdirSync(join(catOut, "entries"), { recursive: true });
  }

  // Inject base path for GitHub project pages
  const configJs = `window.__SITE__ = ${JSON.stringify(
    {
      base,
      catalogBase: "catalog",
      repo: repoUrl,
    },
    null,
    2,
  )};\n`;
  writeFileSync(join(outDir, "assets/config.js"), configJs, "utf8");

  // Fix stylesheet/script paths when under base — HTML uses relative paths so OK.
  writeFileSync(join(outDir, ".nojekyll"), "", "utf8");
  writeFileSync(
    join(outDir, "robots.txt"),
    `User-agent: *\nAllow: /\nSitemap: ${origin}${base}/sitemap.xml\n`,
    "utf8",
  );

  // Lightweight sitemap (full 20k URLs optional later via browse shards)
  const urls = [`${origin}${base}/`, `${origin}${base}/about.html`];
  writeFileSync(
    join(outDir, "sitemap.xml"),
    `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `  <url><loc>${u.replace(/&/g, "&amp;")}</loc></url>`).join("\n")}
</urlset>
`,
    "utf8",
  );

  console.log(
    JSON.stringify(
      {
        outDir,
        base,
        browseShards,
        entryFiles: entryCount,
        mode: "json-shell-browse",
      },
      null,
      2,
    ),
  );
}

main();
