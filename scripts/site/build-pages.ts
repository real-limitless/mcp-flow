#!/usr/bin/env tsx
/**
 * Build a static GitHub Pages catalog from local sharded catalog data.
 *
 *   npm run site:build
 *   SITE_BASE=/mcp-flow CATALOG_DIR=./catalog OUT_DIR=./site/out npm run site:build
 */
import {
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  cpSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  entryFilename,
  loadIndex,
  readEntryFile,
  type GalleryIndexRow,
} from "../../src/catalog/shard.js";
import type { McpGalleryEntry } from "../../src/catalog/types.js";
import { escapeHtml, markdownToHtml } from "./md.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "../..");

const catalogDir = process.env.CATALOG_DIR || join(ROOT, "catalog");
const outDir = process.env.OUT_DIR || join(ROOT, "site/out");
/** Project Pages default; set SITE_BASE= for user/org root site */
const base = normalizeBase(process.env.SITE_BASE ?? "/mcp-flow");
const siteTitle = process.env.SITE_TITLE || "mcp-flow catalog";
const repoUrl =
  process.env.SITE_REPO || "https://github.com/real-limitless/mcp-flow";

function normalizeBase(b: string): string {
  if (!b || b === "/") return "";
  return b.endsWith("/") ? b.slice(0, -1) : b;
}

function href(path: string): string {
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${base}${p}`;
}

function safePageName(id: string): string {
  return entryFilename(id).replace(/\.json$/, "");
}

function serverHref(id: string): string {
  return href(`/server/${safePageName(id)}.html`);
}

function ensureDir(p: string): void {
  mkdirSync(p, { recursive: true });
}

function layout(opts: {
  title: string;
  body: string;
  description?: string;
  active?: "home" | "about";
}): string {
  const desc = escapeHtml(
    opts.description || "Browse MCP servers — enriched catalog from mcp-flow",
  );
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(opts.title)}</title>
  <meta name="description" content="${desc}" />
  <link rel="stylesheet" href="${href("/assets/style.css")}" />
</head>
<body>
  <header class="top">
    <a class="brand" href="${href("/")}">${escapeHtml(siteTitle)}</a>
    <nav>
      <a href="${href("/")}" class="${opts.active === "home" ? "on" : ""}">Servers</a>
      <a href="${href("/about.html")}" class="${opts.active === "about" ? "on" : ""}">About</a>
      <a href="${repoUrl}" rel="noopener noreferrer">GitHub</a>
    </nav>
  </header>
  <main class="wrap">
${opts.body}
  </main>
  <footer class="foot">
    <p>Catalog data from the <a href="https://registry.modelcontextprotocol.io">official MCP Registry</a>,
    enriched by <a href="${repoUrl}">mcp-flow</a>. No upstream secrets stored.</p>
  </footer>
  <script src="${href("/assets/app.js")}" defer></script>
</body>
</html>
`;
}

function badge(text: string, kind = ""): string {
  return `<span class="badge ${kind}">${escapeHtml(text)}</span>`;
}

function toolsBadge(row: GalleryIndexRow | McpGalleryEntry): string {
  const status =
    "toolsPreviewStatus" in row ? row.toolsPreviewStatus : undefined;
  const count =
    "toolsCount" in row
      ? row.toolsCount
      : "toolsPreview" in row
        ? row.toolsPreview?.length
        : undefined;
  if (status === "ok" || (count && count > 0)) {
    return badge(`${count ?? 0} tools`, "ok");
  }
  if (status === "auth_required") return badge("auth required", "warn");
  if (status === "unreachable") return badge("unreachable", "muted");
  if (status === "unsupported") return badge("stdio", "muted");
  if (status === "skipped") return badge("tools n/a", "muted");
  return badge("tools ?", "muted");
}

function card(row: GalleryIndexRow): string {
  const flags = (row.flags || []).map((f) => badge(f)).join(" ");
  return `<a class="card" href="${serverHref(row.id)}" data-id="${escapeHtml(row.id)}" data-title="${escapeHtml(row.title)}" data-summary="${escapeHtml(row.summary)}" data-transport="${escapeHtml(row.transport)}">
  <div class="card-top">
    <h2>${escapeHtml(row.title)}</h2>
    <div class="badges">${badge(row.transport)} ${toolsBadge(row)} ${flags}</div>
  </div>
  <p class="muted id">${escapeHtml(row.id)}</p>
  <p class="sum">${escapeHtml(row.summary || "")}</p>
</a>`;
}

function copyConfigSnippet(e: McpGalleryEntry): string {
  if (e.endpointUrl && (e.transport === "streamable-http" || e.transport === "sse")) {
    const name = e.id.split("/").pop() || e.id;
    const obj = {
      mcpServers: {
        [name]: {
          type: "remote",
          url: e.endpointUrl,
          ...(e.requiresHeaders?.length
            ? {
                headers: Object.fromEntries(
                  e.requiresHeaders.map((h) => [h, `YOUR_${h.toUpperCase()}`]),
                ),
              }
            : {}),
        },
      },
    };
    return JSON.stringify(obj, null, 2);
  }
  if (e.install?.kind === "npm" && e.install.package) {
    const name = e.id.split("/").pop() || e.id;
    const obj = {
      mcpServers: {
        [name]: {
          command: "npx",
          args: ["-y", e.install.package],
        },
      },
    };
    return JSON.stringify(obj, null, 2);
  }
  return JSON.stringify(
    {
      note: "Install via self-hosted mcp-flow gateway",
      id: e.id,
      command: `npx mcp-flow catalog install '${e.id}' --enable`,
    },
    null,
    2,
  );
}

function serverPage(e: McpGalleryEntry): string {
  const headers =
    e.headerDocs?.length || e.requiresHeaders?.length
      ? `<section>
  <h2>Headers</h2>
  <ul class="docs">
    ${(
      e.headerDocs?.length
        ? e.headerDocs
        : (e.requiresHeaders || []).map((name) => ({
            name,
            required: true as boolean | undefined,
          }))
    )
      .map((h) => {
        const bits = [
          h.required ? "required" : "optional",
          "secret" in h && h.secret ? "secret" : "",
        ].filter(Boolean);
        const vars =
          "variables" in h && h.variables?.length
            ? `<ul class="sub">${h.variables
                .map(
                  (v) =>
                    `<li><code>{${escapeHtml(v.name)}}</code>${v.secret ? " secret" : ""}${v.description ? ` — ${escapeHtml(v.description)}` : ""}</li>`,
                )
                .join("")}</ul>`
            : "";
        const tmpl =
          "valueTemplate" in h && h.valueTemplate
            ? `<div class="tmpl"><code>${escapeHtml(h.valueTemplate)}</code></div>`
            : "";
        return `<li><code>${escapeHtml(h.name)}</code> <span class="muted">(${bits.join(", ")})</span>${h.description ? ` — ${escapeHtml(h.description)}` : ""}${tmpl}${vars}</li>`;
      })
      .join("\n")}
  </ul>
  <p class="muted">Templates and names only — never store secrets in the public catalog.</p>
</section>`
      : "";

  const packages =
    e.packages?.length || e.environmentVariables?.length
      ? `<section>
  <h2>Packages</h2>
  ${
    e.packages?.length
      ? `<ul class="docs">${e.packages
          .map(
            (p) =>
              `<li><code>${escapeHtml(p.kind)}</code> <code>${escapeHtml(p.package || "")}</code>${p.version ? ` @ ${escapeHtml(p.version)}` : ""}${p.transport ? ` · ${escapeHtml(p.transport)}` : ""}${
                p.environmentVariables?.length
                  ? `<ul class="sub">${p.environmentVariables
                      .map(
                        (ev) =>
                          `<li><code>${escapeHtml(ev.name)}</code>${ev.secret ? " secret" : ""}${ev.required ? " required" : " optional"}${ev.description ? ` — ${escapeHtml(ev.description)}` : ""}</li>`,
                      )
                      .join("")}</ul>`
                  : ""
              }</li>`,
          )
          .join("\n")}</ul>`
      : ""
  }
  ${
    e.environmentVariables?.length && !e.packages?.some((p) => p.environmentVariables?.length)
      ? `<h3>Environment variables</h3><ul class="docs">${e.environmentVariables
          .map(
            (ev) =>
              `<li><code>${escapeHtml(ev.name)}</code>${ev.secret ? " secret" : ""}${ev.description ? ` — ${escapeHtml(ev.description)}` : ""}</li>`,
          )
          .join("")}</ul>`
      : ""
  }
</section>`
      : "";

  let toolsBlock = "";
  if (e.toolsPreview?.length) {
    toolsBlock = `<section>
  <h2>Tools preview <span class="badge ok">${e.toolsPreview.length}</span></h2>
  <ul class="tools">
    ${e.toolsPreview
      .map(
        (t) =>
          `<li><code>${escapeHtml(t.name)}</code>${t.description ? `<span>${escapeHtml(t.description)}</span>` : ""}</li>`,
      )
      .join("\n")}
  </ul>
  ${e.toolsPreviewAt ? `<p class="muted">Probed ${escapeHtml(e.toolsPreviewAt)}</p>` : ""}
</section>`;
  } else {
    const st = e.toolsPreviewStatus || "skipped";
    toolsBlock = `<section>
  <h2>Tools preview</h2>
  <p>${badge(st, st === "auth_required" ? "warn" : "muted")}
  ${e.toolsPreviewError ? `<span class="muted"> — ${escapeHtml(e.toolsPreviewError.slice(0, 200))}</span>` : ""}</p>
  <p class="muted">Live <code>tools/list</code> when the remote is reachable without secrets; auth-walled servers soft-fail.</p>
</section>`;
  }

  const readme = e.readme?.markdown
    ? `<section class="readme">
  <h2>README</h2>
  ${e.readme.source && e.readme.url ? `<p class="muted">source: <a href="${escapeHtml(e.readme.url)}" rel="noopener noreferrer">${escapeHtml(e.readme.url)}</a></p>` : ""}
  <div class="md">${markdownToHtml(e.readme.markdown)}</div>
</section>`
    : e.readme?.error
      ? `<section><h2>README</h2><p class="muted">${escapeHtml(e.readme.error)}</p></section>`
      : "";

  const links = [
    e.homepage
      ? `<a href="${escapeHtml(e.homepage)}" rel="noopener noreferrer">Homepage</a>`
      : "",
    e.sourceUrl
      ? `<a href="${escapeHtml(e.sourceUrl)}" rel="noopener noreferrer">Source</a>`
      : "",
    e.endpointUrl
      ? `<a href="${escapeHtml(e.endpointUrl)}" rel="noopener noreferrer">Endpoint</a>`
      : "",
  ]
    .filter(Boolean)
    .join(" · ");

  const snippet = copyConfigSnippet(e);

  const body = `
<article class="server">
  <p class="crumb"><a href="${href("/")}">Servers</a> / ${escapeHtml(e.id)}</p>
  <h1>${escapeHtml(e.title)}</h1>
  <p class="muted id">${escapeHtml(e.id)}${e.version ? ` · v${escapeHtml(e.version)}` : ""} · ${escapeHtml(e.transport)}${e.status ? ` · ${escapeHtml(e.status)}` : ""}</p>
  <div class="badges">${badge(e.transport)} ${toolsBadge(e)} ${(e.flags || []).map((f) => badge(f)).join(" ")}</div>
  <p class="lead">${escapeHtml(e.description || e.summary || "")}</p>
  ${e.offersHint ? `<p class="offers"><strong>Offers:</strong> ${escapeHtml(e.offersHint)}</p>` : ""}
  ${links ? `<p class="links">${links}</p>` : ""}

  <section>
    <h2>Connect / install</h2>
    ${e.endpointUrl ? `<p><code class="url">${escapeHtml(e.transport)}</code> <code class="url">${escapeHtml(e.endpointUrl)}</code></p>` : ""}
    ${e.install?.package ? `<p>Package: <code>${escapeHtml(e.install.kind)}:${escapeHtml(e.install.package)}</code></p>` : ""}
    <p class="muted">Prefer a self-hosted <a href="${repoUrl}">mcp-flow</a> gateway so harnesses never see upstream secrets:</p>
    <pre class="copy"><code>npx mcp-flow catalog install '${escapeHtml(e.id)}' --enable</code></pre>
    <h3>Harness snippet (direct)</h3>
    <pre class="copy" id="cfg"><code>${escapeHtml(snippet)}</code></pre>
    <button type="button" class="btn" data-copy-target="cfg">Copy JSON</button>
  </section>

  ${packages}
  ${headers}
  ${toolsBlock}
  ${readme}
</article>`;

  return layout({
    title: `${e.title} · ${siteTitle}`,
    description: e.summary || e.description?.slice(0, 160),
    body,
  });
}

function homePage(rows: GalleryIndexRow[], metaNote: string): string {
  const body = `
<section class="hero">
  <h1>MCP server catalog</h1>
  <p>Browse registry servers enriched by <strong>mcp-flow</strong> (README + live tools when public).
  Install into a self-hosted gateway — one URL, sealed secrets.</p>
  <p class="muted">${escapeHtml(metaNote)}</p>
  <label class="search-label">Search
    <input type="search" id="q" placeholder="name, id, summary…" autocomplete="off" />
  </label>
</section>
<section id="grid" class="grid">
  ${rows.map(card).join("\n")}
</section>
<p id="empty" class="muted hidden">No servers match.</p>`;
  return layout({ title: siteTitle, body, active: "home" });
}

function aboutPage(): string {
  const body = `
<article>
  <h1>About</h1>
  <p>This site is a <strong>static</strong> build of the mcp-flow catalog (GitHub Pages). Data comes from the official MCP Registry plus factory enrichment — not scraped from other marketplaces.</p>
  <ul>
    <li><strong>README</strong> — public GitHub/GitLab when <code>sourceUrl</code> is known</li>
    <li><strong>Tools preview</strong> — live MCP <code>tools/list</code> without secrets; auth-walled servers show <code>auth_required</code></li>
    <li><strong>Install</strong> — use <a href="${repoUrl}">mcp-flow</a> or Project Everflow allowlists; this site does not host MCP runtimes</li>
  </ul>
  <p><a href="${href("/")}">← Back to servers</a></p>
</article>`;
  return layout({ title: `About · ${siteTitle}`, body, active: "about" });
}

function main(): void {
  const index = loadIndex(catalogDir);
  const rows = index?.entries ?? [];
  if (!rows.length) {
    console.warn(
      `warn: no catalog index at ${catalogDir}/index.json — building empty site`,
    );
  }

  if (existsSync(outDir)) {
    rmSync(outDir, { recursive: true, force: true });
  }
  ensureDir(join(outDir, "server"));
  ensureDir(join(outDir, "assets"));

  const assetsSrc = join(__dirname, "assets");
  cpSync(assetsSrc, join(outDir, "assets"), { recursive: true });

  let metaNote = `${rows.length} servers`;
  const metaPath = join(catalogDir, "meta.json");
  if (existsSync(metaPath)) {
    try {
      const meta = JSON.parse(readFileSync(metaPath, "utf8")) as {
        syncedAt?: string;
        counts?: { total?: number; withReadme?: number; withTools?: number };
      };
      const parts = [`${meta.counts?.total ?? rows.length} servers`];
      if (meta.counts?.withReadme != null) parts.push(`${meta.counts.withReadme} with README`);
      if (meta.counts?.withTools != null) parts.push(`${meta.counts.withTools} with tools`);
      if (meta.syncedAt) parts.push(`synced ${meta.syncedAt}`);
      metaNote = parts.join(" · ");
    } catch {
      /* ignore */
    }
  }

  writeFileSync(join(outDir, "index.html"), homePage(rows, metaNote), "utf8");
  writeFileSync(join(outDir, "about.html"), aboutPage(), "utf8");

  const search = rows.map((r) => ({
    id: r.id,
    title: r.title,
    summary: r.summary,
    transport: r.transport,
    href: serverHref(r.id),
    toolsCount: r.toolsCount,
    toolsPreviewStatus: r.toolsPreviewStatus,
    hasReadme: r.hasReadme,
  }));
  writeFileSync(
    join(outDir, "search.json"),
    `${JSON.stringify(search)}\n`,
    "utf8",
  );

  // base path helper for client JS
  let built = 0;
  let missing = 0;
  for (const row of rows) {
    const entry = readEntryFile(catalogDir, row.id);
    if (!entry) {
      missing++;
      continue;
    }
    const name = safePageName(row.id);
    writeFileSync(join(outDir, "server", `${name}.html`), serverPage(entry), "utf8");
    built++;
  }

  const origin = process.env.SITE_ORIGIN || "https://real-limitless.github.io";
  const siteRoot = `${origin}${base}`;
  const urls = [
    `${siteRoot}/`,
    `${siteRoot}/about.html`,
    ...rows.map((r) => `${origin}${serverHref(r.id)}`),
  ];
  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `  <url><loc>${escapeHtml(u)}</loc></url>`).join("\n")}
</urlset>
`;
  writeFileSync(join(outDir, "sitemap.xml"), sitemap, "utf8");
  writeFileSync(
    join(outDir, "robots.txt"),
    `User-agent: *\nAllow: /\nSitemap: ${siteRoot}/sitemap.xml\n`,
    "utf8",
  );
  writeFileSync(
    join(outDir, ".nojekyll"),
    "",
    "utf8",
  );

  console.log(
    JSON.stringify(
      {
        outDir,
        base,
        index: rows.length,
        serverPages: built,
        missingEntries: missing,
      },
      null,
      2,
    ),
  );
}

main();
