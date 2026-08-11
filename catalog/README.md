# mcp-flow catalog

Normalized gallery of MCP servers (official registry snapshot and/or live search).

**Consumers**

- mcp-flow gateway — browse → add Backend  
- OpenFlow — palette gallery  
- ProjectEverflow — marketplace `mcps[]` (browse all / install allowlisted)

**Contract:** `McpGalleryEntry` — `schema.json` (**schemaVersion 1.2.0**).  
Stable allowlist key: **`id`** (= official registry `server.name`).

## Storage layout (sharded — default)

One big `gallery.json` does **not** scale. Default layout:

```text
catalog/
  schema.json          # entry JSON Schema (tracked)
  blocklist.txt
  meta.json            # counts + storage: "sharded"
  index.json           # slim browse index (id, title, summary, …)
  entries/
    io.github.foo--bar.json   # full McpGalleryEntry per server
    …
  gallery.json         # optional export OR tiny deprecated pointer
```

| File | What’s in it |
| --- | --- |
| **`entries/<id>.json`** | Full card: `title`, **`description`**, `summary`, `offersHint`, transport, URLs, install package, `requiresHeaders` (names only), homepage, sourceUrl, flags |
| **`index.json`** | Lightweight list for search/TUI (no need to open every file) |
| **`meta.json`** | `syncedAt`, counts, `storage: "sharded"` |

### What is saved (and what is not)

**From the official registry (normalize)** — full detail, secrets stripped

- Identity: `id`, `title`, `version`, `status`, `publishedAt`
- **Description / summary** — registry prose  
- **`packages[]`**: npm/pypi/oci + version + package env var *names/docs* (`isSecret` flag, never values)
- **`install`**: preferred primary package (npm > pypi > first)
- **`environmentVariables`**: aggregated env docs across packages
- **`remotes[]`**: url/type + per-remote `headers` with `valueTemplate` (e.g. `Bearer {api_key}`) + `variables`
- **`headerDocs` / `requiresHeaders`**: only *required* names go in `requiresHeaders`
- **`repository`**: url, source, id · `homepage` / `sourceUrl`
- `flags`: `remote` | `stdio` | `incomplete`

**From factory enrichment**

- **`readme`** — public GitHub/GitLab README.md (capped size)
- **`sourceRepo`** — live check of GitHub/GitLab `sourceUrl`; **`not_found` (404/410) → `status: inactive` + flag `repo-offline`**
- **`toolsPreview`** — live MCP `tools/list` (names + descriptions) when remote is reachable without secrets
- Soft statuses: `auth_required`, `unreachable`, `unsupported`

**Never in catalog**

- API keys / sealed secrets (gateway SQLite vault only)

### Enrich one server

```bash
npx mcp-flow catalog enrich "owner/name" --pretty
npx mcp-flow catalog show "owner/name" --pretty
npx mcp-flow catalog show "owner/name" --enrich --pretty
```

### Public static site (GitHub Pages)

Campaign-styled **HTML shell** + **individual catalog JSON** (no 20k prebuilt pages).

```bash
# Local: uses ./catalog (gitignored shards)
SITE_BASE= npm run site:build
npx serve site/out

# Or
npm run site:preview
```

| Path | Role |
| --- | --- |
| `site/` | Tracked HTML/CSS/JS (library chrome from campaign) |
| `catalog/index.json` + `entries/*.json` | Data the browser `fetch`es |
| branch **`catalog-data`** | CI publishes shards for Pages |
| release **`catalog-latest`** | `catalog-bundle.tgz` for Everflow/OpenFlow |

Workflows:
- `catalog-build.yml` — sync + incremental enrich → push `catalog-data` + release
- `pages.yml` — copy `site/` + `catalog-data` → deploy (no enrich)

### Push local factory work → `catalog-data` (Pages)

Factory writes **gitignored** `catalog/entries` + `index.json`. Pages reads the **`catalog-data`** branch, not `main`.

```bash
# 1) factory as usual
npm run factory:scrape -- --max-pages 1 --enqueue   # or catalog sync
npm run factory:worker                              # enrich

# 2) publish shards to origin/catalog-data (force-updates that branch only)
npm run catalog:publish-data

# optional: also refresh GitHub Release asset catalog-latest.tgz
npm run catalog:publish-data -- --release

# 3) redeploy site (pulls catalog-data)
gh workflow run pages.yml
```

CI path (no laptop): **Actions → catalog-build → Run workflow**.

See issue #2.

### Factory full pipeline

```bash
# optional clean slate
npm run catalog:wipe -- --yes

npm run factory:scrape -- --max-pages 3 --enqueue
npm run factory:worker              # normalize → README → tools/list

# re-enrich gaps
npm run factory:enqueue-enrich -- --missing-readme --limit 50
npm run factory:enqueue-enrich -- --missing-tools --limit 50
npm run factory:worker -- --once
```

### Migrate an old monolith

If you already have a huge `gallery.json`:

```bash
npm run catalog:migrate-shards
```

Optional rebuild of one-file export for consumers that still want it:

```bash
npm run catalog:export
```

## Generate / search / install

```bash
npm run catalog:sync
npx mcp-flow catalog search github
npx mcp-flow catalog show 'io.github.example/server'
npx mcp-flow catalog install 'io.github.example/server' --enable
npm run catalog:validate
```

REST (admin token):

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/v1/catalog/search?q=` | live or local **index** |
| `GET` | `/v1/catalog/entries/:id` | **full** entry file |
| `POST` | `/v1/catalog/sync` | write shards + index |
| `POST` | `/v1/catalog/install` | `{ id, slug?, enable?, headers? }` → Backend |

Install only creates **remote** backends (streamable-http/sse). Stdio/OCI → P3.

## Factory (queue + proxies)

```bash
npm run factory:tui
```

See [scripts/factory/README.md](../scripts/factory/README.md).
