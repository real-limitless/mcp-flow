# mcp-flow catalog

Normalized gallery of MCP servers (official registry snapshot and/or live search).

**Consumers**

- mcp-flow gateway — browse → add Backend  
- OpenFlow — palette gallery  
- ProjectEverflow — marketplace `mcps[]` (browse all / install allowlisted)

**Contract:** `McpGalleryEntry` — `schema.json` (**schemaVersion 1.0.0**).  
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

**From the official registry (normalize)**

- Identity: `id`, `title`, `version`, `status`
- **Description / summary** — registry prose  
- **`offersHint`**, `headerDocs` (names + descriptions, never secret values)
- Connect: `transport`, `endpointUrl`, `remotes[]`
- Install: `install.kind` / `package`
- Links: `homepage`, `sourceUrl`
- `flags`: `remote` | `stdio` | `incomplete`

**From factory enrichment**

- **`readme`** — public GitHub/GitLab README.md (capped size)
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

```bash
npm run site:build            # reads catalog/ → site/out/
# Deploy: .github/workflows/pages.yml (Actions → Pages)
# Local preview: npx serve site/out
```

Builder: `scripts/site/build-pages.ts`. Client search over cards; server pages include README + tools preview when enriched.

See consumer plan on issue #2 (Pages + Everflow embed).

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
