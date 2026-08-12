# mcp-flow — agent guide

Self-hosted **MCP workspace gateway** + **official-registry catalog** + **static GitHub Pages gallery**. Dual-tracked with OpenFlow and ProjectEverflow.

Stack: **TypeScript / Node ≥ 22**, Hono HTTP, MCP SDK, SQLite (`node:sqlite`), AES-256-GCM vault.

---

## What this repo is

| Surface | Role |
| --- | --- |
| **Gateway** | One `/mcp` URL + agent API keys (`mf_*`); proxies namespaced tools; upstream secrets sealed |
| **Catalog** | Normalized `McpGalleryEntry` shards from [MCP Registry](https://registry.modelcontextprotocol.io) + factory enrichment |
| **Site** | Campaign-styled static HTML that `fetch`es catalog JSON (no 20k prebuilt pages) |
| **Consumers** | Agents/IDEs → gateway; OpenFlow → gallery palette; Everflow → marketplace allowlist → backends |

**Priority: gateway-first.** Catalog/site support the dual-track; do not block gateway fixes for gallery polish.

---

## Hard rules

1. **Never commit secrets** — no live API keys, master keys, decrypted headers/env, or `.env`. Redact in logs and tool results.
2. **Catalog never stores secret values** — header *names*, `valueTemplate` (e.g. `Bearer {api_key}`), env *names* only.
3. **Schema bumps** — changing `McpGalleryEntry` requires `catalog/schema.json` + `CATALOG_SCHEMA_VERSION` in `src/catalog/types.ts` (and consumer awareness). Current: **1.2.0**.
4. **Stable allowlist id** = registry `server.name` → entry `id`.
5. **Placement** is first-class: `remote` | `central-sandbox` | `edge-sandbox` | `edge-bare`. Edge-bare requires workspace `allowEdgeBare`.
6. **Enterprise defaults** — deny edge-bare; no unrestricted enable-any-URL in enterprise mode.
7. **Do not scrape competitor marketplaces** (e.g. mcpmarket) as catalog SoT — official registry + public GitHub/GitLab + live MCP probe only.
8. **Do not commit** `catalog/entries/`, `catalog/index.json`, or `site/out/` (gitignored). Publish data via **`catalog-data` branch** or CI.
9. **No force-push `main`**, no commit unless the user asks.
10. Prefer shared contracts/fixtures with OpenFlow over silent drift.

---

## Layout (where to edit)

```text
src/
  api/app.ts          # REST admin + /mcp + catalog routes
  mcp/gateway.ts      # aggregate MCP server, scopes, audit, mf_*
  mcp/upstream.ts     # upstream pool (remote + central-sandbox + edge route)
  mcp/runners/        # stdio + oci central/edge runners
  edge/               # hub, router, protocol, agent daemon
  admin/              # static /admin UI
  db/store.ts         # SQLite keys/backends/devices/scopes/audit
  crypto.ts           # seal/unseal
  placement.ts        # placement + transport validation
  catalog/            # types, normalize, sync, shard, install, enrich/*
  cli.ts              # serve, tui, key, backend, device, edge, catalog, doctor
  tui/app.ts          # operator TUI
  types.ts            # Backend, ApiKey, Device, placement, scopes
scripts/
  factory/            # scrape, queue-worker, TUI, proxy pool, enqueue-enrich
  site/build-pages.ts # assemble site/out = site shell + catalog JSON
  catalog/            # bundle.tgz, publish-data-branch
site/                 # tracked HTML/CSS/JS (campaign look) — browser fetches catalog/
catalog/
  schema.json         # tracked SoT contract
  blocklist.txt
  README.md
  entries/            # gitignored shards
  index.json          # gitignored slim browse index
docs/campaign/        # storyboard frames + styles (design SoT for site)
.github/workflows/
  ci.yml
  catalog-build.yml   # sync+enrich → catalog-data + release
  pages.yml           # site + catalog-data → GitHub Pages
```

Env (see `.env.example`): `MCP_FLOW_MASTER_KEY`, `MCP_FLOW_ADMIN_TOKEN`, optional `MCP_FLOW_API_KEY` for harnesses.

---

## Gateway (P1)

- **Serve:** `npx mcp-flow serve --port 8787` → `POST/GET /mcp`, admin under `/v1/*` with Bearer admin token.
- **Tools:** `{slug}__{upstreamTool}`; meta `mf_*`.
- **Keys:** hashed at rest; optional tool-prefix scopes; optional `scopes.admin` operator keys (`mf_admin_*` + `/v1`); audit log.
- **Backends:** remote streamable-http / SSE; multi-header seal; SSRF guards.
- **Install from gallery:** `npx mcp-flow catalog install '<id>' --enable` → remote or central-sandbox Backend.

Tests: `npm test` · typecheck: `npm run typecheck` · build: `npm run build`.

---

## Catalog + factory

### Data model

- **Sharded SoT:** `catalog/entries/<safe-id>.json` + slim `catalog/index.json` + `meta.json`.
- **Normalize** from registry (`version=latest` query — required so you get full packages/headers, not thin historical versions).
- **Enrich pipeline** (per job):  
  `normalize → sourceRepo → readme → tools/list`  
  - **sourceRepo:** GitHub/GitLab 404/410 → `status: inactive` + flag `repo-offline`  
  - **readme:** public README only  
  - **tools:** soft-fail `auth_required` / `unreachable` / `unsupported` (never store upstream secrets)

### Commands

```bash
# Sync one page (~100 latest) into local shards
npx mcp-flow catalog sync --max-pages 1

# Factory queue
npm run factory:scrape -- --max-pages 1 --enqueue
npm run factory:enqueue-enrich -- --all --limit 100
npm run factory:worker              # drain queue, then EXIT
npm run factory:worker -- --watch   # keep polling
npm run factory:worker -- --once    # one batch (CI)

# One-off
npx mcp-flow catalog enrich 'ai.bowmark/bowmark' --pretty
npx mcp-flow catalog show 'ai.bowmark/bowmark' --pretty

# Publish local factory output for Pages / consumers
npm run catalog:publish-data           # force-push origin/catalog-data
npm run catalog:publish-data -- --release   # + catalog-latest.tgz release
gh workflow run pages.yml

# Wipe local data + jobs
npm run catalog:wipe -- --yes
```

### Branches / releases

| Artifact | Purpose |
| --- | --- |
| **`main`** | Code + `site/` shell + `catalog/schema.json` — **not** 20k entry JSON |
| **`catalog-data`** | Published shards (`index.json`, `meta.json`, `entries/*`) for Pages |
| **Release `catalog-latest`** | `catalog-bundle.tgz` for Everflow/OpenFlow offline |

CI: `catalog-build.yml` (nightly/manual) → `catalog-data` + release.  
Pages: `pages.yml` loads `catalog-data`, runs `site:build`, deploys — **no enrich on Pages**.

---

## Public site (GitHub Pages)

- **Live:** https://real-limitless.github.io/mcp-flow/
- **Design:** reuse campaign tokens from `docs/campaign/assets/styles.css` (Syne / IBM Plex, brand-mark, pills, panels, data-table). Fluid layout, not fixed 1440×900 canvas.
- **Runtime model:** static shell + `fetch('catalog/index.json')` + `fetch('catalog/entries/<safe>.json')`.
- **Build:** `SITE_BASE= npm run site:build` → `site/out/` (copy shell + catalog).  
  Pages uses `SITE_BASE=/mcp-flow`.
- **Local preview:** `npm run site:preview` or `npx serve site/out`.

Safe id filename: `/` → `--` (see `entryFilename` in `src/catalog/shard.ts`).

---

## Issues / plan pointers

| Issue | Topic |
| --- | --- |
| [#1](https://github.com/real-limitless/mcp-flow/issues/1) | Core gateway + catalog + placement |
| [#2](https://github.com/real-limitless/mcp-flow/issues/2) | Consumers + public catalog site + release artifact |
| [#3](https://github.com/real-limitless/mcp-flow/issues/3) | Edge agent + sandbox/bare |

Also: [PLAN.md](./PLAN.md), [catalog/README.md](./catalog/README.md), [scripts/factory/README.md](./scripts/factory/README.md).

---

## Agent workflow tips

1. Read this file + relevant README before large changes.
2. After code edits: `npm run typecheck && npm test` (and `npm run build` if shipping CLI).
3. Catalog shape changes → update schema + tests under `tests/catalog-*.ts` / `tests/enrich.test.ts`.
4. Site UI changes → `site/` only; rebuild with `site:build`; design match campaign screenshots in `docs/images/campaign-*.png`.
5. To refresh production gallery from a laptop factory run: enrich locally → `npm run catalog:publish-data` → `gh workflow run pages.yml`.
6. Do not re-enable long enrich inside `pages.yml` at 20k scale — keep heavy work on `catalog-build` / local factory.
7. When user says “push,” push only what they asked; never force-push `main`.

---

## Non-goals (for agents)

- Multi-tenant public SaaS gateway
- Replacing the official MCP Registry
- Building Everflow/OpenFlow UI inside this repo (contract + artifact only)
- Committing full registry snapshots onto `main`
- Storing or logging upstream credentials in catalog JSON or site HTML
