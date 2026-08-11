# mcp-flow catalog factory

Factory-style **TUI + queue** that scrapes the **official MCP Registry**, normalizes entries, and writes **sharded** `catalog/entries/<id>.json` + `index.json` — same role as [ansible-flow-mcp’s Galaxy factory](https://github.com/real-limitless/ansible-flow-mcp/tree/main/scripts/factory).

## Quick start

```bash
cd mcp-flow
npm install
npm run factory:tui
# or
npx mcp-flow factory
```

### Headless

```bash
# optional wipe local catalog data
npm run catalog:wipe -- --yes

# 1) Scan registry → enqueue enrich jobs
npm run factory:scrape -- --max-pages 5 --enqueue

# with proxy
npm run factory:scrape -- --max-pages 5 --enqueue --use-proxy --proxy socks5h://127.0.0.1:1080

# 2) Worker: normalize → sourceRepo → README → tools/list → shards
npm run factory:worker              # drain all pending jobs, then exit
npm run factory:worker -- --watch   # keep polling for new jobs
npm run factory:worker -- --once    # one batch only (CI loops)

# 3) Re-enrich gaps
npm run factory:enqueue-enrich -- --missing-tools --limit 20
npm run factory:worker
```

One-off without queue:

```bash
npx mcp-flow catalog enrich "ai.smithery/some-server" --pretty
```

## Mental model

```text
MCP Registry API (paginate / search)
  → SCAN inventory (+ cherry-pick)
  → QUEUE enrich jobs
  → WORKER stages per server:
       1) normalize (+ registry detail)
       2) fetch README from public GitHub/GitLab
       3) probe tools/list on remote endpoint
  → upsert catalog/entries/<id>.json + slim index.json
  → optional PROXIES for registry/README (SOCKS5/HTTP)
```

Each entry can include **description, README markdown, toolsPreview[]** (names + descriptions).  
Auth-gated servers soft-fail tools as `auth_required` (no secrets stored in catalog).

## TUI screens (Tab)

| Mode | What |
|------|------|
| **SCAN** | Enter scrape; Space toggle; `e` enqueue selected; `E` all unknown |
| **LIST** | `/` filter; `k` hide known; `e`/`E` enqueue; `n` enqueue + start worker |
| **QUEUE** | **S** start worker · **X** stop · `r` requeue failed · `d` drop done · `f` filter |
| **PROXIES** | `t` useProxy · **R** refresh list · **H** health · `a` add fixed · `c` clear · `s` save |
| **SETTINGS** | Edit `.jobs/settings.json` keys |
| **LOG** | Tail `.jobs/worker.log` |

## Proxy

| Key | Action |
|-----|--------|
| **t** / Space | Toggle `useProxy` |
| **R** | Refresh free SOCKS list (`proxyListUrl`) |
| **H** | Health-check sample against registry |
| **a** | Add fixed proxy (`socks5h://host:port`) |
| **c** | Clear fixed proxy (rotate pool) |

Also honors `ALL_PROXY` / `HTTPS_PROXY` / `HTTP_PROXY`.

Settings: `useProxy`, `proxy`, `proxyListUrl`, `proxyProbeLimit`, `proxyProbeTimeout`.

**Scope:** factory registry fetch only — not live `/mcp` upstream tool calls.

## Settings

`scripts/factory/.jobs/settings.json` (gitignored):

| Key | Default | Meaning |
|-----|---------|---------|
| `maxPages` | 10 | Registry pages per scan (0 = unlimited) |
| `pageLimit` | 100 | Page size |
| `latestOnly` | true | Skip non-latest registry versions |
| `concurrency` | 4 | Worker batch size |
| `preferRemoteOnly` | false | Skip stdio-only on enqueue/process |
| `registryUrl` | official v0.1 servers | Base URL |
| `search` | `""` | Optional scan search string |

## Layout

```text
scripts/factory/
  tui.ts
  scrape-registry.ts
  queue-worker.ts
  lib/
    paths.ts settings.ts job-store.ts
    proxy-pool.ts http-util.ts registry-client.ts
    catalog-io.ts          # locked atomic gallery write
  .jobs/                   # gitignored
    settings.json queue/ scans/ proxies/ worker.log
```

Gallery writes are **lock-file + atomic rename** (avoids parallel corruption).

## Related

- Operator TUI (backends/keys): `npx mcp-flow tui`
- Simple sync (no queue): `npm run catalog:sync`
- ansible-flow-mcp factory: `scripts/factory/` in that repo
