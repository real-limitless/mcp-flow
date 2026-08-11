# mcp-flow — agent guide

Self-hosted **MCP workspace gateway** + registry catalog. Dual-tracked with OpenFlow and ProjectEverflow.

## Rules

1. **Gateway-first** — shared `/mcp` + API keys + sealed upstream secrets; catalog supports gallery consumers.
2. Catalog SoT for offline gallery is `catalog/` — do not diverge `McpGalleryEntry` without a schema version bump (`catalog/schema.json`).
3. Consumers: OpenFlow (one-node gallery), Everflow (marketplace allowlist → backends), agents (gateway).
4. **Placement** is first-class: `remote` | `central-sandbox` | `edge-sandbox` | `edge-bare`. Stub `remote` until runtimes exist.
5. Never commit secrets, live API keys, or decrypted env payloads. Redact secrets in logs and tool results.
6. Enterprise defaults: deny edge-bare; no unrestricted enable-any-URL.
7. Prefer shared golden fixtures/contracts with OpenFlow over silent drift.

## Read next

- [PLAN.md](./PLAN.md)
- [README.md](./README.md) (campaign embeds under `docs/images/campaign-*.png`)
- [docs/campaign/](./docs/campaign/) — enterprise storyboard frames; `./capture.sh` to re-shoot
- [catalog/README.md](./catalog/README.md)
- Issues #1 (core), #2 (consumers), #3 (edge)
