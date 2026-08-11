# mcp-flow — agent guide

Dual-track MCP **catalog + session plane** with [OpenFlow](https://github.com/real-limitless/OpenFlow).

## Rules

1. Catalog SoT is `catalog/` — OpenFlow syncs from here; do not diverge shapes without a versioned schema bump.
2. Public registry API + MCP protocol docs only for upstream data — no vendoring foreign workflow-engine source.
3. Default MCP profile is **discovery-only**. Enable/proxy is allowlisted and opt-in.
4. Never commit secrets, tokens, or live credential payloads.
5. Prefer shared golden fixtures with OpenFlow over silent contract drift.

## Read next

- [PLAN.md](./PLAN.md)
- [catalog/README.md](./catalog/README.md)
- OpenFlow dual-track `[PLAN]` issue (MCP gallery, one runtime node)
