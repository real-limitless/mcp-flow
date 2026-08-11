# mcp-flow catalog

Normalized gallery of MCP servers (official registry snapshot and/or live search).

**Consumers**

- mcp-flow gateway — browse → add Backend  
- OpenFlow — `data/mcp-catalog/` palette (one runtime node)  
- ProjectEverflow — marketplace `mcps[]` (browse all / install allowlisted)

**Contract:** `McpGalleryEntry` in [PLAN.md](../PLAN.md); versioned schema planned as `schema.json`.

## Generate (planned)

```bash
npm run catalog:sync
```

Upstream: `https://registry.modelcontextprotocol.io/v0.1/servers` (API v0.1).

## Files

| File | Purpose |
| --- | --- |
| `gallery.json` | Array of `McpGalleryEntry` (may be empty until sync) |
| `meta.json` | syncedAt, source, counts |
| `schema.json` | JSON Schema (planned) |
| `blocklist.txt` | ids to drop (planned) |

Gateway-first note: a full committed snapshot is optional for P1; live registry search may ship first. OpenFlow/Everflow offline gallery still wants a stable artifact ([#2](https://github.com/real-limitless/mcp-flow/issues/2)).
