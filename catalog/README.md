# mcp-flow catalog

Normalized gallery of MCP servers. **Source of truth** for dual-track:

- mcp-flow MCP server (search / describe / later enable)
- OpenFlow `data/mcp-catalog/` via sync script

## Generate

```bash
# from repo root (implementation TBD — see PLAN.md)
npm run catalog:sync
# or
python scripts/sync_registry.py
```

Upstream: `https://registry.modelcontextprotocol.io/v0.1/servers` (API freeze v0.1).

## Files (planned)

| File | Purpose |
| --- | --- |
| `gallery.json` | Array of `McpGalleryEntry` |
| `meta.json` | syncedAt, source, counts by transport |
| `schema.json` | JSON Schema for gallery entries |
| `blocklist.txt` | ids to drop |

OpenFlow sync (planned): sibling checkout → `bash scripts/sync-mcp-catalog.sh` in OpenFlow.
