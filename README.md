# mcp-flow

**MCP registry gallery + controlled session plane — dual-tracked with OpenFlow.**

Browse thousands of MCP servers from the [official MCP Registry](https://registry.modelcontextprotocol.io/), expose them to agents via a small control-plane MCP, and feed the same catalog into OpenFlow as **one runtime node** with a palette gallery (same pattern as [ansible-flow-mcp](https://github.com/real-limitless/ansible-flow-mcp) + OpenFlow Ansible).

| Track | What you get |
| --- | --- |
| **Agent loop** | `search → describe → enable/lock/switch → list_tools → call` (policy-gated) |
| **OpenFlow** | One node type + catalog gallery (remote HTTP/SSE + installable/stdio metadata) |

[OpenFlow dual-track](https://github.com/real-limitless/OpenFlow) · Apache-2.0

Not affiliated with Anthropic or the Model Context Protocol project beyond using the **public** registry API and MCP protocol docs.

## Status

**Planning.** See [PLAN.md](./PLAN.md) and the GitHub `[PLAN]` issue.

## Dual-track

```
mcp-flow/catalog/          ← source of truth (registry snapshot)
        │
        ├─► mcp-flow MCP server (IDE / agents)
        │
        └─► OpenFlow sync → data/mcp-catalog/
                 │
                 └─► palette gallery + openflow-node-base.mcp (single runtime type)
```

## Catalog (planned)

```bash
# Sync from official registry (v0.1 API freeze)
npm run catalog:sync   # or: python scripts/sync_registry.py
```

Outputs under `catalog/`:

- `gallery.json` — normalized server entries (remote + stdio/installable)
- `meta.json` — sync time, counts by transport

## Agent ritual (planned)

```text
search_servers → get_server → enable(server_id) → list_tools → call_tool → disable | switch
```

- **Discovery-only** profile by default (search/describe)
- **Session** profile: allowlisted enable/lock/switch + optional namespaced proxy
- Max active slots (e.g. 1–3); no open-internet god-mode enable

## OpenFlow (planned)

Same UX model as Ansible:

- Palette shows many **virtual cards** (one per gallery server)
- Workflow stores **one** type: `openflow-node-base.mcp`
- Drop presets `parameters.serverId` / endpoint / transport
- Executor connects to remote MCP or documents stdio install (bridge later)

## License

Apache-2.0
