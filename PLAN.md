# [PLAN] mcp-flow — dual-track MCP gallery + session plane

## Summary

Build **mcp-flow** as the catalog source of truth and standalone MCP control plane, dual-tracked with **OpenFlow** the same way **ansible-flow-mcp** pairs with the OpenFlow Ansible gallery:

1. **mcp-flow** — registry snapshot + MCP tools for agents/IDEs  
2. **OpenFlow** — **one** runtime node + palette gallery over that catalog (not N node types)

Related OpenFlow issue: see dual-track `[PLAN]` on `real-limitless/OpenFlow`.

---

## Decisions

| Concern | Choice |
| --- | --- |
| Catalog source | Official MCP Registry API `v0.1` (`registry.modelcontextprotocol.io`) snapshot |
| Scope | **Remote HTTP/SSE + stdio/installable** metadata |
| OpenFlow shape | **One** type `openflow-node-base.mcp` (+ optional `mcpTool` later); gallery = discovery layer |
| Agent v1 | Discovery tools only (`search` / `get_server`) |
| Agent v2 | Enable / lock / switch + `tools/list_changed` or namespaced `call_tool` proxy |
| Policy | Allowlist + max slots; no unrestricted enable of arbitrary URLs by default |
| Dual-track | Shared `catalog/` artifacts; OpenFlow syncs like ansible-catalog |

---

## Why dual-track

| Consumer | Needs |
| --- | --- |
| OpenFlow users | Palette browse thousands of servers, one node, credentials, workflow runData |
| Agent/IDE users | MCP meta-tools without OpenFlow |
| Us | One place to fix normalize/dedupe/blocklist/sync |

Avoid forking gallery JSON shapes between repos.

---

## Architecture

```
Official Registry API (paginate)
        │
        ▼
scripts/sync_registry.*
        │
        ▼
catalog/gallery.json + meta.json
        │
        ├──────────────────────┐
        ▼                      ▼
mcp-flow MCP server      OpenFlow data/mcp-catalog/
  search_servers           GET /api/v1/mcp/servers
  get_server               palette virtual cards
  (later) enable/…         type: openflow-node-base.mcp
        │                  parameters: { serverId, endpointUrl, toolName, … }
        ▼                      │
IDE / OpenCode                 ▼
                         executor → MCP client session (remote)
```

### Why not N real OpenFlow node types

Same as Ansible: static registry would explode the bundle. Gallery = discovery; one executor + one description.

### Why not force every call through mcp-flow in OpenFlow

Canvas **MCP** node talks **direct** to the chosen remote endpoint (simpler debug). mcp-flow gateway hop is for **agents** and optional later “router” resource—not required for v1 gallery execute.

---

## Work breakdown — Track B (this repo)

### Phase 0 — Bootstrap
- [x] Create public repo + README + PLAN
- [ ] LICENSE Apache-2.0
- [ ] Minimal package layout (TS or Python — TBD; prefer TS if sharing types with OpenFlow, or Python for MCP SDK speed)
- [ ] CI: lint + catalog schema validate

### Phase 1 — Catalog pipeline
- [ ] Paginate registry `GET /v0.1/servers`
- [ ] Dedupe by `server.name` (prefer latest / `isLatest`)
- [ ] Normalize → `McpGalleryEntry` (id, title, description, transport, endpointUrl?, install?, provenance)
- [ ] Split/filter flags: `remote` | `stdio` | `incomplete`
- [ ] Blocklist file for known junk ids
- [ ] Commit snapshot **or** release artifact + sync script (size-dependent)
- [ ] `catalog/README.md` + `meta.json`

### Phase 2 — Discovery MCP (safe default)
- [ ] Tools: `search_servers`, `get_server`, `list_stats` / transports
- [ ] Stdio entrypoint + example OpenCode/Claude config
- [ ] Tests on normalize + search scoring

### Phase 3 — Session plane (opt-in profile)
- [ ] `enable` / `disable` / `switch` / `status` with allowlist + max slots
- [ ] Optional namespaced proxy `call_tool(server, name, args)`
- [ ] Emit tool list changes when host supports it
- [ ] Audit log hooks
- [ ] Secrets via env/credential slots — never model-supplied raw keys in logs

### Phase 4 — Polish
- [ ] Featured/curated overlay
- [ ] Optional GitHub stars enrichment
- [ ] Site or Schema Lab (optional, ansible-flow style)

---

## Shared catalog contract

```ts
type McpGalleryEntry = {
  id: string;                 // registry name e.g. io.github.foo/bar
  title: string;
  description: string;
  version?: string;
  status?: string;
  transport: "streamable-http" | "sse" | "stdio" | "unknown";
  endpointUrl?: string;       // remote
  install?: {
    kind: "npm" | "pypi" | "docker" | "binary" | "unknown";
    package?: string;
    command?: string[];
  };
  homepage?: string;
  sourceUrl?: string;
  categories?: string[];
  updatedAt?: string;
  provenance: "official-registry" | "manual";
};
```

OpenFlow and mcp-flow **must** consume this shape (or a versioned schema file in `catalog/schema.json`).

---

## Security

- Default profile: **discovery only**
- Enable only allowlisted catalog ids (or admin-approved custom)
- Stdio children (phase 3+): package allowlist, no shell, resource limits
- No secret commit; redact tokens in logs
- Document supply-chain risk of third-party MCP servers

---

## Success criteria (mcp-flow)

1. `catalog:sync` produces searchable gallery with remote + stdio entries  
2. Agent can `search_servers` / `get_server` over stdio MCP  
3. OpenFlow can sync `catalog/` and drive one-node gallery (Track A)  
4. Phase 3: agent enable → tools available under policy without host JSON edit  

---

## Non-goals (v1)

- Replacing the official registry
- Unrestricted “enable any URL”
- Vendoring foreign workflow-engine source into OpenFlow
- Claiming drop-in compatibility with other vendors’ node packages
