# [PLAN] mcp-flow — workspace MCP gateway + dual-track catalog

## Summary

**mcp-flow** is a self-hosted **MCP workspace gateway**: one URL and one auth for many AI harnesses, with upstream MCP servers (private + vendor), encrypted env/API keys, and optional **sandboxed or bare** runtimes on **central or edge (local machine)** devices.

It remains dual-tracked with:

| Consumer | Role |
| --- | --- |
| **Agents / IDEs** | Single MCP endpoint (HTTP or stdio shim); never see upstream secrets |
| **[OpenFlow](https://github.com/real-limitless/OpenFlow)** | Catalog → one runtime node gallery ([OpenFlow#57](https://github.com/real-limitless/OpenFlow/issues/57)); assistant may use workspace mcp-flow |
| **[ProjectEverflow](https://github.com/real-limitless/ProjectEverflow)** | Marketplace MCP tab + org allowlist → library backends ([Everflow#5](https://github.com/real-limitless/ProjectEverflow/issues/5)) |

**Priority: gateway-first (P1+).** Full registry snapshot catalog is valuable but secondary to the shared proxy.

GitHub: [#1](https://github.com/real-limitless/mcp-flow/issues/1) · consumer [#2](https://github.com/real-limitless/mcp-flow/issues/2) · edge [#3](https://github.com/real-limitless/mcp-flow/issues/3)

---

## Locked decisions

| Concern | Choice |
| --- | --- |
| Language | **TypeScript / Node ≥ 22** |
| Runtime | **HTTP service** (`/mcp` + `/v1/*`) **+ stdio wrapper** for stdio-only hosts |
| Upstream P1 | **Remote** streamable-http / SSE |
| Secrets | Encrypted at rest; injected only on outbound upstream calls; **never** returned to models/tools list |
| Multi-agent | Many API keys → same workspace library |
| Catalog | Thin at first (live registry search and/or sync); full `gallery.json` for OpenFlow/Everflow offline |
| Placement | First-class: `remote` \| `central-sandbox` \| `edge-sandbox` \| `edge-bare` |
| Enterprise default | Deny **edge-bare**; sandbox required for executable MCPs |
| OpenFlow canvas | May call upstream **direct** for a fixed node; agents prefer gateway hop |

---

## Product thesis

```text
Enterprise or power user
  installs mcp-flow (Compose)
  adds private + vendor MCP servers
  sets upstream env / API keys (vault)
  mints employee or personal API keys
        │
Employee / user AI harnesses (Cursor, Claude, OpenCode, …)
  configure ONLY: mcp-flow URL + API key
        │
  tools appear namespaced (slug__tool)
  upstream secrets never enter the harness or model context
```

Optional: multiple desktops enroll as **edge devices**; local-only MCPs run **sandboxed or bare** on those machines under the same control plane.

---

## Architecture

### Control plane vs data planes

```text
                    CONTROL PLANE (mcp-flow-api)
                    catalog, backends, vault, keys,
                    placement policy, audit, /mcp gateway
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        Central runtime   Edge agent A    Edge agent B
        (VPC / home host) (laptop)        (desktop / lab)
              │               │               │
         sandbox/remote    sandbox|bare    sandbox|bare
```

### Agent connection

```text
Harness ──HTTP Bearer──► mcp-flow /mcp
Harness ──stdio shim───► mcp-flow /mcp   (same auth)
```

### Tool surface

- Proxied tools: `{slug}__{upstreamToolName}`
- Meta tools (examples): `mf_list_backends`, `mf_list_tools`, `mf_status`
- Admin add/enable backends: **REST/CLI first**; agent-driven enable only with scopes later
- On enable/disable: refresh tools; `notifications/tools/list_changed` when supported

---

## Placement (per backend)

| Mode | Where it runs | Typical use |
| --- | --- | --- |
| `remote` | Vendor or internal URL; called from control plane | SaaS / internal HTTP MCP |
| `central-sandbox` | Container/microVM on mcp-flow workers | Untrusted or installable stdio/OCI |
| `edge-sandbox` | Container on enrolled device | Local files/tools with isolation |
| `edge-bare` | Host process on device (opt-in) | Trusted local tools; weaker isolation |

**Device fields (edge):** id, name, tags, capabilities (`docker`/`podman`/`none`, bare allowed), online status.

**Affinity (later):** `harness-local` \| `pinned` \| `any-online` \| failover; optional `mf_use_device`.

**Edge connectivity:** outbound tunnel/WebSocket to control plane (NAT-friendly). Details: [#3](https://github.com/real-limitless/mcp-flow/issues/3).

---

## Data model (v1+)

```ts
Workspace { id, name }

ApiKey {
  id, workspaceId, name, tokenHash, prefix
  scopes?: { toolPrefixAllowlist?: string[] }
}

Backend {
  id, workspaceId, slug, title
  transport: "streamable-http" | "sse" | "stdio" | "oci"
  url?: string
  image?: string
  command?: string[]
  headersEnc?, envEnc?     // sealed secrets
  enabled: boolean
  toolAllowlist?: string[]
  placement: {
    mode: "remote" | "central-sandbox" | "edge-sandbox" | "edge-bare"
    deviceId?: string
    deviceTags?: string[]
    affinity?: "harness-local" | "pinned" | "any-online"
  }
  sandbox?: { mounts?, egress?, cpuMem? }
}

Device {
  id, workspaceId, name, tags[]
  capabilities: { sandbox: "docker" | "podman" | "none", bare: boolean }
  status: "online" | "offline"
  lastSeen?: string
}

// Catalog (shared with OpenFlow / Everflow)
McpGalleryEntry {
  id, title, description, version?, status?
  transport: "streamable-http" | "sse" | "stdio" | "unknown"
  endpointUrl?, remotes?: { type, url }[]
  install?: { kind, package?, command? }
  flags?: ("remote" | "stdio" | "incomplete")[]
  homepage?, sourceUrl?, categories?, updatedAt?
  provenance: "official-registry" | "manual"
}
```

Storage v1: **SQLite** + `MCP_FLOW_MASTER_KEY`. Postgres later.

---

## Admin / CLI surface

| Interface | Purpose |
| --- | --- |
| `POST /v1/keys` | Mint agent API key (secret shown once) |
| `POST/PATCH/GET /v1/backends` | Library CRUD (GET redacts secrets) |
| `POST /v1/backends/:id/test` | Connectivity + tools/list smoke |
| `GET /mcp` | MCP Streamable HTTP for agents |
| `mcp-flow serve` | Run API |
| `mcp-flow stdio` | Stdio bridge → HTTP `/mcp` |
| `mcp-flow backend add\|list` | CLI library ops |
| `mcp-flow key create` | CLI key mint |
| `mcp-flow edge` | Device agent (P4+) |

---

## Phases

| Phase | Deliverable | Unlocks |
| --- | --- | --- |
| **P0** | Repo bootstrap, types, schema stubs, Compose skeleton | — |
| **P1** | HTTP gateway + API keys + **remote** proxy + encrypted secrets + namespaced tools + stdio shim | **One auth, many agents; upstream keys hidden** |
| **P1b** | Thin catalog: live registry search and/or `catalog:sync` + `schema.json` | Browse → add; OpenFlow/Everflow contract |
| **P2** | Scopes, audit log basics, richer CLI; optional small admin UI | Enterprise hygiene |
| **P3** | **Central-sandbox** stdio/OCI backends | Safe installable MCPs on gateway host |
| **P4** | **Edge agent** + device enrollment + **edge-sandbox** | Multi-desktop local tools, isolated |
| **P5** | **edge-bare** (workspace policy opt-in) | Power-user friction reduction |
| **P6** | Routing polish: tags, pin, failover, `mf_use_device` | Multi-machine workflows |

**Implementation order for next coding pass:** P0 → P1 (gateway-first). Stub `placement.mode = "remote"` in schema from day one.

---

## Catalog contract (OpenFlow / Everflow)

- Versioned `catalog/schema.json` for `McpGalleryEntry`
- SoT for offline gallery: `catalog/gallery.json` + `meta.json` (sync from official Registry API v0.1)
- Release artifact optional for CI without sibling checkout ([#2](https://github.com/real-limitless/mcp-flow/issues/2))
- Everflow: browse all / **install allowlisted only** → creates **Backend** rows (or marketplace pack), not unbounded enable
- OpenFlow: palette virtual cards → `openflow-node-base.mcp` (or equivalent); sync like ansible-catalog

---

## Security

- Bearer API keys hashed at rest; upstream secrets sealed with master key
- SSRF guards on backend URLs (private ranges opt-in via env)
- Enterprise: admin-only library edits; employees get keys only
- Executable MCPs: sandbox default; bare requires explicit policy
- Edge: short-lived sealed runtime secrets; wipe on disable
- Audit: key_id, backend, tool, device_id, placement
- No secrets in gallery JSON, logs, or tool schemas/results
- Document third-party MCP supply-chain risk

---

## Dual-track notes

### OpenFlow

- Gallery/catalog independent of gateway hop for canvas execute
- Assistant/OpenCode may attach to workspace mcp-flow (recommended for multi-server agents)
- See [OpenFlow#57](https://github.com/real-limitless/OpenFlow/issues/57)

### ProjectEverflow

- Marketplace MCP tab from mcp-flow catalog
- Allowlist install aligns with Backend library + scopes
- Everflow project microVM complementary to edge-sandbox (heavier project isolation)
- Ansible hub/spoke is **ansible-flow-mcp**, not mcp-flow ([ansible-flow-mcp#44](https://github.com/real-limitless/ansible-flow-mcp/issues/44))
- See [Everflow#5](https://github.com/real-limitless/ProjectEverflow/issues/5)

---

## Success criteria

### P1 gateway

1. Compose up mcp-flow; create API key  
2. Add one remote MCP with auth header (encrypted)  
3. Enable → `/mcp` tools/list shows `slug__…` tools  
4. tools/call proxies successfully  
5. Second API key same workspace sees same tools  
6. Harness config is **only** mcp-flow URL (or stdio shim)  
7. Secrets never appear in list/get payloads  

### Catalog / dual-track

8. `catalog:sync` or live search yields usable entries for OpenFlow/Everflow  
9. Schema stable enough for allowlists (`id` stability)  

### Edge (P4+)

10. Two devices enrolled; edge-sandbox backend runs on pinned device  
11. Employee key still only talks to control plane  

---

## Non-goals

- Replacing the official MCP Registry  
- Unrestricted “enable any URL” in enterprise mode  
- Multi-tenant public SaaS (self-hosted workspace first)  
- Vendoring foreign workflow-engine source into OpenFlow  
- Claiming drop-in compatibility with other vendors’ node packages  
- Building Everflow UI or ansible-flow hub inside this repo  

---

## Bootstrap status

- [x] Public repo, LICENSE Apache-2.0, README, PLAN stub  
- [x] Package layout (TS), CI, Compose / Dockerfile  
- [x] P1 gateway: SQLite + crypto, REST keys/backends, remote proxy, `/mcp`, CLI, stdio shim  
- [x] P1b catalog: schema.json, normalize/sync/search, install → Backend  
- [x] P2 scopes (tool prefix allowlist) + audit log + CLI doctor + admin UI  
- [x] P3 central-sandbox: stdio + OCI runners, catalog install packages  
- [x] P4 edge-sandbox: device enroll, WS hub, `mcp-flow edge`, pin deviceId  
- [x] P5 edge-bare: workspace `allowEdgeBare` policy (default false)  
- [x] P6 routing: tags / any-online / `mf_use_device` sticky + richer `mf_status`  

