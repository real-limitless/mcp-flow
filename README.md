# mcp-flow

**One MCP endpoint for every AI harness — upstream secrets stay on the gateway.**

Self-hosted **workspace MCP gateway**: register private and vendor MCP servers, store env/API keys encrypted, mint agent API keys, and share the same tool library across Cursor, Claude, OpenCode, OpenFlow assistants, and more. Optional **central or edge** runtimes run installable MCPs in a **sandbox** (or bare, if you opt in).

Also dual-tracked as a **registry catalog** for [OpenFlow](https://github.com/real-limitless/OpenFlow) (one-node gallery) and [ProjectEverflow](https://github.com/real-limitless/ProjectEverflow) (marketplace MCP tab).

| Audience | What you get |
| --- | --- |
| **Individuals / teams** | Configure upstream MCPs once; every harness uses one URL + key |
| **Enterprise** | Corp vault of private + vendor MCPs; employees get scoped keys only |
| **OpenFlow** | Catalog → palette gallery + single runtime node type |
| **Everflow** | Marketplace browse/allowlist + optional org gateway |

[PLAN.md](./PLAN.md) · [Issues](https://github.com/real-limitless/mcp-flow/issues) · Apache-2.0

Not affiliated with Anthropic or the Model Context Protocol project beyond using the **public** registry API and MCP protocol docs.

## Status

**Planning → implementation.** Gateway-first roadmap in [PLAN.md](./PLAN.md).

| Issue | Topic |
| --- | --- |
| [#1](https://github.com/real-limitless/mcp-flow/issues/1) | Core plan: gateway + catalog + placement |
| [#2](https://github.com/real-limitless/mcp-flow/issues/2) | Everflow / OpenFlow catalog consumer contract |
| [#3](https://github.com/real-limitless/mcp-flow/issues/3) | Edge agent + multi-device sandbox/bare |

## Architecture (target)

```text
AI harnesses  ──HTTP or stdio shim──►  mcp-flow /mcp  (API key)
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    ▼                       ▼                       ▼
              Remote MCPs            Central sandbox           Edge agents
              (SaaS / internal)      (stdio/OCI)               (laptop/desktop)
              + sealed env/headers                              sandbox | bare
```

**Placement per backend:** `remote` · `central-sandbox` · `edge-sandbox` · `edge-bare`

## Dual-track catalog

```text
Official MCP Registry API
        │
        ▼
mcp-flow catalog/ (gallery.json + schema)
        │
        ├─► OpenFlow data/mcp-catalog/  → one node type + palette
        ├─► Everflow marketplace mcps[] → browse all / install allowlisted
        └─► Gateway “add from gallery” → Backend library rows
```

## Phases (short)

| Phase | Focus |
| --- | --- |
| **P1** | HTTP gateway + keys + remote proxy + encrypted secrets + stdio shim |
| **P1b** | Catalog sync / live search + schema |
| **P2** | Scopes, audit, CLI polish |
| **P3** | Central sandboxed installable MCPs |
| **P4–P5** | Edge agent; edge-sandbox; optional edge-bare |
| **P6** | Multi-device routing polish |

## Security (non-negotiable)

- Upstream API keys and env **never** returned to models or harness config  
- Agent keys are workspace-scoped and revocable  
- Executable MCPs default to **sandbox**; bare is explicit policy  
- Enterprise: admin library; employees only get mcp-flow keys  

## License

Apache-2.0
