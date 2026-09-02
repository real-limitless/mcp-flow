# Agent tools (`/mcp`)

Streamable HTTP MCP endpoint for harnesses (Cursor, Grok Bots, any MCP client). Send `Authorization: Bearer` with an agent API key. No bearer → `401` `{ "error": "missing bearer token" }`. `GET /health` returns `{ ok, service: "mcp-flow", version }` (`0.1.0` as of 2026-09-02).

Do not paste keys, session tokens, or device ids into docs or tickets.

## Connector listing vs backends

A Cursor/Grok-style connector listing is the **7 `mf_*` tools only**. Backend tools are namespaced `{slug}__{tool}` (pattern only; slugs are workspace-specific). They often do **not** appear in `GetDynamicTools`-style listings. Call `mf_list_tools`, then JSON-RPC `tools/call` if the connector did not surface the namespaced name.

## Meta tools

| Tool | Purpose | Args |
| --- | --- | --- |
| `mf_status` | Gateway status for the current API key / workspace / project | none (`{}`) |
| `mf_list_projects` | List projects (tool collections) this key may use. Call `mf_use_project` to switch. | none |
| `mf_use_project` | Activate a project for this chat/session. Returns `sessionToken` (optional bearer) and binds the MCP session. Re-list tools after switching. | `project` (string, required — project slug); `mintSessionToken` (boolean, optional — if true, mint a short-lived session token bound to this project) |
| `mf_current_project` | Show the active project and its backend membership | none |
| `mf_list_backends` | List MCP backends in the active project (secrets redacted) | none |
| `mf_list_tools` | List namespaced tools (`slug__tool`) for the active project. Returns `name` / `description` / `backend` only — no input schemas. | none |
| `mf_use_device` | Pin subsequent edge tool calls for this key to a device id (session sticky). Empty `deviceId` clears. | `deviceId` (string — device id, or empty to clear) |

Typical sequence: `mf_status` → `mf_list_projects` → `mf_use_project` if needed → `mf_list_backends` → `mf_list_tools`.

Session tokens exist for project-scoped `/mcp` calls. Do not paste them into docs.

## Status and backends (redacted)

`mf_status` returns workspace/key identifiers, scopes, active `project` (`slug`, `backendSlugs`), backend counts (`total`, `enabled`, `inProject`), device counts (`total`, `online`), `stickyDeviceId`, `placementModesSupported`, and workspace `policy` (includes `allowEdgeBare`). No decrypted secrets.

`mf_list_backends` returns `project` plus backends with `slug`, `title`, `transport`, `enabled`, `placement`, `hasHeaders` / `hasEnv` (booleans), `url`, and `runsOn` (device id/name/status, or `host: "central"` / `host: "remote"`). Header and env **values** are never included.

Placement modes the gateway understands: `remote`, `central-sandbox`, `edge-sandbox`, `edge-bare`. `allowEdgeBare` is a workspace policy field.

## Namespaced tools (JSON-RPC fallback)

When `{slug}__{tool}` names do not appear in the connector listing, call JSON-RPC on the gateway HTTP URL:

1. `initialize` with `protocolVersion` `"2024-11-05"`. Headers: `Accept: application/json, text/event-stream` and `Authorization: Bearer`.
2. `notifications/initialized`.
3. Keep `mcp-session-id` if the server returns one.
4. `tools/list`, or `tools/call` with `params.name` = the namespaced tool and `params.arguments` per its schema.

`mcp-remote` requires `--allow-http` when the gateway is plain HTTP (it refuses non-HTTPS without it).

Do not commit or publish real gateway URLs, keys, or session tokens.
