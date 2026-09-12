# Agent tools (`/mcp`)

Streamable HTTP MCP endpoint for harnesses (Cursor, Grok Bots, any MCP client). Send `Authorization: Bearer` with an agent API key. No bearer → `401` `{ "error": "missing bearer token" }`. `GET /health` returns `{ ok, service: "mcp-flow", version }` (`0.1.0` as of 2026-09-02).

Do not paste keys, session tokens, or device ids into docs or tickets.

## Connector listing vs backends

A Cursor/Grok-style connector listing is the **`mf_*` meta tools**. Backend tools are namespaced `{slug}__{tool}` (pattern only; slugs are workspace-specific).

On a default (eager) key, `tools/list` also returns every in-scope namespaced tool. That overflows harnesses with a ~200-tool cap. Flip **dynamic tool discovery** on the key so `tools/list` stays small.

## Dynamic tool discovery (per key)

Opt in when minting or patching a key:

```bash
npx mcp-flow key create --name cursor --dynamic-tools
# optional always-on prefixes (listed and callable without enable):
npx mcp-flow key create --name cursor --dynamic-tools --dynamic-tools-hot 'github__'

# Flip the flag on an existing key (keeps prefixes / projects / admin):
npx mcp-flow key scopes <id> --dynamic-tools
npx mcp-flow key scopes <id> --no-dynamic-tools
```

REST: `POST /v1/keys` or `PATCH /v1/keys/:id` with `"dynamicTools": true|false` (optional `"dynamicToolsHot": ["github__"]`). Admin UI Keys tab: **discovery** toggle on each row, or **Edit**.

When the flag is on:

1. `tools/list` returns metas plus at most 32 enabled/hot namespaced tools (never the full catalog).
2. `mf_list_tools({ q, backend, limit, offset })` lists the **full in-scope catalog** by default (names + descriptions, no schemas). Default page is up to 5000 tools — enough for ~1k catalogs. `hasMore` + `offset` pages if larger. `limit` is optional to shortlist.
3. `mf_enable_tools({ names, backends, prefixes })` adds matches to this session working set (still scope/project gated). Cap 32.
4. `mf_get_tool_schema({ name })` then `mf_call_tool({ name, arguments })`. Native `tools/call` of an enabled name also works.
5. `mf_disable_tools({ names })` or `{ all: true }` drops the working set. Hot prefixes stay enabled until you change the key.

Typical sequence: `mf_status` → `mf_list_tools()` (or `{ q: "…" }`) → `mf_enable_tools` → `mf_call_tool`.

## Meta tools

| Tool | Purpose | Args |
| --- | --- | --- |
| `mf_status` | Gateway status for the current API key / workspace / project. Includes `dynamicTools` when the flag is on. | none (`{}`) |
| `mf_list_projects` | List projects (tool collections) this key may use. Call `mf_use_project` to switch. | none |
| `mf_use_project` | Activate a project for this chat/session. Returns `sessionToken` (optional bearer) and binds the MCP session. Re-list tools after switching. | `project` (string, required — project slug); `mintSessionToken` (boolean, optional — if true, mint a short-lived session token bound to this project) |
| `mf_current_project` | Show the active project and its backend membership | none |
| `mf_list_backends` | List MCP backends in the active project (secrets redacted) | none |
| `mf_list_tools` | List/search namespaced tools (`slug__tool`) for the active project. Returns the full in-scope catalog by default (`name` / `description` / `backend` / `enabled`, plus `total` / `hasMore`) — no input schemas. | `q` (string), `backend` (slug), `limit` (optional, default entire catalog up to 5000), `offset`, `all` |
| `mf_get_tool_schema` | Full `inputSchema` for one namespaced name (listed when `dynamicTools` is on) | `name` (string, required) |
| `mf_enable_tools` | Add tools to the session working set (`dynamicTools` keys only) | `names` / `backends` / `prefixes` |
| `mf_disable_tools` | Remove from the working set | `names` / `backends` / `prefixes` / `all` |
| `mf_call_tool` | Invoke a namespaced tool by name (does not require the harness to re-list) | `name` (string, required); `arguments` (object) |
| `mf_use_device` | Pin subsequent edge tool calls for this key to a device id (session sticky). Empty `deviceId` clears. | `deviceId` (string — device id, or empty to clear) |

Typical sequence (eager key): `mf_status` → `mf_list_projects` → `mf_use_project` if needed → `mf_list_backends` → `mf_list_tools`.

If a namespaced tool is gated, the same `tools/call` (or `mf_call_tool`) **waits** up to 3 minutes for a human in Admin → Approvals. Timeout returns `reason: "authz_timeout"` — tell the user to approve, then retry. Deny returns `authz_denied`. Discovery metas (`mf_status`, `mf_list_tools`, …) are never gated. Details: [AUTHZ-STEP-UP.md](./AUTHZ-STEP-UP.md).

Session tokens exist for project-scoped `/mcp` calls. Do not paste them into docs.

## Status and backends (redacted)

`mf_status` returns workspace/key identifiers, scopes, active `project` (`slug`, `backendSlugs`), backend counts (`total`, `enabled`, `inProject`), device counts (`total`, `online`), `stickyDeviceId`, `placementModesSupported`, workspace `policy` (includes `allowEdgeBare`), and `dynamicTools` (`enabled` / `enabledCount` / `enabledCap` / `tools` names when the flag is on). No decrypted secrets.

`mf_list_backends` returns `project` plus backends with `slug`, `title`, `transport`, `enabled`, `placement`, `hasHeaders` / `hasEnv` (booleans), `url`, and `runsOn` (device id/name/status, or `host: "central"` / `host: "remote"`). Header and env **values** are never included.

Placement modes the gateway understands: `remote`, `central-sandbox`, `edge-sandbox`, `edge-bare`. `allowEdgeBare` is a workspace policy field.

## Namespaced tools (JSON-RPC fallback)

When `{slug}__{tool}` names do not appear in the connector listing, call JSON-RPC on the gateway HTTP URL:

1. `initialize` with `protocolVersion` `"2024-11-05"`. Headers: `Accept: application/json, text/event-stream` and `Authorization: Bearer`.
2. `notifications/initialized`.
3. Keep `mcp-session-id` if the server returns one.
4. `tools/list`, or `tools/call` with `params.name` = the namespaced tool and `params.arguments` per its schema. On a dynamicTools key, use `mf_call_tool` if the harness cached an empty catalog.

`mcp-remote` requires `--allow-http` when the gateway is plain HTTP (it refuses non-HTTPS without it).

Do not commit or publish real gateway URLs, keys, or session tokens.
