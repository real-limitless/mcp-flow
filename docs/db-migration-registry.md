# Database migration registry

Shipped migrations `0001`–`0014` are immutable. Never edit their SQL.

| Id | Status | Notes |
| --- | --- | --- |
| 0001–0014 | shipped | Immutable. |
| 0015_call_payload | shipped (Secrets A1) | `mcpflow_call_payload` plus hash and redaction columns on `mcpflow_call_audit`. DOWN refuses while any ciphertext row exists. |
| 0016–0019 | reserved | Later Secrets phases. Do not add empty migration files for these ids. |
| 0020_sidecar_connections | shipped | `sidecar_connections` plus nullable `backends.connection_id`. The column add no-ops when the legacy `backends` table is absent. |
| 0021 | next free | |

## Connection pragmas

Every connection sets `PRAGMA secure_delete=ON`, so deleted pages are overwritten.

A new empty database also sets `PRAGMA auto_vacuum=INCREMENTAL` before the first table. An existing file keeps its current auto_vacuum mode until an operator runs the offline command `mcp-flow db vacuum`. The gateway must not hold the file. That command is what reclaims pages already freed. `secure_delete` on a live connection does not rewrite pages that were freed before the pragma was set.

## Down migrations

A down script that would drop ciphertext must refuse while rows exist. `0015` inserts the payload row count into a guard table whose `CHECK` accepts only zero, then drops `mcpflow_call_payload` and the six `call_audit` columns added by the up migration.
