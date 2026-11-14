# Database migration registry

Shipped migrations `0001`–`0014` are immutable. Never edit their SQL.

| Id | Status | Notes |
| --- | --- | --- |
| 0001–0014 | shipped | Immutable. |
| 0015_call_payload | shipped (Secrets A1) | `mcpflow_call_payload` plus hash and redaction columns on `mcpflow_call_audit`. DOWN refuses while any ciphertext row exists. |
| 0016_secret | shipped (Secrets B) | `mcpflow_secret` and `mcpflow_secret_version`. STRICT, `sec_` idCheck, FKs ON DELETE RESTRICT. DOWN refuses while any row exists. |
| 0017_secret_sink_grant | shipped (Secrets B) | `mcpflow_secret_sink` (`snk_`) and `mcpflow_secret_grant` (`sgr_`). DOWN refuses while any row exists. |
| 0018_secret_value_index | shipped (Secrets B) | Echo-scrub index. B does not read it on dispatch. DOWN refuses while any row exists. |
| 0019_secret_reveal | shipped (Secrets B) | Append-only `mcpflow_reveal_event` and human-only columns on `mcpflow_api_key`. DOWN refuses while a reveal row exists. |
| 0020_sidecar_connections | shipped | `sidecar_connections` plus nullable `backends.connection_id`. The column add no-ops when the legacy `backends` table is absent. |
| 0021_env_sink_template | shipped (Secrets phase C) | `mcpflow_env_template` storing ref form only for env resync. DOWN refuses while rows exist. |
| 0022_project_secret_scope | shipped (issue #74) | `secrets_project_write` on `mcpflow_api_key` (default 0), `mcpflow_project_env_target` (`etg_`), `mcpflow_secret_upload` (`upl_`, token hash only), `mcpflow_project_secret_approval` (`psa_`, refs only). DOWN refuses while a target, ticket, approval, or granted flag remains, then drops the tables and the column. |
| 0023 | next free | |

## Connection pragmas

Every connection sets `PRAGMA secure_delete=ON`, so deleted pages are overwritten.

A new empty database also sets `PRAGMA auto_vacuum=INCREMENTAL` before the first table. An existing file keeps its current auto_vacuum mode until an operator runs the offline command `mcp-flow db vacuum`. The gateway must not hold the file. That command is what reclaims pages already freed. `secure_delete` on a live connection does not rewrite pages that were freed before the pragma was set.

## Down migrations

A down script that would drop ciphertext must refuse while rows exist. `0015` inserts the payload row count into a guard table whose `CHECK` accepts only zero, then drops `mcpflow_call_payload` and the six `call_audit` columns added by the up migration. `0016` through `0019` use the same guard: each refuses while its secrets tables hold any row, then drops only those tables. `0019` also drops the three `mcpflow_api_key` flag columns after the reveal table is empty. `0022` refuses while a target, upload ticket, approval, or `secrets_project_write` flag remains, then drops those tables and the column.

Destroyed secret versions are nulled under `secure_delete`, then the connection runs `wal_checkpoint(TRUNCATE)` and `incremental_vacuum`. That reclaim needs `auto_vacuum=INCREMENTAL`, which new databases already have. An older file still needs the offline `mcp-flow db vacuum` before freed pages return to the OS. The restore drill is documented in `docs/secrets-restore-drill.md`. It is not a startup check.
