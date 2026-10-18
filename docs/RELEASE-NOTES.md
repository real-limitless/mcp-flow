# Release notes

## Next deploy: migration 0013 (call_audit purge actor)

The first gateway start on this release applies migration `0013_call_audit_purge_actor`, which
**rebuilds `mcpflow_call_audit`** (the full table is copied) while holding the SQLite write lock.

- **Downtime.** The gateway does not serve until the rebuild finishes. Measured: about **20 s for
  1M** audit rows, and about **9.5 min for 10M** rows (it grows faster than linear). Before the rebuild the
  gateway logs the row count and an estimate on stderr:
  `[mcp-flow] migration 0013_call_audit_purge_actor: rebuilding mcpflow_call_audit: N rows, ... estimated ...`.
  If the DB is large, plan a maintenance window, and don't let a supervisor or health check kill the process
  while the rebuild runs.
- **Disk.** Peak extra disk use is about the size of the table again (measured +1.85 GB at 1M rows,
  +18.5 GB at 10M). Startup **refuses to run 0013** unless the DB's filesystem has free space of at least
  **2x the DB size** (main file plus WAL), and exits with an error that says how much is needed and how much is
  free. Nothing is applied when it refuses. If you've checked the space yourself, you can override with
  `MCP_FLOW_MIGRATE_SKIP_DISK_CHECK=1` (only the exact value `1` works). A warning is still logged.
- **Afterwards.** The DB file keeps the space the old table used (it goes to free pages, not back to
  the OS). In a later window, stop the gateway and run `mcp-flow db vacuum`. This is offline: it needs the
  gateway lock and about 1x the DB size free, and it also switches the DB to `auto_vacuum=INCREMENTAL`.
- **Audit trail.** 0013 sets every `result_purge` row's actor to `system:sweeper` or `system:quota` (based on
  its reason) and writes one `mcpflow_migration_note` row `{"null_backfilled": N, "agt_actor_overwritten": M}`.
  M counts purge rows that carried an `agt_` actor before; those actors are replaced, so check the note if M > 0.

## Next deploy: backend startup (QA v5.5)

- A backend that takes longer than `MCP_FLOW_BACKEND_INIT_TIMEOUT_MS` (default 20 s) to start is no longer
  killed and respawned in a loop. Callers stop waiting at that point and get `backend_unavailable`
  (`retry_after_ms`), but the init keeps going and the backend serves calls once it's ready (one spawn).
- New `MCP_FLOW_BACKEND_INIT_HARD_TIMEOUT_MS` (default 300 s): the ceiling for a truly hung init. Past it the
  spawn is killed and retries back off from 30 s to at most 10 min. A backend that exits or errors during
  init backs off from 1 s to at most 60 s instead of respawning on every call.
- Invalid or out-of-range values for either timeout are now logged at startup instead of being replaced silently.
