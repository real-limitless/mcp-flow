import type { DatabaseSync } from "node:sqlite";

/**
 * Exactly-once dispatch claim for an approved pending call (db-t2.1 "Dispatch once").
 * Returns true only for the single caller whose UPDATE changed exactly one row.
 */
export function claimPendingDispatch(
  db: DatabaseSync,
  pendingCallId: string,
  at: string = new Date().toISOString(),
): boolean {
  const res = db
    .prepare(
      `UPDATE mcpflow_pending_call SET dispatched_at = ?
        WHERE id = ? AND status = 'approved' AND dispatched_at IS NULL`,
    )
    .run(at, pendingCallId);
  return Number(res.changes) === 1;
}
