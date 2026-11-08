/**
 * Online secure purge (Secrets §0.5).
 * Connections already set secure_delete=ON and, on a new database, auto_vacuum=INCREMENTAL (A1).
 * Destroyed versions finish with wal_checkpoint(TRUNCATE) and incremental_vacuum.
 * A full VACUUM stays on the offline `mcp-flow db vacuum` command.
 */

import type { DatabaseSync } from "node:sqlite";
import { autoVacuumMode, incrementalVacuum, type AutoVacuumMode, type IncrementalVacuumResult } from "../db/maintenance.js";

export function verifyAutoVacuumOnStartup(db: DatabaseSync): AutoVacuumMode {
  return autoVacuumMode(db);
}

export function assertSecureDelete(db: DatabaseSync): void {
  const row = db.prepare("PRAGMA secure_delete").get() as Record<string, unknown>;
  if (Number(Object.values(row)[0]) !== 1) throw new Error("secure_delete must be ON");
}

/** Run outside a transaction, after ciphertext has been nulled. */
export function secureReclaim(db: DatabaseSync): IncrementalVacuumResult {
  if (db.isTransaction) throw new Error("secure reclaim must run outside a transaction");
  db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  return incrementalVacuum(db);
}
