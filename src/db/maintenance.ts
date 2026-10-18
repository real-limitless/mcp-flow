/**
 * PM: SQLite space reclaim.
 * - New DBs are created with auto_vacuum = INCREMENTAL (applyConnectionPragmas, before any table).
 * - Existing DBs keep their mode until a one-time OFFLINE conversion: `mcp-flow db vacuum` sets
 *   auto_vacuum = INCREMENTAL and runs a full VACUUM. That needs the gateway lock (refused while a
 *   gateway holds the DB) and is never reachable from the gateway (no API route or MCP tool imports it).
 * - incrementalVacuum(db, pages) gives freelist pages back to the OS. Retention calls it after deleting
 *   rows; the future archive job should too. On a DB that isn't INCREMENTAL it is a no-op.
 */
import { DatabaseSync } from "node:sqlite";
import { acquireGatewayLock } from "./gateway-lock.js";
import { applyConnectionPragmas, type ConnectionPragmaOptions } from "./migrations/index.js";

export type AutoVacuumMode = "none" | "full" | "incremental";
const MODES: AutoVacuumMode[] = ["none", "full", "incremental"];

const one = (db: DatabaseSync, pragma: string): number =>
  Number(Object.values(db.prepare(`PRAGMA ${pragma}`).get() as Record<string, unknown>)[0]);

export function autoVacuumMode(db: DatabaseSync): AutoVacuumMode {
  return MODES[one(db, "auto_vacuum")] ?? "none";
}

export interface SpaceStats {
  autoVacuum: AutoVacuumMode;
  pageSize: number;
  pageCount: number;
  freelistCount: number;
}

export function spaceStats(db: DatabaseSync): SpaceStats {
  return { autoVacuum: autoVacuumMode(db), pageSize: one(db, "page_size"), pageCount: one(db, "page_count"), freelistCount: one(db, "freelist_count") };
}

export interface IncrementalVacuumResult {
  autoVacuum: AutoVacuumMode;
  /** false when the DB is not INCREMENTAL (run `mcp-flow db vacuum` once) or nothing was free */
  ran: boolean;
  freelistBefore: number;
  freelistAfter: number;
  freedPages: number;
}

/**
 * PRAGMA incremental_vacuum(N): release up to `pages` free pages (default: all) back to the file system.
 * Must run outside a transaction. Cheap and bounded by N; safe to call while the gateway runs.
 */
export function incrementalVacuum(db: DatabaseSync, pages?: number): IncrementalVacuumResult {
  if (pages !== undefined && (!Number.isSafeInteger(pages) || pages < 1)) throw new Error("pages must be a positive integer");
  if (db.isTransaction) throw new Error("incrementalVacuum must run outside a transaction");
  const mode = autoVacuumMode(db);
  const before = one(db, "freelist_count");
  if (mode !== "incremental" || before === 0) {
    return { autoVacuum: mode, ran: false, freelistBefore: before, freelistAfter: before, freedPages: 0 };
  }
  db.exec(pages === undefined ? "PRAGMA incremental_vacuum;" : `PRAGMA incremental_vacuum(${pages});`);
  const after = one(db, "freelist_count");
  return { autoVacuum: mode, ran: true, freelistBefore: before, freelistAfter: after, freedPages: before - after };
}

export interface ConvertResult {
  changed: boolean;
  before: SpaceStats;
  after: SpaceStats;
}

/**
 * One-time OFFLINE conversion of an existing DB to auto_vacuum = INCREMENTAL (full VACUUM).
 * Takes the gateway lock first, so it refuses while a gateway runs on this DB. `check` only reports.
 * VACUUM rewrites the whole file: needs free disk about the DB size; take a backup first.
 */
export async function convertToIncrementalVacuum(
  dbPath: string,
  opts: { check?: boolean; pragmas?: ConnectionPragmaOptions } = {},
): Promise<ConvertResult> {
  if (dbPath === ":memory:") throw new Error("db vacuum needs a database file");
  const busy = (why: string) => new Error(`the database is in use by a running gateway; stop it first (db vacuum is an offline step): ${why}`);
  let lock: Awaited<ReturnType<typeof acquireGatewayLock>>;
  try {
    lock = await acquireGatewayLock(dbPath);
  } catch (err) {
    throw busy((err as Error).message);
  }
  if (!lock) throw busy("lock held");
  try {
    const db = new DatabaseSync(dbPath);
    try {
      applyConnectionPragmas(db, opts.pragmas);
      const before = spaceStats(db);
      if (opts.check || before.autoVacuum === "incremental") return { changed: false, before, after: before };
      db.exec("PRAGMA auto_vacuum = INCREMENTAL;");
      db.exec("VACUUM;");
      db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
      const after = spaceStats(db);
      if (after.autoVacuum !== "incremental") throw new Error(`VACUUM did not switch auto_vacuum (now ${after.autoVacuum})`);
      return { changed: true, before, after };
    } finally {
      db.close();
    }
  } finally {
    lock.release();
  }
}
