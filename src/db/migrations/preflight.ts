/**
 * Database (ops, review of f9388505): 0013 rebuilds mcpflow_call_audit at startup while holding the
 * write lock. Measured: 1M rows ~20 s with +1.85 GB peak disk; 10M rows ~9.5 min with +18.5 GB.
 * Before it runs we (1) refuse unless free disk on the DB's filesystem is at least 2x the DB size
 * (main file + WAL), overridable with MCP_FLOW_MIGRATE_SKIP_DISK_CHECK=1, and (2) log the row count
 * and an estimated duration so operators know the gateway is not hung.
 */
import { statfsSync, statSync } from "node:fs";
import { dirname } from "node:path";
import type { DatabaseSync } from "node:sqlite";

export const DISK_CHECK_OVERRIDE_ENV = "MCP_FLOW_MIGRATE_SKIP_DISK_CHECK";
export const DISK_HEADROOM_FACTOR = 2;

export interface PreflightDeps {
  /** free bytes available to this process on the filesystem holding `dir` */
  freeBytes?: (dir: string) => number;
  /** size in bytes of a file, 0 if missing */
  fileBytes?: (path: string) => number;
  log?: (line: string) => void;
  env?: Record<string, string | undefined>;
}

export class MigrationPreflightError extends Error {
  readonly code = "migration_preflight_failed";
  constructor(message: string) {
    super(message);
    this.name = "MigrationPreflightError";
  }
}

const one = (db: DatabaseSync, sql: string): number =>
  Number(Object.values(db.prepare(sql).get() as Record<string, unknown>)[0]);

/** Path of the main DB file, or null for :memory: / temp DBs. */
export function mainDbPath(db: DatabaseSync): string | null {
  const rows = db.prepare("PRAGMA database_list").all() as Array<{ name: string; file: string }>;
  const file = rows.find((r) => r.name === "main")?.file ?? "";
  return file ? file : null;
}

const defaultFree = (dir: string): number => {
  const s = statfsSync(dir);
  return Number(s.bavail) * Number(s.bsize);
};
const defaultFileBytes = (p: string): number => {
  try {
    return statSync(p).size;
  } catch {
    return 0;
  }
};

/** Per-row cost interpolated between the two measured points (20 us/row at 1M, 57 us/row at 10M). */
export function estimateRebuildSeconds(rows: number): number {
  const lo = 1_000_000, hi = 10_000_000, usLo = 20, usHi = 57;
  const us = rows <= lo ? usLo : rows >= hi ? usHi : usLo + ((usHi - usLo) * (rows - lo)) / (hi - lo);
  return (rows * us) / 1e6;
}

export const fmtBytes = (n: number): string => {
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i ? 1 : 0)} ${u[i]}`;
};

const fmtSecs = (s: number): string => (s < 90 ? `${Math.ceil(s)} s` : `${(s / 60).toFixed(1)} min`);

/** Preflight for a migration that rebuilds `table`. Throws MigrationPreflightError to refuse. */
export function tableRebuildPreflight(migrationId: string, table: string) {
  return (db: DatabaseSync, deps: PreflightDeps = {}): void => {
    const log = deps.log ?? ((l: string) => process.stderr.write(`${l}\n`));
    const env = deps.env ?? process.env;
    const rows = one(db, `SELECT count(*) FROM ${table}`);
    const pageBytes = one(db, "PRAGMA page_count") * one(db, "PRAGMA page_size");
    const path = mainDbPath(db);
    const wal = path ? (deps.fileBytes ?? defaultFileBytes)(`${path}-wal`) : 0;
    const dbBytes = pageBytes + wal;
    const tag = `[mcp-flow] migration ${migrationId}`;
    if (path) {
      const free = (deps.freeBytes ?? defaultFree)(dirname(path));
      const need = DISK_HEADROOM_FACTOR * dbBytes;
      if (free < need) {
        if (env[DISK_CHECK_OVERRIDE_ENV] === "1") {
          log(`${tag}: WARNING free disk ${fmtBytes(free)} is below ${DISK_HEADROOM_FACTOR}x the DB size (${fmtBytes(need)} needed); continuing because ${DISK_CHECK_OVERRIDE_ENV}=1`);
        } else {
          throw new MigrationPreflightError(
            `${tag} refused: it rebuilds ${table} (${rows} rows) and needs free disk of at least ` +
              `${DISK_HEADROOM_FACTOR}x the DB size: ${fmtBytes(need)} needed, ${fmtBytes(free)} free on ` +
              `${dirname(path)} (DB ${fmtBytes(dbBytes)} incl. WAL). Free up disk or move the DB, then restart. ` +
              `To run anyway, set ${DISK_CHECK_OVERRIDE_ENV}=1.`,
          );
        }
      }
    }
    if (rows === 0) return; // fresh/empty table: instant, nothing worth announcing
    log(
      `${tag}: rebuilding ${table}: ${rows} rows, DB ${fmtBytes(dbBytes)}; estimated ${fmtSecs(estimateRebuildSeconds(rows))} ` +
        `holding the write lock (gateway does not serve until it finishes)`,
    );
  };
}
