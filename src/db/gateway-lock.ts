/**
 * Security T2.5 R2-4: single gateway process per DB.
 *
 * Restart recovery (recoverOrphans) treats every open hold as orphaned, so a second gateway on the
 * same DB would cancel the first one's live holds. Until a leader lease lands (multi-instance
 * follow-up in the plan), startup takes an exclusive lock file next to the DB and a second process
 * refuses to start.
 *
 * Node has no flock(2); this is the portable equivalent: O_CREAT|O_EXCL create of `<db>.gateway.lock`
 * (mode 0600) holding {pid, host, started}, plus a heartbeat (mtime touched every 10 s). A lock is
 * stale, and is taken over, only if its mtime is older than 30 s, or it names this host and a pid
 * that is dead (or our own pid, e.g. pid 1 in a restarted container). Single host only; not for NFS.
 */
import { closeSync, openSync, readFileSync, renameSync, rmSync, statSync, utimesSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import { randomBytes } from "node:crypto";

export const LOCK_HEARTBEAT_MS = 10_000;
export const LOCK_STALE_MS = 30_000;

/** Locks held by THIS process: our own pid in a lock file is only stale if we don't hold it. */
const heldHere = new Set<string>();

export interface GatewayLock {
  path: string;
  release(): void;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function isStale(path: string, now: number, staleMs: number): boolean {
  let st;
  try {
    st = statSync(path);
  } catch {
    return true; // vanished
  }
  if (now - st.mtimeMs > staleMs) return true;
  try {
    const info = JSON.parse(readFileSync(path, "utf8")) as { pid?: number; host?: string };
    if (info.host === hostname() && typeof info.pid === "number") {
      if (info.pid === process.pid) return !heldHere.has(path); // previous incarnation with our pid (containers)
      return !pidAlive(info.pid);
    }
  } catch {
    /* unreadable/partial: fall back to the mtime rule */
  }
  return false;
}

export function acquireGatewayLock(
  dbPath: string,
  opts: { heartbeatMs?: number; staleMs?: number } = {},
): GatewayLock | null {
  if (!dbPath || dbPath === ":memory:") return null;
  const path = `${dbPath}.gateway.lock`;
  const staleMs = opts.staleMs ?? LOCK_STALE_MS;
  const body = JSON.stringify({ pid: process.pid, host: hostname(), started: new Date().toISOString() });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fd = openSync(path, "wx", 0o600);
      try {
        writeSync(fd, body);
      } finally {
        closeSync(fd);
      }
      const hb = setInterval(() => {
        try {
          const t = new Date();
          utimesSync(path, t, t);
        } catch {
          /* removed under us; the next start will notice */
        }
      }, opts.heartbeatMs ?? LOCK_HEARTBEAT_MS);
      hb.unref();
      heldHere.add(path);
      let released = false;
      return {
        path,
        release() {
          if (released) return;
          released = true;
          clearInterval(hb);
          heldHere.delete(path);
          try {
            const cur = JSON.parse(readFileSync(path, "utf8")) as { pid?: number; started?: string };
            if (cur.pid === process.pid && body.includes(String(cur.started))) rmSync(path, { force: true });
          } catch {
            /* already gone */
          }
        },
      };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      if (attempt === 0 && isStale(path, Date.now(), staleMs)) {
        // move the stale lock aside atomically, then retry the exclusive create
        try {
          renameSync(path, `${path}.stale-${randomBytes(4).toString("hex")}`);
        } catch {
          /* another process took it over first */
        }
        continue;
      }
      let holder = "";
      try {
        const info = JSON.parse(readFileSync(path, "utf8")) as { pid?: number; host?: string; started?: string };
        holder = ` (pid ${info.pid} on ${info.host}, started ${info.started})`;
      } catch {
        /* ignore */
      }
      throw new Error(
        `another mcp-flow gateway process holds ${path}${holder}; only one gateway may use a database at a time`,
      );
    }
  }
  throw new Error(`could not acquire ${path}`);
}
