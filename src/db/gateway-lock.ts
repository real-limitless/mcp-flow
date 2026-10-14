/**
 * Security T2.5 R2-4 / R3-1..R3-3: single gateway process per DB.
 *
 * Restart recovery (recoverOrphans) treats every open hold as orphaned, so a second gateway on the
 * same DB would cancel the first one's live holds. Until the DB leader lease lands (multi-instance
 * follow-up in the plan), startup takes an exclusive lock file next to the DB.
 *
 * - Lock file `<db>.gateway.lock` (0600): {nonce, pid, host, bootId, pidNs, started}, created with
 *   O_CREAT|O_EXCL. The random nonce identifies the holder.
 * - Takeover of a stale lock (R3-1): the stale file is renamed aside and the aside copy re-read; if it
 *   is not the exact stale lock we judged (another starter already replaced it), it is put back and we
 *   lose. After any create we wait `settleMs` and read the lock back; our nonce must still be there.
 * - Heartbeat (R3-2): every `heartbeatMs` the holder re-reads the file. If the nonce is not ours (paused
 *   process, someone took over) it does NOT touch the file and calls onLost (server: log + exit).
 * - Staleness (R3-3): mtime older than `staleMs`. The faster pid rules (dead pid / our own pid) apply
 *   only when host, kernel boot id and pid namespace all match ours; a hostname + pid match alone is
 *   never trusted (containers sharing a hostname have separate pid namespaces).
 * Single host only; not for NFS.
 */
import { closeSync, linkSync, openSync, readFileSync, readlinkSync, renameSync, rmSync, statSync, utimesSync, writeSync } from "node:fs";
import { hostname } from "node:os";
import { randomBytes } from "node:crypto";

/** R4-1: 3 s heartbeat (lock loss detected within ~3 s); stale stays at 30 s = 10 missed beats. */
export const LOCK_HEARTBEAT_MS = 3_000;
export const LOCK_STALE_MS = 30_000;
export const LOCK_SETTLE_MS = 150;

export interface LockBody {
  nonce: string;
  pid: number;
  host: string;
  bootId: string | null;
  pidNs: string | null;
  started: string;
}

export interface GatewayLock {
  path: string;
  nonce: string;
  /** R4-1: true while the lock file still carries our nonce (checked right before recovery). */
  owned(): boolean;
  release(): void;
}

export interface LockOptions {
  heartbeatMs?: number;
  staleMs?: number;
  settleMs?: number;
  /** Called once if the lock is lost while held (R3-2). The server logs and exits. */
  onLost?: (reason: string) => void;
  /** Test hooks for deterministic race simulation. */
  hooks?: { beforeRename?: () => void; afterCreate?: () => void };
}

/** Locks held by THIS process (own-pid rule only applies to locks we don't hold). */
const heldHere = new Set<string>();

function readOr<T>(f: () => T, fallback: T): T {
  try {
    return f();
  } catch {
    return fallback;
  }
}

/** Identity of this process's host + kernel boot + pid namespace (null parts where unavailable). */
export function lockIdentity(): { host: string; bootId: string | null; pidNs: string | null } {
  return {
    host: hostname(),
    bootId: readOr(() => readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim() || null, null),
    pidNs: readOr(() => readlinkSync("/proc/self/ns/pid"), null),
  };
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

function readBody(path: string): LockBody | null {
  return readOr(() => JSON.parse(readFileSync(path, "utf8")) as LockBody, null);
}

function isStale(path: string, body: LockBody | null, now: number, staleMs: number): boolean {
  const st = readOr(() => statSync(path), null);
  if (!st) return true; // vanished
  if (now - st.mtimeMs > staleMs) return true;
  if (!body || typeof body.pid !== "number") return false;
  const me = lockIdentity();
  const sameNamespace = body.host === me.host && me.bootId !== null && body.bootId === me.bootId && me.pidNs !== null && body.pidNs === me.pidNs;
  if (!sameNamespace) return false; // R3-3: hostname + pid alone is not trusted; wait out the mtime rule
  if (body.pid === process.pid) return !heldHere.has(path);
  return !pidAlive(body.pid);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function acquireGatewayLock(dbPath: string, opts: LockOptions = {}): Promise<GatewayLock | null> {
  if (!dbPath || dbPath === ":memory:") return null;
  const path = `${dbPath}.gateway.lock`;
  const staleMs = opts.staleMs ?? LOCK_STALE_MS;
  const nonce = randomBytes(16).toString("hex");
  const body: LockBody = { nonce, pid: process.pid, ...lockIdentity(), started: new Date().toISOString() };
  const contention = (holder: LockBody | null) =>
    new Error(
      `another mcp-flow gateway process holds ${path}` +
        (holder ? ` (pid ${holder.pid} on ${holder.host}, started ${holder.started})` : "") +
        "; only one gateway may use a database at a time",
    );

  for (let attempt = 0; attempt < 2; attempt++) {
    let fd: number;
    try {
      fd = openSync(path, "wx", 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      const seen = readBody(path);
      if (attempt > 0 || !isStale(path, seen, Date.now(), staleMs)) throw contention(seen);
      // R3-1: move it aside, then make sure what we moved is the stale lock we judged
      opts.hooks?.beforeRename?.();
      const aside = `${path}.stale-${randomBytes(4).toString("hex")}`;
      try {
        renameSync(path, aside);
      } catch {
        throw contention(readBody(path)); // someone else moved it first
      }
      const moved = readBody(aside);
      if ((moved?.nonce ?? null) !== (seen?.nonce ?? null) || JSON.stringify(moved) !== JSON.stringify(seen)) {
        // we moved another starter's fresh lock: put it back (only if the slot is still empty) and lose
        try {
          linkSync(aside, path);
        } catch {
          /* slot already refilled; the heartbeat check fences whoever is not in the file */
        }
        rmSync(aside, { force: true });
        throw contention(moved);
      }
      rmSync(aside, { force: true });
      continue;
    }
    try {
      writeSync(fd, JSON.stringify(body));
    } finally {
      closeSync(fd);
    }
    heldHere.add(path);
    opts.hooks?.afterCreate?.();
    // R3-1: settle, then read back; a concurrent takeover that replaced our file wins, we lose
    await sleep(opts.settleMs ?? LOCK_SETTLE_MS);
    const back = readBody(path);
    if (back?.nonce !== nonce) {
      heldHere.delete(path);
      throw contention(back);
    }
    return startHeartbeat(path, nonce, opts);
  }
  throw contention(readBody(path));
}

function startHeartbeat(path: string, nonce: string, opts: LockOptions): GatewayLock {
  let released = false;
  const lost = (reason: string) => {
    if (released) return;
    released = true;
    clearInterval(hb);
    heldHere.delete(path);
    opts.onLost?.(reason);
  };
  const hb = setInterval(() => {
    // R3-2: only refresh a file that is still ours; otherwise fence ourselves
    const cur = readBody(path);
    if (!cur) return lost(`lock file ${path} is missing`);
    if (cur.nonce !== nonce) return lost(`lock file ${path} was taken over by pid ${cur.pid} on ${cur.host}`);
    try {
      const t = new Date();
      utimesSync(path, t, t);
    } catch {
      lost(`lock file ${path} could not be refreshed`);
    }
  }, opts.heartbeatMs ?? LOCK_HEARTBEAT_MS);
  hb.unref();
  return {
    path,
    nonce,
    owned() {
      return !released && readBody(path)?.nonce === nonce;
    },
    release() {
      if (released) return;
      released = true;
      clearInterval(hb);
      heldHere.delete(path);
      if (readBody(path)?.nonce === nonce) rmSync(path, { force: true });
    },
  };
}
