/** Security R5-1: entries kept per owner (API key). One key's bindings can only evict its own. */
export const SESSION_MAP_PER_KEY_MAX = 64;
/** Owners (keys) tracked at once. Keys are admin-issued, so no single caller can push this. */
export const SESSION_MAP_MAX = 1024;

/** Security R5-2: a session id bound by one key cannot be re-bound by another. */
export class SessionIdInUseError extends Error {
  constructor() {
    super("session id is bound to another key; reconnect without an Mcp-Session-Id header to get a fresh one");
    this.name = "SessionIdInUseError";
  }
}

interface Row<T> {
  value: T;
  exp: number;
  owner: string;
}

/**
 * TTL map partitioned by owner (Security R5-1): each owner has its own LRU capped at `maxPerOwner`,
 * so inserting under one owner only ever evicts that owner's oldest entries. At most `maxOwners`
 * owners are tracked; beyond that the least recently active owner's partition is dropped (only
 * reachable with that many distinct live keys). set() refuses to overwrite a live row that belongs
 * to a different owner (R5-2). get() refreshes recency; sweep() drops expired rows.
 * Without `ownerOf`, everything is one partition (plain LRU with a cap of maxPerOwner).
 */
export class TtlLru<T> {
  private readonly rows = new Map<string, Row<T>>();
  /** owner -> its keys in LRU order; the outer Map is in owner-recency order */
  private readonly parts = new Map<string, Map<string, true>>();
  private readonly timer: ReturnType<typeof setInterval>;
  private readonly ownerOf: (v: T) => string;
  private readonly maxOwners: number;

  constructor(
    private readonly maxPerOwner: number,
    sweepMs = 60_000,
    opts: { ownerOf?: (v: T) => string; maxOwners?: number } = {},
  ) {
    this.ownerOf = opts.ownerOf ?? (() => "");
    this.maxOwners = Math.max(1, opts.maxOwners ?? SESSION_MAP_MAX);
    this.timer = setInterval(() => this.sweep(), sweepMs);
    this.timer.unref?.();
  }

  get size(): number {
    return this.rows.size;
  }

  /** Owner of a live row, or undefined. */
  ownerOfKey(key: string): string | undefined {
    const row = this.rows.get(key);
    if (!row) return undefined;
    if (row.exp <= Date.now()) {
      this.remove(key);
      return undefined;
    }
    return row.owner;
  }

  /** Throws SessionIdInUseError if a live row under `key` belongs to another owner. */
  set(key: string, value: T, ttlMs: number): void {
    this.sweep();
    const owner = this.ownerOf(value);
    const existing = this.rows.get(key);
    if (existing && existing.owner !== owner) throw new SessionIdInUseError();
    if (existing) this.remove(key);
    this.rows.set(key, { value, exp: Date.now() + ttlMs, owner });
    let part = this.parts.get(owner);
    if (part) this.parts.delete(owner);
    else part = new Map();
    this.parts.set(owner, part); // most recently active owner last
    part.set(key, true);
    while (part.size > this.maxPerOwner) {
      const oldest = part.keys().next().value as string;
      this.remove(oldest);
    }
    while (this.parts.size > this.maxOwners) {
      const [, victim] = this.parts.entries().next().value as [string, Map<string, true>];
      for (const k of [...victim.keys()]) this.remove(k);
    }
  }

  get(key: string): T | undefined {
    const row = this.rows.get(key);
    if (!row) return undefined;
    if (row.exp <= Date.now()) {
      this.remove(key);
      return undefined;
    }
    const part = this.parts.get(row.owner)!;
    part.delete(key);
    part.set(key, true);
    this.parts.delete(row.owner);
    this.parts.set(row.owner, part);
    return row.value;
  }

  /** Read without refreshing recency. Drops the row if it has expired. */
  peek(key: string): T | undefined {
    const row = this.rows.get(key);
    if (!row) return undefined;
    if (row.exp <= Date.now()) {
      this.remove(key);
      return undefined;
    }
    return row.value;
  }

  delete(key: string): void {
    this.remove(key);
  }

  /** Entries currently held by one owner. */
  sizeOf(owner: string): number {
    return this.parts.get(owner)?.size ?? 0;
  }

  private remove(key: string): void {
    const row = this.rows.get(key);
    if (!row) return;
    this.rows.delete(key);
    const part = this.parts.get(row.owner);
    if (!part) return;
    part.delete(key);
    if (part.size === 0) this.parts.delete(row.owner);
  }

  sweep(now = Date.now()): void {
    for (const [key, row] of this.rows) {
      if (row.exp <= now) this.remove(key);
    }
  }

  stop(): void {
    clearInterval(this.timer);
  }
}
