export const SESSION_MAP_MAX = 1024;

/**
 * Insertion-ordered map with a hard cap and TTL.
 * get() refreshes recency. sweep() drops expired rows without waiting for a read.
 */
export class TtlLru<T> {
  private readonly rows = new Map<string, { value: T; exp: number }>();
  private readonly timer: ReturnType<typeof setInterval>;

  constructor(
    private readonly maxEntries: number,
    sweepMs = 60_000,
  ) {
    this.timer = setInterval(() => this.sweep(), sweepMs);
    this.timer.unref?.();
  }

  get size(): number {
    return this.rows.size;
  }

  set(key: string, value: T, ttlMs: number): void {
    this.sweep();
    if (this.rows.has(key)) this.rows.delete(key);
    this.rows.set(key, { value, exp: Date.now() + ttlMs });
    while (this.rows.size > this.maxEntries) {
      const oldest = this.rows.keys().next().value;
      if (oldest === undefined) break;
      this.rows.delete(oldest);
    }
  }

  get(key: string): T | undefined {
    const row = this.rows.get(key);
    if (!row) return undefined;
    if (row.exp <= Date.now()) {
      this.rows.delete(key);
      return undefined;
    }
    this.rows.delete(key);
    this.rows.set(key, row);
    return row.value;
  }

  /** Read without refreshing recency. Drops the row if it has expired. */
  peek(key: string): T | undefined {
    const row = this.rows.get(key);
    if (!row) return undefined;
    if (row.exp <= Date.now()) {
      this.rows.delete(key);
      return undefined;
    }
    return row.value;
  }

  delete(key: string): void {
    this.rows.delete(key);
  }

  sweep(now = Date.now()): void {
    for (const [key, row] of this.rows) {
      if (row.exp <= now) this.rows.delete(key);
    }
  }

  stop(): void {
    clearInterval(this.timer);
  }
}
