/**
 * PM: basic per-agent rate limit on tools/call. In-memory token bucket per agent_id.
 * MCP_FLOW_RATE_LIMIT_PER_MIN: capacity = N calls, refilled continuously at N per minute.
 * Off when 0/unset/invalid. Buckets are bounded: at most `maxBuckets` (default 10 000) agents are
 * tracked; on overflow, buckets that have refilled to full are dropped first (no state lost), then the
 * least recently used. Per-process only (one gateway per DB, R2-4).
 */
export const DEFAULT_RATE_LIMIT_MAX_BUCKETS = 10_000;

interface Bucket { tokens: number; at: number }

export type RateTake = { ok: true; remaining: number } | { ok: false; retryAfterMs: number };

export class AgentRateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly perMs: number;
  private readonly maxBuckets: number;
  private readonly clock: () => number;

  constructor(readonly perMinute: number, opts: { maxBuckets?: number; clock?: () => number } = {}) {
    if (!Number.isSafeInteger(perMinute) || perMinute < 1) throw new Error("perMinute must be a positive integer");
    this.perMs = perMinute / 60_000;
    this.maxBuckets = Math.max(1, opts.maxBuckets ?? DEFAULT_RATE_LIMIT_MAX_BUCKETS);
    this.clock = opts.clock ?? Date.now;
  }

  get size(): number {
    return this.buckets.size;
  }

  private refill(b: Bucket, now: number): void {
    if (now > b.at) b.tokens = Math.min(this.perMinute, b.tokens + (now - b.at) * this.perMs);
    b.at = Math.max(b.at, now);
  }

  /** Take one token for `agentId`. */
  take(agentId: string): RateTake {
    const now = this.clock();
    let b = this.buckets.get(agentId);
    if (b) {
      this.buckets.delete(agentId); // re-insert below: Map order = least recently used first
      this.refill(b, now);
    } else {
      this.evictFor(now);
      b = { tokens: this.perMinute, at: now };
    }
    this.buckets.set(agentId, b);
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return { ok: true, remaining: Math.floor(b.tokens) };
    }
    return { ok: false, retryAfterMs: Math.max(1, Math.ceil((1 - b.tokens) / this.perMs)) };
  }

  private evictFor(now: number): void {
    if (this.buckets.size < this.maxBuckets) return;
    for (const [id, b] of this.buckets) {
      this.refill(b, now);
      if (b.tokens >= this.perMinute) this.buckets.delete(id); // full again: same as untracked
    }
    while (this.buckets.size >= this.maxBuckets) {
      const oldest = this.buckets.keys().next().value as string;
      this.buckets.delete(oldest);
    }
  }
}

/** MCP_FLOW_RATE_LIMIT_PER_MIN: whole calls per minute per agent; 0/unset/invalid = off (returns 0). */
export function parseRateLimitPerMin(raw: string | number | undefined | null): number {
  const s = raw == null ? "" : String(raw).trim();
  if (!/^\d+$/.test(s)) return 0;
  const n = Number(s);
  return Number.isSafeInteger(n) ? Math.min(n, 1_000_000) : 0;
}
