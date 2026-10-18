/**
 * In-memory MCP session → active project sticky (per process).
 * Keyed by mcp-session-id when the client supports Streamable HTTP sessions;
 * also supports synthetic ids from X-MCP-Flow-Session header.
 */
import { SESSION_MAP_PER_KEY_MAX, TtlLru } from "./ttl-lru.js";

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface SessionProject {
  projectId: string;
  projectSlug: string;
  keyId: string;
}

export class SessionProjectMap {
  private readonly rows: TtlLru<SessionProject>;

  /** maxPerKey: bindings kept per API key (R5-1: partitioned by key; one key can't evict another's) */
  constructor(maxPerKey = SESSION_MAP_PER_KEY_MAX, sweepMs = 60_000, maxKeys?: number) {
    this.rows = new TtlLru<SessionProject>(maxPerKey, sweepMs, { ownerOf: (v) => v.keyId, maxOwners: maxKeys });
  }

  /** Throws SessionIdInUseError when another key owns this session id (R5-2). */
  set(
    sessionId: string,
    opts: SessionProject,
    ttlMs = SESSION_TTL_MS,
  ): void {
    this.rows.set(sessionId, { ...opts }, ttlMs);
  }

  get(sessionId: string | null | undefined): SessionProject | null {
    if (!sessionId) return null;
    return this.rows.get(sessionId) ?? null;
  }

  clear(sessionId: string): void {
    this.rows.delete(sessionId);
  }

  /** Drop the row only when it belongs to this key. */
  clearIfOwner(sessionId: string, keyId: string): boolean {
    const row = this.rows.peek(sessionId);
    if (!row || row.keyId !== keyId) return false;
    this.rows.delete(sessionId);
    return true;
  }

  /** True when a live binding for this session id belongs to a different key (R5-2). */
  ownedByOther(sessionId: string, keyId: string): boolean {
    const o = this.rows.ownerOfKey(sessionId);
    return o !== undefined && o !== keyId;
  }

  sizeForKey(keyId: string): number {
    return this.rows.sizeOf(keyId);
  }

  sweep(): void {
    this.rows.sweep();
  }

  get size(): number {
    return this.rows.size;
  }

  stop(): void {
    this.rows.stop();
  }
}

/** Process-wide map shared by HTTP app + gateway */
export const globalSessionProjects = new SessionProjectMap();
