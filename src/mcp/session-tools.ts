/**
 * In-memory MCP session → enabled namespaced tools (dynamicTools working set).
 * Keyed like SessionProjectMap: mcp-session-id or synthetic key:${keyId}.
 */
import { globalSessionProjects } from "./session-project.js";
import { SESSION_MAP_PER_KEY_MAX, TtlLru } from "./ttl-lru.js";

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

interface ToolRow {
  keyId: string;
  names: Set<string>;
}

export class SessionToolSetMap {
  private readonly rows: TtlLru<ToolRow>;

  /** maxPerKey: working sets kept per API key (R5-1: partitioned by key; one key can't evict another's) */
  constructor(maxPerKey = SESSION_MAP_PER_KEY_MAX, sweepMs = 60_000, maxKeys?: number) {
    this.rows = new TtlLru<ToolRow>(maxPerKey, sweepMs, { ownerOf: (v) => v.keyId, maxOwners: maxKeys });
  }

  /** True when a live working set for this session id belongs to a different key (R5-2). */
  ownedByOther(sessionId: string, keyId: string): boolean {
    const o = this.rows.ownerOfKey(sessionId);
    return o !== undefined && o !== keyId;
  }

  sizeForKey(keyId: string): number {
    return this.rows.sizeOf(keyId);
  }

  set(
    sessionId: string,
    opts: { keyId: string; names: Iterable<string> },
    ttlMs = SESSION_TTL_MS,
  ): Set<string> {
    const names = new Set(
      [...opts.names].map((n) => String(n).trim()).filter(Boolean),
    );
    this.rows.set(sessionId, { keyId: opts.keyId, names }, ttlMs);
    return new Set(names);
  }

  get(
    sessionId: string | null | undefined,
    keyId?: string | null,
  ): Set<string> {
    if (!sessionId || !keyId) return new Set();
    const row = this.rows.get(sessionId);
    if (!row || row.keyId !== keyId) return new Set();
    return new Set(row.names);
  }

  add(
    sessionId: string,
    keyId: string,
    names: Iterable<string>,
    ttlMs = SESSION_TTL_MS,
  ): Set<string> {
    const current = this.get(sessionId, keyId);
    for (const n of names) {
      const t = String(n).trim();
      if (t) current.add(t);
    }
    return this.set(sessionId, { keyId, names: current }, ttlMs);
  }

  remove(
    sessionId: string,
    keyId: string,
    names: Iterable<string>,
    ttlMs = SESSION_TTL_MS,
  ): Set<string> {
    const current = this.get(sessionId, keyId);
    for (const n of names) current.delete(String(n));
    return this.set(sessionId, { keyId, names: current }, ttlMs);
  }

  clear(sessionId: string, keyId: string): Set<string> {
    return this.set(sessionId, { keyId, names: [] });
  }

  /**
   * Remove the session. When keyId is set, delete only if it owns the row,
   * the same check get() uses.
   */
  delete(sessionId: string, keyId?: string | null): void {
    if (keyId) {
      const row = this.rows.peek(sessionId);
      if (!row || row.keyId !== keyId) return;
    }
    this.rows.delete(sessionId);
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

/**
 * Security R5-2: true when this session id is already bound (project or tool set) by another key.
 * The /mcp entry refuses such a request; set() also refuses (SessionIdInUseError) as a backstop.
 */
export function sessionIdOwnedByOther(sessionId: string | null | undefined, keyId: string | null | undefined): boolean {
  if (!sessionId || !keyId) return false;
  return globalSessionProjects.ownedByOther(sessionId, keyId) || globalSessionToolSets.ownedByOther(sessionId, keyId);
}

/** Process-wide map shared by HTTP app + gateway */
export const globalSessionToolSets = new SessionToolSetMap();

/**
 * Drop sticky project and dynamic tool state when an MCP session ends.
 * keyId must own each row, matching get(); a different key cannot clear it.
 */
export function forgetMcpSession(
  sessionId: string | null | undefined,
  keyId?: string | null,
): void {
  if (!sessionId || !keyId) return;
  globalSessionProjects.clearIfOwner(sessionId, keyId);
  globalSessionToolSets.delete(sessionId, keyId);
}
