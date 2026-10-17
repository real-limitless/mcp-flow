/**
 * In-memory MCP session → enabled namespaced tools (dynamicTools working set).
 * Keyed like SessionProjectMap: mcp-session-id or synthetic key:${keyId}.
 */
import { globalSessionProjects } from "./session-project.js";
import { SESSION_MAP_MAX, TtlLru } from "./ttl-lru.js";

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

interface ToolRow {
  keyId: string;
  names: Set<string>;
}

export class SessionToolSetMap {
  private readonly rows: TtlLru<ToolRow>;

  constructor(maxEntries = SESSION_MAP_MAX, sweepMs = 60_000) {
    this.rows = new TtlLru<ToolRow>(maxEntries, sweepMs);
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
