/**
 * In-memory MCP session → active project sticky (per process).
 * Keyed by mcp-session-id when the client supports Streamable HTTP sessions;
 * also supports synthetic ids from X-MCP-Flow-Session header.
 */
import { SESSION_MAP_MAX, TtlLru } from "./ttl-lru.js";

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

export interface SessionProject {
  projectId: string;
  projectSlug: string;
  keyId: string;
}

export class SessionProjectMap {
  private readonly rows: TtlLru<SessionProject>;

  constructor(maxEntries = SESSION_MAP_MAX, sweepMs = 60_000) {
    this.rows = new TtlLru<SessionProject>(maxEntries, sweepMs);
  }

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
