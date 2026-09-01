/**
 * In-memory MCP session → active project sticky (per process).
 * Keyed by mcp-session-id when the client supports Streamable HTTP sessions;
 * also supports synthetic ids from X-MCP-Flow-Session header.
 */
export class SessionProjectMap {
  private readonly map = new Map<
    string,
    { projectId: string; projectSlug: string; keyId: string; exp: number }
  >();

  set(
    sessionId: string,
    opts: { projectId: string; projectSlug: string; keyId: string },
    ttlMs = 24 * 60 * 60 * 1000,
  ): void {
    this.map.set(sessionId, {
      ...opts,
      exp: Date.now() + ttlMs,
    });
  }

  get(
    sessionId: string | null | undefined,
  ): { projectId: string; projectSlug: string; keyId: string } | null {
    if (!sessionId) return null;
    const row = this.map.get(sessionId);
    if (!row) return null;
    if (row.exp < Date.now()) {
      this.map.delete(sessionId);
      return null;
    }
    return {
      projectId: row.projectId,
      projectSlug: row.projectSlug,
      keyId: row.keyId,
    };
  }

  clear(sessionId: string): void {
    this.map.delete(sessionId);
  }
}

/** Process-wide map shared by HTTP app + gateway */
export const globalSessionProjects = new SessionProjectMap();
