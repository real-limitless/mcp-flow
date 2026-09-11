/**
 * In-memory MCP session → enabled namespaced tools (dynamicTools working set).
 * Keyed like SessionProjectMap: mcp-session-id or synthetic key:${keyId}.
 */
export class SessionToolSetMap {
  private readonly map = new Map<
    string,
    { keyId: string; names: Set<string>; exp: number }
  >();

  set(
    sessionId: string,
    opts: { keyId: string; names: Iterable<string> },
    ttlMs = 24 * 60 * 60 * 1000,
  ): Set<string> {
    const names = new Set(
      [...opts.names].map((n) => String(n).trim()).filter(Boolean),
    );
    this.map.set(sessionId, {
      keyId: opts.keyId,
      names,
      exp: Date.now() + ttlMs,
    });
    return new Set(names);
  }

  get(
    sessionId: string | null | undefined,
    keyId?: string | null,
  ): Set<string> {
    if (!sessionId || !keyId) return new Set();
    const row = this.map.get(sessionId);
    if (!row || row.keyId !== keyId) return new Set();
    if (row.exp < Date.now()) {
      this.map.delete(sessionId);
      return new Set();
    }
    return new Set(row.names);
  }

  add(
    sessionId: string,
    keyId: string,
    names: Iterable<string>,
    ttlMs = 24 * 60 * 60 * 1000,
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
    ttlMs = 24 * 60 * 60 * 1000,
  ): Set<string> {
    const current = this.get(sessionId, keyId);
    for (const n of names) current.delete(String(n));
    return this.set(sessionId, { keyId, names: current }, ttlMs);
  }

  clear(sessionId: string, keyId: string): Set<string> {
    return this.set(sessionId, { keyId, names: [] });
  }
}

/** Process-wide map shared by HTTP app + gateway */
export const globalSessionToolSets = new SessionToolSetMap();
