/**
 * Parse "Name=value" or "Name: value" (mcp-remote style).
 * Value may contain `=` or `:` — only the first separator splits.
 */
export function parseHeaderFlag(raw: string): { name: string; value: string } {
  const s = raw.trim();
  if (!s) throw new Error("empty header");

  const eq = s.indexOf("=");
  const colon = s.indexOf(":");

  let sep = -1;
  if (eq >= 0 && (colon < 0 || eq < colon)) sep = eq;
  else if (colon >= 0) sep = colon;

  if (sep <= 0) {
    throw new Error(`invalid header (use Name=value or Name: value): ${raw}`);
  }

  const name = s.slice(0, sep).trim();
  let value = s.slice(sep + 1).trim();
  // allow "Name: value" with optional space already trimmed
  if (!name) throw new Error(`invalid header name: ${raw}`);
  return { name, value };
}

/** Parse repeatable CLI flags into a header map (later flags win on same name). */
export function parseHeaderFlags(flags: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of flags) {
    const { name, value } = parseHeaderFlag(f);
    out[name] = value;
  }
  return out;
}

/**
 * Multi-header free text for TUI / forms.
 * Separators: newline, `;`, or `|` between pairs. Each pair is Name=value or Name: value.
 */
export function parseHeadersBlob(blob: string): Record<string, string> {
  const parts = blob
    .split(/[\n;|]+/)
    .map((p) => p.trim())
    .filter(Boolean);
  return parseHeaderFlags(parts);
}

export function formatHeadersHint(headers: Record<string, string>): string {
  return Object.keys(headers)
    .map((k) => `${k}=…`)
    .join("; ");
}

/**
 * Drop blank names/values so we never seal `Authorization: ""` (or empty env).
 * Returns undefined when nothing remains.
 */
export function compactSecretRecord(
  rec: Record<string, string> | null | undefined,
): Record<string, string> | undefined {
  if (!rec) return undefined;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(rec)) {
    const name = String(k).trim();
    const value = String(v ?? "").trim();
    if (name && value) out[name] = value;
  }
  return Object.keys(out).length ? out : undefined;
}

const AUTH_SCHEME = /^(Bearer|Basic|Digest|Token)\s+(\S[\s\S]*)$/i;

/**
 * OpenFlow and most remote MCP servers require `Authorization: Bearer <token>`.
 * Pasting a raw key (`of_…`, JWT, `mf_…`) without the scheme 401s as
 * `{ error: "Authentication required" }`. Known HTTP auth schemes are left intact.
 */
export function normalizeAuthorizationValue(value: string): string {
  const v = value.trim();
  if (!v) return v;
  const m = AUTH_SCHEME.exec(v);
  if (m) {
    const rest = m[2]!.trim();
    if (/^Bearer$/i.test(m[1]!)) return `Bearer ${rest}`;
    return `${m[1]} ${rest}`;
  }
  return `Bearer ${v}`;
}

/**
 * Compact + fold Authorization (any case) and prefix Bearer on raw tokens.
 * Does not rewrite other headers (e.g. X-Api-Key).
 */
export function normalizeUpstreamHeaders(
  rec: Record<string, string> | null | undefined,
): Record<string, string> | undefined {
  const compact = compactSecretRecord(rec);
  if (!compact) return undefined;
  const out: Record<string, string> = {};
  let authorization: string | undefined;
  for (const [k, v] of Object.entries(compact)) {
    if (k.toLowerCase() === "authorization") authorization = v;
    else out[k] = v;
  }
  if (authorization) {
    out.Authorization = normalizeAuthorizationValue(authorization);
  }
  return Object.keys(out).length ? out : undefined;
}

/**
 * If `apiKey` is set, it becomes Authorization (replacing any existing one).
 * Then compact + Bearer-normalize.
 */
export function withAuthorizationToken(
  headers: Record<string, string> | null | undefined,
  apiKey: string | null | undefined,
): Record<string, string> | undefined {
  const token = apiKey?.trim();
  const base: Record<string, string> = { ...(headers ?? {}) };
  if (token) {
    for (const k of Object.keys(base)) {
      if (k.toLowerCase() === "authorization") delete base[k];
    }
    base.Authorization = token;
  }
  return normalizeUpstreamHeaders(base);
}
