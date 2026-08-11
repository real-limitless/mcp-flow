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
