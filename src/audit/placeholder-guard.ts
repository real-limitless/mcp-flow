/**
 * Write guard (Secrets §7.5).
 * A write argument that contains a redaction placeholder is refused so a caller cannot
 * write a scrubbed value back over the real one.
 * A scan that throws fails closed.
 */

const PLACEHOLDER_RE = /\[secret:[^\]]{0,128}\]|\[secret-redacted\]|\[redacted\]|\[REDACTED\]/;

const WRITE_SEGMENT_RE =
  /(?:^|[_\-./])(?:create|update|delete|write|set|put|patch|apply|deploy|upsert|insert|remove|edit|unset|grant|revoke|rotate|import|provision|save)(?:$|[_\-./])/i;

/** camelCase writes such as compose-saveEnvironment. Case-sensitive so `saved` or `savepoint` stay reads. */
const CAMEL_WRITE_RE = /(?:^|[_\-./])save[A-Z]/;

const WRITE_FIELDS = new Set([
  "env",
  "headers",
  "composefile",
  "command",
  "entrypoint",
  "script",
  "apikey",
  "unsetenv",
]);

function walkStrings(value: unknown, depth: number, hit: { placeholder: boolean; writeField: boolean }): void {
  if (value == null || depth > 12 || (hit.placeholder && hit.writeField)) return;
  if (typeof value === "string") {
    if (PLACEHOLDER_RE.test(value)) hit.placeholder = true;
    return;
  }
  if (typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) walkStrings(item, depth + 1, hit);
    return;
  }
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    if (WRITE_FIELDS.has(key.toLowerCase())) hit.writeField = true;
    if (PLACEHOLDER_RE.test(key)) hit.placeholder = true;
    walkStrings(item, depth + 1, hit);
  }
}

export function isWriteIntent(tool: string, args: unknown): boolean {
  if (WRITE_SEGMENT_RE.test(tool) || CAMEL_WRITE_RE.test(tool)) return true;
  const hit = { placeholder: false, writeField: false };
  walkStrings(args, 0, hit);
  return hit.writeField;
}

export function containsPlaceholder(value: unknown): boolean {
  const hit = { placeholder: false, writeField: false };
  walkStrings(value, 0, hit);
  return hit.placeholder;
}

/**
 * A reason code when this write must be refused, otherwise null.
 * Fail closed when the arguments cannot be scanned.
 */
export function placeholderWriteBlock(tool: string, args: unknown): "placeholder_write" | null {
  try {
    if (!isWriteIntent(tool, args)) return null;
    return containsPlaceholder(args) ? "placeholder_write" : null;
  } catch {
    return "placeholder_write";
  }
}
