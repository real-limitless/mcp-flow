/**
 * Audit copy of mf_admin_* arguments.
 * env, headers, and apiKey values are replaced with "[redacted]" before any
 * audit row is written. Names stay. The object passed to the tool is not mutated.
 * Null stays null so a per-key delete is still visible. A string or array in
 * place of a map is replaced as a whole so a bad payload cannot leak either.
 */

const SECRET_ARG_FIELDS = ["env", "headers", "apiKey"] as const;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function redactMap(value: unknown): unknown {
  if (value === null) return null;
  if (!isPlainRecord(value)) return "[redacted]";
  const out: Record<string, unknown> = {};
  for (const [name, entry] of Object.entries(value)) {
    out[name] = entry === null ? null : "[redacted]";
  }
  return out;
}

export function redactAdminToolAuditArgs(
  tool: string,
  args: Record<string, unknown>,
): Record<string, unknown> {
  if (!tool.startsWith("mf_admin_") || !args || typeof args !== "object") {
    return args;
  }
  if (!SECRET_ARG_FIELDS.some((field) => field in args)) return args;
  const copy: Record<string, unknown> = { ...args };
  if ("env" in copy) copy.env = redactMap(copy.env);
  if ("headers" in copy) copy.headers = redactMap(copy.headers);
  if ("apiKey" in copy && copy.apiKey != null) copy.apiKey = "[redacted]";
  return copy;
}
