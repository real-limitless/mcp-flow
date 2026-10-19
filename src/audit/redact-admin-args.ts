/**
 * Audit and approval copy of mf_admin_* arguments.
 * env, headers, and apiKey values are replaced with "[redacted]". Names stay.
 * Those fields match case-insensitively, including when nested under placement
 * or sandbox. The object passed to the tool is not mutated.
 * Null stays null so a per-key delete is still visible. A string or array in
 * place of a map is replaced as a whole so a bad payload cannot leak either.
 */

const MAP_FIELDS = new Set(["env", "headers"]);
const VALUE_FIELDS = new Set(["apikey"]);
const NEST_FIELDS = new Set(["placement", "sandbox"]);

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

function hasSecretShape(args: Record<string, unknown>): boolean {
  for (const key of Object.keys(args)) {
    const lower = key.toLowerCase();
    if (MAP_FIELDS.has(lower) || VALUE_FIELDS.has(lower) || NEST_FIELDS.has(lower)) {
      return true;
    }
  }
  return false;
}

function redactLevel(
  rec: Record<string, unknown>,
  nested: boolean,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rec)) {
    const lower = key.toLowerCase();
    if (MAP_FIELDS.has(lower)) {
      out[key] = redactMap(value);
    } else if (VALUE_FIELDS.has(lower)) {
      out[key] = value == null ? value : "[redacted]";
    } else if (!nested && NEST_FIELDS.has(lower) && isPlainRecord(value)) {
      out[key] = redactLevel(value, true);
    } else {
      out[key] = value;
    }
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
  if (!hasSecretShape(args)) return args;
  return redactLevel(args, false);
}
