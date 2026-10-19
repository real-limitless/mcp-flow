/**
 * Audit and approval copy of mf_admin_* arguments.
 * env, headers, and apiKey values are replaced with "[redacted]". Names stay.
 * Those fields match case-insensitively at the top level. The object passed
 * to the tool is not mutated.
 * Null stays null so a per-key delete is still visible. A string or array in
 * place of a map is replaced as a whole so a bad payload cannot leak either.
 * placement and sandbox copies keep only known keys. Unknown keys such as
 * extra are omitted so their values never reach tools/call or list_audit.
 * A known key whose value is the wrong type is replaced with "[redacted]".
 */

import { AFFINITIES, PLACEMENT_MODES } from "../db/secret-input.js";

const MAP_FIELDS = new Set(["env", "headers"]);
const VALUE_FIELDS = new Set(["apikey"]);
const NEST_FIELDS = new Set(["placement", "sandbox"]);
const PLACEMENT_MODE_SET = new Set<string>(PLACEMENT_MODES);
const AFFINITY_SET = new Set<string>(AFFINITIES);

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

function copyEnum(value: unknown, allowed: Set<string>): unknown {
  return typeof value === "string" && allowed.has(value) ? value : "[redacted]";
}

function copyString(value: unknown): unknown {
  return typeof value === "string" ? value : "[redacted]";
}

function copyStringArray(value: unknown): unknown {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    return "[redacted]";
  }
  return value.slice();
}

/** Known placement keys only. Unknown keys, including extra and env, are omitted. */
function projectPlacement(value: unknown): unknown {
  if (value == null) return value;
  if (!isPlainRecord(value)) return "[redacted]";
  const out: Record<string, unknown> = {};
  if (Object.prototype.hasOwnProperty.call(value, "mode")) {
    out.mode = copyEnum(value.mode, PLACEMENT_MODE_SET);
  }
  if (Object.prototype.hasOwnProperty.call(value, "deviceId")) {
    out.deviceId = copyString(value.deviceId);
  }
  if (Object.prototype.hasOwnProperty.call(value, "deviceTags")) {
    out.deviceTags = copyStringArray(value.deviceTags);
  }
  if (Object.prototype.hasOwnProperty.call(value, "affinity")) {
    out.affinity = copyEnum(value.affinity, AFFINITY_SET);
  }
  return out;
}

/** Known sandbox keys only. Unknown keys, including extra and token, are omitted. */
function projectSandbox(value: unknown): unknown {
  if (value == null) return value;
  if (!isPlainRecord(value)) return "[redacted]";
  const out: Record<string, unknown> = {};
  for (const key of ["memory", "cpus", "networkMode"] as const) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      out[key] = copyString(value[key]);
    }
  }
  return out;
}

function redactLevel(rec: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rec)) {
    const lower = key.toLowerCase();
    if (MAP_FIELDS.has(lower)) {
      out[key] = redactMap(value);
    } else if (VALUE_FIELDS.has(lower)) {
      out[key] = value == null ? value : "[redacted]";
    } else if (NEST_FIELDS.has(lower)) {
      out[key] = lower === "sandbox" ? projectSandbox(value) : projectPlacement(value);
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
  return redactLevel(args);
}
