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
 * Top-level keys that the tool schema does not define are omitted as well,
 * including when the payload has no env, header, or apiKey field.
 */

import {
  AFFINITIES,
  isBoundedConfigString,
  PLACEMENT_MODES,
} from "../db/secret-input.js";
import { adminToolPropertyNames } from "../mcp/admin-tools.js";

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
  if (value === null) return null;
  return typeof value === "string" && allowed.has(value) ? value : "[redacted]";
}

function copyConfigString(value: unknown): unknown {
  if (value === null) return null;
  return typeof value === "string" && isBoundedConfigString(value)
    ? value
    : "[redacted]";
}

function copyStringArray(value: unknown): unknown {
  if (value === null) return null;
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || !isBoundedConfigString(item))
  ) {
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
    out.deviceId = copyConfigString(value.deviceId);
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
      out[key] = copyConfigString(value[key]);
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

function projectSchemaArgs(
  tool: string,
  args: Record<string, unknown>,
): Record<string, unknown> {
  const allowed = adminToolPropertyNames(tool);
  const out: Record<string, unknown> = {};
  if (!allowed) return out;
  for (const key of Object.keys(args)) {
    if (allowed.has(key)) out[key] = args[key];
  }
  return out;
}

const NAME_CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/gu;
const AUDIT_NAME_MAX = 64;

/** slug__tool. Same rule as parseNamespacedTool: "__" after the first character. */
function isUpstreamToolName(name: string): boolean {
  return name.indexOf("__") > 0;
}

/**
 * Inner name stored for a rejected mf_call_tool that is not an upstream tool.
 * Trimmed, control characters removed, capped at 64 UTF-16 units.
 */
function auditCallToolName(value: unknown): string {
  if (typeof value !== "string") return "[invalid]";
  return value.trim().replace(NAME_CONTROL_RE, "").slice(0, AUDIT_NAME_MAX);
}

/**
 * A rejected mf_call_tool whose target is not slug__tool records only the
 * inner name and a redacted arguments blob. Nested wrappers, case variants,
 * extra wrapper keys, and a non-string name all collapse to that shape.
 * An upstream slug__tool keeps its arguments for the content sanitizer.
 */
function auditCallToolArgs(args: Record<string, unknown>): Record<string, unknown> {
  if (typeof args.name === "string" && isUpstreamToolName(args.name.trim())) {
    return args;
  }
  return { name: auditCallToolName(args.name), arguments: "[redacted]" };
}

export function redactAdminToolAuditArgs(
  tool: string,
  args: Record<string, unknown>,
): Record<string, unknown> {
  if (!args || typeof args !== "object" || Array.isArray(args)) return args;
  if (/^mf_call_tool$/i.test(tool)) return auditCallToolArgs(args);
  if (!/^mf_admin_/i.test(tool)) return args;
  const projected = projectSchemaArgs(tool, args);
  if (!hasSecretShape(projected)) return projected;
  return redactLevel(projected);
}
