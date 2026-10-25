import type { UpdateBackendInput } from "../types.js";

/**
 * Names submitted on a backend edit. Secret values are never copied.
 * A name is listed because it was in the request, not because the sealed
 * value differed. Shape is an array of `{ field }` / `{ name }` objects so
 * the audit sanitizer keeps every name (a flat string list is treated as
 * name/value pairs).
 */

const SCALAR_FIELDS = [
  "title",
  "transport",
  "url",
  "image",
  "enabled",
  "command",
  "placement",
  "sandbox",
  "toolAllowlist",
] as const;

const DROPPED = new Set(["__proto__", "constructor", "prototype"]);

function named(names: string[]): Array<{ name: string }> {
  return names.map((name) => ({ name }));
}

function fields(names: string[]): Array<{ field: string }> {
  return names.map((field) => ({ field }));
}

function auditName(raw: string): string {
  const name = raw.trim();
  if (!name || DROPPED.has(name)) return "";
  if (name.length > 256 || name.includes("=") || /[\u0000-\u001f\u007f]/.test(name)) {
    return "";
  }
  return name;
}

function submittedNames(
  map: Record<string, unknown>,
  extraUnset: string[],
): { set: string[]; unset: string[] } {
  const unset = new Set<string>(extraUnset);
  const set: string[] = [];
  for (const [raw, value] of Object.entries(map)) {
    const name = auditName(raw);
    if (!name) continue;
    if (value === null) {
      unset.add(name);
      continue;
    }
    if (typeof value === "string" && value.trim() !== "") set.push(name);
  }
  const setOnly = [...new Set(set.filter((name) => !unset.has(name)))].sort();
  return { set: setOnly, unset: [...unset].sort() };
}

function unsetNames(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const names: string[] = [];
  for (const item of raw) {
    if (typeof item !== "string") continue;
    const name = auditName(item);
    if (name) names.push(name);
  }
  return names;
}

export function backendUpdateAuditDetail(
  input: UpdateBackendInput,
): Record<string, unknown> {
  const changed: string[] = [];
  for (const field of SCALAR_FIELDS) {
    if (input[field] !== undefined) changed.push(field);
  }
  if (typeof input.apiKey === "string" && input.apiKey.trim()) {
    changed.push("apiKey");
  }

  const detail: Record<string, unknown> = {};

  if (input.headers === null) {
    changed.push("headers");
    detail.headersCleared = true;
  } else if (input.headers && typeof input.headers === "object") {
    const replace = input.headerMode === "replace";
    const { set, unset } = submittedNames(
      input.headers as Record<string, unknown>,
      [],
    );
    if (replace) {
      changed.push("headers");
      detail.headerMode = "replace";
      if (set.length) detail.headerSet = named(set);
      else detail.headersCleared = true;
    } else if (set.length || unset.length) {
      changed.push("headers");
      detail.headerMode = "merge";
      if (set.length) detail.headerSet = named(set);
      if (unset.length) detail.headerUnset = named(unset);
    }
  }

  if (input.env === null) {
    changed.push("env");
    detail.envCleared = true;
  } else if (input.env !== undefined || input.unsetEnv !== undefined) {
    const replace = input.envMode === "replace";
    const map =
      input.env && typeof input.env === "object"
        ? (input.env as Record<string, unknown>)
        : {};
    const { set, unset } = submittedNames(map, replace ? [] : unsetNames(input.unsetEnv));
    if (replace) {
      changed.push("env");
      detail.envMode = "replace";
      if (set.length) detail.envSet = named(set);
      else detail.envCleared = true;
    } else if (set.length || unset.length) {
      changed.push("env");
      detail.envMode = "merge";
      if (set.length) detail.envSet = named(set);
      if (unset.length) detail.envUnset = named(unset);
    }
  }

  detail.changed = fields(changed);
  return detail;
}
