import type { Placement, PlacementMode } from "../types.js";

/**
 * Validate env and header writes before they touch the database.
 * Blank (empty or all whitespace) is a keep, not a value to trim and store.
 * `__proto__`, `constructor`, and `prototype` are dropped and never stored.
 */

export class BackendInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackendInputError";
  }
}

export const MAX_SECRET_NAME_LEN = 256;

const CONTROL_RE = /[\u0000-\u001f\u007f]/;
const DROPPED_NAMES = new Set(["__proto__", "constructor", "prototype"]);
/** RFC 9110 token. Header names that are not tokens are rejected. */
const HTTP_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export const PLACEMENT_KEYS = ["mode", "deviceId", "deviceTags", "affinity"] as const;
export const SANDBOX_KEYS = ["memory", "cpus", "networkMode"] as const;
export const PLACEMENT_MODES = [
  "remote",
  "central-sandbox",
  "edge-sandbox",
  "edge-bare",
] as const;
export const AFFINITIES = ["harness-local", "pinned", "any-online"] as const;

export function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/** Trimmed name, or "" when the name is empty or a dropped prototype key. */
export function checkedSecretName(raw: string, kind: "env" | "header"): string {
  const name = raw.trim();
  if (!name || DROPPED_NAMES.has(name)) return "";
  if (
    name.length > MAX_SECRET_NAME_LEN ||
    name.includes("=") ||
    CONTROL_RE.test(name) ||
    (kind === "header" && !HTTP_TOKEN.test(name))
  ) {
    throw new BackendInputError(
      kind === "env" ? "env name is invalid" : "header name is invalid",
    );
  }
  return name;
}

/** Keep only the known placement or sandbox fields. Extra keys are dropped. */
export function pickKnownKeys(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> | undefined {
  if (!isPlainRecord(value)) return undefined;
  const out: Record<string, unknown> = {};
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(value, key)) out[key] = value[key];
  }
  return out;
}

/**
 * Placement written on create or update. A missing or null mode keeps the
 * fallback mode. Null optional fields stay null.
 */
export function placementForWrite(
  value: unknown,
  fallback: { mode: PlacementMode },
): Placement {
  const picked = pickKnownKeys(value, PLACEMENT_KEYS) ?? {};
  const mode = (
    typeof picked.mode === "string" ? picked.mode : fallback.mode
  ) as PlacementMode;
  return { ...(picked as Partial<Placement>), mode };
}

function assertMode(mode: unknown, label: "envMode" | "headerMode"): void {
  if (mode === undefined || mode === null || mode === "") return;
  if (mode !== "merge" && mode !== "replace") {
    throw new BackendInputError(`${label} must be merge or replace`);
  }
}

function assertApiKey(apiKey: unknown): void {
  if (apiKey === undefined || apiKey === null) return;
  if (typeof apiKey !== "string") {
    throw new BackendInputError("apiKey must be a string");
  }
}

function assertSecretMap(
  value: unknown,
  kind: "env" | "header",
  opts: { allowNull: boolean; allowNullValues: boolean },
): void {
  if (value === undefined) return;
  if (value === null) {
    if (!opts.allowNull) {
      throw new BackendInputError(`${kind} must be an object`);
    }
    return;
  }
  if (!isPlainRecord(value)) {
    throw new BackendInputError(`${kind} must be an object`);
  }
  const valueError = opts.allowNullValues
    ? `${kind} values must be strings or null`
    : `${kind} values must be strings`;
  for (const [rawName, rawValue] of Object.entries(value)) {
    checkedSecretName(rawName, kind);
    if (rawValue === null) {
      if (!opts.allowNullValues) throw new BackendInputError(valueError);
      continue;
    }
    if (typeof rawValue !== "string") throw new BackendInputError(valueError);
  }
}

export function readUnsetEnv(raw: unknown): string[] {
  if (raw === undefined || raw === null) return [];
  if (!Array.isArray(raw)) {
    throw new BackendInputError("unsetEnv must be an array of strings");
  }
  const names: string[] = [];
  for (const item of raw) {
    if (typeof item !== "string") {
      throw new BackendInputError("unsetEnv must be an array of strings");
    }
    const name = checkedSecretName(item, "env");
    if (name) names.push(name);
  }
  return names;
}

/**
 * Identifiers and sandbox limits: non-empty, at most 256 UTF-16 units,
 * no whitespace, no C0/C1/DEL controls (including U+0085 NEL), and no
 * format or bidi characters.
 */
export const MAX_CONFIG_STRING_LEN = 256;

const CONFIG_CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/u;
const CONFIG_FORMAT_RE = /\p{Cf}/u;

export function isBoundedConfigString(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_CONFIG_STRING_LEN &&
    !/\s/.test(value) &&
    !CONFIG_CONTROL_RE.test(value) &&
    !CONFIG_FORMAT_RE.test(value)
  );
}

function assertConfigString(value: unknown, label: string): void {
  if (value === undefined || value === null) return;
  if (typeof value !== "string") {
    throw new BackendInputError(`${label} must be a string`);
  }
  if (!isBoundedConfigString(value)) {
    throw new BackendInputError(`${label} is invalid`);
  }
}

/**
 * Known placement fields must match their types.
 * Omitted mode, null placement, and null optional fields are left as they were.
 * A non-null value of the wrong type or format is a 400.
 * Unknown keys are ignored here; callers drop them and never store them.
 */
export function assertPlacementValue(value: unknown): void {
  if (value === undefined || value === null) return;
  if (!isPlainRecord(value)) {
    throw new BackendInputError("placement must be an object");
  }
  if (value.mode !== undefined && value.mode !== null) {
    if (
      typeof value.mode !== "string" ||
      !(PLACEMENT_MODES as readonly string[]).includes(value.mode)
    ) {
      throw new BackendInputError("placement.mode is invalid");
    }
  }
  assertConfigString(value.deviceId, "placement.deviceId");
  if (value.deviceTags !== undefined && value.deviceTags !== null) {
    if (
      !Array.isArray(value.deviceTags) ||
      value.deviceTags.some((item) => typeof item !== "string")
    ) {
      throw new BackendInputError("placement.deviceTags must be an array of strings");
    }
    if (value.deviceTags.some((item) => !isBoundedConfigString(item))) {
      throw new BackendInputError("placement.deviceTags is invalid");
    }
  }
  if (value.affinity !== undefined && value.affinity !== null) {
    if (
      typeof value.affinity !== "string" ||
      !(AFFINITIES as readonly string[]).includes(value.affinity)
    ) {
      throw new BackendInputError("placement.affinity is invalid");
    }
  }
}

/** memory, cpus, and networkMode are strings. null clears the sandbox. */
export function assertSandboxValue(value: unknown): void {
  if (value === undefined || value === null) return;
  if (!isPlainRecord(value)) {
    throw new BackendInputError("sandbox must be an object");
  }
  for (const key of SANDBOX_KEYS) {
    if (value[key] !== undefined && value[key] !== null) {
      assertConfigString(value[key], `sandbox.${key}`);
    }
  }
}

export function validateCreateSecrets(input: {
  env?: unknown;
  headers?: unknown;
  apiKey?: unknown;
  placement?: unknown;
  sandbox?: unknown;
}): void {
  assertApiKey(input.apiKey);
  assertSecretMap(input.env, "env", { allowNull: true, allowNullValues: false });
  assertSecretMap(input.headers, "header", {
    allowNull: true,
    allowNullValues: false,
  });
  assertPlacementValue(input.placement);
  assertSandboxValue(input.sandbox);
}

export function validateUpdateSecrets(input: {
  env?: unknown;
  headers?: unknown;
  apiKey?: unknown;
  unsetEnv?: unknown;
  envMode?: unknown;
  headerMode?: unknown;
  placement?: unknown;
  sandbox?: unknown;
}): void {
  assertMode(input.envMode, "envMode");
  assertMode(input.headerMode, "headerMode");
  assertApiKey(input.apiKey);
  readUnsetEnv(input.unsetEnv);
  assertSecretMap(input.env, "env", { allowNull: true, allowNullValues: true });
  assertSecretMap(input.headers, "header", {
    allowNull: true,
    allowNullValues: true,
  });
  assertPlacementValue(input.placement);
  assertSandboxValue(input.sandbox);
}

/**
 * Env values are stored exactly. Whitespace-only values are omitted.
 * Header maps keep using compactSecretRecord, which trims.
 */
export function compactEnvRecord(
  rec: Record<string, string> | null | undefined,
): Record<string, string> | undefined {
  if (!rec) return undefined;
  const out: Record<string, string> = {};
  for (const [rawName, rawValue] of Object.entries(rec)) {
    const name = checkedSecretName(rawName, "env");
    if (!name || typeof rawValue !== "string" || rawValue.trim() === "") continue;
    out[name] = rawValue;
  }
  return Object.keys(out).length ? out : undefined;
}

function deleteHeader(next: Record<string, string>, name: string): void {
  for (const key of Object.keys(next)) {
    if (key.toLowerCase() === name.toLowerCase()) delete next[key];
  }
}

export function applyHeaderPatch(
  current: Record<string, string>,
  input: {
    headers?: Record<string, string | null> | null;
    headerMode?: "merge" | "replace" | string;
  },
): { next: Record<string, string> | null | undefined } {
  if (input.headers === undefined) return { next: undefined };
  if (input.headers === null) return { next: null };

  const mode = input.headerMode === "replace" ? "replace" : "merge";
  const next: Record<string, string> = mode === "replace" ? {} : { ...current };
  for (const [rawName, rawValue] of Object.entries(input.headers)) {
    const name = checkedSecretName(rawName, "header");
    if (!name) continue;
    if (rawValue === null) {
      if (mode === "merge") deleteHeader(next, name);
      continue;
    }
    if (typeof rawValue !== "string" || rawValue.trim() === "") continue;
    deleteHeader(next, name);
    next[name] = rawValue;
  }
  return { next };
}
