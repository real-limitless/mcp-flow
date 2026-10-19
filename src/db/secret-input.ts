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
    CONTROL_RE.test(name)
  ) {
    throw new BackendInputError(
      kind === "env" ? "env name is invalid" : "header name is invalid",
    );
  }
  return name;
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

export function validateCreateSecrets(input: {
  env?: unknown;
  headers?: unknown;
  apiKey?: unknown;
}): void {
  assertApiKey(input.apiKey);
  assertSecretMap(input.env, "env", { allowNull: true, allowNullValues: false });
  assertSecretMap(input.headers, "header", {
    allowNull: true,
    allowNullValues: false,
  });
}

export function validateUpdateSecrets(input: {
  env?: unknown;
  headers?: unknown;
  apiKey?: unknown;
  unsetEnv?: unknown;
  envMode?: unknown;
  headerMode?: unknown;
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
