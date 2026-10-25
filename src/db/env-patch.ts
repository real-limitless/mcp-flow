/**
 * Per-key env updates.
 *
 * `merge` (default) sets keys that have a non-blank string and leaves every
 * other key sealed. A null value, or a name in `unsetEnv`, deletes that key.
 * Empty or all-whitespace values are ignored so a masked field can be left
 * empty. Stored values are not trimmed.
 * `replace` swaps the whole map for the non-blank entries in `env`.
 * `env: null` clears every key.
 *
 * `set` / `unset` compare the stored map. Audit logs must not use them:
 * they would show whether a submitted value matched the sealed one.
 */

import {
  BackendInputError,
  checkedSecretName,
  isPlainRecord,
  readUnsetEnv,
} from "./secret-input.js";

export type EnvMode = "merge" | "replace";

export interface EnvPatchInput {
  env?: unknown;
  envMode?: unknown;
  unsetEnv?: unknown;
}

export interface EnvPatchApplied {
  /** `undefined` when this patch does not touch env. `null` clears the seal. */
  next: Record<string, string> | null | undefined;
  /** Names whose stored values differ. Not an audit source. */
  set: string[];
  /** Names removed from the stored map. Not an audit source. */
  unset: string[];
  cleared: boolean;
  mode: EnvMode | null;
}

export function parseEnvMode(mode: unknown): EnvMode | "invalid" {
  if (mode === undefined || mode === null || mode === "") return "merge";
  if (mode === "merge" || mode === "replace") return mode;
  return "invalid";
}

function diffEnv(
  current: Record<string, string>,
  next: Record<string, string> | null,
): { set: string[]; unset: string[] } {
  if (next === null) {
    return { set: [], unset: Object.keys(current).sort() };
  }
  const set: string[] = [];
  const unset: string[] = [];
  for (const [name, value] of Object.entries(next)) {
    if (current[name] !== value) set.push(name);
  }
  for (const name of Object.keys(current)) {
    if (!Object.prototype.hasOwnProperty.call(next, name)) unset.push(name);
  }
  set.sort();
  unset.sort();
  return { set, unset };
}

export function applyEnvPatch(
  current: Record<string, string>,
  input: EnvPatchInput,
): EnvPatchApplied {
  const mode = parseEnvMode(input.envMode);
  if (mode === "invalid") {
    throw new BackendInputError("envMode must be merge or replace");
  }
  const unsetNames = readUnsetEnv(input.unsetEnv);
  const touches = input.env !== undefined || unsetNames.length > 0;
  if (!touches) {
    return { next: undefined, set: [], unset: [], cleared: false, mode: null };
  }

  if (input.env === null) {
    const { unset } = diffEnv(current, null);
    return {
      next: null,
      set: [],
      unset,
      cleared: true,
      mode: null,
    };
  }

  if (input.env !== undefined && !isPlainRecord(input.env)) {
    throw new BackendInputError("env must be an object");
  }

  const resolved: EnvMode = mode === "replace" ? "replace" : "merge";
  const incoming = (input.env ?? {}) as Record<string, unknown>;

  let next: Record<string, string>;
  if (resolved === "replace") {
    next = {};
    for (const [rawName, rawValue] of Object.entries(incoming)) {
      const name = checkedSecretName(rawName, "env");
      if (!name || rawValue === null) continue;
      if (typeof rawValue !== "string") {
        throw new BackendInputError("env values must be strings or null");
      }
      if (rawValue.trim() === "") continue;
      next[name] = rawValue;
    }
  } else {
    next = { ...current };
    for (const [rawName, rawValue] of Object.entries(incoming)) {
      const name = checkedSecretName(rawName, "env");
      if (!name) continue;
      if (rawValue === null) {
        delete next[name];
        continue;
      }
      if (typeof rawValue !== "string") {
        throw new BackendInputError("env values must be strings or null");
      }
      if (rawValue.trim() === "") continue;
      next[name] = rawValue;
    }
    for (const name of unsetNames) delete next[name];
  }

  const stored = Object.keys(next).length ? next : null;
  const { set, unset } = diffEnv(current, stored);
  return {
    next: stored,
    set,
    unset,
    cleared: stored === null && Object.keys(current).length > 0,
    mode: resolved,
  };
}
