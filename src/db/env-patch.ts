/**
 * Per-key env updates.
 *
 * `merge` (default) sets keys that have a non-empty string and leaves every
 * other key sealed. A null value, or a name in `unsetEnv`, deletes that key.
 * A blank string is ignored so a masked field can be left empty.
 * `replace` swaps the whole map for the non-empty entries in `env`.
 * `env: null` clears every key.
 */

export type EnvMode = "merge" | "replace";

export interface EnvPatchInput {
  env?: Record<string, string | null> | null;
  envMode?: string;
  unsetEnv?: string[];
}

export interface EnvPatchApplied {
  /** `undefined` when this patch does not touch env. `null` clears the seal. */
  next: Record<string, string> | null | undefined;
  /** Names whose values changed. Values are never included. */
  set: string[];
  /** Names removed. */
  unset: string[];
  cleared: boolean;
  mode: EnvMode | null;
}

export function parseEnvMode(mode: unknown): EnvMode | "invalid" {
  if (mode === undefined || mode === null || mode === "") return "merge";
  if (mode === "merge" || mode === "replace") return mode;
  return "invalid";
}

function trimmedName(raw: unknown): string {
  return typeof raw === "string" ? raw.trim() : "";
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
  const unsetNames = (input.unsetEnv ?? [])
    .map(trimmedName)
    .filter(Boolean);
  const touches =
    input.env !== undefined || unsetNames.length > 0;
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

  const mode = parseEnvMode(input.envMode);
  const resolved: EnvMode = mode === "replace" ? "replace" : "merge";
  const incoming = input.env ?? {};

  let next: Record<string, string>;
  if (resolved === "replace") {
    next = {};
    for (const [rawName, rawValue] of Object.entries(incoming)) {
      const name = rawName.trim();
      if (!name || rawValue === null || typeof rawValue !== "string") continue;
      const value = rawValue.trim();
      if (!value) continue;
      next[name] = value;
    }
  } else {
    next = { ...current };
    for (const [rawName, rawValue] of Object.entries(incoming)) {
      const name = rawName.trim();
      if (!name) continue;
      if (rawValue === null) {
        delete next[name];
        continue;
      }
      if (typeof rawValue !== "string") continue;
      const value = rawValue.trim();
      if (!value) continue;
      next[name] = value;
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
