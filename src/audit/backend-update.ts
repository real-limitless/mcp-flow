import { applyEnvPatch } from "../db/env-patch.js";
import type { UpdateBackendInput } from "../types.js";

/**
 * Names that changed on a backend edit. Secret values are never copied.
 * Shape is an array of `{ field }` / `{ name }` objects so the audit sanitizer
 * keeps every name (a flat string list is treated as name/value pairs).
 */
export interface BackendUpdateSnapshot {
  title: string;
  transport: string;
  url: string | null;
  image: string | null;
  enabled: boolean;
  commandJson: string | null;
  placementJson: string;
  sandboxJson: string | null;
  toolAllowlistJson: string | null;
  env: Record<string, string>;
  headerNames: string[];
}

function named(names: string[]): Array<{ name: string }> {
  return names.map((name) => ({ name }));
}

function fields(names: string[]): Array<{ field: string }> {
  return names.map((field) => ({ field }));
}

function jsonOrNull(value: unknown): string | null {
  if (value === undefined) return null;
  if (value === null) return null;
  return JSON.stringify(value);
}

export function backendUpdateAuditDetail(
  existing: BackendUpdateSnapshot,
  input: UpdateBackendInput,
): Record<string, unknown> {
  const changed: string[] = [];

  if (input.title !== undefined && input.title !== existing.title) {
    changed.push("title");
  }
  if (input.transport !== undefined && input.transport !== existing.transport) {
    changed.push("transport");
  }
  if (input.url !== undefined && input.url !== existing.url) {
    changed.push("url");
  }
  if (input.image !== undefined && input.image !== existing.image) {
    changed.push("image");
  }
  if (input.enabled !== undefined && input.enabled !== existing.enabled) {
    changed.push("enabled");
  }
  if (
    input.command !== undefined &&
    jsonOrNull(input.command) !== existing.commandJson
  ) {
    changed.push("command");
  }
  if (
    input.placement !== undefined &&
    JSON.stringify(input.placement) !== existing.placementJson
  ) {
    changed.push("placement");
  }
  if (
    input.sandbox !== undefined &&
    jsonOrNull(input.sandbox) !== existing.sandboxJson
  ) {
    changed.push("sandbox");
  }
  if (
    input.toolAllowlist !== undefined &&
    jsonOrNull(input.toolAllowlist) !== existing.toolAllowlistJson
  ) {
    changed.push("toolAllowlist");
  }
  if (typeof input.apiKey === "string" && input.apiKey.trim()) {
    changed.push("apiKey");
  }

  const detail: Record<string, unknown> = {};

  if (input.headers === null) {
    changed.push("headers");
    detail.headersCleared = true;
    if (existing.headerNames.length) {
      detail.headerUnset = named([...existing.headerNames].sort());
    }
  } else if (input.headers) {
    const set: string[] = [];
    for (const [raw, value] of Object.entries(input.headers)) {
      const name = raw.trim();
      if (name && typeof value === "string" && value.trim()) set.push(name);
    }
    set.sort();
    const keep = new Set(set.map((n) => n.toLowerCase()));
    const unset = existing.headerNames.filter(
      (n) => !keep.has(n.toLowerCase()),
    );
    if (set.length || unset.length) changed.push("headers");
    if (set.length) detail.headerSet = named(set);
    if (unset.length) detail.headerUnset = named(unset.sort());
  }

  const envPatch = applyEnvPatch(existing.env, input);
  if (envPatch.next !== undefined) {
    if (envPatch.set.length || envPatch.unset.length || envPatch.cleared) {
      changed.push("env");
    }
    if (envPatch.mode) detail.envMode = envPatch.mode;
    if (envPatch.cleared) detail.envCleared = true;
    if (envPatch.set.length) detail.envSet = named(envPatch.set);
    if (envPatch.unset.length) detail.envUnset = named(envPatch.unset);
  }

  detail.changed = fields(changed);
  return detail;
}
