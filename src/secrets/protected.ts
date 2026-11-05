/**
 * Protected targets (Secrets §6.4).
 * Deployment ids are host config only. No API reads or writes them.
 * Secret APIs fail closed when the config is unparseable or an argument names one of the ids.
 * Deep-walk of encoded strings on other tools is later work; this walk covers secret API arguments.
 */

const TOKEN = /^[A-Za-z0-9_.:-]{1,128}$/;

export interface ProtectedTargets {
  ids: ReadonlySet<string>;
  invalid: boolean;
}

export function parseProtectedTargets(raw: string | null | undefined): ProtectedTargets {
  if (raw == null || raw.trim() === "") return { ids: new Set(), invalid: false };
  const parts = raw.split(",").map((part) => part.trim()).filter((part) => part.length > 0);
  if (parts.length === 0 || parts.some((part) => !TOKEN.test(part))) {
    return { ids: new Set(), invalid: true };
  }
  return { ids: new Set(parts), invalid: false };
}

export class ProtectedTargetError extends Error {
  constructor() {
    super("protected target");
    this.name = "ProtectedTargetError";
  }
}

export function assertSecretTargetAllowed(targets: ProtectedTargets, value: unknown): void {
  if (targets.invalid) throw new ProtectedTargetError();
  walk(value, targets.ids, 0);
}

function walk(value: unknown, ids: ReadonlySet<string>, depth: number): void {
  if (depth > 12) throw new ProtectedTargetError();
  if (value == null) return;
  const kind = typeof value;
  if (kind === "string") {
    const text = value as string;
    if (ids.has(text)) throw new ProtectedTargetError();
    for (const part of text.split(/[^A-Za-z0-9_.:-]+/)) {
      if (part.length > 0 && ids.has(part)) throw new ProtectedTargetError();
    }
    return;
  }
  if (kind === "number" || kind === "boolean") return;
  if (kind !== "object") throw new ProtectedTargetError();
  if (Array.isArray(value)) {
    for (const item of value) walk(item, ids, depth + 1);
    return;
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new ProtectedTargetError();
  for (const item of Object.values(value as Record<string, unknown>)) walk(item, ids, depth + 1);
}
