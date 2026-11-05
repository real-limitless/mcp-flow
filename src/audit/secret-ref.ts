/**
 * secret:// refs (Secrets §0.12 / §6.4).
 * The policy enforcer may carry a ref. Every legacy authorization and approval path refuses one.
 * A scan that throws fails closed (treated as a ref) so a malformed value is not dispatched.
 */

export class LegacySecretRefError extends Error {
  constructor() {
    super("secret:// refs are refused on legacy authorization paths");
    this.name = "LegacySecretRefError";
  }
}

const REF_RE = /secret:\/\//;

export interface SecretRef {
  ref: string;
  version: string | null;
}

const PURE_REF_RE = /^secret:\/\/[A-Za-z0-9_./#@:-]{1,512}$/;
const REF_FIND_RE = /secret:\/\/[A-Za-z0-9_./#@:-]{1,512}/g;

export function isPureSecretRef(value: string): boolean {
  return PURE_REF_RE.test(value.trim());
}

/** `@version` before a fragment, or null when the ref is bare. */
export function secretRefVersion(ref: string): string | null {
  const m = /@([^#/\s]+)/.exec(ref);
  return m ? m[1]! : null;
}

export function findSecretRefs(value: unknown): SecretRef[] {
  const out: SecretRef[] = [];
  const seen = new Set<string>();
  const push = (ref: string) => {
    if (seen.has(ref)) return;
    seen.add(ref);
    out.push({ ref, version: secretRefVersion(ref) });
  };
  const walk = (v: unknown, depth: number): void => {
    if (v == null || depth > 12) return;
    if (typeof v === "string") {
      if (isPureSecretRef(v)) {
        push(v.trim());
        return;
      }
      const embedded = v.match(REF_FIND_RE);
      if (embedded) for (const ref of embedded) push(ref);
      return;
    }
    if (typeof v !== "object") return;
    if (Array.isArray(v)) {
      for (const item of v) walk(item, depth + 1);
      return;
    }
    for (const item of Object.values(v as Record<string, unknown>)) walk(item, depth + 1);
  };
  walk(value, 0);
  return out;
}

/** True when the value carries a secret:// ref. Throws are fail-closed (true). */
export function containsSecretRef(value: unknown): boolean {
  try {
    if (value == null) return false;
    if (typeof value === "string") return REF_RE.test(value);
    return findSecretRefs(value).length > 0 || REF_RE.test(JSON.stringify(value));
  } catch {
    return true;
  }
}
