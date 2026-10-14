/**
 * Rule matchers (T2.1 §2). Args are matched on parsed JSON, never a re-serialized string.
 * Regex: JS RegExp behind RE2-style guards (no backreferences/lookaround, length caps),
 * because no RE2 binding is available in this build. See blockers.
 */
export interface ArgMatcher {
  path: string;
  op: "equals" | "regex" | "prefix" | "in" | "exists";
  value?: unknown;
}

export const MAX_REGEX_LEN = 256;
export const MAX_SUBJECT_LEN = 16_384;

/** Glob with `*` only; exact otherwise. Case-sensitive. */
export function globMatch(pattern: string, value: string): boolean {
  if (pattern === "*") return true;
  if (!pattern.includes("*")) return pattern === value;
  const re = new RegExp(
    "^" + pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + "$",
  );
  return re.test(value);
}

export function anyGlob(patterns: string[], value: string | null | undefined): boolean {
  if (!patterns.length) return false;
  if (patterns.includes("*")) return true;
  if (value == null) return false;
  return patterns.some((p) => globMatch(p, value));
}

/** `$`, `$.a.b`, `$.a[0].b`, `$["key with.dot"]`. Returns {found:false} if missing. */
export function readPath(root: unknown, path: string): { found: boolean; value?: unknown } {
  if (path === "$") return { found: true, value: root };
  if (!path.startsWith("$")) return { found: false };
  const tokens: Array<string | number> = [];
  const re = /\.([A-Za-z0-9_\-]+)|\[(\d+)\]|\["((?:[^"\\]|\\.)*)"\]/gy;
  re.lastIndex = 1;
  while (re.lastIndex < path.length) {
    const m = re.exec(path);
    if (!m) return { found: false };
    tokens.push(m[1] ?? (m[2] !== undefined ? Number(m[2]) : JSON.parse(`"${m[3]}"`)));
  }
  let cur: unknown = root;
  for (const t of tokens) {
    if (typeof t === "number") {
      if (!Array.isArray(cur) || t >= cur.length) return { found: false };
      cur = cur[t];
    } else {
      if (!cur || typeof cur !== "object" || Array.isArray(cur) || !Object.prototype.hasOwnProperty.call(cur, t)) {
        return { found: false };
      }
      cur = (cur as Record<string, unknown>)[t];
    }
  }
  return { found: true, value: cur };
}

const UNSAFE_RE = /\\[1-9]|\\k<|\(\?[=!]|\(\?<[=!]/;

export function safeRegex(src: string): RegExp {
  if (typeof src !== "string" || src.length > MAX_REGEX_LEN) throw new Error("regex too long");
  if (UNSAFE_RE.test(src)) throw new Error("regex uses backreferences or lookaround");
  return new RegExp(src);
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

export function argMatch(m: ArgMatcher, args: unknown): boolean {
  const r = readPath(args, m.path);
  if (!r.found) return false; // missing path = no match (T2.1 §2)
  switch (m.op) {
    case "exists":
      return true;
    case "equals":
      return deepEqual(r.value, m.value);
    case "prefix":
      return typeof r.value === "string" && typeof m.value === "string" && r.value.startsWith(m.value);
    case "in":
      return Array.isArray(m.value) && m.value.some((v) => deepEqual(v, r.value));
    case "regex": {
      if (typeof r.value !== "string") return false;
      return safeRegex(String(m.value)).test(r.value.slice(0, MAX_SUBJECT_LEN));
    }
    default:
      throw new Error(`unknown matcher op: ${(m as { op: string }).op}`);
  }
}

export function allArgsMatch(matchers: ArgMatcher[], args: unknown): boolean {
  return matchers.every((m) => argMatch(m, args));
}
