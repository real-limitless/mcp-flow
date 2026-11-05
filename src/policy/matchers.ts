/**
 * Rule matchers (T2.1 §2). Args are matched on parsed JSON, never a re-serialized string.
 * Regex: JS RegExp behind RE2-style guards (no backreferences/lookaround, length caps),
 * because no RE2 binding is available in this build. See blockers.
 */
import vm from "node:vm";
import { canonicalJson } from "./crypto.js";

export interface ArgMatcher {
  path: string;
  op: "equals" | "regex" | "prefix" | "in" | "exists";
  value?: unknown;
}

export const MAX_REGEX_LEN = 256;
export const MAX_SUBJECT_LEN = 16_384;

/**
 * Validate matchers supplied by a human (approve-similar) or a rule author. Throws on bad input.
 * Note (Security T2.5 L-3): matchers compare raw values; deny rules on paths/URLs do not normalize
 * `//`, `./`, `..` or case, and a missing path never matches. Prefer allowlists for such args.
 */
export function validateArgMatchers(v: unknown): ArgMatcher[] {
  if (!Array.isArray(v) || v.length > 16) throw new Error("match_args must be an array of ≤16 matchers");
  return v.map((m) => {
    if (!m || typeof m !== "object") throw new Error("matcher must be an object");
    const { path, op, value } = m as Record<string, unknown>;
    if (typeof path !== "string" || !path.startsWith("$") || path.length > 256) throw new Error("matcher path must be a $-path");
    if (!["equals", "regex", "prefix", "in", "exists"].includes(String(op))) throw new Error("unknown matcher op");
    if (op === "regex") safeRegex(String(value));
    if (op === "prefix" && (typeof value !== "string" || !value.length)) throw new Error("prefix needs a non-empty string");
    if (op === "in" && !Array.isArray(value)) throw new Error("in needs an array");
    return { path, op, value } as ArgMatcher;
  });
}

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
/** A quantified group that itself contains a quantifier or alternation: (a+)+, (.*,)*, (a|ab)* … */
const NESTED_QUANT_RE = /\((?:[^()\\]|\\.)*(?:[+*}|])(?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d+,?\d*\})/;
export const REGEX_TIMEOUT_MS = 50;

/**
 * Until RE2 (plan follow-up): reject backrefs/lookaround and nested quantifiers at compile time,
 * and run every match in a vm context with a hard timeout (Security T2.5 M-6).
 */
export function safeRegex(src: string): RegExp {
  if (typeof src !== "string" || src.length > MAX_REGEX_LEN) throw new Error("regex too long");
  if (UNSAFE_RE.test(src)) throw new Error("regex uses backreferences or lookaround");
  if (NESTED_QUANT_RE.test(src)) throw new Error("regex uses nested quantifiers (ReDoS risk)");
  return new RegExp(src);
}

const regexCtx = vm.createContext({});
/** Test with a hard timeout; a timeout throws (callers fail closed). */
export function regexTest(re: RegExp, subject: string, timeoutMs = REGEX_TIMEOUT_MS): boolean {
  const script = new vm.Script("__re.test(__s)");
  (regexCtx as Record<string, unknown>).__re = re;
  (regexCtx as Record<string, unknown>).__s = subject;
  try {
    return Boolean(script.runInContext(regexCtx, { timeout: timeoutMs }));
  } finally {
    (regexCtx as Record<string, unknown>).__re = undefined;
    (regexCtx as Record<string, unknown>).__s = undefined;
  }
}

/** Key-order independent equality (Security T2.5 L-2). */
function deepEqual(a: unknown, b: unknown): boolean {
  return canonicalJson(a) === canonicalJson(b);
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
      // never silently truncate: an over-long subject is an error, and every caller fails closed
      // (Security T2.5 M-1: padding past the cap must not slip under a deny rule)
      if (r.value.length > MAX_SUBJECT_LEN) throw new Error("regex subject exceeds cap; failing closed");
      return regexTest(safeRegex(String(m.value)), r.value);
    }
    default:
      throw new Error(`unknown matcher op: ${(m as { op: string }).op}`);
  }
}

export function allArgsMatch(matchers: ArgMatcher[], args: unknown): boolean {
  return matchers.every((m) => argMatch(m, args));
}
