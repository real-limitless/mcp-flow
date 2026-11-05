/**
 * Shared redact-before-persist (Secrets §7.7 / A1).
 * Secret-named fields, a line-anchored env parser, token patterns (via redactSecrets),
 * and structuredContent are all walked. secret:// refs stay in the stored form.
 * A failure withholds the body (fail closed): the original value is not returned.
 */

import { isSecretName, redactSecrets } from "./sanitize.js";
import { findSecretRefs, isPureSecretRef, type SecretRef } from "./secret-ref.js";

export const PAYLOAD_MAX_BYTES = 64 * 1024;

const MAX_DEPTH = 12;
const MAX_NODES = 50_000;
const MAX_STRING = 16_384;

export interface PersistRedaction {
  value: unknown;
  truncated: boolean;
  scrubCount: number;
  flags: string[];
  plaintextSuspected: boolean;
  secretRefs: SecretRef[];
  withheld: boolean;
}

const ENV_LINE_RE = /^(\s*)([A-Za-z_][A-Za-z0-9_.-]{0,256})(\s*[=:]\s*)(.*)$/;

function flagAdd(flags: Set<string>, name: string): void {
  flags.add(name);
}

function redactEnvLine(line: string, flags: Set<string>, scrub: { n: number }): string {
  const m = ENV_LINE_RE.exec(line);
  if (!m) return redactFreeString(line, flags, scrub);
  const name = m[2]!;
  const rawValue = m[4] ?? "";
  const unquoted = rawValue.replace(/^["']|["']$/g, "").trim();
  if (!isSecretName(name)) return `${m[1]}${name}${m[3]}${redactFreeString(rawValue, flags, scrub)}`;
  if (isPureSecretRef(unquoted)) {
    flagAdd(flags, "ref");
    flagAdd(flags, "env");
    return line;
  }
  flagAdd(flags, "env");
  flagAdd(flags, "secret_name");
  scrub.n += 1;
  return `${m[1]}${name}${m[3]}[redacted]`;
}

function redactFreeString(input: string, flags: Set<string>, scrub: { n: number }): string {
  if (isPureSecretRef(input)) {
    flagAdd(flags, "ref");
    return input.trim();
  }
  const found = findSecretRefs(input);
  if (found.length) flagAdd(flags, "ref");
  let shielded = input;
  const tokens: string[] = [];
  if (found.length) {
    shielded = input.replace(/secret:\/\/[A-Za-z0-9_./#@:-]{1,512}/g, (ref) => {
      const token = `MFREF${tokens.length}END`;
      tokens.push(ref);
      return token;
    });
  }
  const redacted = redactSecrets(shielded);
  if (redacted !== shielded) {
    scrub.n += 1;
    if (/bearer|github_pat_|gh[pousr]_|^eyJ|sk-|AKIA|ASIA/i.test(input)) flagAdd(flags, "token");
    else flagAdd(flags, "token");
  }
  let restored = redacted;
  tokens.forEach((ref, i) => {
    restored = restored.replaceAll(`MFREF${i}END`, ref);
  });
  return restored;
}

function redactString(input: string, flags: Set<string>, scrub: { n: number }): string {
  if (isPureSecretRef(input)) {
    flagAdd(flags, "ref");
    return input.trim();
  }
  if (!input.includes("\n") && !input.includes("\r")) {
    return redactEnvLine(input, flags, scrub);
  }
  return input.split(/(\r\n|\n|\r)/).map((part) => {
    if (part === "\n" || part === "\r" || part === "\r\n") return part;
    return redactEnvLine(part, flags, scrub);
  }).join("");
}

function isSecretKey(key: string): boolean {
  return isSecretName(key) || /secret|password|passwd|api[_-]?key|authorization|credential|bearer/i.test(key);
}

interface WalkState {
  flags: Set<string>;
  scrub: { n: number };
  nodes: { n: number };
}

function walk(value: unknown, depth: number, state: WalkState): unknown {
  if (value == null) return value;
  if (++state.nodes.n > MAX_NODES) {
    flagAdd(state.flags, "fail_closed");
    throw new Error("redact budget exceeded");
  }
  if (typeof value === "string") {
    const keep = value.length > MAX_STRING ? value.slice(0, MAX_STRING) : value;
    if (value.length > MAX_STRING) flagAdd(state.flags, "truncated");
    return redactString(keep, state.flags, state.scrub);
  }
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function" || typeof value === "symbol") return `[${typeof value}]`;
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return { _omitted: "binary", byteLength: (value as ArrayBufferView | ArrayBuffer).byteLength };
  }
  if (depth >= MAX_DEPTH) return "[max_depth]";
  if (Array.isArray(value)) {
    const limit = Math.min(value.length, 200);
    const out: unknown[] = [];
    for (let i = 0; i < limit; i++) out.push(walk(value[i], depth + 1, state));
    if (value.length > limit) out.push(`…[${value.length - limit} more items]`);
    return out;
  }
  if (typeof value === "object") {
    const src = value as Record<string, unknown>;
    if (Object.prototype.hasOwnProperty.call(src, "structuredContent")) flagAdd(state.flags, "structuredContent");
    const keys = Object.keys(src);
    const limit = Math.min(keys.length, 100);
    const out: Record<string, unknown> = {};
    for (let i = 0; i < limit; i++) {
      const key = keys[i]!;
      const child = src[key];
      if (key === "$secret" && typeof child === "string" && isPureSecretRef(child)) {
        flagAdd(state.flags, "ref");
        out[key] = child.trim();
        continue;
      }
      if (isSecretKey(key)) {
        if (typeof child === "string" && isPureSecretRef(child)) {
          flagAdd(state.flags, "ref");
          out[key] = child.trim();
          continue;
        }
        flagAdd(state.flags, "secret_name");
        state.scrub.n += 1;
        out[key] = "[redacted]";
        continue;
      }
      out[key] = walk(child, depth + 1, state);
    }
    if (keys.length > limit) out._omittedKeys = keys.length - limit;
    return out;
  }
  return String(value);
}

function withheld(refs: SecretRef[]): PersistRedaction {
  return {
    value: { withheld: "scrub_failed" },
    truncated: false,
    scrubCount: 0,
    flags: ["fail_closed"],
    plaintextSuspected: true,
    secretRefs: refs,
    withheld: true,
  };
}

/** Redact a value before it is written. The returned value is safe to persist. */
export function redactBeforePersist(value: unknown): PersistRedaction {
  const flags = new Set<string>();
  let refs: SecretRef[] = [];
  try {
    refs = findSecretRefs(value);
  } catch {
    return withheld([]);
  }
  if (refs.length) flagAdd(flags, "ref");
  const state: WalkState = { flags, scrub: { n: 0 }, nodes: { n: 0 } };
  let walked: unknown;
  try {
    walked = walk(value, 0, state);
  } catch {
    return withheld(refs);
  }
  let truncated = flags.has("truncated");
  let stored = walked;
  try {
    const json = JSON.stringify(walked);
    if (json != null && Buffer.byteLength(json, "utf8") > PAYLOAD_MAX_BYTES) {
      truncated = true;
      flagAdd(flags, "truncated");
      const preview = redactString(json.slice(0, 2000), flags, state.scrub);
      stored = { truncated: true, byteLength: Buffer.byteLength(json, "utf8"), preview };
    }
  } catch {
    return withheld(refs);
  }
  const plaintextSuspected = state.scrub.n > 0 || flags.has("fail_closed");
  if (plaintextSuspected) flagAdd(flags, "plaintext_suspected");
  return {
    value: stored,
    truncated,
    scrubCount: state.scrub.n,
    flags: [...flags].sort(),
    plaintextSuspected,
    secretRefs: refs,
    withheld: false,
  };
}
