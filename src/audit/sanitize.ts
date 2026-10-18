import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

/**
 * Keys whose whole value is redacted. Deliberately narrower than "contains token/session"
 * so benign keys (max_tokens, session_name) stay readable (Security T2.5 M-2).
 */
const SECRET_KEY_RE =
  /secret|password|passwd|passphrase|^pwd$|^pass$|authorization|^auth$|api[_-]?key|apikey|cookie|private[_-]?key|access[_-]?key|refresh[_-]?token|access[_-]?token|id[_-]?token|(^|[_-])token$|^token|bearer|credential|session[_-]?(id|token|key|secret)$|^dsn$|database[_-]?url|connection[_-]?string/i;

/**
 * Unanchored secret patterns: only the matched substring is replaced, so a command keeps its
 * shape but loses the secret. All patterns are linear (no nested quantifiers).
 */
const SECRET_SUBSTRING_RES: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[redacted]"],
  [/\b(Authorization\s*[:=]\s*["']?(?:token|bearer|basic|digest)\s+)[^\s"']+/gi, "$1[redacted]"],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]"],
  // URL userinfo in any scheme, empty user or password included (redis://:pw@h, https://tok@h)
  [/(\b[A-Za-z][A-Za-z0-9+.-]*:\/\/)[^\s/?#@"'<>\\]*@/g, "$1[redacted]@"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, "[redacted]"],
  [/\bgithub_pat_[A-Za-z0-9_]{20,}/g, "[redacted]"],
  [/\bgh[pousr]_[A-Za-z0-9]{20,}/g, "[redacted]"],
  [/\bglpat-[A-Za-z0-9_-]{20,}/g, "[redacted]"],
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, "[redacted]"],
  [/\bsk-[A-Za-z0-9_-]{16,}/g, "[redacted]"],
  [/\bmf_[A-Za-z0-9_-]{16,}/g, "[redacted]"],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}/g, "[redacted]"],
  [/https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g, "[redacted]"],
  [/([?&;](?:access_token|refresh_token|id_token|token|api_key|apikey|key|secret|password|passwd|sig|signature|code)=)[^&#\s"']+/gi, "$1[redacted]"],
  [/(--(?:password|token|secret|api-key)[= ])\S+/gi, "$1[redacted]"],
];

/** camelCase secret keys: apiToken, authToken, githubToken, accessKeyId, clientSecret, … */
const CAMEL_SECRET_KEY_RE = /[a-z0-9](?:Token|Secret|Password|Passwd|ApiKey|AccessKey|PrivateKey|SecretKey|Credentials?)$|^(?:token|auth|pass|pw)[A-Z]/;

/** Shannon entropy in bits per char. */
function entropy(s: string): number {
  const f = new Map<string, number>();
  for (const ch of s) f.set(ch, (f.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Opaque high-entropy tokens under neutral keys ({"value":"<random>"}): a single 32-512 char
 * base64/base64url-ish word with > 4.3 bits/char. Hex digests and UUIDs (≤ 4 bits/char) stay.
 */
function looksLikeOpaqueSecret(s: string): boolean {
  const t = s.trim();
  if (t.length < 32 || t.length > 512 || !/^[A-Za-z0-9+/=_.-]+$/.test(t)) return false;
  if (!/[0-9]/.test(t) || !/[A-Z]/.test(t) || !/[a-z]/.test(t)) return false;
  return entropy(t) > 4.3;
}

/**
 * Secret names, used both for object keys and for NAME=value / NAME: value text (env files,
 * shell, YAML, HTTP headers, JSON text). Suffix rule rather than an allowlist:
 *  - any name ending in _PASS/_PWD/_PASSWD/_PASSWORD/_KEY/_KEYS/_SECRET(S)/_TOKEN/_AUTH/
 *    _CREDENTIAL(S)/_PASSPHRASE (separator _ . or -, case-insensitive): DB_PASS, POSTGRES_PWD,
 *    JWT_KEY, STRIPE_KEY, SMTP_AUTH, GH_CREDENTIALS, MCP_FLOW_MASTER_KEY, x-auth-token;
 *  - the bare names PASS, PASSWD, PASSWORD, PWD, SECRET(S), TOKEN, AUTH, AUTHORIZATION,
 *    CREDENTIAL(S), PASSPHRASE, APIKEY, BEARER, COOKIE, DSN;
 *  - names containing PASSWORD/PASSWD/PASSPHRASE/SECRET/CREDENTIAL/AUTHORIZATION/COOKIE,
 *    PRIVATE_KEY/ACCESS_KEY/API_KEY, a TOKEN segment, DATABASE_URL or CONNECTION_STRING.
 * Known false positives (accepted, audit text only loses the value): *_KEY names that are not
 * secrets (PRIMARY_KEY, SORT_KEY, PUBLIC_KEY, IDEMPOTENCY_KEY), PWD=/cwd in env dumps, prose
 * like "Token: ...". Bare KEY is NOT a secret name (key=value, KEY_COUNT=5 stay readable), and
 * plural *_TOKENS is not either (max_tokens stays readable).
 */
const SECRET_NAME_SUFFIX_RE =
  /[_.-](?:PASS|PWD|PASSWD|PASSWORD|KEYS?|SECRETS?|TOKEN|AUTH|CREDENTIALS?|PASSPHRASE)$/i;
const SECRET_NAME_BARE_RE =
  /^(?:PASS|PASSWD|PASSWORD|PWD|SECRETS?|TOKEN|AUTH|AUTHORIZATION|CREDENTIALS?|PASSPHRASE|APIKEY|BEARER|COOKIE|DSN)$/i;
const SECRET_NAME_CONTAINS_RE =
  /PASSWORD|PASSWD|PASSPHRASE|SECRET|CREDENTIAL|AUTHORIZATION|COOKIE|PRIVATE[_.-]?KEY|ACCESS[_.-]?KEY|API[_.-]?KEY|(?:^|[_.-])TOKEN(?:$|[_.-])|DATABASE[_.-]?URL|CONNECTION[_.-]?STRING/i;

/** True when a key or variable name names a secret (see the rules above). */
export function isSecretName(name: string): boolean {
  if (name.length > 256) return false;
  return (
    SECRET_NAME_SUFFIX_RE.test(name) ||
    SECRET_NAME_BARE_RE.test(name) ||
    SECRET_NAME_CONTAINS_RE.test(name)
  );
}

/**
 * NAME=value / NAME: value candidates. Group 1 is the char before the name (or a JSON-escaped
 * quote or literal \n / \r / \t escape, for env text inside JSON strings), group 2 an optional
 * quote around the name ("NAME": or \"NAME\":), group 3 the name.
 * Linear: the name is bounded and nothing is nested.
 */
const ASSIGN_RE =
  /(^|\\["'nrt]|[^A-Za-z0-9_.\\])((?:\\?["'])?)([A-Za-z_][A-Za-z0-9_.-]{0,127})\2[ \t]*[=:][ \t]*/g;

/** Index of the end of the line starting at i: a real CR/LF or a literal \n / \r escape. */
function lineEnd(s: string, i: number): number {
  for (let j = i; j < s.length; j++) {
    const c = s.charCodeAt(j);
    if (c === 10 || c === 13) return j;
    if (c === 92 /* \ */ && (s[j + 1] === "n" || s[j + 1] === "r")) return j;
  }
  return s.length;
}

/** End index (exclusive) of the value starting at i, given its surrounding context. */
function valueEnd(s: string, i: number, prefix: string, nameQuote: string): { end: number; quote: string } {
  const c = s[i];
  // \"value\" inside JSON-escaped text: ends at the next \" that is not itself escaped (\\\")
  if (c === "\\" && (s[i + 1] === '"' || s[i + 1] === "'")) {
    const q = s[i + 1]!;
    for (let j = i + 2; j < s.length - 1; j++) {
      if (s[j] === "\\" && s[j + 1] === q && s[j - 1] !== "\\") return { end: j + 2, quote: `\\${q}` };
    }
    return { end: lineEnd(s, i), quote: "" };
  }
  // "value" / 'value' with backslash escapes; unterminated runs to the end of the line
  if (c === '"' || c === "'") {
    for (let j = i + 1; j < s.length; j++) {
      if (s[j] === "\\") { j++; continue; }
      if (s[j] === c) return { end: j + 1, quote: c };
    }
    return { end: lineEnd(s, i), quote: "" };
  }
  const eol = lineEnd(s, i);
  let stop = (_ch: string, _j: number) => false;
  if (prefix === '"' || prefix === "'") {
    // "DB_PASS=x y" / -H 'Authorization: Basic x': ends at the unescaped quote that opened it
    stop = (ch, j) => ch === prefix && s[j - 1] !== "\\";
  } else if (prefix === '\\"' || prefix === "\\'") {
    const q = prefix[1]!;
    stop = (ch, j) => ch === "\\" && s[j + 1] === q;
  } else if (prefix === "?" || prefix === "&" || prefix === ";") {
    // URL query parameter
    stop = (ch) => ch === "&" || ch === "#" || ch === " " || ch === "\t" || ch === '"' || ch === "'";
  } else if (nameQuote) {
    // "DB_PASS": 12345 in JSON text
    stop = (ch) => ch === "," || ch === "}" || ch === "]";
  }
  for (let j = i; j < eol; j++) if (stop(s[j]!, j)) return { end: j, quote: "" };
  return { end: eol, quote: "" };
}

/** Redact the values of NAME=value / NAME: value pairs whose NAME is a secret name. */
function redactAssignments(s: string): string {
  let out = "";
  let last = 0;
  ASSIGN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ASSIGN_RE.exec(s)) !== null) {
    const [whole, prefix = "", nameQuote = "", name = ""] = m;
    const vStart = m.index + whole.length;
    if (!isSecretName(name)) continue;
    // "scheme://" is a URL, not an assignment (userinfo is handled separately)
    if (s.startsWith("//", vStart)) continue;
    const { end, quote } = valueEnd(s, vStart, prefix, nameQuote);
    if (end <= vStart) continue;
    out += s.slice(last, vStart) + (quote ? `${quote}[redacted]${quote}` : "[redacted]");
    last = end;
    ASSIGN_RE.lastIndex = Math.max(end, vStart);
  }
  return last === 0 ? s : out + s.slice(last);
}

/** "Basic <base64>" credentials; plain words ("Basic authentication") are left alone. */
function redactBasic(s: string): string {
  return s.replace(/\bBasic\s+([A-Za-z0-9+/]{8,}={0,2})(?![A-Za-z0-9+/=])/gi, (all, tok: string) =>
    /[0-9+/=]/.test(tok) || /[A-Z]/.test(tok.slice(1)) ? "Basic [redacted]" : all,
  );
}

/** Replace every embedded secret in a string (exported for tests and push payloads). */
export function redactSecrets(s: string): string {
  let out = s;
  for (const [re, rep] of SECRET_SUBSTRING_RES) out = out.replace(re, rep);
  out = redactBasic(out);
  return redactAssignments(out);
}

const DEFAULT_MAX_BYTES = 65_536;
const DEFAULT_MAX_STRING = 16_384;
const DEFAULT_MAX_DEPTH = 12;

export function auditMaxDetailBytes(): number {
  const n = Number(process.env.MCP_FLOW_AUDIT_MAX_DETAIL_BYTES ?? "");
  if (Number.isFinite(n) && n >= 1024 && n <= 1_000_000) return Math.floor(n);
  return DEFAULT_MAX_BYTES;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function redactString(input: string, maxString: number): string {
  // scan the whole string (bounded) before truncating, so a secret past the cut is still caught
  // only the kept prefix is ever stored, so scan exactly that (plus a margin so a secret that
  // straddles the cut is still caught); nothing beyond the margin is persisted
  const keep = input.length > maxString ? input.slice(0, maxString + 4096) : input;
  if (looksLikeOpaqueSecret(keep)) return "[redacted]";
  const s = redactSecrets(keep);
  if (s.length <= maxString) return s;
  return `${s.slice(0, maxString)}…[truncated ${s.length} chars]`;
}

/**
 * Deep-sanitize a value for audit storage: redact secrets, cap depth/size.
 */
export function sanitizeForAudit(
  value: unknown,
  opts: {
    maxBytes?: number;
    maxString?: number;
    maxDepth?: number;
  } = {},
): unknown {
  const maxBytes = opts.maxBytes ?? auditMaxDetailBytes();
  const maxString = opts.maxString ?? DEFAULT_MAX_STRING;
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;

  try {
    const walked = walk(value, 0, maxDepth, maxString);
    const json = JSON.stringify(walked);
    if (json === undefined) return null;
    const bytes = Buffer.byteLength(json, "utf8");
    if (bytes <= maxBytes) {
      return walked === undefined ? null : walked;
    }
    const preview = json.slice(0, Math.min(maxString, 2000));
    return {
      _truncated: true,
      byteLength: bytes,
      maxBytes,
      preview: `${preview}…`,
    };
  } catch {
    return { _error: "sanitize_failed" };
  }
}

function walk(
  value: unknown,
  depth: number,
  maxDepth: number,
  maxString: number,
): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value, maxString);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function" || typeof value === "symbol") {
    return `[${typeof value}]`;
  }
  if (depth >= maxDepth) return "[max_depth]";

  if (Array.isArray(value)) {
    const out: unknown[] = [];
    const limit = Math.min(value.length, 200);
    for (let i = 0; i < limit; i++) {
      out.push(walk(value[i], depth + 1, maxDepth, maxString));
    }
    if (value.length > limit) {
      out.push(`…[${value.length - limit} more items]`);
    }
    return out;
  }

  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    const keys = Object.keys(value);
    const limit = Math.min(keys.length, 100);
    for (let i = 0; i < limit; i++) {
      const k = keys[i]!;
      if (SECRET_KEY_RE.test(k) || CAMEL_SECRET_KEY_RE.test(k) || isSecretName(k)) {
        out[k] = "[redacted]";
        continue;
      }
      out[k] = walk(value[k], depth + 1, maxDepth, maxString);
    }
    if (keys.length > limit) {
      out._omittedKeys = keys.length - limit;
    }
    return out;
  }

  return String(value);
}

/**
 * Normalize CallToolResult for audit (drop huge binary blobs).
 */
export function summarizeCallToolResult(result: CallToolResult): unknown {
  const content = Array.isArray(result.content) ? result.content : [];
  const summarized = content.map((block) => {
    if (!block || typeof block !== "object") return block;
    const b = block as Record<string, unknown>;
    const type = String(b.type ?? "unknown");
    if (type === "text") {
      return { type: "text", text: b.text };
    }
    if (type === "image" || type === "audio" || type === "resource") {
      const data = b.data;
      const len =
        typeof data === "string"
          ? data.length
          : Buffer.isBuffer(data)
            ? data.length
            : undefined;
      return {
        type,
        mimeType: b.mimeType,
        _omitted: "binary",
        byteLength: len,
      };
    }
    return walk(b, 0, 6, DEFAULT_MAX_STRING);
  });

  const out: Record<string, unknown> = {
    isError: Boolean(result.isError),
    content: summarized,
  };
  if ("structuredContent" in result && result.structuredContent !== undefined) {
    out.structuredContent = result.structuredContent;
  }
  return out;
}

/** Build standard tools/call audit detail blob (pre-store sanitize). */
export function toolCallAuditDetail(input: {
  arguments?: unknown;
  result?: CallToolResult | unknown;
  denied?: boolean;
  reason?: string;
  meta?: boolean;
  durationMs?: number;
  extra?: Record<string, unknown>;
}): Record<string, unknown> {
  const detail: Record<string, unknown> = {};
  if (input.meta) detail.meta = true;
  if (input.denied) {
    detail.denied = true;
    if (input.reason) detail.reason = input.reason;
  }
  if (input.arguments !== undefined) {
    detail.arguments = input.arguments;
  }
  if (input.result !== undefined) {
    const r = input.result as CallToolResult;
    if (r && typeof r === "object" && Array.isArray((r as CallToolResult).content)) {
      detail.result = summarizeCallToolResult(r);
      detail.isError = Boolean(r.isError);
    } else {
      detail.result = input.result;
      if (
        input.result &&
        typeof input.result === "object" &&
        "isError" in (input.result as object)
      ) {
        detail.isError = Boolean(
          (input.result as { isError?: boolean }).isError,
        );
      }
    }
  }
  if (input.durationMs !== undefined) {
    detail.durationMs = input.durationMs;
  }
  if (input.extra) {
    Object.assign(detail, input.extra);
  }
  return detail;
}
