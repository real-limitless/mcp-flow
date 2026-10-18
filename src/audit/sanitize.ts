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
  [/\b(Authorization\s*[:=]\s*["']?(?:token|bearer|basic|digest)\s+)[^\s"']+/gi, "$1[redacted]"],
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, "Bearer [redacted]"],
  // URL userinfo in any scheme, empty user or password included (redis://:pw@h, https://tok@h).
  // The run is greedy, so it ends at the LAST '@' before / ? # or whitespace (p@ss@host).
  // Linear: the scheme is bounded and runs cannot overlap (each one stops at the next '/').
  [/(\b[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\/)[^\s/?#"'<>\\]*@/g, "$1[redacted]@"],
  // scheme-less fallback for longer or unusual schemes; same last-'@' rule, linear (runs stop at '/')
  [/:\/\/[^\s/?#"'<>\\]*@/g, "://[redacted]@"],
  // mysql/mariadb -p<password> (no space; "-p" alone prompts and is left alone)
  [/(\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mysqlshow|mariadb(?:-dump|-admin)?)\b[^\n]{0,2000}?\s-p)(?:'[^'\n]*'|"[^"\n]*"|[^\s'"]+)/g, "$1[redacted]"],
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
 * Common non-secret *_KEY names stay readable through an explicit list (PRIMARY_KEY, SORT_KEY,
 * PUBLIC_KEY, IDEMPOTENCY_KEY, CACHE_KEY, PARTITION_KEY, …; see BENIGN_KEY_WORDS); any other
 * *_KEY is redacted. Known false positives (accepted, audit text only loses the value): other
 * non-secret *_KEY names (APP_KEY_FILE is fine, SSH_HOST_KEY is not), PWD=/cwd in env dumps,
 * prose like "Token: ...". Bare KEY is NOT a secret name (key=value, KEY_COUNT=5 stay readable).
 * *_TOKENS is a secret name (API_TOKENS) except token counts and limits: max_tokens,
 * *_max_tokens, max_{input,output,completion,prompt,new,context}_tokens, and
 * min/num/total/prompt/completion/input/output/cached/reasoning_tokens stay readable
 * (MAX_ACCESS_TOKENS, max_refresh_tokens are secret names).
 */
const SECRET_NAME_SUFFIX_RE =
  /[_.-](?:PASS|PWD|PASSWD|PASSWORD|KEYS?|SECRETS?|TOKENS?|AUTH|CREDENTIALS?|PASSPHRASE)$/i;
/** *_TOKENS names that are counts or limits, not secrets (max_tokens, max_output_tokens, …). */
const TOKEN_COUNT_NAME_RE =
  /^(?:min|num|total|prompt|completion|input|output|cached|reasoning)[_.-]tokens$|(?:^|[_.-])max(?:[_.-](?:input|output|completion|prompt|new|context))?[_.-]tokens$/i;
const SECRET_NAME_BARE_RE =
  /^(?:PASS|PASSWD|PASSWORD|PWD|SECRETS?|TOKEN|AUTH|AUTHORIZATION|CREDENTIALS?|PASSPHRASE|APIKEY|BEARER|COOKIE|DSN)$/i;
const SECRET_NAME_CONTAINS_RE =
  /PASSWORD|PASSWD|PASSPHRASE|SECRET|CREDENTIAL|AUTHORIZATION|COOKIE|PRIVATE[_.-]?KEY|ACCESS[_.-]?KEY|API[_.-]?KEY|(?:^|[_.-])TOKEN(?:$|[_.-])|DATABASE[_.-]?URL|CONNECTION[_.-]?STRING/i;

/**
 * camelCase names: a lowercase letter or digit followed by an uppercase secret suffix (dbPass,
 * dbPwd, smtpAuth, jwtKey, masterKey, signingKey, basicAuth, apiToken, clientSecret, apiTokens).
 * Readable on purpose: common non-secret *Key names (primaryKey, sortKey, idempotencyKey,
 * partitionKey, foreignKey, cacheKey, publicKey, routingKey, …) and token counts (maxTokens,
 * maxOutputTokens, promptTokens, totalTokens, …). Other camelCase *Key / *Auth names are
 * redacted (accepted false positives: hotKey, oAuth, isAuth).
 */
const CAMEL_SECRET_SUFFIX_RE =
  /[a-z0-9](?:Pass|Pwd|Passwd|Password|Passphrase|Keys?|Secrets?|Tokens?|Auth|Credentials?)$/;
const BENIGN_KEY_WORDS =
  "primary|sort|idempotency|partition|foreign|cache|public|routing|row|hash|range|object|composite|unique|lookup|dedupe?|group|shard|index|search|order|parent|join";
/** Non-secret *Key / *_KEY names, camelCase or separated: primaryKey, sort_key, PUBLIC_KEY, … */
const CAMEL_BENIGN_KEY_RE = new RegExp(`^(?:${BENIGN_KEY_WORDS})Keys?$`);
const SEP_BENIGN_KEY_RE = new RegExp(`^(?:${BENIGN_KEY_WORDS})[_.-]keys?$`, "i");
/**
 * Token counts in camelCase. Count words in lowercase only at the start of the name
 * (maxTokens, promptTokens, totalTokens); after a camel hump only Max (modelMaxTokens,
 * modelMaxOutputTokens). So adminTokens and adminMinTokens are secret names (fail closed).
 */
const CAMEL_TOKEN_COUNT_RE =
  /^(?:max(?:Input|Output|Completion|Prompt|New|Context)?|min|num|total|prompt|completion|input|output|cached|reasoning)Tokens$|[a-z0-9]Max(?:Input|Output|Completion|Prompt|New|Context)?Tokens$/;

/** Names longer than this are treated as secret names (fail closed), never skipped. */
const MAX_NAME_LEN = 256;

/** True when a key or variable name names a secret (see the rules above). */
export function isSecretName(name: string): boolean {
  if (name.length > MAX_NAME_LEN) return true;
  if (TOKEN_COUNT_NAME_RE.test(name) || CAMEL_TOKEN_COUNT_RE.test(name)) return false;
  if (CAMEL_BENIGN_KEY_RE.test(name) || SEP_BENIGN_KEY_RE.test(name)) return false;
  return (
    SECRET_NAME_SUFFIX_RE.test(name) ||
    SECRET_NAME_BARE_RE.test(name) ||
    SECRET_NAME_CONTAINS_RE.test(name) ||
    CAMEL_SECRET_SUFFIX_RE.test(name)
  );
}

/**
 * NAME=value / NAME: value candidates. Group 1 is the char before the name (or a JSON-escaped
 * quote or literal \n / \r / \t escape, for env text inside JSON strings), group 2 an optional
 * quote around the name ("NAME": or \"NAME\":), group 3 the name.
 * Bounded: the name is capped (1024) and nothing is nested; a name longer than MAX_NAME_LEN is
 * treated as secret by isSecretName.
 */
const ASSIGN_RE =
  /(^|\\["'nrt]|[^A-Za-z0-9_.\\])((?:\\?["'])?)([A-Za-z_][A-Za-z0-9_.-]{0,1023})\2[ \t]*[=:][ \t]*/g;

/**
 * True when a literal \n / \r escape at j ends a line of escaped text: what follows is the end,
 * another escape or quote, or the next NAME= / NAME: pair. Otherwise the escape is taken as part
 * of the value (a password containing "\n" is not cut short). Bounded lookahead.
 */
const NEXT_PAIR_RE = /[A-Za-z_][A-Za-z0-9_.-]{0,127}[ \t]*[=:]/y;
function escapedLineBreakAt(s: string, k: number): boolean {
  if (k >= s.length) return true;
  const c = s[k];
  if (c === "\\" || c === '"' || c === "'" || c === "\n" || c === "\r" || c === "#") return true;
  NEXT_PAIR_RE.lastIndex = k;
  return NEXT_PAIR_RE.test(s);
}

/** Index of the end of the line starting at i: a real CR/LF or a literal \n / \r line break. */
function lineEnd(s: string, i: number): number {
  return scanToStop(s, i, null);
}

/**
 * First index from i that ends the line (as lineEnd) or where stop(s[j], j) holds, in one forward
 * pass. valueEnd used to compute the whole line end first and then look for a stop char, so an
 * empty value repeated on one line ("&token=&token=…", "\"password\":,…") cost a line scan per
 * match (quadratic); now an early stop char returns at once. Same result as before.
 */
function scanToStop(s: string, i: number, stop: ((ch: string, j: number) => boolean) | null): number {
  for (let j = i; j < s.length; j++) {
    const c = s.charCodeAt(j);
    if (c === 10 || c === 13) return j;
    if (c === 92 /* \ */ && (s[j + 1] === "n" || s[j + 1] === "r")) {
      // skip the whole run of escapes once, so the scan stays linear
      let k = j;
      while (k < s.length - 1 && s[k] === "\\" && (s[k + 1] === "n" || s[k + 1] === "r")) k += 2;
      if (escapedLineBreakAt(s, k)) return j;
      if (stop) for (let t = j; t < k; t++) if (stop(s[t]!, t)) return t;
      j = k - 1;
      continue;
    }
    if (stop && stop(s[j]!, j)) return j;
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
  let stop: ((ch: string, j: number) => boolean) | null = null;
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
  return { end: scanToStop(s, i, stop), quote: "" };
}

/** Name characters (as in ASSIGN_RE). */
function isNameChar(c: number): boolean {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95 || c === 46 || c === 45;
}

/**
 * ASSIGN_RE caps a name at 1024 characters and needs a non-name character before it, so a longer
 * name ("<1100 chars>_PASSWORD=v") never matched and its value was kept. Names longer than that are
 * secret names (fail closed, as isSecretName treats any name over MAX_NAME_LEN): one linear pass
 * over name-character runs; a run longer than 1024 followed by an optional (escaped) quote,
 * [ \t]* and = or : has its value redacted with the same value rules.
 */
const LONG_NAME_MIN = 1025;
function redactLongNameAssignments(s: string): string {
  if (s.length < LONG_NAME_MIN + 1) return s;
  let out = "";
  let last = 0;
  let i = 0;
  while (i < s.length) {
    if (!isNameChar(s.charCodeAt(i))) {
      i++;
      continue;
    }
    const start = i;
    while (i < s.length && isNameChar(s.charCodeAt(i))) i++;
    if (i - start < LONG_NAME_MIN) continue;
    let j = i;
    let nameQuote = "";
    if (s[j] === "\\" && (s[j + 1] === '"' || s[j + 1] === "'")) {
      nameQuote = s.slice(j, j + 2);
      j += 2;
    } else if (s[j] === '"' || s[j] === "'") {
      nameQuote = s[j]!;
      j++;
    }
    while (s[j] === " " || s[j] === "\t") j++;
    if (s[j] !== "=" && s[j] !== ":") continue;
    j++;
    while (s[j] === " " || s[j] === "\t") j++;
    if (j < last || s.startsWith("//", j)) continue;
    const before = start > 0 ? s[start - 1]! : "";
    const prefix = (before === '"' || before === "'") && s[start - 2] === "\\" ? `\\${before}` : before;
    const { end, quote } = valueEnd(s, j, prefix, nameQuote);
    if (end <= j) continue;
    out += s.slice(last, j) + (quote ? `${quote}[redacted]${quote}` : "[redacted]");
    last = end;
    i = Math.max(i, end);
  }
  return last === 0 ? s : out + s.slice(last);
}

/** Redact the values of NAME=value / NAME: value pairs whose NAME is a secret name. */
function redactAssignments(input: string): string {
  const s = redactLongNameAssignments(input);
  let out = "";
  let last = 0;
  ASSIGN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = ASSIGN_RE.exec(s)) !== null) {
    const [whole, prefix = "", nameQuote = "", name = ""] = m;
    const vStart = m.index + whole.length;
    if (!isSecretName(name)) {
      // "a: password=x", "denied: API_KEY=x": a non-secret NAME: consumed the separator and the
      // spaces that are the next name's left boundary; rescan from the last consumed char
      // (always past m.index, so the scan still moves forward)
      ASSIGN_RE.lastIndex = vStart - 1;
      continue;
    }
    // "scheme://" is a URL, not an assignment (userinfo is handled separately)
    if (s.startsWith("//", vStart)) continue;
    const { end, quote } = valueEnd(s, vStart, prefix, nameQuote);
    if (end <= vStart) {
      ASSIGN_RE.lastIndex = vStart - 1; // empty value ("password: token=x"): rescan likewise
      continue;
    }
    out += s.slice(last, vStart) + (quote ? `${quote}[redacted]${quote}` : "[redacted]");
    last = end;
    ASSIGN_RE.lastIndex = Math.max(end, vStart);
  }
  return last === 0 ? s : out + s.slice(last);
}

/**
 * ASCII-armor markers: PEM (`-----BEGIN RSA PRIVATE KEY-----`), PGP
 * (`-----BEGIN PGP PRIVATE KEY BLOCK-----`), SSH.com (`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`),
 * OpenVPN (`-----BEGIN OpenVPN Static key V1-----`). Case-insensitive (`-----begin pgp private
 * key block-----`), 4 or 5 dashes, spaces or tabs around BEGIN/END and inside the label.
 * Bounded quantifiers only.
 */
const ARMOR_MARKER_RE = /-{4,5}[ \t]{0,8}(BEGIN|END)[ \t]{1,8}([A-Za-z0-9][A-Za-z0-9 \t._]{0,79}?)[ \t]{0,8}-{4,5}/gi;
/**
 * Labels whose block body is secret key material. Public keys, certificates, and PGP MESSAGE /
 * SIGNATURE blocks stay readable by design: a MESSAGE body is ciphertext (useless without the
 * private key) and a SIGNATURE is public, and both are useful when reading an audit trail.
 */
const SECRET_ARMOR_LABEL_RE = /\b(?:PRIVATE|SECRET|STATIC)[ \t]+KEY\b/i;

export interface ArmorMarker {
  begin: boolean;
  start: number;
  end: number;
}

/** Secret-key armor BEGIN/END markers in s, in order. Linear: one global regex pass. */
export function secretArmorMarkers(s: string): ArmorMarker[] {
  const out: ArmorMarker[] = [];
  if (s.indexOf("----") < 0) return out;
  ARMOR_MARKER_RE.lastIndex = 0;
  for (let m; (m = ARMOR_MARKER_RE.exec(s)); ) {
    if (SECRET_ARMOR_LABEL_RE.test(m[2]!)) {
      out.push({ begin: m[1]!.toUpperCase() === "BEGIN", start: m.index, end: m.index + m[0].length });
    }
  }
  return out;
}

const ARMOR_BODY_RE = /^[A-Za-z0-9+/=]{16,}$/;
/** A short last line of a base64 body with its padding ("AbC=", "Zg=="). */
const ARMOR_BODY_PADDED_RE = /^[A-Za-z0-9+/]{1,15}={1,2}$/;
/** Any base64-charset text (allowed only right before an END marker: the short last line). */
const ARMOR_BODY_SHORT_RE = /^[A-Za-z0-9+/=]{1,15}$/;
const ARMOR_HEADER_RE = /^(?:Comment|Version|Hash|Charset|MessageID|Proc-Type|DEK-Info)[ \t]*:/i;
const ARMOR_CHECKSUM_RE = /^=[A-Za-z0-9+/]{4}$/;

/**
 * Line (trimmed) that looks like the inside of a key armor block: base64 of 16+ characters, a
 * padded short last line, an armor header (Comment:, Version:, …) or a PGP checksum (=XXXX).
 */
export function isArmorBodyLine(line: string): boolean {
  const t = line.trim();
  if (!t) return false;
  return ARMOR_BODY_RE.test(t) || ARMOR_BODY_PADDED_RE.test(t) || ARMOR_CHECKSUM_RE.test(t) || ARMOR_HEADER_RE.test(t);
}

/** Start of the line break that ends just before `pos` ("\n", "\r\n" or an escaped "\\n"), or -1. */
function prevBreak(s: string, from: number, pos: number): { at: number; len: number } {
  for (let i = pos - 1; i >= from; i--) {
    if (s[i] === "\n") return { at: i > from && s[i - 1] === "\r" ? i - 1 : i, len: i > from && s[i - 1] === "\r" ? 2 : 1 };
    if (s[i] === "n" && i > from && s[i - 1] === "\\") {
      const crlf = i - 3 >= from && s[i - 2] === "r" && s[i - 3] === "\\";
      return crlf ? { at: i - 3, len: 4 } : { at: i - 1, len: 2 };
    }
  }
  return { at: -1, len: 0 };
}

/**
 * Where to start redacting for an END marker at `endStart` with no BEGIN before it (the start of
 * the block was cut off): the run of key-body-shaped lines right before the END, back to `from`
 * at most. Fails closed on that run only; text above it stays readable.
 */
function bodyRunStart(s: string, from: number, endStart: number): number {
  // text on the END line before the marker
  let b = prevBreak(s, from, endStart);
  let lineStart = b.at < 0 ? from : b.at + b.len;
  const head = s.slice(lineStart, endStart).trim();
  if (head && !isArmorBodyLine(head) && !ARMOR_BODY_SHORT_RE.test(head)) return endStart;
  let runStart = head ? lineStart : endStart;
  // a short unpadded base64 line is only taken as the block's last line: right before the END,
  // or right before a PGP checksum that is right before the END
  let allowShort = !head;
  while (b.at >= 0) {
    const pos = b.at;
    b = prevBreak(s, from, pos);
    lineStart = b.at < 0 ? from : b.at + b.len;
    const t = s.slice(lineStart, pos).trim();
    if (!t) continue; // blank lines inside the run do not end it (PGP header / body gap)
    if (!(isArmorBodyLine(t) || (allowShort && ARMOR_BODY_SHORT_RE.test(t)))) break;
    allowShort = allowShort && ARMOR_CHECKSUM_RE.test(t);
    runStart = lineStart;
  }
  return runStart;
}

/**
 * Private key armor blocks (PEM, PGP, SSH2, OpenVPN static keys). Fail closed:
 * - an unterminated BEGIN redacts to the end of the string;
 * - an END with no BEGIN before it (the start of the block was cut off by a tail slice or a
 *   line cap) redacts the run of key-body-shaped lines right before it, and the marker.
 */
function redactPem(s: string): string {
  const marks = secretArmorMarkers(s);
  if (!marks.length) return s;
  let out = "";
  let last = 0;
  let open = -1;
  for (const mk of marks) {
    if (mk.begin) {
      if (open < 0) open = mk.start;
      continue;
    }
    out += s.slice(last, open < 0 ? bodyRunStart(s, last, mk.start) : open) + "[redacted]";
    last = mk.end;
    open = -1;
  }
  if (open >= 0) return out + s.slice(last, open) + "[redacted]";
  return out + s.slice(last);
}

/**
 * PuTTY .ppk (`PuTTY-User-Key-File-2:` / `-3:` header): "Private-Lines: N" (the N lines after it
 * are the private key) and "Private-MAC:". A count over PPK_MAX_PRIVATE_LINES is not trusted.
 */
export const PPK_MAX_PRIVATE_LINES = 1024;
const PPK_PRIVATE_LINES_RE = /Private-Lines:[ \t]*(\d{1,6})[ \t]*(?:\r?\n|\\r\\n|\\n)/g;
const PPK_MAC_RE = /(Private-MAC:[ \t]*)[^\s"'\\]+/g;

/** Next line break at or after pos ("\n", "\r\n" or an escaped "\\n"): its start and length. */
function nextBreak(s: string, pos: number): { at: number; len: number } {
  for (let i = pos; i < s.length; i++) {
    if (s[i] === "\r" && s[i + 1] === "\n") return { at: i, len: 2 };
    if (s[i] === "\n") return { at: i, len: 1 };
    if (s[i] === "\\" && s[i + 1] === "n") return { at: i, len: 2 };
    if (s[i] === "\\" && s[i + 1] === "r" && s[i + 2] === "\\" && s[i + 3] === "n") return { at: i, len: 4 };
  }
  return { at: -1, len: 0 };
}

/**
 * PuTTY private keys (`PuTTY-User-Key-File-2/3:`). The N lines after "Private-Lines: N" are
 * redacted (to the end of the string if fewer follow, or if N is over the cap: fail closed), and
 * so is the Private-MAC.
 * Applied with or without the header line, so a tail that cut the header off is still covered.
 */
function redactPpk(s: string): string {
  if (s.indexOf("Private-") < 0) return s;
  let out = "";
  let last = 0;
  PPK_PRIVATE_LINES_RE.lastIndex = 0;
  for (let m; (m = PPK_PRIVATE_LINES_RE.exec(s)); ) {
    const count = Number(m[1]);
    const start = m.index + m[0].length;
    if (count > PPK_MAX_PRIVATE_LINES) return (out + s.slice(last, start) + "[redacted]").replace(PPK_MAC_RE, "$1[redacted]");
    const n = count;
    let pos = start;
    let i = 0;
    for (; i < n; i++) {
      const b = nextBreak(s, pos);
      if (b.at < 0) {
        pos = s.length;
        break;
      }
      pos = i === n - 1 ? b.at : b.at + b.len;
    }
    if (n === 0 || pos <= start) continue;
    out += s.slice(last, start) + "[redacted]";
    last = pos;
    PPK_PRIVATE_LINES_RE.lastIndex = Math.max(pos, start);
  }
  const r = last === 0 ? s : out + s.slice(last);
  return r.replace(PPK_MAC_RE, "$1[redacted]");
}

/** fish / csh: `set -x DB_PASS value`, `setenv DB_PASS value` (value runs to the end of the line). */
function redactShellSet(s: string): string {
  return s.replace(
    /(\b(?:set|setenv)(?:[ \t]+-{1,2}[A-Za-z]+)*[ \t]+)([A-Za-z_][A-Za-z0-9_]{0,255})([ \t]+)([^\r\n]+)/g,
    (all, head: string, name: string, sp: string) =>
      isSecretName(name) ? `${head}${name}${sp}[redacted]` : all,
  );
}

const URL_AUTH_STOP = new Set([" ", "\t", "\n", "\r", "/", "?", "#", '"', "'", "<", ">", "\\", "@"]);
const URL_TOKEN_STOP = new Set([" ", "\t", "\n", "\r", '"', "<", ">"]);

/**
 * URL passwords holding a raw / # ' or ? (not RFC-valid, common in hand-written DSNs):
 * postgres://u:p/x@h/db, u:p/a=x@h, u:p/&x@h. Only when the authority has user:pass whose
 * "pass" is not a port (digits), and an '@' follows within the same token (1024-char window).
 * A ?email=a@b query is only reached after a user:<non-port> authority, so normal URLs
 * (https://h:8080/a@b, /path/@user, https://h/x?email=a@b) are kept. Linear: the '@' search
 * never rescans text an earlier search already cleared.
 */
function redactRawUrlPasswords(s: string): string {
  let out = "";
  let last = 0;
  let from = 0;
  // [clearFrom, clearUntil) is known to hold no '@' and no token stop; clearStop says the
  // scan that cleared it ended on a token stop (so no '@' can follow within the token)
  let clearFrom = -1;
  let clearUntil = -1;
  let clearStop = false;
  for (;;) {
    const at = s.indexOf("://", from);
    if (at < 0) break;
    const a = at + 3;
    from = a;
    let e = a;
    let colon = -1;
    const authMax = Math.min(s.length, a + 1024);
    while (e < authMax && !URL_AUTH_STOP.has(s[e]!)) {
      if (colon < 0 && s[e] === ":") colon = e;
      e++;
    }
    if (e >= s.length || s[e] === "@" || colon < 0) continue;
    const stop = s[e]!;
    if (!(stop === "/" || stop === "#" || stop === "'" || stop === "?" || stop === "\\")) continue;
    if (/^\d*$/.test(s.slice(colon + 1, e))) continue; // host:port
    let x = -1;
    const tokMax = Math.min(s.length, e + 1024);
    let j = e;
    if (e >= clearFrom && e < clearUntil) {
      if (clearStop) continue;
      j = clearUntil;
    }
    let stopped = false;
    for (; j < tokMax; j++) {
      const c = s[j]!;
      if (URL_TOKEN_STOP.has(c)) {
        stopped = true;
        break;
      }
      if (c === "@") {
        x = j;
        break;
      }
    }
    if (x < 0) {
      if (!(e >= clearFrom && e < clearUntil)) clearFrom = e;
      clearUntil = j;
      clearStop = stopped;
      continue;
    }
    out += s.slice(last, a) + "[redacted]";
    last = x;
    from = x;
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
  let out = redactRawUrlPasswords(redactPpk(redactPem(s)));
  for (const [re, rep] of SECRET_SUBSTRING_RES) out = out.replace(re, rep);
  out = redactBasic(out);
  return redactShellSet(redactAssignments(out));
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
    const walked = walk(value, 0, maxDepth, maxString, { n: 0 });
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

/** Fields that name a variable in a name/value pair, and the sibling fields holding its value. */
const PAIR_NAME_FIELD_RE = /^(?:name|key|variable|var|env|env_?name|variable_?name|key_?name)$/i;
const PAIR_VALUE_FIELD_RE =
  /^(?:value|val|values|value_?from|env_?value|default|default_?value|secret_?value|data|content|text)$/i;

/** Upper bound on nodes visited per sanitize call (self-referential wide arrays). */
const MAX_NODES = 50_000;

/** Object key text with embedded secrets redacted; very long keys are cut (fail closed). */
function safeKeyName(k: string): string {
  if (k.length > MAX_NAME_LEN) return `${redactSecrets(k.slice(0, 64))}…[key truncated]`;
  if (looksLikeOpaqueSecret(k)) return "[redacted]";
  return redactSecrets(k);
}

function walk(
  value: unknown,
  depth: number,
  maxDepth: number,
  maxString: number,
  budget: { n: number } = { n: 0 },
): unknown {
  if (value === null || value === undefined) return value;
  if (++budget.n > MAX_NODES) return "[omitted]";
  if (typeof value === "string") return redactString(value, maxString);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function" || typeof value === "symbol") {
    return `[${typeof value}]`;
  }
  // Buffer / Uint8Array / DataView / ArrayBuffer: never emit raw bytes
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) {
    return { _omitted: "binary", byteLength: (value as ArrayBufferLike | ArrayBufferView).byteLength };
  }
  if (depth >= maxDepth) return "[max_depth]";

  if (Array.isArray(value)) {
    const out: unknown[] = [];
    const limit = Math.min(value.length, 200);
    // [name, value] tuples and flat name/value lists (header arrays, rawHeaders; odd lengths
    // too, the last name then has no value):
    // [["X-Api-Key","v"]], ["Authorization","Bearer x"], ["Accept","a","X-Api-Key","v"]
    const pairs =
      value.length >= 2 && value.every((v, i) => i % 2 === 1 || typeof v === "string");
    for (let i = 0; i < limit; i++) {
      if (pairs && i % 2 === 1 && isSecretName(String(value[i - 1]).trim())) {
        out.push("[redacted]");
        continue;
      }
      out.push(walk(value[i], depth + 1, maxDepth, maxString, budget));
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
    // name/value pairs (Dokploy/Docker/k8s env arrays): {"name":"DB_PASS","value":"x"}
    const secretPair = keys.some((k) => {
      const v = value[k];
      return PAIR_NAME_FIELD_RE.test(k) && typeof v === "string" && isSecretName(v.trim());
    });
    for (let i = 0; i < limit; i++) {
      const k = keys[i]!;
      let outKey = safeKeyName(k);
      if (outKey !== k) {
        let n = 1;
        while (Object.prototype.hasOwnProperty.call(out, outKey)) outKey = `${safeKeyName(k)}#${++n}`;
      }
      if (
        SECRET_KEY_RE.test(k) ||
        CAMEL_SECRET_KEY_RE.test(k) ||
        isSecretName(k) ||
        outKey !== k ||
        (secretPair && PAIR_VALUE_FIELD_RE.test(k))
      ) {
        out[outKey] = "[redacted]";
        continue;
      }
      out[k] = walk(value[k], depth + 1, maxDepth, maxString, budget);
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
    return walk(b, 0, 6, DEFAULT_MAX_STRING, { n: 0 });
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
