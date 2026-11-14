/**
 * Secret generators (Secrets §3 / §0.7).
 * Generated values are at least 128 bits. Caller-supplied values are refused.
 * Import is not implemented here.
 */

import { generateKeyPairSync, randomBytes, type JsonWebKey } from "node:crypto";
import {
  b64urlToBuf,
  ed25519PrivateOpenSsh,
  ed25519PublicLine,
  rsaPrivateOpenSsh,
  rsaPublicLine,
} from "./openssh.js";

export const MIN_ENTROPY_BITS = 128;
export const SECRET_MAX_BYTES = 64 * 1024;

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT = "0123456789";
const SYMBOL = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~\\";
const ENV_UNSAFE = new Set(["'", '"', "`", "$", "\\", " ", "#", "="]);
const AMBIGUOUS = new Set(["0", "O", "o", "1", "l", "I", "|"]);
const TOKEN_ALPHABET: Record<string, string> = {
  hex: "0123456789abcdef",
  base64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  base64url: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
};

export class GeneratorError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GeneratorError";
  }
}

export type SecretType = "token" | "password" | "uuid" | "keypair";

export interface GeneratedSecret {
  type: SecretType;
  /** Wiped by the envelope sealer. */
  value: Buffer;
  publicPart: string | null;
  generatorJson: string;
}

export function entropyBits(length: number, alphabetSize: number): number {
  if (length < 1 || alphabetSize < 2) return 0;
  return length * Math.log2(alphabetSize);
}

export function unbiasedIndex(size: number, next: () => number): number {
  if (!Number.isInteger(size) || size < 2 || size > 0xffff) throw new GeneratorError("alphabet is invalid");
  const limit = Math.floor(0x1_0000_0000 / size) * size;
  for (let i = 0; i < 128; i++) {
    const n = next() >>> 0;
    if (n < limit) return n % size;
  }
  throw new GeneratorError("generator entropy source failed");
}

function nextUint32(): number {
  return randomBytes(4).readUInt32BE(0);
}

function pickChar(alphabet: string): string {
  return alphabet[unbiasedIndex(alphabet.length, nextUint32)]!;
}

function assertPlainParams(params: unknown): Record<string, unknown> {
  if (params == null) return {};
  if (typeof params !== "object" || Array.isArray(params)) throw new GeneratorError("params must be an object");
  const proto = Object.getPrototypeOf(params);
  if (proto !== Object.prototype && proto !== null) throw new GeneratorError("params must be an object");
  return params as Record<string, unknown>;
}

function unknownKeys(params: Record<string, unknown>, allowed: readonly string[]): void {
  for (const key of Object.keys(params)) {
    if (!allowed.includes(key)) throw new GeneratorError("unknown generator param");
  }
}

function intField(value: unknown, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value)) throw new GeneratorError(`${name} must be an integer`);
  return value;
}

function boolField(value: unknown, name: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "boolean") throw new GeneratorError(`${name} must be a boolean`);
  return value;
}

function rejectControls(alphabet: string): void {
  if (/[\r\n\0]/.test(alphabet)) throw new GeneratorError("alphabet contains a forbidden character");
}

function finish(type: SecretType, value: string, publicPart: string | null, generator: unknown): GeneratedSecret {
  const buf = Buffer.from(value, "utf8");
  if (buf.length > SECRET_MAX_BYTES) {
    buf.fill(0);
    throw new GeneratorError("secret exceeds 64KiB");
  }
  if (type !== "keypair" && /[\r\n\0]/.test(value)) {
    buf.fill(0);
    throw new GeneratorError("generated value contains a forbidden character");
  }
  return { type, value: buf, publicPart, generatorJson: JSON.stringify(generator) };
}

function entryNames(value: unknown): string[] | null {
  if (value === undefined) return null;
  if (!Array.isArray(value) || value.length < 1 || value.length > 16) {
    throw new GeneratorError("entries must be 1..16 names");
  }
  const names: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !/^[a-z0-9_-]{1,64}$/.test(item) || names.includes(item)) {
      throw new GeneratorError("entries names must be unique [a-z0-9_-]");
    }
    names.push(item);
  }
  return names;
}

function generateToken(params: Record<string, unknown>): GeneratedSecret {
  unknownKeys(params, ["encoding", "bytes", "length", "entries"]);
  const entries = entryNames(params.entries);
  const encoding = params.encoding === undefined ? "base64url" : params.encoding;
  if (encoding !== "hex" && encoding !== "base64" && encoding !== "base64url") {
    throw new GeneratorError("token encoding is invalid");
  }
  const bytes = intField(params.bytes, "bytes");
  const length = intField(params.length, "length");
  if (bytes !== undefined && length !== undefined) throw new GeneratorError("token accepts bytes or length, not both");
  const alphabet = TOKEN_ALPHABET[encoding]!;
  const encodeOne = (n: number | undefined, chars: number | undefined): string => {
    if (chars !== undefined) {
      let out = "";
      for (let i = 0; i < chars; i++) out += pickChar(alphabet);
      return out;
    }
    const raw = randomBytes(n ?? 32);
    return encoding === "hex" ? raw.toString("hex") : raw.toString(encoding).replace(/=+$/, "");
  };
  if (length !== undefined) {
    if (length < 1 || length > 4096) throw new GeneratorError("token length is out of range");
    if (entropyBits(length, alphabet.length) < MIN_ENTROPY_BITS) throw new GeneratorError("token entropy is below 128 bits");
    if (!entries) return finish("token", encodeOne(undefined, length), null, { encoding, length });
    const map: Record<string, string> = {};
    for (const name of entries) map[name] = encodeOne(undefined, length);
    return finish("token", JSON.stringify(map), null, { encoding, length, entries });
  }
  const n = bytes ?? 32;
  if (n < 16 || n > 1024) throw new GeneratorError("token bytes must be 16..1024");
  if (n * 8 < MIN_ENTROPY_BITS) throw new GeneratorError("token entropy is below 128 bits");
  if (!entries) return finish("token", encodeOne(n, undefined), null, { encoding, bytes: n });
  const map: Record<string, string> = {};
  for (const name of entries) map[name] = encodeOne(n, undefined);
  return finish("token", JSON.stringify(map), null, { encoding, bytes: n, entries });
}

interface ClassSet {
  name: string;
  chars: string;
}

function passwordAlphabet(params: Record<string, unknown>): { alphabet: string; classes: ClassSet[]; minPer: number; stored: Record<string, unknown> } {
  unknownKeys(params, ["length", "classes", "charset", "exclude_ambiguous", "exclude", "env_safe", "min_per_class"]);
  const excludeAmbiguous = boolField(params.exclude_ambiguous, "exclude_ambiguous") ?? false;
  const envSafe = boolField(params.env_safe, "env_safe") ?? true;
  const exclude = params.exclude === undefined ? "" : params.exclude;
  if (typeof exclude !== "string" || exclude.length > 128) throw new GeneratorError("exclude is invalid");
  const drop = new Set(exclude);
  if (excludeAmbiguous) for (const ch of AMBIGUOUS) drop.add(ch);
  const filter = (chars: string, symbols: boolean): string => {
    let out = "";
    const seen = new Set<string>();
    for (const ch of chars) {
      if (seen.has(ch) || drop.has(ch)) continue;
      if (symbols && envSafe && ENV_UNSAFE.has(ch)) continue;
      seen.add(ch);
      out += ch;
    }
    return out;
  };

  if (params.charset !== undefined) {
    if (typeof params.charset !== "string" || params.charset.length < 2 || params.charset.length > 256) {
      throw new GeneratorError("charset is invalid");
    }
    rejectControls(params.charset);
    if (params.classes !== undefined) throw new GeneratorError("charset and classes cannot both be set");
    const alphabet = filter(params.charset, false);
    if (alphabet.length < 2) throw new GeneratorError("charset is too small");
    const minPer = intField(params.min_per_class, "min_per_class") ?? 0;
    if (minPer > 0) throw new GeneratorError("min_per_class does not apply to charset");
    return {
      alphabet,
      classes: [],
      minPer,
      stored: { charset: alphabet, exclude_ambiguous: excludeAmbiguous, env_safe: envSafe },
    };
  }

  let flags = { lower: true, upper: true, digit: true, symbol: true };
  let minPer = intField(params.min_per_class, "min_per_class") ?? 1;
  if (params.classes !== undefined) {
    if (typeof params.classes !== "object" || params.classes === null || Array.isArray(params.classes)) {
      throw new GeneratorError("classes must be an object");
    }
    const classes = params.classes as Record<string, unknown>;
    unknownKeys(classes, ["lower", "upper", "digit", "symbol", "min_per_class"]);
    const anyFlag = ["lower", "upper", "digit", "symbol"].some((name) => classes[name] !== undefined);
    flags = {
      lower: boolField(classes.lower, "lower") ?? !anyFlag,
      upper: boolField(classes.upper, "upper") ?? !anyFlag,
      digit: boolField(classes.digit, "digit") ?? !anyFlag,
      symbol: boolField(classes.symbol, "symbol") ?? !anyFlag,
    };
    const nested = intField(classes.min_per_class, "min_per_class");
    if (nested !== undefined) minPer = nested;
  }
  if (!Number.isInteger(minPer) || minPer < 0 || minPer > 64) throw new GeneratorError("min_per_class is invalid");
  const selected: ClassSet[] = [];
  if (flags.lower) selected.push({ name: "lower", chars: filter(LOWER, false) });
  if (flags.upper) selected.push({ name: "upper", chars: filter(UPPER, false) });
  if (flags.digit) selected.push({ name: "digit", chars: filter(DIGIT, false) });
  if (flags.symbol) selected.push({ name: "symbol", chars: filter(SYMBOL, true) });
  if (!selected.length) throw new GeneratorError("password needs a character class");
  for (const set of selected) {
    if (!set.chars.length) throw new GeneratorError("a character class is empty");
  }
  const alphabet = [...new Set(selected.flatMap((set) => [...set.chars]))].join("");
  return { alphabet, classes: selected, minPer, stored: { classes: flags, min_per_class: minPer, exclude_ambiguous: excludeAmbiguous, env_safe: envSafe } };
}

function generatePassword(params: Record<string, unknown>): GeneratedSecret {
  const length = intField(params.length, "length") ?? 32;
  if (length < 12 || length > 256) throw new GeneratorError("password length must be 12..256");
  const built = passwordAlphabet(params);
  if (entropyBits(length, built.alphabet.length) < MIN_ENTROPY_BITS) {
    throw new GeneratorError("password entropy is below 128 bits");
  }
  if (built.minPer > 0 && built.classes.length * built.minPer > length) {
    throw new GeneratorError("min_per_class does not fit the length");
  }
  rejectControls(built.alphabet);
  for (let attempt = 0; attempt < 200; attempt++) {
    let out = "";
    for (let i = 0; i < length; i++) out += pickChar(built.alphabet);
    if (built.minPer > 0 && built.classes.some((set) => countClass(out, set.chars) < built.minPer)) continue;
    return finish("password", out, null, { ...built.stored, length });
  }
  throw new GeneratorError("generator could not satisfy class minimums");
}

function countClass(value: string, chars: string): number {
  const set = new Set(chars);
  let n = 0;
  for (const ch of value) if (set.has(ch)) n++;
  return n;
}

function generateUuid(): GeneratedSecret {
  const bytes = randomBytes(16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  const value = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  return finish("uuid", value, null, {});
}

function pem(key: { export(opts: { type: string; format: "pem" }): string | Buffer }, type: "pkcs8" | "spki"): string {
  const out = key.export({ type, format: "pem" });
  return typeof out === "string" ? out : out.toString("utf8");
}

function generateKeypair(params: Record<string, unknown>): GeneratedSecret {
  unknownKeys(params, ["alg", "bits", "format"]);
  const alg = params.alg;
  if (alg !== "ed25519" && alg !== "rsa") throw new GeneratorError("keypair alg is invalid");
  const format = params.format === undefined ? "pem" : params.format;
  if (format !== "pem" && format !== "openssh") throw new GeneratorError("keypair format is invalid");
  if (alg === "ed25519") {
    if (params.bits !== undefined) throw new GeneratorError("ed25519 does not take bits");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const jwk = privateKey.export({ format: "jwk" }) as JsonWebKey;
    if (!jwk.d || !jwk.x) throw new GeneratorError("ed25519 export failed");
    const seed = b64urlToBuf(jwk.d);
    const pub = b64urlToBuf(jwk.x);
    const value = format === "pem" ? pem(privateKey, "pkcs8") : ed25519PrivateOpenSsh(seed, pub);
    const publicPart = format === "pem" ? pem(publicKey, "spki") : ed25519PublicLine(pub);
    return finish("keypair", value, publicPart, { alg, format });
  }
  const bits = intField(params.bits, "bits") ?? 3072;
  if (bits !== 3072 && bits !== 4096) throw new GeneratorError("rsa bits must be 3072 or 4096");
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: bits });
  const jwk = privateKey.export({ format: "jwk" }) as JsonWebKey;
  if (!jwk.n || !jwk.e || !jwk.d || !jwk.p || !jwk.q || !jwk.qi) throw new GeneratorError("rsa export failed");
  const value = format === "pem"
    ? pem(privateKey, "pkcs8")
    : rsaPrivateOpenSsh({
        n: b64urlToBuf(jwk.n),
        e: b64urlToBuf(jwk.e),
        d: b64urlToBuf(jwk.d),
        iqmp: b64urlToBuf(jwk.qi),
        p: b64urlToBuf(jwk.p),
        q: b64urlToBuf(jwk.q),
      });
  const publicPart = format === "pem" ? pem(publicKey, "spki") : rsaPublicLine(b64urlToBuf(jwk.e), b64urlToBuf(jwk.n));
  return finish("keypair", value, publicPart, { alg, bits, format });
}

export function generateSecret(type: string, params: unknown): GeneratedSecret {
  if (type === "import") throw new GeneratorError("import is not available");
  const body = assertPlainParams(params);
  if (type === "token") return generateToken(body);
  if (type === "password") return generatePassword(body);
  if (type === "uuid") {
    unknownKeys(body, []);
    return generateUuid();
  }
  if (type === "keypair") return generateKeypair(body);
  throw new GeneratorError("secret type is invalid");
}
