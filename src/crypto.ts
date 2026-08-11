import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

const KEY_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const TOKEN_BYTES = 32;
const TOKEN_PREFIX = "mf_";

/** Derive a 32-byte AES key from env material (base64, hex, or passphrase). */
export function deriveMasterKey(raw: string): Buffer {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error("master key is empty");
  }

  // 64 hex chars
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, "hex");
  }

  // base64 / base64url that decodes to 32 bytes
  try {
    const b64 = Buffer.from(
      trimmed.replace(/-/g, "+").replace(/_/g, "/"),
      "base64",
    );
    if (b64.length === KEY_LEN) return b64;
  } catch {
    // fall through
  }

  // passphrase → scrypt
  return scryptSync(trimmed, "mcp-flow-v1", KEY_LEN);
}

/** Seal JSON-serializable secrets: base64(iv || tag || ciphertext) */
export function seal(masterKey: Buffer, value: unknown): string {
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", masterKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

export function unseal<T = unknown>(masterKey: Buffer, blob: string): T {
  const buf = Buffer.from(blob, "base64");
  if (buf.length < IV_LEN + TAG_LEN + 1) {
    throw new Error("invalid sealed blob");
  }
  const iv = buf.subarray(0, IV_LEN);
  const tag = buf.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ciphertext = buf.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv("aes-256-gcm", masterKey, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return JSON.parse(plaintext.toString("utf8")) as T;
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function mintApiToken(): { token: string; prefix: string; hash: string } {
  const secret = randomBytes(TOKEN_BYTES).toString("base64url");
  const token = `${TOKEN_PREFIX}${secret}`;
  const prefix = token.slice(0, 10);
  return { token, prefix, hash: hashToken(token) };
}

export function safeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(12).toString("hex")}`;
}
