import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

/** Canonical JSON: object keys sorted recursively, no whitespace. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      out[k] = sortDeep((v as Record<string, unknown>)[k]);
    }
    return out;
  }
  return v;
}

/** Keyed args hash (HMAC-SHA256 hex) shared by call_audit and pending_call. */
export function argsHash(hmacKey: Buffer, args: unknown): string {
  return createHmac("sha256", hmacKey).update(canonicalJson(args ?? {}), "utf8").digest("hex");
}

const IV = 12;
const TAG = 16;

/** AES-256-GCM envelope for pending_call.args_ciphertext: iv | tag | ct. */
export function encryptArgs(key: Buffer, args: unknown): Buffer {
  const iv = randomBytes(IV);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(JSON.stringify(args ?? {}), "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), ct]);
}

export function decryptArgs(key: Buffer, blob: Uint8Array): Record<string, unknown> {
  const buf = Buffer.from(blob);
  const d = createDecipheriv("aes-256-gcm", key, buf.subarray(0, IV));
  d.setAuthTag(buf.subarray(IV, IV + TAG));
  const pt = Buffer.concat([d.update(buf.subarray(IV + TAG)), d.final()]);
  return JSON.parse(pt.toString("utf8")) as Record<string, unknown>;
}
