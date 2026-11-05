/**
 * Per-version envelope (Secrets §5.2).
 * Value: AES-256-GCM under a fresh 256-bit DEK, AAD
 *   mcp-flow/secret/v1|workspace|project|secret|version
 * DEK: wrapped by the KEK, AAD
 *   mcp-flow/dek/v1|secret|version|kek_id
 * value_hmac uses the secrets-index purpose key, not the KEK.
 */

import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import type { KekProvider } from "../crypto/kek.js";
import { KekError } from "../crypto/kek.js";

const IV = 12;
const TAG = 16;

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

export function secretAad(workspaceId: string, projectId: string, secretId: string, version: number): Buffer {
  return Buffer.from(`mcp-flow/secret/v1|${workspaceId}|${projectId}|${secretId}|${version}`, "utf8");
}

export function dekAad(secretId: string, version: number, kekId: string): Buffer {
  return Buffer.from(`mcp-flow/dek/v1|${secretId}|${version}|${kekId}`, "utf8");
}

export function valueHmac(indexKey: Buffer, value: Buffer): string {
  if (indexKey.length !== 32) throw new EnvelopeError("secrets index key must be 32 bytes");
  return createHmac("sha256", indexKey).update(value).digest("hex");
}

function wipe(buf: Buffer): void {
  buf.fill(0);
}

export interface SealedSecret {
  ciphertext: Buffer;
  wrappedDek: Buffer;
  kekId: string;
  valueHmac: string;
}

export function sealSecretValue(
  kek: KekProvider,
  indexKey: Buffer,
  input: { workspaceId: string; projectId: string; secretId: string; version: number; value: Buffer },
): SealedSecret {
  const dek = randomBytes(32);
  try {
    const iv = randomBytes(IV);
    const cipher = createCipheriv("aes-256-gcm", dek, iv);
    cipher.setAAD(secretAad(input.workspaceId, input.projectId, input.secretId, input.version));
    const ct = Buffer.concat([cipher.update(input.value), cipher.final()]);
    const ciphertext = Buffer.concat([iv, cipher.getAuthTag(), ct]);
    const kekId = kek.id();
    let wrappedDek: Buffer;
    try {
      wrappedDek = kek.wrap(dek, dekAad(input.secretId, input.version, kekId));
    } catch (err) {
      if (err instanceof KekError) throw new EnvelopeError("KEK wrap failed");
      throw new EnvelopeError("KEK wrap failed");
    }
    return { ciphertext, wrappedDek, kekId, valueHmac: valueHmac(indexKey, input.value) };
  } finally {
    wipe(dek);
    wipe(input.value);
  }
}

/** Test and drill helper. Not an MCP or REST reveal. */
export function openSecretValue(
  kek: KekProvider,
  input: {
    workspaceId: string;
    projectId: string;
    secretId: string;
    version: number;
    ciphertext: Buffer;
    wrappedDek: Buffer;
    kekId: string;
  },
): Buffer {
  if (input.kekId !== kek.id()) throw new EnvelopeError("KEK id does not match");
  if (input.ciphertext.length < IV + TAG + 1) throw new EnvelopeError("ciphertext is too short");
  let dek: Buffer;
  try {
    dek = kek.unwrap(input.wrappedDek, dekAad(input.secretId, input.version, input.kekId));
  } catch {
    throw new EnvelopeError("KEK unwrap failed");
  }
  try {
    const decipher = createDecipheriv("aes-256-gcm", dek, input.ciphertext.subarray(0, IV));
    decipher.setAAD(secretAad(input.workspaceId, input.projectId, input.secretId, input.version));
    decipher.setAuthTag(input.ciphertext.subarray(IV, IV + TAG));
    return Buffer.concat([decipher.update(input.ciphertext.subarray(IV + TAG)), decipher.final()]);
  } catch {
    throw new EnvelopeError("secret ciphertext failed authentication");
  } finally {
    wipe(dek);
  }
}
