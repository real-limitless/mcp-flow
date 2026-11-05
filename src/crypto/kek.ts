/**
 * KEK provider (Secrets §5.1 / §5.2).
 * Production sources are a mode-0400 file (host file or Docker secret mount) or a KMS hook.
 * The KEK is never read from the environment and never derived with HKDF.
 * wrap/unwrap take a 32-byte DEK only. Secret values are not passed to the provider.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { closeSync, openSync, readFileSync, statSync } from "node:fs";

const IV = 12;
const TAG = 16;
const KEY_LEN = 32;

export class KekError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KekError";
  }
}

export interface KekProvider {
  id(): string;
  wrap(dek: Buffer, aad: Buffer): Buffer;
  unwrap(wrapped: Buffer, aad: Buffer): Buffer;
}

/** KMS implementations wrap key material only. They must not be given a secret value. */
export interface KmsWrapHook {
  keyId: string;
  version: string;
  wrap(dek: Buffer, aad: Buffer): Buffer;
  unwrap(wrapped: Buffer, aad: Buffer): Buffer;
}

const KEK_ID = /^[a-z0-9][a-z0-9_.:-]{0,127}$/;

export function assertKekId(id: string): string {
  if (!KEK_ID.test(id)) throw new KekError("KEK id is not a provider id");
  return id;
}

function assertDek(dek: Buffer): void {
  if (dek.length !== KEY_LEN) throw new KekError("DEK must be 32 bytes");
}

export function gcmWrap(key: Buffer, dek: Buffer, aad: Buffer): Buffer {
  if (key.length !== KEY_LEN) throw new KekError("KEK must be 32 bytes");
  assertDek(dek);
  const iv = randomBytes(IV);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(dek), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

export function gcmUnwrap(key: Buffer, wrapped: Buffer, aad: Buffer): Buffer {
  if (key.length !== KEY_LEN) throw new KekError("KEK must be 32 bytes");
  if (wrapped.length < IV + TAG + KEY_LEN) throw new KekError("wrapped DEK is too short");
  const decipher = createDecipheriv("aes-256-gcm", key, wrapped.subarray(0, IV));
  decipher.setAAD(aad);
  decipher.setAuthTag(wrapped.subarray(IV, IV + TAG));
  const pt = Buffer.concat([decipher.update(wrapped.subarray(IV + TAG)), decipher.final()]);
  if (pt.length !== KEY_LEN) {
    pt.fill(0);
    throw new KekError("unwrapped DEK is the wrong length");
  }
  return pt;
}

function readKekFile(path: string): Buffer {
  let mode = 0;
  try {
    mode = statSync(path).mode & 0o777;
  } catch {
    throw new KekError("KEK file is missing");
  }
  if ((mode & 0o077) !== 0) throw new KekError("KEK file must be mode 0400");
  let fd: number | null = null;
  try {
    fd = openSync(path, "r");
    const buf = readFileSync(fd);
    if (buf.length !== KEY_LEN) {
      buf.fill(0);
      throw new KekError("KEK file must be 32 bytes");
    }
    return buf;
  } catch (err) {
    if (err instanceof KekError) throw err;
    throw new KekError("KEK file could not be read");
  } finally {
    if (fd != null) closeSync(fd);
  }
}

/**
 * File or Docker-secret KEK. The mount path stays on the host; id() is `file:kek:v1`.
 * Mode 0400 is required on every read (group/other bits refuse the file).
 */
export class FileKekProvider implements KekProvider {
  constructor(private readonly path: string) {}

  id(): string {
    return assertKekId("file:kek:v1");
  }

  wrap(dek: Buffer, aad: Buffer): Buffer {
    assertDek(dek);
    const kek = readKekFile(this.path);
    try {
      return gcmWrap(kek, dek, aad);
    } finally {
      kek.fill(0);
    }
  }

  unwrap(wrapped: Buffer, aad: Buffer): Buffer {
    const kek = readKekFile(this.path);
    try {
      return gcmUnwrap(kek, wrapped, aad);
    } finally {
      kek.fill(0);
    }
  }
}

/** Pluggable KMS. mcp-flow sends the DEK and AAD, never a secret value. */
export class KmsKekProvider implements KekProvider {
  private readonly keyId: string;

  constructor(private readonly hook: KmsWrapHook) {
    if (!/^[A-Za-z0-9_.:-]{1,64}$/.test(hook.keyId) || !/^[A-Za-z0-9_.:-]{1,32}$/.test(hook.version)) {
      throw new KekError("KMS key id is invalid");
    }
    this.keyId = assertKekId(`kms:${hook.keyId}:${hook.version}`);
  }

  id(): string {
    return this.keyId;
  }

  wrap(dek: Buffer, aad: Buffer): Buffer {
    assertDek(dek);
    const wrapped = this.hook.wrap(dek, aad);
    if (!Buffer.isBuffer(wrapped) || wrapped.length < IV + TAG + 1) throw new KekError("KMS wrap returned nothing");
    return wrapped;
  }

  unwrap(wrapped: Buffer, aad: Buffer): Buffer {
    const dek = this.hook.unwrap(wrapped, aad);
    if (!Buffer.isBuffer(dek)) throw new KekError("KMS unwrap failed");
    try {
      assertDek(dek);
    } catch (err) {
      dek.fill(0);
      throw err;
    }
    return dek;
  }
}
