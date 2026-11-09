/**
 * Per-purpose keyring (Secrets §0.1 / §5.1, A1).
 * Production reads purpose keys from a directory of files wrapped by a KEK file.
 * It refuses environment keys and any HKDF derivation, including MCP_FLOW_POLICY_DEV_KEY
 * and the API-key pepper. Dev keeps the HKDF dev-v1 keys.
 * Pepper carry-over writes the current derived pepper into the keyring once so existing
 * key hashes stay valid. A dev-v1 slot, when sealed, is decrypt-only for at most 24h.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, statSync, writeSync } from "node:fs";
import { join } from "node:path";
import { decryptArgs } from "../policy/crypto.js";
import { derivePolicyKeys, DEV_KEY_REF, type LegacyKeySlot, type PolicyKeys } from "../identity/dev-keys.js";

export const KEYRING_VERSION = "kr-v1";
export const DEV_DECRYPT_WINDOW_MS = 24 * 60 * 60 * 1000;

export const KEYRING_PURPOSES = [
  "pepper",
  "args-hmac",
  "args-enc",
  "result-enc",
  "audit-enc",
  "secrets-index",
  "secrets-data",
] as const;

export type KeyringPurpose = (typeof KEYRING_PURPOSES)[number];

/** Env names production refuses. The values are never read as key material. */
export const PRODUCTION_REFUSED_ENV = [
  "MCP_FLOW_POLICY_DEV_KEY",
  "MCP_FLOW_PEPPER",
  "MCP_FLOW_KEK",
  "MCP_FLOW_ARGS_HMAC_KEY",
  "MCP_FLOW_ARGS_ENC_KEY",
  "MCP_FLOW_RESULT_ENC_KEY",
  "MCP_FLOW_AUDIT_ENC_KEY",
  "MCP_FLOW_SECRETS_INDEX_KEY",
  "MCP_FLOW_SECRETS_DATA_KEY",
] as const;

const IV = 12;
const TAG = 16;
const KEY_LEN = 32;

export class KeyringError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyringError";
  }
}

export function assertProductionEnv(env: NodeJS.ProcessEnv): void {
  const set = PRODUCTION_REFUSED_ENV.filter((name) => {
    const value = env[name];
    return value != null && value !== "";
  });
  if (set.length) {
    throw new KeyringError(`production refuses env key material: ${set.join(", ")}`);
  }
}

function aad(purpose: string, version: string): Buffer {
  return Buffer.from(`mcp-flow/keyring/v1|${purpose}|${version}`, "utf8");
}

export function wrapPurposeKey(kek: Buffer, purpose: string, key: Buffer, version = KEYRING_VERSION): Buffer {
  if (kek.length !== KEY_LEN || key.length !== KEY_LEN) throw new KeyringError("key material must be 32 bytes");
  const iv = randomBytes(IV);
  const cipher = createCipheriv("aes-256-gcm", kek, iv);
  cipher.setAAD(aad(purpose, version));
  const ct = Buffer.concat([cipher.update(key), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

export function unwrapPurposeKey(kek: Buffer, purpose: string, blob: Buffer, version = KEYRING_VERSION): Buffer {
  if (kek.length !== KEY_LEN || blob.length < IV + TAG + KEY_LEN) throw new KeyringError(`keyring purpose ${purpose} is too short`);
  const decipher = createDecipheriv("aes-256-gcm", kek, blob.subarray(0, IV));
  decipher.setAAD(aad(purpose, version));
  decipher.setAuthTag(blob.subarray(IV, IV + TAG));
  const pt = Buffer.concat([decipher.update(blob.subarray(IV + TAG)), decipher.final()]);
  if (pt.length !== KEY_LEN) throw new KeyringError(`keyring purpose ${purpose} is the wrong length`);
  return pt;
}

function readKeyFile(path: string, production: boolean): Buffer {
  if (!existsSync(path)) throw new KeyringError(`keyring file missing: ${purposeName(path)}`);
  if (production) {
    const mode = statSync(path).mode & 0o777;
    if ((mode & 0o077) !== 0) throw new KeyringError(`keyring file ${purposeName(path)} must be mode 0400`);
  }
  return readFileSync(path);
}

function purposeName(path: string): string {
  const parts = path.split(/[/\\]/);
  return parts.slice(-2).join("/");
}

function writeKeyFile(path: string, body: Buffer): void {
  const fd = openSync(path, "wx", 0o400);
  try {
    writeSync(fd, body);
  } finally {
    closeSync(fd);
  }
  chmodSync(path, 0o400);
}

function sameKey(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

function loadPurpose(dir: string, kek: Buffer, purpose: KeyringPurpose, production: boolean, version: string): Buffer {
  const path = join(dir, purpose);
  let blob: Buffer;
  try {
    blob = readKeyFile(path, production);
  } catch (err) {
    if (err instanceof KeyringError) throw err;
    throw new KeyringError(`keyring purpose ${purpose} could not be read`);
  }
  try {
    return unwrapPurposeKey(kek, purpose, blob, version);
  } catch (err) {
    if (err instanceof KeyringError) throw err;
    throw new KeyringError(`keyring purpose ${purpose} failed authentication`);
  }
}

function readKek(path: string, production: boolean): Buffer {
  const buf = readKeyFile(path, production);
  if (buf.length !== KEY_LEN) throw new KeyringError("KEK file must be 32 bytes");
  return buf;
}

export interface LoadKeyringOptions {
  production: boolean;
  keyringDir?: string | null;
  kekFile?: string | null;
  /** Dev only. Ignored, and refused, when production is set. */
  devMaterial?: string | null;
  env?: NodeJS.ProcessEnv;
  now?: number;
}

export function loadPolicyKeys(opts: LoadKeyringOptions): PolicyKeys {
  const env = opts.env ?? process.env;
  if (opts.production) {
    assertProductionEnv(env);
    if (opts.devMaterial) throw new KeyringError("production refuses a derived or dev policy key");
    if (!opts.keyringDir) throw new KeyringError("production requires MCP_FLOW_KEYRING_DIR");
    if (!opts.kekFile) throw new KeyringError("production requires MCP_FLOW_KEK_FILE");
    return loadWrapped(opts.keyringDir, opts.kekFile, true, opts.now ?? Date.now());
  }
  if (opts.keyringDir && opts.kekFile && existsSync(opts.keyringDir)) {
    return loadWrapped(opts.keyringDir, opts.kekFile, false, opts.now ?? Date.now());
  }
  if (!opts.devMaterial) throw new KeyringError("policy dev key material is required");
  return derivePolicyKeys(opts.devMaterial);
}

function loadWrapped(dir: string, kekFile: string, production: boolean, now: number): PolicyKeys {
  const kek = readKek(kekFile, production);
  const versionPath = join(dir, "version");
  const version = existsSync(versionPath) ? readFileSync(versionPath, "utf8").trim() || KEYRING_VERSION : KEYRING_VERSION;
  const material = new Map<KeyringPurpose, Buffer>();
  for (const purpose of KEYRING_PURPOSES) {
    material.set(purpose, loadPurpose(dir, kek, purpose, production, version));
  }
  const values = [...material.values()];
  for (let i = 0; i < values.length; i++) {
    for (let j = i + 1; j < values.length; j++) {
      if (sameKey(values[i]!, values[j]!)) throw new KeyringError("keyring purpose keys must not be reused");
    }
  }
  const keys: PolicyKeys = {
    pepper: material.get("pepper")!,
    argsHmac: material.get("args-hmac")!,
    argsEnc: material.get("args-enc")!,
    resultEnc: material.get("result-enc")!,
    auditEnc: material.get("audit-enc")!,
    secretsIndex: material.get("secrets-index")!,
    keyRef: version,
    legacy: loadDevSlot(dir, kek, production, now),
  };
  return keys;
}

function loadDevSlot(dir: string, kek: Buffer, production: boolean, now: number): Map<string, LegacyKeySlot> | undefined {
  const slotDir = join(dir, "dev-v1");
  const untilPath = join(slotDir, "until");
  if (!existsSync(untilPath)) return undefined;
  const until = Date.parse(readFileSync(untilPath, "utf8").trim());
  if (!Number.isFinite(until)) throw new KeyringError("dev-v1 until is not a timestamp");
  if (now > until) {
    if (production) throw new KeyringError("dev-v1 decrypt window has closed");
    return undefined;
  }
  const slot: LegacyKeySlot = {
    until,
    pepper: unwrapPurposeKey(kek, "pepper", readKeyFile(join(slotDir, "pepper"), production), DEV_KEY_REF),
    argsHmac: unwrapPurposeKey(kek, "args-hmac", readKeyFile(join(slotDir, "args-hmac"), production), DEV_KEY_REF),
    argsEnc: unwrapPurposeKey(kek, "args-enc", readKeyFile(join(slotDir, "args-enc"), production), DEV_KEY_REF),
    resultEnc: unwrapPurposeKey(kek, "result-enc", readKeyFile(join(slotDir, "result-enc"), production), DEV_KEY_REF),
    auditEnc: unwrapPurposeKey(kek, "audit-enc", readKeyFile(join(slotDir, "audit-enc"), production), DEV_KEY_REF),
  };
  return new Map([[DEV_KEY_REF, slot]]);
}

export interface KeyringInitOptions {
  dir: string;
  kekFile: string;
  /** Mint a new pepper. Refused when a pepper file already exists. */
  newPepper?: boolean;
  /** Dev material used only by carry-pepper, never in production. */
  devMaterial?: string | null;
  /** Production refuses carrying a derived pepper. */
  production?: boolean;
  now?: Date;
}

function ensureKek(path: string): Buffer {
  if (existsSync(path)) return readKek(path, true);
  mkdirSync(join(path, ".."), { recursive: true });
  writeKeyFile(path, randomBytes(KEY_LEN));
  return readKek(path, true);
}

function directoryHasEntries(dir: string): boolean {
  if (!existsSync(dir)) return false;
  return readdirSync(dir).length > 0;
}

/** Create missing purpose files. Does not overwrite. Pepper is carried or minted, never derived in production. */
export function initKeyring(opts: KeyringInitOptions): { created: string[]; pepper: "existing" | "carried" | "new" } {
  if (opts.production && opts.devMaterial) throw new KeyringError("production refuses a derived pepper");
  if (!existsSync(opts.kekFile) && directoryHasEntries(opts.dir)) {
    throw new KeyringError(
      `KEK file missing at ${opts.kekFile} but ${opts.dir} is not empty. Refusing to mint a new KEK. Restore the mode-0400 32-byte KEK file, or use an empty directory for a fresh install.`,
    );
  }
  mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
  chmodSync(opts.dir, 0o700);
  const kek = ensureKek(opts.kekFile);
  const versionPath = join(opts.dir, "version");
  if (!existsSync(versionPath)) writeKeyFile(versionPath, Buffer.from(`${KEYRING_VERSION}\n`, "utf8"));
  const created: string[] = [];
  let pepper: "existing" | "carried" | "new" = "existing";
  const pepperPath = join(opts.dir, "pepper");
  if (!existsSync(pepperPath)) {
    if (opts.devMaterial) {
      const derived = derivePolicyKeys(opts.devMaterial).pepper;
      writeKeyFile(pepperPath, wrapPurposeKey(kek, "pepper", derived));
      pepper = "carried";
      created.push("pepper");
    } else if (opts.newPepper) {
      writeKeyFile(pepperPath, wrapPurposeKey(kek, "pepper", randomBytes(KEY_LEN)));
      pepper = "new";
      created.push("pepper");
    } else {
      throw new KeyringError("pepper is missing; carry the current pepper or pass newPepper for a fresh install");
    }
  }
  for (const purpose of KEYRING_PURPOSES) {
    if (purpose === "pepper") continue;
    const path = join(opts.dir, purpose);
    if (existsSync(path)) continue;
    writeKeyFile(path, wrapPurposeKey(kek, purpose, randomBytes(KEY_LEN)));
    created.push(purpose);
  }
  return { created, pepper };
}

/**
 * Production boot helper. Creates the keyring directory and a mode-0400 32-byte KEK
 * when the file is missing, then fills any missing purpose files. Does not overwrite
 * an existing KEK or purpose file. No key bytes are logged.
 */
export function ensureBootKeyring(opts: {
  production: boolean;
  keyringDir?: string | null;
  kekFile?: string | null;
}): { created: string[]; pepper: "existing" | "carried" | "new" } | null {
  if (!opts.production) return null;
  if (!opts.keyringDir || !opts.kekFile) {
    throw new KeyringError(
      "production requires MCP_FLOW_KEYRING_DIR and MCP_FLOW_KEK_FILE (filesystem paths). When unset, a production process defaults them beside the data directory and creates a mode-0400 32-byte KEK if the file is missing. It does not overwrite an existing KEK and does not read key material from the environment.",
    );
  }
  let out: { created: string[]; pepper: "existing" | "carried" | "new" };
  try {
    out = initKeyring({
      dir: opts.keyringDir,
      kekFile: opts.kekFile,
      newPepper: true,
      production: true,
    });
  } catch (err) {
    if (err instanceof KeyringError) throw err;
    const detail = err instanceof Error ? err.message : "unknown error";
    throw new KeyringError(
      `could not create the keyring at ${opts.keyringDir} (KEK ${opts.kekFile}): ${detail}. The directory must be writable by the gateway user. The KEK file is mode 0400 and is not stored in the environment.`,
    );
  }
  if (out.created.length) {
    console.error(
      `[mcp-flow] keyring init created ${out.created.join(", ")} under ${opts.keyringDir} (KEK ${opts.kekFile}, values not logged)`,
    );
  }
  return out;
}

/**
 * Export the current derived API-key pepper into the keyring once.
 * Refuses to overwrite a different pepper. Refuses when production is set.
 */
export function carryPepper(opts: {
  dir: string;
  kekFile: string;
  devMaterial: string;
  production?: boolean;
}): { wrote: boolean } {
  if (opts.production) throw new KeyringError("production refuses a derived pepper");
  const pepper = derivePolicyKeys(opts.devMaterial).pepper;
  mkdirSync(opts.dir, { recursive: true, mode: 0o700 });
  const kek = ensureKek(opts.kekFile);
  const path = join(opts.dir, "pepper");
  if (existsSync(path)) {
    const current = unwrapPurposeKey(kek, "pepper", readFileSync(path));
    if (!sameKey(current, pepper)) throw new KeyringError("pepper file already exists and does not match the derived pepper");
    return { wrote: false };
  }
  writeKeyFile(path, wrapPurposeKey(kek, "pepper", pepper));
  return { wrote: true };
}

/** Seal dev-v1 keys for decrypt-only use until now+24h. One shot. */
export function sealDevDecryptSlot(opts: { dir: string; kekFile: string; devMaterial: string; now?: Date; production?: boolean }): { until: string } {
  if (opts.production) throw new KeyringError("production refuses a dev decrypt slot");
  const now = opts.now ?? new Date();
  const until = new Date(now.getTime() + DEV_DECRYPT_WINDOW_MS);
  const slotDir = join(opts.dir, "dev-v1");
  if (existsSync(join(slotDir, "until"))) throw new KeyringError("dev-v1 slot already sealed");
  mkdirSync(slotDir, { recursive: true, mode: 0o700 });
  chmodSync(slotDir, 0o700);
  const kek = readKek(opts.kekFile, true);
  const dev = derivePolicyKeys(opts.devMaterial);
  const files: Array<[string, Buffer]> = [
    ["pepper", dev.pepper],
    ["args-hmac", dev.argsHmac],
    ["args-enc", dev.argsEnc],
    ["result-enc", dev.resultEnc],
    ["audit-enc", dev.auditEnc],
  ];
  for (const [purpose, key] of files) {
    writeKeyFile(join(slotDir, purpose), wrapPurposeKey(kek, purpose, key, DEV_KEY_REF));
  }
  writeKeyFile(join(slotDir, "until"), Buffer.from(`${until.toISOString()}\n`, "utf8"));
  return { until: until.toISOString() };
}

export function decryptForKey(
  keys: PolicyKeys,
  purpose: "args" | "result",
  blob: Uint8Array,
  keyRef: string | null,
  now = Date.now(),
): Record<string, unknown> {
  const pick = (slot: { argsEnc: Buffer; resultEnc: Buffer }) => (purpose === "args" ? slot.argsEnc : slot.resultEnc);
  const attempts: Buffer[] = [];
  if (keyRef == null || keyRef === keys.keyRef) {
    attempts.push(pick(keys));
    if (keyRef == null && keys.legacy) {
      for (const slot of keys.legacy.values()) {
        if (now <= slot.until) attempts.push(pick(slot));
      }
    }
  } else {
    const slot = keys.legacy?.get(keyRef);
    if (!slot) throw new KeyringError("unknown key ref");
    if (now > slot.until) throw new KeyringError("dev-v1 decrypt window has closed");
    attempts.push(pick(slot));
  }
  let last: unknown;
  for (const key of attempts) {
    try {
      return decryptArgs(key, blob);
    } catch (err) {
      last = err;
    }
  }
  throw last instanceof Error ? last : new KeyringError("decrypt failed");
}
