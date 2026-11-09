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
import { DatabaseSync } from "node:sqlite";
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
  /**
   * Mint a pepper only when the pepper file is absent.
   * Ignored when that file exists: an existing pepper is never rewritten.
   */
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

const WRAPPED_LEN = IV + TAG + KEY_LEN;

interface SealedFinding {
  label: string;
  purposes: readonly KeyringPurpose[];
}

/** Rows that a newly generated KEK or purpose key would not be able to open. */
const SEALED_QUERIES: readonly {
  table: string;
  where: string;
  label: string;
  purposes: readonly KeyringPurpose[];
}[] = [
  { table: "mcpflow_api_key", where: "1=1", label: "API key hashes", purposes: ["pepper"] },
  { table: "mcpflow_session", where: "1=1", label: "session token hashes", purposes: ["pepper"] },
  { table: "mcpflow_secret_version", where: "ciphertext IS NOT NULL OR wrapped_dek IS NOT NULL", label: "sealed secret versions", purposes: ["secrets-index", "secrets-data"] },
  { table: "mcpflow_call_payload", where: "ciphertext IS NOT NULL", label: "call payload ciphertext", purposes: ["audit-enc"] },
  { table: "mcpflow_pending_call", where: "args_ciphertext IS NOT NULL", label: "pending call ciphertext", purposes: ["args-enc", "args-hmac"] },
  { table: "mcpflow_call_outcome", where: "result_ciphertext IS NOT NULL", label: "call result ciphertext", purposes: ["result-enc"] },
];

function modeText(mode: number): string {
  return `0${mode.toString(8)}`;
}

function assertReadable(path: string, label: string): void {
  let fd: number | null = null;
  try {
    fd = openSync(path, "r");
  } catch {
    throw new KeyringError(`${label} at ${path} could not be read. Restore the escrowed file. Startup did not replace it.`);
  } finally {
    if (fd != null) closeSync(fd);
  }
}

/** Read-only check. Does not chmod or rewrite the file. */
function assertExistingKek(path: string): void {
  let st;
  try {
    st = statSync(path);
  } catch {
    throw new KeyringError(
      `KEK file at ${path} could not be read. Restore the escrowed 32-byte mode-0400 file at MCP_FLOW_KEK_FILE. Startup did not replace it. Do not set MCP_FLOW_KEK.`,
    );
  }
  if (!st.isFile()) {
    throw new KeyringError(
      `MCP_FLOW_KEK_FILE (${path}) is not a file. Restore the escrowed 32-byte mode-0400 file. Startup did not replace it. Do not set MCP_FLOW_KEK.`,
    );
  }
  const mode = st.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new KeyringError(
      `KEK file at ${path} is mode ${modeText(mode)}, which is not 0400. Restore a mode-0400 file at MCP_FLOW_KEK_FILE. Startup did not change this file. Do not set MCP_FLOW_KEK.`,
    );
  }
  if (st.size !== KEY_LEN) {
    throw new KeyringError(
      `KEK file at ${path} is ${st.size} bytes, not 32. Restore the escrowed 32-byte mode-0400 file at MCP_FLOW_KEK_FILE. Startup did not replace it. Do not set MCP_FLOW_KEK.`,
    );
  }
  assertReadable(path, "KEK file");
}

/** Read-only check for a wrapped purpose file, including pepper. Does not chmod or rewrite it. */
function assertExistingPurpose(path: string, purpose: string): void {
  let st;
  try {
    st = statSync(path);
  } catch {
    throw new KeyringError(
      `Keyring file ${purpose} at ${path} could not be read. Restore it from escrow into MCP_FLOW_KEYRING_DIR. Startup did not replace it.`,
    );
  }
  if (!st.isFile()) {
    throw new KeyringError(
      `Keyring file ${purpose} at ${path} is not a file. Restore it from escrow. Startup did not replace it.`,
    );
  }
  const mode = st.mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new KeyringError(
      `Keyring file ${purpose} at ${path} is mode ${modeText(mode)}, which is not 0400. Restore a mode-0400 file. Startup did not change it.`,
    );
  }
  if (st.size < WRAPPED_LEN) {
    throw new KeyringError(
      `Keyring file ${purpose} at ${path} is too short to be a wrapped key. Restore it from escrow. Startup did not replace it.`,
    );
  }
  assertReadable(path, `Keyring file ${purpose}`);
}

function assertKekUnwrapsPepper(dir: string, kekFile: string): void {
  const pepperPath = join(dir, "pepper");
  if (!existsSync(pepperPath)) return;
  const kek = readKek(kekFile, true);
  try {
    const key = unwrapPurposeKey(kek, "pepper", readFileSync(pepperPath));
    key.fill(0);
  } catch {
    throw new KeyringError(
      `KEK file at ${kekFile} does not unwrap keyring/pepper. Restore the escrowed 32-byte mode-0400 KEK that wrapped this keyring. Startup did not replace the KEK or the pepper.`,
    );
  } finally {
    kek.fill(0);
  }
}

function sealedFindings(dbPath: string | null | undefined): SealedFinding[] {
  if (!dbPath || dbPath === ":memory:" || !existsSync(dbPath)) return [];
  let db: DatabaseSync;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
  } catch {
    throw new KeyringError(
      `Could not read the database at MCP_FLOW_DB_PATH (${dbPath}). Refusing to generate a KEK or pepper. Restore the escrowed keyring and KEK, or use an empty data volume. Startup did not create a key.`,
    );
  }
  try {
    const found: SealedFinding[] = [];
    for (const query of SEALED_QUERIES) {
      const table = db.prepare(`SELECT 1 AS ok FROM sqlite_master WHERE type = 'table' AND name = ?`).get(query.table) as { ok: number } | undefined;
      if (!table) continue;
      const row = db.prepare(`SELECT count(*) AS n FROM ${query.table} WHERE ${query.where}`).get() as { n: number };
      if (Number(row.n) > 0) found.push({ label: query.label, purposes: query.purposes });
    }
    return found;
  } finally {
    db.close();
  }
}

/**
 * Production boot helper. Creates a missing keyring directory, a missing
 * mode-0400 32-byte KEK, and missing purpose files (including pepper) on a
 * safe first boot. Never overwrites an existing KEK, purpose file, or pepper.
 * newPepper is passed only when the pepper file is absent and minting it
 * cannot invalidate stored API key hashes. No key bytes are logged.
 */
export function ensureBootKeyring(opts: {
  production: boolean;
  keyringDir?: string | null;
  kekFile?: string | null;
  dbPath?: string | null;
  env?: NodeJS.ProcessEnv;
}): { created: string[]; pepper: "existing" | "carried" | "new" } | null {
  if (!opts.production) return null;
  assertProductionEnv(opts.env ?? process.env);
  if (!opts.keyringDir || !opts.kekFile) {
    throw new KeyringError(
      "production requires MCP_FLOW_KEYRING_DIR and MCP_FLOW_KEK_FILE (filesystem paths). When unset, a production process defaults them beside the data directory and creates a mode-0400 32-byte KEK if the file is missing. It does not overwrite an existing KEK and does not read key material from the environment. Leave MCP_FLOW_KEK unset.",
    );
  }
  const keyringDir = opts.keyringDir;
  const kekFile = opts.kekFile;
  if (existsSync(keyringDir) && !statSync(keyringDir).isDirectory()) {
    throw new KeyringError(
      `MCP_FLOW_KEYRING_DIR (${keyringDir}) exists and is not a directory. Startup did not replace it.`,
    );
  }
  const kekExists = existsSync(kekFile);
  if (kekExists) assertExistingKek(kekFile);
  if (existsSync(keyringDir)) {
    for (const purpose of KEYRING_PURPOSES) {
      const path = join(keyringDir, purpose);
      if (existsSync(path)) assertExistingPurpose(path, purpose);
    }
  }
  if (kekExists) assertKekUnwrapsPepper(keyringDir, kekFile);

  const findings = sealedFindings(opts.dbPath);
  const pepperPath = join(keyringDir, "pepper");
  const pepperExists = existsSync(pepperPath);
  if (!kekExists && (directoryHasEntries(keyringDir) || findings.length > 0)) {
    const why = [
      directoryHasEntries(keyringDir) ? `keyring directory ${keyringDir} is not empty` : null,
      ...findings.map((finding) => finding.label),
    ].filter((item): item is string => item != null);
    throw new KeyringError(
      `Refusing to mint a new KEK at ${kekFile} because existing material would not match a new key (${why.join("; ")}). Restore the escrowed 32-byte mode-0400 KEK to MCP_FLOW_KEK_FILE and the keyring directory, including pepper, to MCP_FLOW_KEYRING_DIR. Leave MCP_FLOW_KEK unset. Startup did not create a key.`,
    );
  }
  if (!pepperExists) {
    const pepperBlocks = findings.filter((finding) => finding.purposes.includes("pepper"));
    if (pepperBlocks.length) {
      throw new KeyringError(
        `Refusing to create a pepper in ${keyringDir} because ${pepperBlocks.map((finding) => finding.label).join("; ")} already exist and a new pepper would not match them. Restore the pepper file from escrow into MCP_FLOW_KEYRING_DIR. Startup did not create or rotate a pepper.`,
      );
    }
  }
  for (const purpose of KEYRING_PURPOSES) {
    if (purpose === "pepper" || existsSync(join(keyringDir, purpose))) continue;
    const blocks = findings.filter((finding) => finding.purposes.includes(purpose));
    if (!blocks.length) continue;
    throw new KeyringError(
      `Refusing to create keyring file ${purpose} in ${keyringDir} because ${blocks.map((finding) => finding.label).join("; ")} already exist and a new key would not decrypt them. Restore that file from escrow. Startup did not replace keyring files.`,
    );
  }

  let out: { created: string[]; pepper: "existing" | "carried" | "new" };
  try {
    out = initKeyring({
      dir: keyringDir,
      kekFile,
      newPepper: !pepperExists,
      production: true,
    });
  } catch (err) {
    if (err instanceof KeyringError) throw err;
    const detail = err instanceof Error ? err.message : "unknown error";
    throw new KeyringError(
      `could not create the keyring at ${keyringDir} (KEK ${kekFile}): ${detail}. The directory must be writable by the gateway user. The KEK file is mode 0400 and is not stored in the environment.`,
    );
  }
  if (out.created.length) {
    console.error(
      `[mcp-flow] keyring bootstrap created ${out.created.join(", ")} under ${keyringDir} (KEK ${kekFile}, values not logged)`,
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
