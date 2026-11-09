/** Secrets A1 §0.1: production refuses env and HKDF keys. Pepper carry-over is one-shot. */
import { randomBytes } from "node:crypto";
import { chmodSync, closeSync, existsSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, unlinkSync, writeSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import {
  carryPepper,
  ensureBootKeyring,
  initKeyring,
  loadPolicyKeys,
  sealDevDecryptSlot,
  unwrapPurposeKey,
  wrapPurposeKey,
  decryptForKey,
} from "../src/crypto/keyring.js";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { derivePolicyKeys, DEV_KEY_REF } from "../src/identity/dev-keys.js";
import { encryptArgs } from "../src/policy/crypto.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function scratch(): { dir: string; kekFile: string } {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-keyring-"));
  dirs.push(dir);
  return { dir: join(dir, "ring"), kekFile: join(dir, "kek") };
}

function write0400(path: string, body: Buffer): void {
  try {
    unlinkSync(path);
  } catch {
    /* first write */
  }
  const fd = openSync(path, "wx", 0o400);
  try {
    writeSync(fd, body);
  } finally {
    closeSync(fd);
  }
  chmodSync(path, 0o400);
}

describe("production key refusal", () => {
  it("refuses env keys, HKDF material, and a missing keyring", () => {
    expect(() => loadPolicyKeys({ production: true, env: { MCP_FLOW_POLICY_DEV_KEY: "x" }, keyringDir: "/none", kekFile: "/none" })).toThrow(/MCP_FLOW_POLICY_DEV_KEY/);
    expect(() => loadPolicyKeys({ production: true, env: { MCP_FLOW_PEPPER: "x" }, keyringDir: "/none", kekFile: "/none" })).toThrow(/MCP_FLOW_PEPPER/);
    expect(() => loadPolicyKeys({ production: true, env: { MCP_FLOW_KEK: "x" }, keyringDir: "/none", kekFile: "/none" })).toThrow(/MCP_FLOW_KEK/);
    expect(() => loadPolicyKeys({ production: true, env: {}, devMaterial: "dev-material", keyringDir: "/none", kekFile: "/none" })).toThrow(/derived or dev/);
    expect(() => loadPolicyKeys({ production: true, env: {}, keyringDir: null, kekFile: null })).toThrow(/MCP_FLOW_KEYRING_DIR/);
    const root = mkdtempSync(join(tmpdir(), "mcp-flow-store-prod-"));
    dirs.push(root);
    expect(() => new Store(join(root, "t.db"), Buffer.alloc(32, 4).toString("base64"), { production: true, policyDevKeyRaw: "dev" })).toThrow(/derived or dev/);
  });

  it("loadConfig records production without requiring a keyring directory", () => {
    const cfg = loadConfig({ dbPath: ":memory:", masterKeyRaw: "x", production: true, keyringDir: null, kekFile: null, policyDevKeyRaw: undefined });
    expect(cfg.production).toBe(true);
    expect(cfg.keyringDir).toBeNull();
    expect(cfg.kekFile).toBeNull();
  });

  it("carries the derived pepper once and refuses a short KEK, a reused purpose key, and a second pepper", () => {
    const { dir, kekFile } = scratch();
    const material = "pepper-carry-material";
    const derived = derivePolicyKeys(material);
    const init = initKeyring({ dir, kekFile, devMaterial: material });
    expect(init.pepper).toBe("carried");
    const keys = loadPolicyKeys({ production: true, env: {}, keyringDir: dir, kekFile });
    expect(keys.pepper.equals(derived.pepper)).toBe(true);
    expect(keys.argsHmac.equals(derived.argsHmac)).toBe(false);
    expect(keys.keyRef).toBe("kr-v1");
    expect(carryPepper({ dir, kekFile, devMaterial: material }).wrote).toBe(false);
    expect(() => carryPepper({ dir, kekFile, devMaterial: "other-material" })).toThrow(/does not match/);
    expect(() => carryPepper({ dir, kekFile, devMaterial: material, production: true })).toThrow(/production refuses a derived pepper/);
    expect(() => initKeyring({ dir, kekFile, devMaterial: material, production: true })).toThrow(/production refuses a derived pepper/);

    write0400(kekFile, randomBytes(16));
    expect(() => loadPolicyKeys({ production: true, env: {}, keyringDir: dir, kekFile })).toThrow(/32 bytes/);

    initKeyring({ dir: join(dir, "..", "fresh"), kekFile: join(dir, "..", "fresh-kek"), newPepper: true });
    const freshDir = join(dir, "..", "fresh");
    const freshKek = readFileSync(join(dir, "..", "fresh-kek"));
    const shared = randomBytes(32);
    write0400(join(freshDir, "args-hmac"), wrapPurposeKey(freshKek, "args-hmac", shared));
    write0400(join(freshDir, "args-enc"), wrapPurposeKey(freshKek, "args-enc", shared));
    expect(() => loadPolicyKeys({ production: true, env: {}, keyringDir: freshDir, kekFile: join(dir, "..", "fresh-kek") })).toThrow(/must not be reused/);
    expect(unwrapPurposeKey(freshKek, "args-hmac", readFileSync(join(freshDir, "args-hmac"))).equals(shared)).toBe(true);
  });

  it("seals a 24h dev-v1 decrypt slot and refuses it after the window, including in production", () => {
    const { dir, kekFile } = scratch();
    const material = "slot-material";
    const dev = derivePolicyKeys(material);
    initKeyring({ dir, kekFile, newPepper: true });
    const until = sealDevDecryptSlot({ dir, kekFile, devMaterial: material, now: new Date("2026-01-01T00:00:00.000Z") });
    expect(until.until).toBe("2026-01-02T00:00:00.000Z");
    const inside = Date.parse("2026-01-01T12:00:00.000Z");
    const keys = loadPolicyKeys({ production: true, env: {}, keyringDir: dir, kekFile, now: inside });
    expect(keys.legacy?.has(DEV_KEY_REF)).toBe(true);
    const blob = encryptArgs(dev.argsEnc, { a: 1 });
    expect(decryptForKey(keys, "args", blob, DEV_KEY_REF, inside)).toEqual({ a: 1 });
    expect(() => loadPolicyKeys({ production: true, env: {}, keyringDir: dir, kekFile, now: Date.parse("2026-01-03T00:00:00.000Z") })).toThrow(/window has closed/);
    expect(() => sealDevDecryptSlot({ dir, kekFile, devMaterial: material, production: true })).toThrow(/production refuses a dev decrypt slot/);
  });

  it("mints a mode-0400 KEK on first production boot and does not replace it", () => {
    const { dir, kekFile } = scratch();
    const lines: string[] = [];
    const orig = console.error;
    console.error = (...args: unknown[]) => {
      lines.push(args.map(String).join(" "));
    };
    try {
      const first = ensureBootKeyring({ production: true, keyringDir: dir, kekFile });
      expect(first?.pepper).toBe("new");
      expect(first?.created).toContain("pepper");
    } finally {
      console.error = orig;
    }
    const kek = readFileSync(kekFile);
    expect(kek.length).toBe(32);
    expect(statSync(kekFile).mode & 0o777).toBe(0o400);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    const text = lines.join("\n");
    expect(text).toContain("values not logged");
    expect(text).not.toContain(kek.toString("base64"));
    expect(text).not.toContain(kek.toString("hex"));
    const keys = loadPolicyKeys({ production: true, env: {}, keyringDir: dir, kekFile });
    const second = ensureBootKeyring({ production: true, keyringDir: dir, kekFile });
    expect(second?.created).toEqual([]);
    expect(readFileSync(kekFile).equals(kek)).toBe(true);
    const again = loadPolicyKeys({ production: true, env: {}, keyringDir: dir, kekFile });
    expect(again.pepper.equals(keys.pepper)).toBe(true);
  });

  it("refuses to mint a KEK when keyring files already exist", () => {
    const { dir, kekFile } = scratch();
    ensureBootKeyring({ production: true, keyringDir: dir, kekFile });
    unlinkSync(kekFile);
    expect(() => ensureBootKeyring({ production: true, keyringDir: dir, kekFile })).toThrow(/Refusing to mint a new KEK/);
    expect(existsSync(kekFile)).toBe(false);
  });

  it("does not mint a keyring outside production and names missing production paths", () => {
    const { dir, kekFile } = scratch();
    expect(ensureBootKeyring({ production: false, keyringDir: dir, kekFile })).toBeNull();
    expect(existsSync(kekFile)).toBe(false);
    expect(() => ensureBootKeyring({ production: true, keyringDir: null, kekFile: null })).toThrow(/MCP_FLOW_KEYRING_DIR/);
  });

  it("opens a production store by creating a missing keyring", () => {
    const root = mkdtempSync(join(tmpdir(), "mcp-flow-store-boot-"));
    dirs.push(root);
    const dir = join(root, "keyring");
    const kekFile = join(root, "kek");
    const master = Buffer.alloc(32, 7).toString("base64");
    const store = new Store(join(root, "t.db"), master, { production: true, keyringDir: dir, kekFile });
    const pepper = Buffer.from(store.policyKeys.pepper);
    store.close();
    const kek = readFileSync(kekFile);
    expect(kek.length).toBe(32);
    const again = new Store(join(root, "t.db"), master, { production: true, keyringDir: dir, kekFile });
    expect(Buffer.from(again.policyKeys.pepper).equals(pepper)).toBe(true);
    expect(readFileSync(kekFile).equals(kek)).toBe(true);
    again.close();
  });

  it("defaults production keyring paths beside the data directory", () => {
    const names = ["MCP_FLOW_KEYRING_DIR", "MCP_FLOW_KEK_FILE", "MCP_FLOW_DATA_DIR", "MCP_FLOW_PRODUCTION"] as const;
    const prev = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    const root = mkdtempSync(join(tmpdir(), "mcp-flow-cfg-"));
    dirs.push(root);
    try {
      for (const name of names) delete process.env[name];
      const db = join(root, "mcp-flow.db");
      const prod = loadConfig({ dbPath: db, masterKeyRaw: "x", adminToken: "y", production: true });
      expect(prod.keyringDir).toBe(join(root, "keyring"));
      expect(prod.kekFile).toBe(join(root, "kek"));
      const dev = loadConfig({ dbPath: db, masterKeyRaw: "x", adminToken: "y", production: false });
      expect(dev.keyringDir).toBeNull();
      expect(dev.kekFile).toBeNull();
      process.env.MCP_FLOW_DATA_DIR = join(root, "vol");
      const fromData = loadConfig({ dbPath: db, masterKeyRaw: "x", adminToken: "y", production: true });
      expect(fromData.keyringDir).toBe(join(root, "vol", "keyring"));
      expect(fromData.kekFile).toBe(join(root, "vol", "kek"));
      process.env.MCP_FLOW_KEYRING_DIR = join(root, "custom-ring");
      process.env.MCP_FLOW_KEK_FILE = join(root, "custom-kek");
      const explicit = loadConfig({ dbPath: db, masterKeyRaw: "x", adminToken: "y", production: true });
      expect(explicit.keyringDir).toBe(join(root, "custom-ring"));
      expect(explicit.kekFile).toBe(join(root, "custom-kek"));
    } finally {
      for (const name of names) {
        if (prev[name] === undefined) delete process.env[name];
        else process.env[name] = prev[name];
      }
    }
  });

  it("creates a missing pepper without rewriting an existing KEK, and leaves both in place on restart", () => {
    const { dir, kekFile } = scratch();
    ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: {} });
    const kek = snap(kekFile);
    const pepperPath = join(dir, "pepper");
    unlinkSync(pepperPath);
    const created = ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: {} });
    expect(created?.pepper).toBe("new");
    expect(created?.created).toContain("pepper");
    expect(snap(kekFile)).toEqual(kek);
    const pepper = snap(pepperPath);
    expect(pepper.mode).toBe(0o400);
    expect(pepper.bytes.length).toBeGreaterThanOrEqual(60);
    const again = ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: {} });
    expect(again?.pepper).toBe("existing");
    expect(again?.created).toEqual([]);
    expect(snap(pepperPath)).toEqual(pepper);
    expect(snap(kekFile)).toEqual(kek);
    const rotated = initKeyring({ dir, kekFile, newPepper: true, production: true });
    expect(rotated.pepper).toBe("existing");
    expect(snap(pepperPath)).toEqual(pepper);
    expect(snap(kekFile)).toEqual(kek);
  });

  it("refuses a new pepper when API key hashes exist and does not retry into a write", () => {
    const { dir, kekFile } = scratch();
    const body = randomBytes(32);
    write0400(kekFile, body);
    const kek = snap(kekFile);
    const dbPath = join(dirname(kekFile), "hashes.db");
    const db = new DatabaseSync(dbPath);
    db.exec("CREATE TABLE mcpflow_api_key (id TEXT)");
    db.exec("INSERT INTO mcpflow_api_key (id) VALUES ('key_existing')");
    db.close();
    const boot = () => ensureBootKeyring({ production: true, keyringDir: dir, kekFile, dbPath, env: {} });
    expect(boot).toThrow(/Refusing to create a pepper/);
    expect(existsSync(join(dir, "pepper"))).toBe(false);
    expect(snap(kekFile)).toEqual(kek);
    expect(boot).toThrow(/Refusing to create a pepper/);
    expect(existsSync(join(dir, "pepper"))).toBe(false);
    expect(snap(kekFile)).toEqual(kek);
  });

  it("refuses a new KEK when ciphertext already exists and does not create the file", () => {
    const { dir, kekFile } = scratch();
    const dbPath = join(dirname(kekFile), "sealed.db");
    const db = new DatabaseSync(dbPath);
    db.exec("CREATE TABLE mcpflow_secret_version (ciphertext BLOB, wrapped_dek BLOB)");
    db.exec("INSERT INTO mcpflow_secret_version (ciphertext, wrapped_dek) VALUES (X'00', X'01')");
    db.close();
    const boot = () => ensureBootKeyring({ production: true, keyringDir: dir, kekFile, dbPath, env: {} });
    expect(boot).toThrow(/Refusing to mint a new KEK/);
    expect(existsSync(kekFile)).toBe(false);
    expect(existsSync(dir)).toBe(false);
    expect(boot).toThrow(/Refusing to mint a new KEK/);
    expect(existsSync(kekFile)).toBe(false);
  });

  it("leaves an unusable KEK in place and still refuses env and HKDF key material", () => {
    const { dir, kekFile } = scratch();
    write0400(kekFile, randomBytes(16));
    const short = snap(kekFile);
    expect(() => ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: {} })).toThrow(/32/);
    expect(snap(kekFile)).toEqual(short);
    unlinkSync(kekFile);
    write0400(kekFile, randomBytes(32));
    chmodSync(kekFile, 0o644);
    const loose = snap(kekFile);
    expect(loose.mode).toBe(0o644);
    expect(() => ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: {} })).toThrow(/0400/);
    expect(snap(kekFile)).toEqual(loose);
    unlinkSync(kekFile);
    expect(() => ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: { MCP_FLOW_KEK: "x" } })).toThrow(/MCP_FLOW_KEK/);
    expect(() => ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: { MCP_FLOW_POLICY_DEV_KEY: "x" } })).toThrow(/MCP_FLOW_POLICY_DEV_KEY/);
    expect(existsSync(kekFile)).toBe(false);
    expect(existsSync(dir)).toBe(false);
  });

  it("does not replace a KEK that cannot unwrap the existing pepper", () => {
    const { dir, kekFile } = scratch();
    ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: {} });
    const pepper = snap(join(dir, "pepper"));
    const wrong = randomBytes(32);
    write0400(kekFile, wrong);
    expect(() => ensureBootKeyring({ production: true, keyringDir: dir, kekFile, env: {} })).toThrow(/does not unwrap/);
    expect(snap(kekFile).bytes.equals(wrong)).toBe(true);
    expect(snap(kekFile).mode).toBe(0o400);
    expect(snap(join(dir, "pepper"))).toEqual(pepper);
  });

  it("wires first boot through the gateway entrypoint and the data-volume paths", () => {
    const root = dirname(fileURLToPath(import.meta.url));
    const read = (rel: string) => readFileSync(join(root, "..", rel), "utf8");
    const entry = read("docker/entrypoint.mjs");
    expect(entry).toMatch(/if \(verb === "serve"\) \{\s*await ensureProductionKeyring\(\)/);
    expect(entry.match(/await ensureProductionKeyring\(/g)).toHaveLength(1);
    expect(entry).toContain("process.exit(1)");
    expect(entry).toContain("ensureBootKeyring");
    const image = read("Dockerfile");
    expect(image).toContain("NODE_ENV=production");
    expect(image).toContain("MCP_FLOW_KEYRING_DIR=/data/keyring");
    expect(image).toContain("MCP_FLOW_KEK_FILE=/data/kek");
    const compose = read("docker-compose.yml");
    expect(compose).toMatch(/MCP_FLOW_KEYRING_DIR: \/data\/keyring/);
    expect(compose).toMatch(/MCP_FLOW_KEK_FILE: \/data\/kek/);
    expect(compose).not.toMatch(/^\s*MCP_FLOW_KEK:/m);
    expect(read("README.md")).toContain("Keyring on first boot");
    expect(read("docs/secrets-restore-drill.md")).toContain("MCP_FLOW_KEYRING_DIR");
    expect(read("docs/secrets-restore-drill.md")).toContain("pepper");
  });
});

function snap(path: string): { bytes: Buffer; mode: number } {
  return { bytes: readFileSync(path), mode: statSync(path).mode & 0o777 };
}
