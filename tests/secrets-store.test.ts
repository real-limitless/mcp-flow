/** Secrets B: generators, KEK, create/list/rotate/delete, protected targets, REST. */
import { chmodSync, closeSync, mkdtempSync, openSync, readFileSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../src/api/app.js";
import { loadConfig } from "../src/config.js";
import { FileKekProvider, gcmUnwrap, gcmWrap, KmsKekProvider } from "../src/crypto/kek.js";
import { autoVacuumMode } from "../src/db/maintenance.js";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { dekAad, openSecretValue, sealSecretValue } from "../src/secrets/envelope.js";
import { entropyBits, generateSecret, MIN_ENTROPY_BITS, unbiasedIndex } from "../src/secrets/generate.js";
import { parseProtectedTargets } from "../src/secrets/protected.js";
import { secureReclaim } from "../src/secrets/purge.js";
import { isSecretTool, SECRET_META_TOOLS, callSecretTool } from "../src/secrets/tools.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { EXACT_ADMIN_TOOL_NAMES } from "../src/audit/redact-admin-args.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function write0400(path: string, body: Buffer): void {
  const fd = openSync(path, "wx", 0o400);
  try {
    writeSync(fd, body);
  } finally {
    closeSync(fd);
  }
  chmodSync(path, 0o400);
}

function scratch(): string {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-secrets-"));
  dirs.push(dir);
  return dir;
}

function openReady(opts: { protectedRaw?: string; mode?: number } = {}): {
  store: Store;
  chen: string;
  chenToken: string;
  bot: string;
  botToken: string;
  ws: string;
} {
  const dir = scratch();
  const kekFile = join(dir, "kek");
  write0400(kekFile, randomBytes(32));
  if (opts.mode) chmodSync(kekFile, opts.mode);
  const store = new Store(join(dir, "t.db"), Buffer.alloc(32, 11).toString("base64"), {
    kek: opts.mode ? undefined : new FileKekProvider(kekFile),
    kekFile: opts.mode ? kekFile : undefined,
    protectedTargets: parseProtectedTargets(opts.protectedRaw),
  });
  const ws = store.ensureWorkspace("default").id;
  const chen = store.identity.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
  store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'default')`).run(chen);
  const chenKey = store.identity.createKey({ agentId: chen, createdBy: chen, projects: ["default"] });
  const bot = store.identity.createAgent({
    workspaceId: ws,
    name: "bot",
    owner: "chen",
    kind: "grokbot",
    projects: ["default"],
    createdBy: chen,
  });
  const botKey = store.identity.createKey({ agentId: bot, createdBy: chen, projects: ["default"] });
  return { store, chen, chenToken: chenKey.token, bot, botToken: botKey.token, ws };
}

function dump(store: Store): string {
  const names = store.db.prepare(
    `SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`,
  ).all() as Array<{ name: string }>;
  let out = "";
  for (const { name } of names) {
    const quoted = `"${name.replaceAll('"', '""')}"`;
    const rows = store.db.prepare(`SELECT * FROM ${quoted}`).all() as Array<Record<string, unknown>>;
    for (const row of rows) {
      for (const value of Object.values(row)) {
        if (typeof value === "string") out += `${value}\n`;
        else if (value instanceof Uint8Array) {
          const buf = Buffer.from(value);
          out += `${buf.toString("utf8")}\n${buf.toString("hex")}\n`;
        }
      }
    }
  }
  return out;
}

describe("generators", () => {
  it("refuses token and password params below 128 bits", () => {
    expect(MIN_ENTROPY_BITS).toBe(128);
    expect(entropyBits(8, 16)).toBeLessThan(128);
    expect(() => generateSecret("token", { encoding: "hex", length: 8 })).toThrow(/128/);
    expect(() => generateSecret("token", { bytes: 8 })).toThrow(/16/);
    expect(() => generateSecret("token", { bytes: 16, length: 32 })).toThrow(/not both/);
    expect(() => generateSecret("password", { length: 12 })).toThrow(/128/);
    expect(() => generateSecret("import", { value: "hunter2hunter2" })).toThrow(/import/);
    expect(() => generateSecret("keypair", { alg: "rsa", bits: 2048 })).toThrow(/3072/);
    expect(() => generateSecret("uuid", { extra: true })).toThrow(/unknown/);
  });

  it("draws token, password, and uuid values from a CSPRNG at the entropy floor", () => {
    const token = generateSecret("token", { encoding: "base64url", bytes: 32 });
    expect(token.value.toString("utf8")).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const hex = generateSecret("token", { encoding: "hex", bytes: 16 });
    expect(hex.value).toHaveLength(32);
    const password = generateSecret("password", {});
    const text = password.value.toString("utf8");
    expect(text).toHaveLength(32);
    expect(text).toMatch(/[a-z]/);
    expect(text).toMatch(/[A-Z]/);
    expect(text).toMatch(/[0-9]/);
    expect(text).not.toMatch(/['"`$\\ #=]/);
    const uuid = generateSecret("uuid", {});
    expect(uuid.value.toString("utf8")).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    token.value.fill(0);
    hex.value.fill(0);
    password.value.fill(0);
    uuid.value.fill(0);
  });

  it("rejection-samples an index so values outside the unbiased range are skipped", () => {
    const size = 3;
    const limit = Math.floor(0x1_0000_0000 / size) * size;
    const seen: number[] = [];
    const index = unbiasedIndex(size, () => {
      seen.push(1);
      return seen.length === 1 ? limit : 4;
    });
    expect(index).toBe(4 % size);
    expect(seen).toHaveLength(2);
  });

  it("builds an ed25519 and rsa keypair and keeps the private key out of the public part", () => {
    const ed = generateSecret("keypair", { alg: "ed25519", format: "openssh" });
    const priv = ed.value.toString("utf8");
    expect(priv).toContain("BEGIN OPENSSH PRIVATE KEY");
    expect(ed.publicPart).toMatch(/^ssh-ed25519 /);
    expect(ed.publicPart).not.toContain("PRIVATE");
    expect(priv).not.toContain("BEGIN PUBLIC KEY");
    ed.value.fill(0);
    const rsa = generateSecret("keypair", { alg: "rsa", bits: 3072, format: "pem" });
    expect(rsa.value.toString("utf8")).toContain("BEGIN PRIVATE KEY");
    expect(rsa.publicPart).toContain("BEGIN PUBLIC KEY");
    expect(rsa.value.toString("utf8")).not.toContain("BEGIN PUBLIC KEY");
    rsa.value.fill(0);
  });
});

describe("KekProvider", () => {
  it("round-trips a file KEK and refuses a file that is not mode 0400", () => {
    const dir = scratch();
    const path = join(dir, "kek");
    write0400(path, randomBytes(32));
    const kek = new FileKekProvider(path);
    expect(kek.id()).toBe("file:kek:v1");
    const dek = randomBytes(32);
    const aad = Buffer.from("mcp-flow/dek/v1|sec|1|file:kek:v1");
    const wrapped = kek.wrap(dek, aad);
    expect(kek.unwrap(wrapped, aad).equals(dek)).toBe(true);
    expect(() => kek.unwrap(wrapped, Buffer.from("other"))).toThrow();
    chmodSync(path, 0o644);
    expect(() => kek.wrap(dek, aad)).toThrow(/0400/);
    expect(readFileSync(join(process.cwd(), "src/crypto/kek.ts"), "utf8")).not.toMatch(/hkdf|MCP_FLOW_KEK\b/);
  });

  it("gives a KMS hook the DEK only", () => {
    const kmsKey = randomBytes(32);
    let calls = 0;
    let seen = 0;
    const kek = new KmsKekProvider({
      keyId: "example-key",
      version: "v1",
      wrap(dek, aad) {
        calls += 1;
        seen = dek.length;
        expect(dek.equals(Buffer.from("this-is-not-a-32-byte-secret-value!!"))).toBe(false);
        return gcmWrap(kmsKey, dek, aad);
      },
      unwrap(wrapped, aad) {
        return gcmUnwrap(kmsKey, wrapped, aad);
      },
    });
    expect(kek.id()).toBe("kms:example-key:v1");
    const dek = randomBytes(32);
    const aad = Buffer.from("aad");
    expect(kek.unwrap(kek.wrap(dek, aad), aad).equals(dek)).toBe(true);
    expect(calls).toBe(1);
    expect(seen).toBe(32);
    expect(() => kek.wrap(Buffer.alloc(64), aad)).toThrow(/32/);
    expect(calls).toBe(1);
  });
});

describe("secret store", () => {
  it("verifies incremental auto_vacuum on startup and create → list → rotate → delete without plaintext", () => {
    const { store, chen, bot, ws } = openReady();
    expect(store.autoVacuum).toBe("incremental");
    expect(autoVacuumMode(store.db)).toBe("incremental");
    const secure = store.db.prepare("PRAGMA secure_delete").get() as { secure_delete: number };
    expect(secure.secure_delete).toBe(1);
    const actor = {
      workspaceId: ws,
      keyId: store.identity.createKey({ agentId: bot, createdBy: chen, projects: ["default"] }).keyId,
      agentId: bot,
      allowedProjects: ["default"] as const,
      humanAdmin: false,
    };
    // the helper already minted one bot key; a second live key is refused. Use the first.
    store.identity.revokeKey(actor.keyId, chen, "test cleanup");
    const first = store.db.prepare(`SELECT id FROM mcpflow_api_key WHERE agent_id = ? AND status = 'active'`).get(bot) as { id: string };
    const who = { ...actor, keyId: first.id };
    const created = store.secrets.create({ ...who, project: "default", name: "db-pass", type: "token", params: { bytes: 32 } });
    expect(created).toEqual({ ref: "secret://default/db-pass", version: 1 });
    expect(Object.keys(created).sort()).toEqual(["ref", "version"]);
    const plain = store.secrets.openForTest({ workspaceId: ws, project: "default", name: "db-pass", version: 1 });
    const value = plain.toString("utf8");
    expect(JSON.stringify(created)).not.toContain(value);
    expect(dump(store)).not.toContain(value);
    const listed = store.secrets.list({ ...who, project: "default" });
    expect(listed.secrets).toHaveLength(1);
    expect(listed.secrets[0]).toMatchObject({ ref: created.ref, type: "token", current_version: 1, grants: 0 });
    expect(JSON.stringify(listed)).not.toContain(value);
    const rotated = store.secrets.rotate({ ...who, ref: created.ref, graceSeconds: 60 });
    expect(rotated.version).toBe(2);
    expect(Object.keys(rotated)).toEqual(["ref", "version"]);
    const next = store.secrets.openForTest({ workspaceId: ws, project: "default", name: "db-pass", version: 2 });
    expect(next.equals(plain)).toBe(false);
    expect(JSON.stringify(rotated)).not.toContain(next.toString("utf8"));
    expect(dump(store)).not.toContain(next.toString("utf8"));
    const states = store.db.prepare(
      `SELECT version, state FROM mcpflow_secret_version ORDER BY version`,
    ).all();
    expect(states).toEqual([{ version: 1, state: "previous" }, { version: 2, state: "active" }]);
    expect(() => store.secrets.rotate({ ...who, ref: created.ref, resync: true })).toThrow(/resync/);
    expect(() => store.secrets.delete({ ...who, ref: created.ref, purge: true })).toThrow(/human admin/);
    expect(store.secrets.delete({ ...who, ref: created.ref })).toEqual({ ref: created.ref, deleted: true });
    expect(store.secrets.list({ ...who }).secrets).toEqual([]);
    expect(() => store.secrets.rotate({ ...who, ref: created.ref })).toThrow(/not found/);
    const adminKey = store.db.prepare(`SELECT id FROM mcpflow_api_key WHERE agent_id = ?`).get(chen) as { id: string };
    const admin = {
      workspaceId: ws,
      keyId: adminKey.id,
      agentId: chen,
      allowedProjects: null,
      humanAdmin: true,
    };
    store.secrets.create({ ...admin, project: "default", name: "other", type: "uuid" });
    const purged = store.secrets.delete({ ...admin, ref: "secret://default/other", purge: true });
    expect(purged).toEqual({ ref: "secret://default/other", deleted: true, purged: true });
    const destroyed = store.db.prepare(
      `SELECT state, ciphertext, wrapped_dek FROM mcpflow_secret_version v
         JOIN mcpflow_secret s ON s.id = v.secret_id WHERE s.name = 'other'`,
    ).get() as { state: string; ciphertext: Buffer | null; wrapped_dek: Buffer | null };
    expect(destroyed).toEqual({ state: "destroyed", ciphertext: null, wrapped_dek: null });
    plain.fill(0);
    next.fill(0);
    store.close();
  });

  it("fails closed on a protected deployment id and on an unparseable host list", () => {
    const ready = openReady({ protectedRaw: "deploy-example-1" });
    const key = ready.store.db.prepare(`SELECT id FROM mcpflow_api_key WHERE agent_id = ?`).get(ready.bot) as { id: string };
    const who = {
      workspaceId: ready.ws,
      keyId: key.id,
      agentId: ready.bot,
      allowedProjects: ["default"] as const,
      humanAdmin: false,
    };
    expect(() => ready.store.secrets.create({
      ...who,
      project: "default",
      name: "deploy-example-1",
      type: "token",
    })).toThrow(/protected target/);
    expect(() => ready.store.secrets.create({
      ...who,
      project: "default",
      name: "ok",
      type: "token",
      description: "uses deploy-example-1",
    })).toThrow(/protected target/);
    ready.store.close();

    const blocked = openReady({ protectedRaw: "not a token" });
    const key2 = blocked.store.db.prepare(`SELECT id FROM mcpflow_api_key WHERE agent_id = ?`).get(blocked.chen) as { id: string };
    expect(() => blocked.store.secrets.list({
      workspaceId: blocked.ws,
      keyId: key2.id,
      agentId: blocked.chen,
      allowedProjects: null,
      humanAdmin: true,
    })).toThrow(/protected target/);
    blocked.store.close();
  });

  it("binds ciphertext to the row AAD and reclaims pages after a purge", () => {
    const dir = scratch();
    const kek = new FileKekProvider(join(dir, "kek"));
    write0400(join(dir, "kek"), randomBytes(32));
    const keys = derivePolicyKeys("secrets-b");
    const secretId = "sec_" + "ab".repeat(12);
    const value = Buffer.from("canary-value-not-stored-in-columns");
    const sealed = sealSecretValue(kek, keys.secretsIndex, {
      workspaceId: "ws",
      projectId: "default",
      secretId,
      version: 1,
      value: Buffer.from(value),
    });
    const opened = openSecretValue(kek, {
      workspaceId: "ws",
      projectId: "default",
      secretId,
      version: 1,
      ciphertext: sealed.ciphertext,
      wrappedDek: sealed.wrappedDek,
      kekId: sealed.kekId,
    });
    expect(opened.equals(value)).toBe(true);
    expect(() => openSecretValue(kek, {
      workspaceId: "other",
      projectId: "default",
      secretId,
      version: 1,
      ciphertext: sealed.ciphertext,
      wrappedDek: sealed.wrappedDek,
      kekId: sealed.kekId,
    })).toThrow();
    expect(dekAad(secretId, 1, sealed.kekId).toString("utf8")).toBe(`mcp-flow/dek/v1|${secretId}|1|${sealed.kekId}`);
    opened.fill(0);

    const { store, chen, ws } = openReady();
    const adminKey = store.db.prepare(`SELECT id FROM mcpflow_api_key WHERE agent_id = ?`).get(chen) as { id: string };
    store.secrets.create({
      workspaceId: ws,
      keyId: adminKey.id,
      agentId: chen,
      allowedProjects: null,
      humanAdmin: true,
      project: "default",
      name: "blob",
      type: "token",
      params: { bytes: 1024 },
    });
    store.secrets.delete({
      workspaceId: ws,
      keyId: adminKey.id,
      agentId: chen,
      allowedProjects: null,
      humanAdmin: true,
      ref: "secret://default/blob",
      purge: true,
    });
    const reclaimed = secureReclaim(store.db);
    expect(reclaimed.autoVacuum).toBe("incremental");
    store.close();
  });

  it("serves REST to a human admin and refuses break-glass and legacy keys", async () => {
    const dir = scratch();
    const kekFile = join(dir, "kek");
    write0400(kekFile, randomBytes(32));
    const master = Buffer.alloc(32, 12).toString("base64");
    const store = new Store(join(dir, "t.db"), master, { kek: new FileKekProvider(kekFile) });
    const ws = store.ensureWorkspace("default");
    const chen = store.identity.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
    store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'app')`).run(chen);
    const token = store.identity.createKey({ agentId: chen, createdBy: chen, projects: ["app"] }).token;
    const legacy = store.createApiKey(ws.id, "legacy", { admin: true });
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: "break-glass-placeholder",
      host: "localhost",
      allowPrivateUrls: false,
      workspaceName: "default",
    });
    const pool = new UpstreamPool(store);
    const app = createApp(store, cfg, pool);
    const body = JSON.stringify({ project: "app", name: "hook", type: "token", params: { bytes: 16, encoding: "hex" } });
    const created = await app.request("/v1/secrets", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body,
    });
    expect(created.status).toBe(201);
    const payload = await created.json() as { ref: string; version: number; public_part?: string };
    expect(payload).toEqual({ ref: "secret://app/hook", version: 1 });
    const plain = store.secrets.openForTest({ workspaceId: ws.id, project: "app", name: "hook", version: 1 }).toString("utf8");
    expect(JSON.stringify(payload)).not.toContain(plain);
    const listed = await app.request("/v1/secrets?project=app", { headers: { authorization: `Bearer ${token}` } });
    expect(listed.status).toBe(200);
    expect(JSON.stringify(await listed.json())).not.toContain(plain);
    const glass = await app.request("/v1/secrets", {
      method: "POST",
      headers: { authorization: "Bearer break-glass-placeholder", "content-type": "application/json" },
      body,
    });
    expect(glass.status).toBe(403);
    const old = await app.request("/v1/secrets", {
      method: "POST",
      headers: { authorization: `Bearer ${legacy.token}`, "content-type": "application/json" },
      body,
    });
    expect(old.status).toBe(403);
    expect(isSecretTool("mf_secret_import")).toBe(false);
    expect(SECRET_META_TOOLS.map((tool) => tool.name)).toEqual([
      "mf_secret_create",
      "mf_secret_list",
      "mf_secret_rotate",
      "mf_secret_delete",
    ]);
    for (const name of EXACT_ADMIN_TOOL_NAMES) expect(name).not.toMatch(/secret_create|secret_import/);
    const bot = store.identity.createAgent({
      workspaceId: ws.id,
      name: "bot",
      owner: "chen",
      kind: "grokbot",
      projects: ["app"],
      createdBy: chen,
    });
    const botKey = store.identity.createKey({ agentId: bot, createdBy: chen, projects: ["app"] });
    const viaTool = callSecretTool(store.secrets, "mf_secret_list", { project: "app" }, {
      workspaceId: ws.id,
      keyId: botKey.keyId,
      agentId: bot,
      agentKind: "grokbot",
      admin: false,
      allowedProjects: ["app"],
      activeProject: "app",
    }) as { secrets: Array<{ ref: string }> };
    expect(viaTool.secrets.map((row) => row.ref)).toEqual(["secret://app/hook"]);
    expect(JSON.stringify(viaTool)).not.toContain(plain);
    expect(() => callSecretTool(store.secrets, "mf_secret_create", { project: "app", name: "x", type: "token" }, {
      workspaceId: ws.id,
      keyId: "key_" + "0".repeat(24),
      agentId: bot,
      agentKind: "grokbot",
      admin: false,
      allowedProjects: ["app"],
      activeProject: "app",
    })).toThrow(/agent key/);
    const gateway = readFileSync(join(process.cwd(), "src/mcp/gateway.ts"), "utf8");
    expect(gateway).toContain("secret tools require an agent key");
    const backend = readFileSync(join(process.cwd(), "src/audit/backend-update.ts"), "utf8");
    const secretSrc = readFileSync(join(process.cwd(), "src/secrets/directory.ts"), "utf8");
    expect(backend).toContain("urlOriginChanged(");
    expect(secretSrc).not.toMatch(/urlOriginChanged\(|new URL\(/);
    await pool.closeAll();
    store.close();
  });
});
