import { chmodSync, closeSync, mkdtempSync, openSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createServer } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { parseProtectedTargets } from "../src/secrets/protected.js";
import { toolAllowedByScopes } from "../src/types.js";
import { startServer, type RunningServer } from "../src/server.js";

const dirs: string[] = [];
let gw: RunningServer | null = null;
afterEach(async () => {
  await gw?.close();
  gw = null;
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function write0400(path: string, body: Buffer) {
  const fd = openSync(path, "wx", 0o400);
  try { writeSync(fd, body); } finally { closeSync(fd); }
  chmodSync(path, 0o400);
}

async function mcpText(url: string, token: string, name: string, args: any): Promise<{ error: boolean; text: string }> {
  const client = new Client({ name: "file-tools", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${url}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  try {
    const result = await client.callTool({ name, arguments: args });
    const text = Array.isArray(result.content) ? result.content.map((part: any) => ("text" in part ? String(part.text) : "")).join("\n") : "";
    return { error: result.isError === true, text };
  } finally {
    await client.close();
  }
}

interface MountRow { mountId: string; mountPath: string; content: string; type: string; }

async function setup(opts: { protectedRaw?: string; initialEnv?: string } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-filetools-"));
  dirs.push(dir);
  const kekFile = join(dir, "kek");
  write0400(kekFile, randomBytes(32));
  const master = Buffer.alloc(32, 7).toString("base64");
  const cfg = loadConfig({
    dbPath: join(dir, "t.db"),
    masterKeyRaw: master,
    adminToken: "break-glass-placeholder",
    host: "localhost",
    allowPrivateUrls: false,
    workspaceName: "default",
    kekFile,
    kekProvider: "file",
    protectedTargets: parseProtectedTargets(opts.protectedRaw),
  });
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "localhost", resolve));
  cfg.port = (probe.address() as any).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  const g = await startServer(cfg);
  gw = g;
  const store = g.store;
  const ws = store.ensureWorkspace("default");
  const chen = store.identity.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
  store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'app')`).run(chen);
  store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'other')`).run(chen);
  const humanKey = store.identity.createKey({ agentId: chen, createdBy: chen, projects: ["app", "other"] });
  const bot = store.identity.createAgent({ workspaceId: ws.id, name: "bot", owner: "chen", kind: "grokbot", projects: ["app", "other"], createdBy: chen });
  const botKey = store.identity.createKey({ agentId: bot, createdBy: chen, projects: ["app", "other"] });

  const envState = { value: opts.initialEnv ?? "KEEP_ME=1\n# a comment\n" };
  const mounts: MountRow[] = [];
  let seq = 1;
  let creates = 0;
  let updates = 0;
  let removes = 0;
  g.pool.callTool = async (_ws: string, name: string, args: any) => {
    if (name === "cmp__compose-one") {
      return { content: [{ type: "text", text: JSON.stringify({ env: envState.value }) }], isError: false, sent: true } as any;
    }
    if (name === "cmp__compose-saveEnvironment") {
      envState.value = args.env;
      return { content: [{ type: "text", text: "ok" }], isError: false, sent: true } as any;
    }
    if (name === "cmp__mounts-listByServiceId") {
      return { content: [{ type: "text", text: JSON.stringify(mounts) }], isError: false, sent: true } as any;
    }
    if (name === "cmp__mounts-one") {
      const row = mounts.find((mount) => mount.mountId === args.mountId);
      if (!row) return { content: [{ type: "text", text: "missing" }], isError: true, sent: true } as any;
      return { content: [{ type: "text", text: JSON.stringify(row) }], isError: false, sent: true } as any;
    }
    if (name === "cmp__mounts-create") {
      creates++;
      const row = { mountId: `mnt_${seq++}`, type: "file", mountPath: args.mountPath, content: String(args.content) };
      mounts.push(row);
      return { content: [{ type: "text", text: JSON.stringify({ mountId: row.mountId }) }], isError: false, sent: true } as any;
    }
    if (name === "cmp__mounts-update") {
      updates++;
      const row = mounts.find((mount) => mount.mountId === args.mountId);
      if (row) row.content = String(args.content);
      return { content: [{ type: "text", text: JSON.stringify({ mountId: args.mountId }) }], isError: false, sent: true } as any;
    }
    if (name === "cmp__mounts-remove") {
      removes++;
      const index = mounts.findIndex((mount) => mount.mountId === args.mountId);
      if (index >= 0) mounts.splice(index, 1);
      return { content: [{ type: "text", text: JSON.stringify({ removed: true }) }], isError: false, sent: true } as any;
    }
    return { content: [{ type: "text", text: "nope" }], isError: true, sent: false } as any;
  };

  const keyForSecret = store.identity.createKey({ agentId: chen, createdBy: chen, projects: ["app"] });
  const sec = store.secrets.create({
    workspaceId: ws.id,
    keyId: keyForSecret.keyId,
    agentId: chen,
    allowedProjects: ["app"],
    humanAdmin: true,
    project: "app",
    name: "apikey",
    type: "token",
    params: { bytes: 16 },
  } as any);
  const buf = store.secrets.openForTest({ workspaceId: ws.id, project: "app", name: "apikey", version: 1 });
  const secretValue = buf.toString("utf8");
  buf.fill(0);

  return {
    g, store, ws, chen, bot,
    humanToken: humanKey.token, humanKeyId: humanKey.keyId,
    botToken: botKey.token, botKeyId: botKey.keyId,
    ref: sec.ref, secretValue, envState, mounts,
    creates: () => creates, updates: () => updates, removes: () => removes,
  };
}

const PATH = "/run/secrets/api.key";
const ENV_KEY = "APP_API_KEY_FILE";

describe("file tools", () => {
  it("set/list/unset deliver the file and an optional *_FILE env key", async () => {
    const s = await setup();
    const before = s.envState.value;
    const set = await mcpText(s.g.url, s.humanToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, ref: s.ref, env_key: ENV_KEY,
    });
    expect(set.error).toBe(false);
    const body = JSON.parse(set.text);
    expect(body.ref).toBe(s.ref);
    expect(body.path).toBe(PATH);
    expect(body.version).toBe(1);
    expect(body.mount_id).toMatch(/^mnt_/);
    expect(body.env_key).toBe(ENV_KEY);
    expect(set.text).not.toContain(s.secretValue);
    expect(s.mounts[0].content).toBe(s.secretValue);
    expect(s.envState.value.startsWith(before)).toBe(true);
    expect(s.envState.value).toContain(`${ENV_KEY}=${PATH}`);
    expect(s.envState.value).not.toContain(s.secretValue);
    const listed = await mcpText(s.g.url, s.humanToken, "mf_secret_file_list", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app",
    });
    expect(listed.error).toBe(false);
    expect(listed.text).toContain(s.ref);
    expect(listed.text).toContain(body.mount_id);
    expect(listed.text).not.toContain(s.secretValue);
    const again = await mcpText(s.g.url, s.humanToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, ref: s.ref,
    });
    expect(again.error).toBe(false);
    expect(s.creates()).toBe(1);
    expect(s.updates()).toBe(1);
    const unset = await mcpText(s.g.url, s.humanToken, "mf_secret_file_unset", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH,
    });
    expect(unset.error).toBe(false);
    expect(s.mounts).toHaveLength(0);
    expect(s.removes()).toBe(1);
    expect(s.envState.value).toContain("KEEP_ME=1");
    expect(s.envState.value).toContain("# a comment");
    expect(s.envState.value).not.toContain(ENV_KEY);
    expect(unset.text).not.toContain(s.secretValue);
  });

  it("protected target refuses everyone and no mount write", async () => {
    const s = await setup({ protectedRaw: "cmp_protected" });
    for (const token of [s.humanToken, s.botToken]) {
      const result = await mcpText(s.g.url, token, "mf_secret_file_set", {
        backend: "cmp", compose_id: "cmp_protected", project: "app", path: PATH, ref: s.ref,
      });
      expect(result.error).toBe(true);
      expect(result.text).toContain("protected target");
    }
    const grant = await mcpText(s.g.url, s.humanToken, "mf_admin_env_grant_create", {
      project: "app", backend: "cmp", compose_ids: ["cmp_protected"], agent_id: s.bot,
    });
    expect(grant.error).toBe(true);
    const listed = await mcpText(s.g.url, s.botToken, "mf_secret_file_list", {
      backend: "cmp", compose_id: "cmp_protected", project: "app",
    });
    expect(listed.error).toBe(true);
    expect(s.creates()).toBe(0);
    expect(s.updates()).toBe(0);
  });

  it("grant scoping denies cross targets and revoked grants", async () => {
    const s = await setup();
    const denied = await mcpText(s.g.url, s.botToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, ref: s.ref,
    });
    expect(denied.error).toBe(true);
    const grant = await mcpText(s.g.url, s.humanToken, "mf_admin_env_grant_create", {
      project: "app", backend: "cmp", compose_ids: ["cmp_test_1"], agent_id: s.bot,
    });
    expect(grant.error).toBe(false);
    const otherCompose = await mcpText(s.g.url, s.botToken, "mf_secret_file_list", {
      backend: "cmp", compose_id: "cmp_test_2", project: "app",
    });
    expect(otherCompose.error).toBe(true);
    const otherBackend = await mcpText(s.g.url, s.botToken, "mf_secret_file_list", {
      backend: "other", compose_id: "cmp_test_1", project: "app",
    });
    expect(otherBackend.error).toBe(true);
    const otherProject = await mcpText(s.g.url, s.botToken, "mf_secret_file_list", {
      backend: "cmp", compose_id: "cmp_test_1", project: "other",
    });
    expect(otherProject.error).toBe(true);
    const allowed = await mcpText(s.g.url, s.botToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, ref: s.ref,
    });
    expect(allowed.error).toBe(false);
    expect(allowed.text).not.toContain(s.secretValue);
    expect(s.mounts[0].content).toBe(s.secretValue);
    const botGrant = await mcpText(s.g.url, s.botToken, "mf_admin_env_grant_create", {
      project: "app", backend: "cmp", compose_ids: ["cmp_test_1"], agent_id: s.bot,
    });
    expect(botGrant.error).toBe(true);
    const grantId = JSON.parse(grant.text).grant_id;
    const revoked = await mcpText(s.g.url, s.humanToken, "mf_admin_env_grant_revoke", { grant_id: grantId });
    expect(revoked.error).toBe(false);
    const after = await mcpText(s.g.url, s.botToken, "mf_secret_file_list", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app",
    });
    expect(after.error).toBe(true);
  });

  it("resync re-applies a file mount after rotate", async () => {
    const s = await setup();
    await mcpText(s.g.url, s.humanToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, ref: s.ref, env_key: ENV_KEY,
    });
    const envBefore = s.envState.value;
    s.store.secrets.rotate({
      workspaceId: s.ws.id, keyId: s.humanKeyId, agentId: s.chen, allowedProjects: ["app"], humanAdmin: true, ref: s.ref,
    } as any);
    const result = await mcpText(s.g.url, s.humanToken, "mf_secret_resync", {});
    expect(result.error).toBe(false);
    const buf = s.store.secrets.openForTest({ workspaceId: s.ws.id, project: "app", name: "apikey", version: 2 });
    const next = buf.toString("utf8");
    buf.fill(0);
    expect(s.mounts[0].content).toBe(next);
    expect(result.text).not.toContain(next);
    expect(result.text).not.toContain(s.secretValue);
    expect(s.envState.value.startsWith("KEEP_ME=1\n# a comment\n")).toBe(true);
    expect(s.envState.value).toContain(`${ENV_KEY}=${PATH}`);
    expect(s.envState.value).not.toContain(next);
    expect(envBefore).toContain(`${ENV_KEY}=${PATH}`);
  });

  it("human admin can generate a file secret and a bot cannot", async () => {
    const s = await setup();
    const grant = await mcpText(s.g.url, s.humanToken, "mf_admin_env_grant_create", {
      project: "app", backend: "cmp", compose_ids: ["cmp_test_1"], agent_id: s.bot,
    });
    expect(grant.error).toBe(false);
    const bot = await mcpText(s.g.url, s.botToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, generate: "token", name: "frombot",
    });
    expect(bot.error).toBe(true);
    expect(bot.text).toContain("human admin");
    expect(s.creates()).toBe(0);
    const human = await mcpText(s.g.url, s.humanToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, generate: "token", name: "fromadmin",
    });
    expect(human.error).toBe(false);
    const body = JSON.parse(human.text);
    expect(body.ref).toBe("secret://app/fromadmin");
    expect(body.version).toBe(1);
    expect(body.mount_id).toMatch(/^mnt_/);
    const buf = s.store.secrets.openForTest({ workspaceId: s.ws.id, project: "app", name: "fromadmin", version: 1 });
    const value = buf.toString("utf8");
    buf.fill(0);
    expect(s.mounts[0].content).toBe(value);
    expect(human.text).not.toContain(value);
  });

  it("refuses a placeholder already stored on the mount and a change between reads", async () => {
    const s = await setup();
    const ph = "[" + "REDACTED" + "]";
    s.mounts.push({ mountId: "mnt_old", type: "file", mountPath: PATH, content: ph });
    const refused = await mcpText(s.g.url, s.humanToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, ref: s.ref,
    });
    expect(refused.error).toBe(true);
    expect(refused.text).toContain("placeholder");
    expect(s.updates()).toBe(0);
    expect(s.mounts[0].content).toBe(ph);
    s.mounts[0].content = "stable";
    const orig = s.g.pool.callTool;
    let reads = 0;
    s.g.pool.callTool = async (ws: string, name: string, args: any) => {
      if (name === "cmp__mounts-one") {
        reads++;
        if (reads === 2) s.mounts[0].content = "tampered";
      }
      return orig(ws, name, args);
    };
    const changed = await mcpText(s.g.url, s.humanToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, ref: s.ref,
    });
    expect(changed.error).toBe(true);
    expect(changed.text).toContain("changed");
    expect(s.updates()).toBe(0);
  });

  it("prefix-restricted keys need mf_secret_file_ in their allowlist", () => {
    expect(toolAllowedByScopes("mf_secret_file_set", { toolPrefixAllowlist: ["mf_env_"] } as any)).toBe(false);
    expect(toolAllowedByScopes("mf_secret_file_list", { toolPrefixAllowlist: ["mf_secret_file_"] } as any)).toBe(true);
    expect(toolAllowedByScopes("mf_secret_file_unset", null)).toBe(true);
  });

  it("no secret value in tool output, audit tables, or captured logs", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const s = await setup();
    await mcpText(s.g.url, s.humanToken, "mf_secret_file_set", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app", path: PATH, ref: s.ref, env_key: ENV_KEY,
    });
    const listed = await mcpText(s.g.url, s.humanToken, "mf_secret_file_list", {
      backend: "cmp", compose_id: "cmp_test_1", project: "app",
    });
    expect(listed.text).not.toContain(s.secretValue);
    const dump = JSON.stringify({
      audit: s.store.db.prepare(`SELECT * FROM mcpflow_call_audit`).all(),
      payload: s.store.db.prepare(`SELECT * FROM mcpflow_call_payload`).all(),
      legacy: s.store.db.prepare(`SELECT * FROM audit_events`).all(),
      template: s.store.db.prepare(`SELECT * FROM mcpflow_file_template`).all(),
    });
    expect(dump).not.toContain(s.secretValue);
    expect(dump).toContain(s.ref);
    const logs = [...logSpy.mock.calls, ...errSpy.mock.calls, ...stdoutSpy.mock.calls].flat().join(" ");
    expect(logs).not.toContain(s.secretValue);
    logSpy.mockRestore();
    errSpy.mockRestore();
    stdoutSpy.mockRestore();
  });
});
