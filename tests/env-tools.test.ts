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
  const client = new Client({ name: "env-tools", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${url}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  try {
    const result = await client.callTool({ name, arguments: args });
    const text = Array.isArray(result.content) ? result.content.map((p: any) => ("text" in p ? String(p.text) : "")).join("\n") : "";
    return { error: result.isError === true, text };
  } finally {
    await client.close();
  }
}

interface SetupOpts { protectedRaw?: string; provisionRaw?: string; initialEnv?: string; }
async function setup(opts: SetupOpts = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-envtools-"));
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
    envProvisionTargets: parseProtectedTargets(opts.provisionRaw),
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
  let writes = 0;
  g.pool.callTool = async (_ws: string, name: string, args: any) => {
    if (name === "cmp__compose-one") {
      return { content: [{ type: "text", text: JSON.stringify({ env: envState.value }) }], isError: false, sent: true } as any;
    }
    if (name === "cmp__compose-saveEnvironment") {
      envState.value = args.env;
      writes++;
      return { content: [{ type: "text", text: "ok" }], isError: false, sent: true } as any;
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
    name: "dburl",
    type: "token",
    params: { bytes: 16 },
  } as any);
  const buf = store.secrets.openForTest({ workspaceId: ws.id, project: "app", name: "dburl", version: 1 });
  const secretValue = buf.toString("utf8");
  buf.fill(0);

  return { g, store, ws, chen, bot, humanToken: humanKey.token, humanKeyId: humanKey.keyId, botToken: botKey.token, ref: sec.ref, secretValue, envState, writes: () => writes };
}

describe("env tools", () => {
  it("set/list/unset preserve lines and store resolved secret", async () => {
    const s = await setup({ initialEnv: "KEEP_ME=1\n# a comment\n" });
    const plain = "plain-value-test-123456";
    const r1 = await mcpText(s.g.url, s.humanToken, "mf_env_keys_set", { backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { DB_URL: s.ref, PLAIN: plain } });
    expect(r1.error).toBe(false);
    const r2 = await mcpText(s.g.url, s.humanToken, "mf_env_keys_list", { backend: "cmp", compose_id: "cmp_test_1", project: "app" });
    expect(r2.text).toContain("KEEP_ME");
    expect(s.envState.value).toContain("KEEP_ME=1");
    expect(s.envState.value).toContain("# a comment");
    expect(s.envState.value).toContain(s.secretValue);
    expect(r1.text).not.toContain(plain);
    const r3 = await mcpText(s.g.url, s.humanToken, "mf_env_keys_unset", { backend: "cmp", compose_id: "cmp_test_1", project: "app", keys: ["PLAIN"] });
    expect(r3.error).toBe(false);
    expect(s.envState.value).toContain("KEEP_ME=1");
    expect(s.envState.value).toContain("# a comment");
  });

  it("protected target refuses everyone and no save", async () => {
    const s = await setup({ protectedRaw: "cmp_protected", initialEnv: "KEEP_ME=1\n" });
    for (const token of [s.humanToken, s.botToken]) {
      const r = await mcpText(s.g.url, token, "mf_env_keys_set", { backend: "cmp", compose_id: "cmp_protected", project: "app", values: { X: "y" } });
      expect(r.error).toBe(true);
    }
    // grant bot
    await mcpText(s.g.url, s.humanToken, "mf_admin_env_grant_create", { project: "app", backend: "cmp", compose_ids: ["cmp_protected"], agent_id: s.bot });
    // still refused due to protected
    const r2 = await mcpText(s.g.url, s.botToken, "mf_env_keys_list", { backend: "cmp", compose_id: "cmp_protected", project: "app" });
    expect(r2.error).toBe(true);
    const r3 = await mcpText(s.g.url, s.humanToken, "mf_admin_env_grant_create", { project: "app", backend: "cmp", compose_ids: ["cmp_protected"], agent_id: s.bot });
    expect(r3.error).toBe(true);
    expect(s.writes()).toBe(0);
  });

  it("grant scoping denies cross targets and revoked grants", async () => {
    const s = await setup({});
    // grant for cmp_test_1
    const g = await mcpText(s.g.url, s.humanToken, "mf_admin_env_grant_create", { project: "app", backend: "cmp", compose_ids: ["cmp_test_1"], agent_id: s.bot });
    expect(g.error).toBe(false);
    // denied on cmp_test_2
    const r1 = await mcpText(s.g.url, s.botToken, "mf_env_keys_list", { backend: "cmp", compose_id: "cmp_test_2", project: "app" });
    expect(r1.error).toBe(true);
    // denied on other backend
    const r2 = await mcpText(s.g.url, s.botToken, "mf_env_keys_list", { backend: "other", compose_id: "cmp_test_1", project: "app" });
    expect(r2.error).toBe(true);
    // denied on project other (bot is in other project too)
    const r3 = await mcpText(s.g.url, s.botToken, "mf_env_keys_list", { backend: "cmp", compose_id: "cmp_test_1", project: "other" });
    expect(r3.error).toBe(true);
    // granted bot can set plain value
    const r4 = await mcpText(s.g.url, s.botToken, "mf_env_keys_set", { backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { FOO: "bar" } });
    expect(r4.error).toBe(false);
    // bot cannot create grant
    const r5 = await mcpText(s.g.url, s.botToken, "mf_admin_env_grant_create", { project: "app", backend: "cmp", compose_ids: ["cmp_test_1"], agent_id: s.bot });
    expect(r5.error).toBe(true);
    // revoke then denied
    const grantId = JSON.parse(g.text).grant_id;
    const rv = await mcpText(s.g.url, s.humanToken, "mf_admin_env_grant_revoke", { grant_id: grantId });
    expect(rv.error).toBe(false);
    const r6 = await mcpText(s.g.url, s.botToken, "mf_env_keys_list", { backend: "cmp", compose_id: "cmp_test_1", project: "app" });
    expect(r6.error).toBe(true);
  });

  it("resync re-applies after rotate", async () => {
    const s = await setup({});
    await mcpText(s.g.url, s.humanToken, "mf_env_keys_set", { backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { DB_URL: s.ref } });
    const before = s.envState.value;
    // rotate secret
    s.store.secrets.rotate({ workspaceId: s.ws.id, keyId: s.humanKeyId, agentId: s.chen, allowedProjects: ["app"], humanAdmin: true, ref: s.ref } as any);
    const r = await mcpText(s.g.url, s.humanToken, "mf_secret_resync", {});
    expect(r.error).toBe(false);
    expect(s.envState.value).not.toBe(before);
    const buf = s.store.secrets.openForTest({ workspaceId: s.ws.id, project: "app", name: "dburl", version: 2 });
    const newVal = buf.toString("utf8");
    buf.fill(0);
    expect(s.envState.value).toContain(newVal);
    expect(r.text).not.toContain(newVal);
  });

  it("provision allowed/refused and bot generate refused", async () => {
    const s = await setup({ provisionRaw: "cmp_test_1" });
    const r1 = await mcpText(s.g.url, s.humanToken, "mf_env_provision", { backend: "cmp", compose_id: "cmp_test_1", project: "app", keys: { X: s.ref } });
    expect(r1.error).toBe(false);
    const r2 = await mcpText(s.g.url, s.humanToken, "mf_env_provision", { backend: "cmp", compose_id: "cmp_test_2", project: "app", keys: { X: s.ref } });
    expect(r2.error).toBe(true);
    // bot passing generate refused
    const r3 = await mcpText(s.g.url, s.botToken, "mf_env_provision", { backend: "cmp", compose_id: "cmp_test_1", project: "app", keys: { Y: { generate: "token" } } });
    expect(r3.error).toBe(true);
    // human generate allowed
    const r4 = await mcpText(s.g.url, s.humanToken, "mf_env_provision", { backend: "cmp", compose_id: "cmp_test_1", project: "app", keys: { Y: { generate: "token" } } });
    expect(r4.error).toBe(false);
  });

  it("fail-closed concurrency returns changed and no save", async () => {
    const s = await setup({});
    await mcpText(s.g.url, s.humanToken, "mf_env_keys_set", { backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { DB_URL: s.ref } });
    // make stub change env between reads
    const origCallTool = s.g.pool.callTool;
    let reads = 0;
    s.g.pool.callTool = async (_ws: string, name: string, args: any) => {
      if (name === "cmp__compose-one") {
        reads++;
        if (reads === 2) s.envState.value = "TAMPERED=1\n";
        return { content: [{ type: "text", text: JSON.stringify({ env: reads === 2 ? "TAMPERED=1\n" : s.envState.value }) }], isError: false, sent: true } as any;
      }
      if (name === "cmp__compose-saveEnvironment") {
        return { content: [{ type: "text", text: "ok" }], isError: false, sent: true } as any;
      }
      return origCallTool(_ws, name, args);
    };
    const beforeWrites = s.writes();
    const r = await mcpText(s.g.url, s.humanToken, "mf_env_keys_set", { backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { X: "y" } });
    expect(r.error).toBe(true);
    expect(r.text).toContain("changed");
    expect(s.writes()).toBe(beforeWrites);
  });

  it("no plaintext in outputs/audit/logs", async () => {
    const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const s = await setup({});
    const plain = "plain-value-test-123456";
    await mcpText(s.g.url, s.humanToken, "mf_env_keys_set", { backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { PLAIN: plain, DB_URL: s.ref } });
    const dumpAudit = () => {
      const rows = s.store.db.prepare(`SELECT * FROM mcpflow_call_audit`).all() as any[];
      const payloadRows = s.store.db.prepare(`SELECT * FROM mcpflow_call_payload`).all() as any[];
      const legacyRows = s.store.db.prepare(`SELECT * FROM audit_events`).all() as any[];
      return JSON.stringify({ rows, payloadRows, legacyRows });
    };
    const dump = dumpAudit();
    expect(dump).not.toContain(plain);
    expect(dump).not.toContain(s.secretValue);
    const allLogs = [...logSpy.mock.calls, ...errSpy.mock.calls, ...stdoutSpy.mock.calls].flat().join(" ");
    expect(allLogs).not.toContain(plain);
    expect(allLogs).not.toContain(s.secretValue);
    logSpy.mockRestore();
    errSpy.mockRestore();
    stdoutSpy.mockRestore();
  });
});