import { chmodSync, closeSync, mkdtempSync, openSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { parseProtectedTargets } from "../src/secrets/protected.js";
import { startServer, type RunningServer } from "../src/server.js";
import { SecretActor } from "../src/secrets/directory.js";

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

describe("env tools", () => {
  it("set/list/unset and ref resolution, provision off, grants", async () => {
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
      envProvisionTargets: parseProtectedTargets(""),
    });
    const probe = (await import("node:http")).createServer();
    await new Promise<void>((resolve) => probe.listen(0, "localhost", resolve));
    cfg.port = (probe.address() as any).port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    gw = await startServer(cfg);
    const store = gw.store;
    const ws = store.ensureWorkspace("default");
    const chen = store.identity.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
    store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'app')`).run(chen);
    const humanToken = store.identity.createKey({ agentId: chen, createdBy: chen, projects: ["app"] }).token;
    const bot = store.identity.createAgent({ workspaceId: ws.id, name: "bot", owner: "chen", kind: "grokbot", projects: ["app"], createdBy: chen });
    const botToken = store.identity.createKey({ agentId: bot, createdBy: chen, projects: ["app"] }).token;

    // stub upstream
    let env = "";
    gw.pool.callTool = async (_ws: string, name: string, args: any) => {
      if (name === "cmp__compose-one") {
        return { content: [{ type: "text", text: JSON.stringify({ env }) }], isError: false, sent: true } as any;
      }
      if (name === "cmp__compose-saveEnvironment") {
        env = args.env;
        return { content: [{ type: "text", text: "ok" }], isError: false, sent: true } as any;
      }
      return { content: [{ type: "text", text: "nope" }], isError: true, sent: false } as any;
    };

    // create a secret
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
    const ref = sec.ref;

    // set plain + ref
    const plain = "plain-value-test-123456";
    const r1 = await mcpText(gw.url, humanToken, "mf_env_keys_set", { backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { DB_URL: ref, PLAIN: plain } });
    expect(r1.error).toBe(false);
    expect(r1.text).toContain("DB_URL");
    expect(r1.text).not.toContain(plain);

    // list
    const r2 = await mcpText(gw.url, humanToken, "mf_env_keys_list", { backend: "cmp", compose_id: "cmp_test_1", project: "app" });
    expect(r2.error).toBe(false);
    expect(r2.text).toContain("***");
    expect(r2.text).toContain(ref);

    // unset
    const r3 = await mcpText(gw.url, humanToken, "mf_env_keys_unset", { backend: "cmp", compose_id: "cmp_test_1", project: "app", keys: ["PLAIN"] });
    expect(r3.error).toBe(false);

    // provision off
    const r4 = await mcpText(gw.url, humanToken, "mf_env_provision", { backend: "cmp", compose_id: "cmp_test_1", project: "app", keys: { X: ref } });
    expect(r4.error).toBe(true);
    expect(r4.text).toContain("mf_env_provision is off");

    // grant scoping: bot without grant denied
    const r5 = await mcpText(gw.url, botToken, "mf_env_keys_list", { backend: "cmp", compose_id: "cmp_test_1", project: "app" });
    expect(r5.error).toBe(true);

    // create grant for bot
    const r6 = await mcpText(gw.url, humanToken, "mf_admin_env_grant_create", { project: "app", backend: "cmp", compose_ids: ["cmp_test_1"], agent_id: bot });
    expect(r6.error).toBe(false);

    // bot with grant allowed
    const r7 = await mcpText(gw.url, botToken, "mf_env_keys_list", { backend: "cmp", compose_id: "cmp_test_1", project: "app" });
    expect(r7.error).toBe(false);

    // bots cannot create secrets (still denied) - mf_secret_create
    const r8 = await mcpText(gw.url, botToken, "mf_secret_create", { project: "app", name: "x", type: "uuid" });
    expect(r8.error).toBe(true);

    // no plaintext in audit tables
    const rows = store.db.prepare(`SELECT * FROM mcpflow_call_audit`).all() as any[];
    const payloadRows = store.db.prepare(`SELECT * FROM mcpflow_call_payload`).all() as any[];
    const legacy = store.db.prepare(`SELECT name FROM sqlite_master WHERE type='table' AND name='audit_events'`).all() as any[];
    let legacyRows: any[] = [];
    if (legacy.length) legacyRows = store.db.prepare(`SELECT * FROM audit_events`).all() as any[];
    const dump = JSON.stringify({ rows, payloadRows, legacyRows });
    expect(dump).not.toContain(plain);

    // resolved secret value not in audit
    const buf = store.secrets.openForTest({ workspaceId: ws.id, project: "app", name: "dburl", version: 1 });
    const secretVal = buf.toString("utf8");
    buf.fill(0);
    expect(dump).not.toContain(secretVal);
  }, 120000);
});