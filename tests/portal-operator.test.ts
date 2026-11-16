/** Portal operator actions: unsealed audit, secret create, rename, delete after revoke. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../src/api/app.js";
import { loadConfig } from "../src/config.js";
import { FileKekProvider } from "../src/crypto/kek.js";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { chmodSync, closeSync, openSync, writeSync } from "node:fs";

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

function openStore(): { store: Store; ws: string; dir: string; master: string } {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-portal-"));
  dirs.push(dir);
  const kekFile = join(dir, "kek");
  write0400(kekFile, randomBytes(32));
  const master = Buffer.alloc(32, 9).toString("base64");
  const store = new Store(join(dir, "t.db"), master, { kek: new FileKekProvider(kekFile) });
  const ws = store.ensureWorkspace("default").id;
  return { store, ws, dir, master };
}

describe("audit detail for the portal", () => {
  it("returns the original arguments and keeps the stored copy redacted", () => {
    const { store, ws } = openStore();
    const secret = "sk-portal-audit-secret-value";
    store.writeAudit({
      workspaceId: ws,
      action: "tools/call",
      tool: "demo__echo",
      detail: { arguments: { api_key: secret, note: "hello" }, result: { ok: true } },
    });
    const shown = store.listAudit(ws, { limit: 5 })[0];
    expect(shown?.detail).toEqual({
      arguments: { api_key: secret, note: "hello" },
      result: { ok: true },
    });
    const stored = store.db
      .prepare(`SELECT detail_json FROM audit_events WHERE action = 'tools/call'`)
      .get() as { detail_json: string };
    expect(stored.detail_json).not.toContain(secret);
    expect(stored.detail_json).toContain("[redacted]");
    expect(stored.detail_json).toContain("hello");
    store.close();
  });
});

describe("portal rename and delete", () => {
  it("renames a bot, a backend, a project, and a device, then deletes a revoked bot and legacy key", async () => {
    const { store, ws, dir, master } = openStore();
    const chen = store.identity.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
    store.ensureDefaultProject(ws);
    store.db.prepare(`INSERT OR IGNORE INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'default')`).run(chen);
    const bot = store.identity.createAgent({
      workspaceId: ws,
      name: "printer",
      owner: "chen",
      kind: "grokbot",
      projects: ["default"],
      createdBy: chen,
    });
    const key = store.identity.createKey({ agentId: bot, createdBy: chen, projects: ["default"] });
    const project = store.createProject(ws, { slug: "web", title: "Web", backendSlugs: ["demo"] });
    store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'web')`).run(bot);
    store.db.prepare(
      `INSERT INTO mcpflow_api_key_project (key_id, agent_id, project_id) VALUES (?, ?, 'web')`,
    ).run(key.keyId, bot);
    const backend = store.createBackend(ws, {
      slug: "demo",
      title: "demo",
      transport: "streamable-http",
      url: "https://example.com/mcp",
      enabled: false,
    });
    const device = store.enrollDevice(ws, { name: "edge-1" });

    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: "portal-admin",
      host: "localhost",
      allowPrivateUrls: false,
      workspaceName: "default",
    });
    const pool = new UpstreamPool(store);
    const app = createApp(store, cfg, pool);
    const auth = { authorization: "Bearer portal-admin", "content-type": "application/json" };

    const renamedBot = await app.request(`/v1/agents/${bot}`, {
      method: "PATCH",
      headers: auth,
      body: JSON.stringify({ name: "press" }),
    });
    expect(renamedBot.status).toBe(200);
    expect(((await renamedBot.json()) as { agent: { name: string } }).agent.name).toBe("press");

    const renamedBackend = await app.request(`/v1/backends/${backend.id}`, {
      method: "PATCH",
      headers: auth,
      body: JSON.stringify({ slug: "press-api" }),
    });
    expect(renamedBackend.status).toBe(200);
    const backendBody = (await renamedBackend.json()) as { backend: { slug: string; title: string } };
    expect(backendBody.backend.slug).toBe("press-api");
    expect(backendBody.backend.title).toBe("press-api");
    expect(store.getProject(ws, project.id)?.backendSlugs).toEqual(["press-api"]);

    const renamedProject = await app.request(`/v1/projects/${project.id}`, {
      method: "PATCH",
      headers: auth,
      body: JSON.stringify({ slug: "sites", title: "Sites" }),
    });
    expect(renamedProject.status).toBe(200);
    expect(store.getProject(ws, project.id)?.slug).toBe("sites");
    const membership = store.db
      .prepare(`SELECT project_id FROM mcpflow_agent_project WHERE agent_id = ? AND project_id = 'sites'`)
      .get(bot);
    expect(membership).toBeTruthy();

    const renamedDevice = await app.request(`/v1/devices/${device.id}`, {
      method: "PATCH",
      headers: auth,
      body: JSON.stringify({ name: "edge-renamed" }),
    });
    expect(renamedDevice.status).toBe(200);
    expect(store.getDevice(ws, device.id)?.name).toBe("edge-renamed");

    const legacy = store.createApiKey(ws, "old-key");
    const revoke = await app.request(`/v1/keys/${legacy.id}`, { method: "DELETE", headers: auth });
    expect(revoke.status).toBe(200);
    const purge = await app.request(`/v1/keys/${legacy.id}`, { method: "DELETE", headers: auth });
    expect(purge.status).toBe(200);
    expect(store.listApiKeys(ws).some((row) => row.id === legacy.id)).toBe(false);

    store.identity.revokeKey(key.keyId, chen, "done");
    const removed = await app.request(`/v1/agents/${bot}`, { method: "DELETE", headers: auth });
    expect(removed.status).toBe(200);
    const listed = await app.request("/v1/agents", { headers: auth });
    const agents = ((await listed.json()) as { agents: Array<{ name: string }> }).agents;
    expect(agents.some((agent) => agent.name === "press")).toBe(false);
    const again = store.identity.createAgent({
      workspaceId: ws,
      name: "press",
      owner: "chen",
      kind: "grokbot",
      projects: ["default"],
      createdBy: chen,
    });
    expect(again).toBeTruthy();
    await pool.closeAll();
    store.close();
  });
});
