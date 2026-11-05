/**
 * REST and MCP authz matrix for the secrets store.
 * Human admin is allowed. Break-glass, legacy api_key, OAuth, and a grokbot key are denied.
 */
import { chmodSync, closeSync, mkdtempSync, openSync, rmSync, writeSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { insertClient, insertGrant } from "../src/db/downstream-oauth.js";
import { startServer, type RunningServer } from "../src/server.js";

const dirs: string[] = [];
let gw: RunningServer | null = null;

afterEach(async () => {
  await gw?.close();
  gw = null;
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

const TOOLS = ["mf_secret_create", "mf_secret_rotate", "mf_secret_delete", "mf_secret_list"] as const;

async function mcpText(url: string, token: string, name: string, args: Record<string, unknown>): Promise<{ error: boolean; text: string }> {
  const client = new Client({ name: "secrets-authz", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${url}/mcp`), {
    requestInit: { headers: { authorization: `Bearer ${token}` } },
  }));
  try {
    const result = await client.callTool({ name, arguments: args });
    const text = Array.isArray(result.content)
      ? result.content.map((part) => ("text" in part ? String(part.text) : "")).join("\n")
      : "";
    return { error: result.isError === true, text };
  } finally {
    await client.close();
  }
}

describe("secret authz matrix", () => {
  it("allows a human admin and denies break-glass, legacy api_key, oauth, and grokbot", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-authz-"));
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
    });
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, "localhost", resolve));
    cfg.port = (probe.address() as { port: number }).port;
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    gw = await startServer(cfg);
    const store = gw.store;
    const ws = store.ensureWorkspace("default");
    const chen = store.identity.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
    store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'app')`).run(chen);
    const human = store.identity.createKey({ agentId: chen, createdBy: chen, projects: ["app"] }).token;
    const bot = store.identity.createAgent({
      workspaceId: ws.id,
      name: "bot",
      owner: "chen",
      kind: "grokbot",
      projects: ["app"],
      createdBy: chen,
    });
    const grokbot = store.identity.createKey({ agentId: bot, createdBy: chen, projects: ["app"] }).token;
    const legacy = store.createApiKey(ws.id, "legacy", { admin: true }).token;
    const client = insertClient(store.db, {
      workspaceId: ws.id,
      name: "example",
      secretHash: null,
      redirectUris: ["https://example.com/cb"],
    });
    const oauth = insertGrant(store.db, {
      workspaceId: ws.id,
      clientId: client.id,
      name: "example",
      scope: "mcp",
      scopes: { admin: true },
    }).accessToken;

    const rest = async (method: string, path: string, token: string, body?: unknown) => {
      const res = await fetch(`${gw!.url}${path}`, {
        method,
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return { status: res.status, text: await res.text() };
    };

    const created = await rest("POST", "/v1/secrets", human, { project: "app", name: "hook", type: "uuid" });
    expect(created.status).toBe(201);
    expect(created.text).toContain("secret://app/hook");
    const listed = await rest("GET", "/v1/secrets?project=app", human);
    expect(listed.status).toBe(200);
    expect(listed.text).toContain("secret://app/hook");

    const deniedRest: Array<[string, string]> = [
      ["break-glass", "break-glass-placeholder"],
      ["legacy", legacy],
      ["oauth", oauth],
      ["grokbot", grokbot],
    ];
    for (const [label, token] of deniedRest) {
      const create = await rest("POST", "/v1/secrets", token, { project: "app", name: `no-${label}`, type: "uuid" });
      const list = await rest("GET", "/v1/secrets?project=app", token);
      const rotate = await rest("POST", "/v1/secrets/rotate", token, { ref: "secret://app/hook" });
      const del = await rest("POST", "/v1/secrets/delete", token, { ref: "secret://app/hook" });
      for (const res of [create, list, rotate, del]) {
        expect(res.status, label).toBe(403);
        expect(res.text, label).not.toContain("secret://");
      }
    }

    const humanList = await mcpText(gw.url, human, "mf_secret_list", { project: "app" });
    expect(humanList.error).toBe(false);
    expect(humanList.text).toContain("secret://app/hook");

    for (const token of [legacy, oauth, grokbot]) {
      for (const name of TOOLS) {
        const args = name === "mf_secret_create"
          ? { project: "app", name: "stolen", type: "uuid" }
          : name === "mf_secret_list"
            ? { project: "app" }
            : { ref: "secret://app/hook" };
        const result = await mcpText(gw.url, token, name, args);
        expect(result.error, name).toBe(true);
        expect(result.text).toMatch(/human admin|not allowed|admin key|legacy_secret_ref/);
        expect(result.text).not.toContain("secret://app/hook");
      }
    }

    const glass = await fetch(`${gw.url}/mcp`, {
      method: "POST",
      headers: {
        authorization: "Bearer break-glass-placeholder",
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "0" } },
      }),
    });
    expect(glass.status).toBeGreaterThanOrEqual(400);
    expect(await glass.text()).not.toContain("secret://");

    const names = store.db.prepare(`SELECT name FROM mcpflow_secret ORDER BY name`).all() as Array<{ name: string }>;
    expect(names).toEqual([{ name: "hook" }]);
  }, 60_000);
});
