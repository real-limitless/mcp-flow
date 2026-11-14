/**
 * Issue #76: minting through the admin API writes an agent key that /mcp accepts
 * while legacy refusal is on, scoped to its project and tool allowlist.
 */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { z } from "zod";
import { loadConfig } from "../src/config.js";
import { saveRuleVersion } from "../src/policy/rule-input.js";
import { startServer, type RunningServer } from "../src/server.js";

const admin = "mint-test-admin";
const dirs: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
const clients: Client[] = [];

afterEach(async () => {
  while (clients.length) await clients.pop()!.close().catch(() => {});
  while (cleanups.length) await cleanups.pop()!();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
}, 30_000);

async function startUpstream(): Promise<{ url: string; close: () => Promise<void> }> {
  const getServer = () => {
    const server = new McpServer({ name: "upstream-test", version: "1.0.0" });
    server.registerTool(
      "echo",
      { description: "Echo text", inputSchema: { text: z.string() } },
      async ({ text }) => ({ content: [{ type: "text", text: `echo:${text}` }] }),
    );
    server.registerTool("secret_probe", { description: "Not on the allowlist" }, async () => ({
      content: [{ type: "text", text: "ok" }],
    }));
    return server;
  };
  const httpServer = createServer(async (req, res) => {
    if (req.method === "POST" && req.url === "/mcp") {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      const server = getServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      return;
    }
    res.statusCode = 404;
    res.end();
  });
  await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const addr = httpServer.address();
  if (!addr || typeof addr === "string") throw new Error("no addr");
  return {
    url: `http://127.0.0.1:${addr.port}/mcp`,
    close: () => new Promise((resolve, reject) => httpServer.close((err) => (err ? reject(err) : resolve()))),
  };
}

async function boot(refuseLegacyMcpKeys: boolean): Promise<RunningServer> {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-mint-"));
  dirs.push(dir);
  const cfg = loadConfig({
    dbPath: join(dir, "t.db"),
    masterKeyRaw: Buffer.alloc(32, 7).toString("base64"),
    adminToken: admin,
    host: "127.0.0.1",
    port: 0 as unknown as number,
    allowPrivateUrls: true,
    workspaceName: "default",
    refuseLegacyMcpKeys,
  });
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) => probe.close((err) => (err ? reject(err) : resolve())));
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  return { Authorization: `Bearer ${admin}`, "Content-Type": "application/json", ...extra };
}

async function mcpInitialize(base: string, token: string): Promise<Response> {
  return fetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } },
    }),
  });
}

async function connect(base: string, token: string): Promise<Client> {
  const client = new Client({ name: "mint-harness", version: "1.0.0" }, { capabilities: {} });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
    }),
  );
  clients.push(client);
  return client;
}

describe("agent key mint", () => {
  it("supported routes mint a key /mcp accepts, scoped to project and allowlist; legacy keys stay refused", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const gw = await boot(true);
    const base = gw.url;

    for (const slug of ["alpha", "beta"]) {
      const created = await fetch(`${base}/v1/backends`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({
          slug,
          url: upstream.url,
          transport: "streamable-http",
          enabled: true,
          placement: { mode: "remote" },
        }),
      });
      expect(created.status).toBe(201);
      const tested = await fetch(`${base}/v1/backends/${slug}/test`, {
        method: "POST",
        headers: authHeaders(),
        body: "{}",
      });
      expect(tested.status).toBe(200);
    }
    for (const [slug, backend] of [["app", "alpha"], ["other", "beta"]] as const) {
      const created = await fetch(`${base}/v1/projects`, {
        method: "POST",
        headers: authHeaders(),
        body: JSON.stringify({ slug, backendSlugs: [backend] }),
      });
      expect(created.status).toBe(201);
    }

    const unknown = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ name: "missing-project", projects: ["no-such-project"], toolPrefixAllowlist: ["alpha__echo"] }),
    });
    expect(unknown.status).toBe(400);

    const dynamic = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ name: "dyn", dynamicTools: true, projects: ["app"] }),
    });
    expect(dynamic.status).toBe(400);
    const legacyBefore = (await (await fetch(`${base}/v1/keys`, { headers: authHeaders() })).json()) as { keys: unknown[] };
    expect(legacyBefore.keys).toHaveLength(0);

    const minted = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        name: "scoped-agent",
        projects: ["app"],
        toolPrefixAllowlist: ["alpha__echo"],
      }),
    });
    expect(minted.status).toBe(201);
    const mintedBody = (await minted.json()) as {
      agent: { id: string; projects: string[] };
      key: { id: string; token: string; scopes: { projects: string[]; toolPrefixAllowlist?: string[] } };
    };
    expect(mintedBody.key.token.startsWith("mf_")).toBe(true);
    expect(mintedBody.key.token.startsWith("mf_sess_")).toBe(false);
    expect(mintedBody.key.scopes.projects).toEqual(["app"]);
    expect(mintedBody.key.scopes.toolPrefixAllowlist).toEqual(["alpha__echo"]);
    expect(mintedBody.agent.projects).toEqual(["app"]);

    const projectOnly = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ name: "project-only", projects: ["app"] }),
    });
    expect(projectOnly.status).toBe(201);
    const projectToken = ((await projectOnly.json()) as { key: { token: string } }).key.token;

    const viaKeys = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ name: "via-keys", projects: ["app"], toolPrefixAllowlist: ["alpha__echo"] }),
    });
    expect(viaKeys.status).toBe(201);
    const viaBody = (await viaKeys.json()) as { key: { id: string; token: string }; agent: { id: string } };
    expect(viaBody.key.token.startsWith("mf_")).toBe(true);

    const legacyRows = (await (await fetch(`${base}/v1/keys`, { headers: authHeaders() })).json()) as {
      keys: Array<{ id: string }>;
    };
    expect(legacyRows.keys.map((k) => k.id)).not.toContain(mintedBody.key.id);
    expect(legacyRows.keys.map((k) => k.id)).not.toContain(viaBody.key.id);

    const agents = (await (await fetch(`${base}/v1/agents`, { headers: authHeaders() })).json()) as {
      agents: Array<{ name: string; keys: Array<{ id: string; toolPrefixAllowlist: string[] }> }>;
    };
    const scoped = agents.agents.find((a) => a.name === "scoped-agent");
    expect(scoped?.keys.some((k) => k.id === mintedBody.key.id && k.toolPrefixAllowlist[0] === "alpha__echo")).toBe(true);
    expect(JSON.stringify(agents)).not.toContain(mintedBody.key.token);

    const wsId = gw.store.ensureWorkspace("default").id;
    const owner = gw.store.db
      .prepare(`SELECT id FROM mcpflow_agent WHERE workspace_id = ? AND created_by IS NULL`)
      .get(wsId) as { id: string };
    saveRuleVersion(gw.store.db, {
      ruleId: `rule_${randomBytes(12).toString("hex")}`,
      workspaceId: wsId,
      createdBy: owner.id,
      description: "allow tools",
      effect: "allow",
      matchTools: ["*"],
    });

    const client = await connect(base, mintedBody.key.token);
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain("alpha__echo");
    expect(names).toContain("mf_status");
    expect(names).not.toContain("alpha__secret_probe");
    expect(names).not.toContain("beta__echo");

    const projects = await client.callTool({ name: "mf_list_projects", arguments: {} });
    const projectPayload = JSON.parse((projects.content as Array<{ text: string }>)[0]!.text) as {
      projects: Array<{ slug: string }>;
    };
    expect(projectPayload.projects.map((p) => p.slug)).toEqual(["app"]);
    const switched = await client.callTool({ name: "mf_use_project", arguments: { project: "other" } });
    expect(switched.isError).toBe(true);
    expect(JSON.stringify(switched)).toMatch(/not permitted/);

    const denied = await client.callTool({ name: "alpha__secret_probe", arguments: {} });
    expect(denied.isError).toBe(true);
    const ok = await client.callTool({ name: "alpha__echo", arguments: { text: "scoped" } });
    expect(JSON.stringify(ok)).toContain("echo:scoped");
    await client.close();

    const broad = await connect(base, projectToken);
    const broadNames = (await broad.listTools()).tools.map((t) => t.name);
    expect(broadNames).toContain("alpha__echo");
    expect(broadNames).toContain("alpha__secret_probe");
    expect(broadNames).not.toContain("beta__echo");
    await broad.close();

    expect((await mcpInitialize(base, viaBody.key.token)).status).toBe(200);

    const second = await fetch(`${base}/v1/agents/${mintedBody.agent.id}/keys`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ projects: ["app"], toolPrefixAllowlist: ["alpha__echo"] }),
    });
    expect(second.status).toBe(201);
    const secondToken = ((await second.json()) as { key: { id: string; token: string } }).key;
    const third = await fetch(`${base}/v1/agents/${mintedBody.agent.id}/keys`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ projects: ["app"] }),
    });
    expect(third.status).toBe(409);

    const revoked = await fetch(`${base}/v1/agents/${mintedBody.agent.id}/keys/${secondToken.id}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
    expect(revoked.status).toBe(200);
    expect((await mcpInitialize(base, secondToken.token)).status).toBe(401);

    const legacy = gw.store.createApiKey(gw.store.ensureWorkspace("default").id, "legacy-row", { projects: ["app"] });
    const refused = await mcpInitialize(base, legacy.token);
    expect(refused.status).toBe(403);
    expect(await refused.text()).toMatch(/legacy keys are not accepted/);
  }, 60_000);

  it("with legacy refusal off, POST /v1/keys still writes a legacy key and POST /v1/agents still writes an agent key", async () => {
    const gw = await boot(false);
    const base = gw.url;
    const legacyRes = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ name: "legacy-ok" }),
    });
    expect(legacyRes.status).toBe(201);
    const legacyBody = (await legacyRes.json()) as { key: { id: string; token: string }; agent?: unknown };
    expect(legacyBody.agent).toBeUndefined();
    const listed = (await (await fetch(`${base}/v1/keys`, { headers: authHeaders() })).json()) as {
      keys: Array<{ id: string }>;
    };
    expect(listed.keys.map((k) => k.id)).toContain(legacyBody.key.id);
    expect((await mcpInitialize(base, legacyBody.key.token)).status).toBe(200);

    const agentRes = await fetch(`${base}/v1/agents`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ name: "still-agent", projects: ["default"] }),
    });
    expect(agentRes.status).toBe(201);
    const agentBody = (await agentRes.json()) as { key: { id: string; token: string } };
    const listedAfter = (await (await fetch(`${base}/v1/keys`, { headers: authHeaders() })).json()) as {
      keys: Array<{ id: string }>;
    };
    expect(listedAfter.keys.map((k) => k.id)).not.toContain(agentBody.key.id);
    expect((await mcpInitialize(base, agentBody.key.token)).status).toBe(200);
  });
});
