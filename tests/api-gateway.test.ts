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
import { startServer, type RunningServer } from "../src/server.js";

const master = Buffer.alloc(32, 3).toString("base64");
const admin = "test-admin-token-please-change";
const dirs: string[] = [];
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length) {
    await cleanups.pop()!();
  }
  while (dirs.length) {
    rmSync(dirs.pop()!, { recursive: true, force: true });
  }
});

async function startUpstream(): Promise<{ url: string; close: () => Promise<void> }> {
  const getServer = () => {
    const server = new McpServer({ name: "upstream-test", version: "1.0.0" });
    server.registerTool(
      "echo",
      {
        description: "Echo text",
        inputSchema: { text: z.string() },
      },
      async ({ text }) => ({
        content: [{ type: "text", text: `echo:${text}` }],
      }),
    );
    server.registerTool(
      "secret_probe",
      { description: "Should not leak gateway secrets" },
      async () => ({
        content: [{ type: "text", text: "ok" }],
      }),
    );
    return server;
  };

  const httpServer = createServer(async (req, res) => {
    if (req.method === "POST" && req.url === "/mcp") {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = chunks.length
        ? JSON.parse(Buffer.concat(chunks).toString("utf8"))
        : undefined;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
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
  const url = `http://127.0.0.1:${addr.port}/mcp`;
  return {
    url,
    close: () =>
      new Promise((resolve, reject) =>
        httpServer.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

async function bootGateway(): Promise<RunningServer> {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-g-"));
  dirs.push(dir);
  const cfg = loadConfig({
    dbPath: join(dir, "t.db"),
    masterKeyRaw: master,
    adminToken: admin,
    host: "127.0.0.1",
    port: 0 as unknown as number,
    allowPrivateUrls: true,
    workspaceName: "default",
  });
  // startServer uses cfg.port — pick a free port
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  const p = (probe.address() as { port: number }).port;
  await new Promise<void>((r, j) => probe.close((e) => (e ? j(e) : r())));
  cfg.port = p;

  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

describe("api + gateway", () => {
  it("mints keys, adds remote backend, proxies tools", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);

    const gw = await bootGateway();
    const base = gw.url;

    const keyRes = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "agent-a" }),
    });
    expect(keyRes.status).toBe(201);
    const keyBody = (await keyRes.json()) as {
      key: { token: string; id: string; prefix: string };
    };
    const token = keyBody.key.token;
    expect(token.startsWith("mf_")).toBe(true);

    // secrets must not appear on list
    const listKeys = await fetch(`${base}/v1/keys`, {
      headers: { Authorization: `Bearer ${admin}` },
    });
    const listJson = await listKeys.text();
    expect(listJson).not.toContain(token);

    const beRes = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        slug: "up",
        url: upstream.url,
        transport: "streamable-http",
        headers: { "X-Upstream-Secret": "never-leak-me" },
        enabled: true,
        placement: { mode: "remote" },
      }),
    });
    expect(beRes.status).toBe(201);
    const beJson = await beRes.text();
    expect(beJson).not.toContain("never-leak-me");
    expect(beJson).toContain('"hasHeaders":true');

    const getBe = await fetch(`${base}/v1/backends/up`, {
      headers: { Authorization: `Bearer ${admin}` },
    });
    const getText = await getBe.text();
    expect(getText).not.toContain("never-leak-me");

    // second key same workspace
    const key2Res = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "agent-b" }),
    });
    const token2 = ((await key2Res.json()) as { key: { token: string } }).key
      .token;

    for (const t of [token, token2]) {
      const client = new Client(
        { name: "test-harness", version: "1.0.0" },
        { capabilities: {} },
      );
      const transport = new StreamableHTTPClientTransport(
        new URL(`${base}/mcp`),
        {
          requestInit: {
            headers: { Authorization: `Bearer ${t}` },
          },
        },
      );
      await client.connect(transport);
      const tools = await client.listTools();
      const names = tools.tools.map((x) => x.name);
      expect(names).toContain("mf_status");
      expect(names).toContain("up__echo");
      expect(names).toContain("up__secret_probe");

      const call = await client.callTool({
        name: "up__echo",
        arguments: { text: "hi" },
      });
      const text = JSON.stringify(call);
      expect(text).toContain("echo:hi");
      expect(text).not.toContain("never-leak-me");
      expect(text).not.toContain(admin);

      await client.close();
    }
  }, 60_000);

  it("rejects unauthenticated /mcp", async () => {
    const gw = await bootGateway();
    const res = await fetch(`${gw.url}/mcp`, { method: "POST" });
    expect(res.status).toBe(401);
  });

  it("enforces key scopes on tools/list and tools/call + audit", async () => {
    const upstream = await startUpstream();
    cleanups.push(upstream.close);
    const gw = await bootGateway();
    const base = gw.url;

    await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        slug: "up",
        url: upstream.url,
        transport: "streamable-http",
        enabled: true,
        placement: { mode: "remote" },
      }),
    });

    const keyRes = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        name: "scoped",
        toolPrefixAllowlist: ["up__echo"],
      }),
    });
    const token = ((await keyRes.json()) as { key: { token: string } }).key
      .token;

    const client = new Client(
      { name: "scoped-harness", version: "1.0.0" },
      { capabilities: {} },
    );
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${token}` } },
      }),
    );
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);
    expect(names).toContain("up__echo");
    expect(names).toContain("mf_status");
    expect(names).not.toContain("up__secret_probe");

    const denied = await client.callTool({
      name: "up__secret_probe",
      arguments: {},
    });
    expect(denied.isError).toBe(true);

    const ok = await client.callTool({
      name: "up__echo",
      arguments: { text: "scoped" },
    });
    expect(JSON.stringify(ok)).toContain("echo:scoped");
    await client.close();

    const auditRes = await fetch(`${base}/v1/audit?limit=50`, {
      headers: { Authorization: `Bearer ${admin}` },
    });
    const audit = (await auditRes.json()) as {
      events: Array<{
        action: string;
        tool?: string;
        detail?: {
          denied?: boolean;
          arguments?: Record<string, unknown>;
          result?: { content?: Array<{ text?: string }>; isError?: boolean };
          isError?: boolean;
        };
      }>;
    };
    expect(audit.events.some((e) => e.action === "tools/list")).toBe(true);
    expect(
      audit.events.some(
        (e) => e.action === "tools/call" && e.detail?.denied === true,
      ),
    ).toBe(true);
    const echoEv = audit.events.find(
      (e) => e.action === "tools/call" && e.tool === "up__echo",
    );
    expect(echoEv?.detail?.arguments).toEqual({ text: "scoped" });
    expect(echoEv?.detail?.result?.content?.[0]?.text).toContain("echo:scoped");
    expect(echoEv?.detail?.isError).toBe(false);
  }, 60_000);

  it("accepts central-sandbox backend create; rejects edge-bare without policy", async () => {
    const gw = await bootGateway();
    const base = gw.url;
    const ok = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        slug: "localstdio",
        transport: "stdio",
        command: ["npx", "-y", "fake"],
        placement: { mode: "central-sandbox" },
      }),
    });
    expect(ok.status).toBe(201);

    const bare = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        slug: "barex",
        transport: "stdio",
        command: ["true"],
        placement: { mode: "edge-bare", deviceId: "missing" },
      }),
    });
    expect(bare.status).toBe(400);
  });

  it("serves admin UI", async () => {
    const gw = await bootGateway();
    const res = await fetch(`${gw.url}/admin/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("mcp-flow");
  });
});
