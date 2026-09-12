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
import { fromBase32, totpCode } from "../src/authz/totp.js";

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

async function startUpstream(calls: string[]): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  const getServer = () => {
    const server = new McpServer({ name: "upstream-test", version: "1.0.0" });
    server.registerTool(
      "echo",
      {
        description: "Echo text",
        inputSchema: { text: z.string() },
      },
      async ({ text }) => {
        calls.push(text);
        return { content: [{ type: "text", text: `echo:${text}` }] };
      },
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
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-azg-"));
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
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  const p = (probe.address() as { port: number }).port;
  await new Promise<void>((r, j) => probe.close((e) => (e ? j(e) : r())));
  cfg.port = p;
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

const hdr = {
  Authorization: `Bearer ${admin}`,
  "Content-Type": "application/json",
};

async function mintAgent(base: string): Promise<{ token: string; id: string }> {
  const keyRes = await fetch(`${base}/v1/keys`, {
    method: "POST",
    headers: hdr,
    body: JSON.stringify({ name: "agent-a" }),
  });
  const keyBody = (await keyRes.json()) as { key: { token: string; id: string } };
  return keyBody.key;
}

async function addEchoBackend(base: string, url: string): Promise<void> {
  const beRes = await fetch(`${base}/v1/backends`, {
    method: "POST",
    headers: hdr,
    body: JSON.stringify({
      slug: "up",
      url,
      transport: "streamable-http",
      enabled: true,
      placement: { mode: "remote" },
    }),
  });
  if (beRes.status !== 201) {
    throw new Error(`backend ${beRes.status} ${await beRes.text()}`);
  }
}

async function connectAgent(base: string, token: string): Promise<Client> {
  const client = new Client(
    { name: "authz-harness", version: "1.0.0" },
    { capabilities: {} },
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
      requestInit: { headers: { Authorization: `Bearer ${token}` } },
    }),
  );
  return client;
}

function resultText(call: unknown): string {
  return JSON.stringify(call);
}

async function waitForPending(
  base: string,
  tool: string,
  timeoutMs = 5_000,
): Promise<{ id: string }> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const res = await fetch(`${base}/v1/approvals?status=pending`, {
      headers: hdr,
    });
    const body = (await res.json()) as {
      approvals: Array<{ id: string; tool: string }>;
    };
    const hit = body.approvals.find((a) => a.tool === tool);
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 40));
  }
  throw new Error("no pending approval");
}

describe("authz gateway hold", () => {
  it("holds tools/call until REST approve, then returns upstream result", async () => {
    const calls: string[] = [];
    const upstream = await startUpstream(calls);
    cleanups.push(upstream.close);
    const gw = await bootGateway();
    const base = gw.url;
    await addEchoBackend(base, upstream.url);
    const { token } = await mintAgent(base);

    const ruleRes = await fetch(`${base}/v1/authz/rules`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({
        name: "echo-gate",
        match: { tools: ["up__echo"] },
        requirement: "notify_approve",
        ttlSeconds: 30,
      }),
    });
    expect(ruleRes.status).toBe(201);

    const client = await connectAgent(base, token);
    const callP = client.callTool({
      name: "up__echo",
      arguments: { text: "gated-hi" },
    });
    const pending = await waitForPending(base, "up__echo");
    expect(calls).toEqual([]);

    const empty = await fetch(`${base}/v1/authz/rules`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({ name: "bad", match: {} }),
    });
    expect(empty.status).toBe(400);

    const agentDecide = await fetch(`${base}/v1/approvals/${pending.id}/decision`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(agentDecide.status).toBe(401);

    const dec = await fetch(`${base}/v1/approvals/${pending.id}/decision`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(dec.status).toBe(200);
    const call = await callP;
    expect(resultText(call)).toContain("echo:gated-hi");
    expect(calls).toEqual(["gated-hi"]);
    await client.close();
  }, 20_000);

  it("deny and timeout never hit upstream; late approve is a no-op", async () => {
    const calls: string[] = [];
    const upstream = await startUpstream(calls);
    cleanups.push(upstream.close);
    const gw = await bootGateway();
    const base = gw.url;
    await addEchoBackend(base, upstream.url);
    const { token } = await mintAgent(base);

    await fetch(`${base}/v1/authz/rules`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({
        name: "echo-gate",
        match: { prefixes: ["up__"] },
        requirement: "notify_approve",
        ttlSeconds: 1,
      }),
    });

    const client = await connectAgent(base, token);
    const denyP = client.callTool({
      name: "up__echo",
      arguments: { text: "nope" },
    });
    const pending = await waitForPending(base, "up__echo");
    const den = await fetch(`${base}/v1/approvals/${pending.id}/decision`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({ decision: "deny" }),
    });
    expect(den.status).toBe(200);
    const denied = await denyP;
    expect(resultText(denied)).toContain("authz_denied");
    expect(calls).toEqual([]);

    const timeoutP = client.callTool({
      name: "up__echo",
      arguments: { text: "slow" },
    });
    const timed = await waitForPending(base, "up__echo");
    const timedResult = await timeoutP;
    expect(resultText(timedResult)).toContain("authz_timeout");
    expect(calls).toEqual([]);

    const late = await fetch(`${base}/v1/approvals/${timed.id}/decision`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(late.status).toBe(409);
    expect(calls).toEqual([]);
    await client.close();
  }, 20_000);

  it("exempts mf_status and requires TOTP when the rule says mfa", async () => {
    const calls: string[] = [];
    const upstream = await startUpstream(calls);
    cleanups.push(upstream.close);
    const gw = await bootGateway();
    const base = gw.url;
    await addEchoBackend(base, upstream.url);
    const { token } = await mintAgent(base);

    await fetch(`${base}/v1/authz/rules`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({
        name: "all-mf",
        match: { prefixes: ["mf_"] },
        requirement: "mfa_and_approve",
        ttlSeconds: 20,
      }),
    });
    await fetch(`${base}/v1/authz/rules`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({
        name: "echo-mfa",
        match: { tools: ["up__echo"] },
        requirement: "mfa_and_approve",
        ttlSeconds: 20,
      }),
    });

    const client = await connectAgent(base, token);
    const status = await Promise.race([
      client.callTool({ name: "mf_status", arguments: {} }),
      new Promise((_, rej) =>
        setTimeout(() => rej(new Error("mf_status was held")), 800),
      ),
    ]);
    expect(resultText(status)).toContain("ok");

    const begin = await fetch(`${base}/v1/operators/mfa/begin`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({}),
    });
    expect(begin.status).toBe(200);
    const beginBody = (await begin.json()) as { secret: string };
    const code = totpCode(fromBase32(beginBody.secret));
    const confirm = await fetch(`${base}/v1/operators/mfa/confirm`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({ totp: code }),
    });
    expect(confirm.status).toBe(200);

    const callP = client.callTool({
      name: "up__echo",
      arguments: { text: "mfa-hi" },
    });
    const pending = await waitForPending(base, "up__echo");
    const noTotp = await fetch(`${base}/v1/approvals/${pending.id}/decision`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({ decision: "approve" }),
    });
    expect(noTotp.status).toBe(400);
    expect(calls).toEqual([]);

    const ok = await fetch(`${base}/v1/approvals/${pending.id}/decision`, {
      method: "POST",
      headers: hdr,
      body: JSON.stringify({
        decision: "approve",
        totp: totpCode(fromBase32(beginBody.secret)),
      }),
    });
    expect(ok.status).toBe(200);
    const call = await callP;
    expect(resultText(call)).toContain("echo:mfa-hi");
    expect(calls).toEqual(["mfa-hi"]);
    await client.close();
  }, 20_000);
});
