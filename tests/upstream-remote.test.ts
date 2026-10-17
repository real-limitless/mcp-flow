import { createServer, type Server as HttpServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";

const master = Buffer.alloc(32, 9).toString("base64");
const dirs: string[] = [];
const closers: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (closers.length) await closers.pop()!();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function listen(server: HttpServer): Promise<string> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") throw new Error("no addr");
      resolve(`http://127.0.0.1:${addr.port}/mcp`);
    });
  });
}

function closeHttp(server: HttpServer): Promise<void> {
  server.closeAllConnections?.();
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

describe("remote connect", () => {
  it("closes the client when tools/list fails after connect", async () => {
    let openSockets = 0;
    const httpServer = createServer(async (req, res) => {
      if (req.method !== "POST" || req.url !== "/mcp") {
        res.statusCode = 404;
        res.end();
        return;
      }
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const body = chunks.length
        ? JSON.parse(Buffer.concat(chunks).toString("utf8"))
        : undefined;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      const mcp = new Server(
        { name: "boom", version: "0.0.1" },
        { capabilities: { tools: {} } },
      );
      mcp.setRequestHandler(ListToolsRequestSchema, async () => {
        throw new Error("list failed");
      });
      try {
        await mcp.connect(transport);
        await transport.handleRequest(req, res, body);
      } catch (err) {
        if (!res.headersSent) {
          res.statusCode = 500;
          res.end(err instanceof Error ? err.message : String(err));
        }
      } finally {
        res.on("close", () => {
          void transport.close();
          void mcp.close();
        });
      }
    });
    httpServer.keepAliveTimeout = 1;
    httpServer.on("connection", (socket) => {
      openSockets += 1;
      socket.on("close", () => {
        openSockets -= 1;
      });
    });
    const url = await listen(httpServer);
    closers.push(() => closeHttp(httpServer));

    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-remote-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "up",
      transport: "streamable-http",
      url,
      enabled: true,
    });
    const pool = new UpstreamPool(store);
    closers.push(async () => {
      await pool.closeAll();
      store.close();
    });

    await expect(pool.listNamespacedTools(ws.id)).resolves.toEqual([]);
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(openSockets).toBe(0);
    expect(
      (pool as unknown as { pool: Map<string, unknown> }).pool.size,
    ).toBe(0);
  });
});
