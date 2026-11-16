/**
 * Issue 83: a tools/list fan-out must not stall the process.
 * A hung backend is capped; /health stays inside a 3s probe; cached lists are not fetched again.
 */
import { createServer, type Server as HttpServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { ListToolsRequestSchema, type Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  DEFAULT_HEADERS_TIMEOUT_GAP_MS,
  DEFAULT_KEEP_ALIVE_TIMEOUT_MS,
  loadConfig,
  parseHeadersTimeoutMs,
  parseKeepAliveTimeoutMs,
  parseToolListTimeoutMs,
} from "../src/config.js";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { applyHttpServerTimeouts, startServer } from "../src/server.js";

const master = Buffer.alloc(32, 7).toString("base64");
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

function fatTools(count: number): Tool[] {
  const tools: Tool[] = [];
  for (let i = 0; i < count; i++) {
    const properties: Record<string, object> = {};
    for (let p = 0; p < 25; p++) {
      properties[`p${p}`] = {
        type: "object",
        description: "d".repeat(80),
        properties: {
          a: { type: "string", minLength: 1, maxLength: 200 },
          b: { type: "array", items: { type: "string" } },
        },
        required: ["a"],
      };
    }
    tools.push({
      name: `tool_${i}`,
      description: `tool ${i}`,
      inputSchema: { type: "object", properties, required: ["p0"] },
      outputSchema: { type: "object", properties, required: ["p0"] },
    });
  }
  return tools;
}

function mockUpstream(opts: {
  hangList?: boolean;
  delayMs?: number;
  tools?: () => Tool[];
}): { url: Promise<string>; lists: () => number; close: () => Promise<void> } {
  let lists = 0;
  let current = opts.tools?.() ?? [{ name: "echo", description: "echo", inputSchema: { type: "object" as const } }];
  const http = createServer(async (req, res) => {
    if (req.method !== "POST") {
      res.statusCode = 404;
      res.end();
      return;
    }
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : undefined;
    const msgs = Array.isArray(body) ? body : [body];
    const isList = msgs.some((msg) => msg && typeof msg === "object" && (msg as { method?: string }).method === "tools/list");
    if (isList) {
      lists += 1;
      if (opts.hangList) return;
      if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
      current = opts.tools?.() ?? current;
    }
    const mcp = new Server({ name: "mock", version: "0" }, { capabilities: { tools: {} } });
    const tools = current;
    mcp.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    await mcp.connect(transport);
    await transport.handleRequest(req, res, body);
  });
  const url = listen(http);
  return {
    url,
    lists: () => lists,
    close: () =>
      new Promise((resolve) => {
        http.closeAllConnections?.();
        http.close(() => resolve());
      }),
  };
}

function poolFor(store: Store, listWaitMs?: number): UpstreamPool {
  const pool = new UpstreamPool(store, {
    allowPrivateUrls: true,
    listWaitMs,
    initTimeoutMs: 8_000,
  });
  closers.push(async () => {
    await pool.closeAll();
    store.close();
  });
  return pool;
}

async function watchHealth(url: string, stop: { v: boolean }): Promise<number[]> {
  const samples: number[] = [];
  while (!stop.v) {
    const t = performance.now();
    try {
      const res = await fetch(`${url}/health`, { signal: AbortSignal.timeout(3_000) });
      samples.push(res.ok ? performance.now() - t : -1);
    } catch {
      samples.push(-1);
    }
  }
  return samples;
}

describe("HTTP server timeouts", () => {
  it("parses optional timeouts and keeps headers above keep-alive", () => {
    expect(parseKeepAliveTimeoutMs(undefined)).toBe(DEFAULT_KEEP_ALIVE_TIMEOUT_MS);
    expect(parseKeepAliveTimeoutMs("nope")).toBe(120_000);
    expect(parseKeepAliveTimeoutMs(50)).toBe(1_000);
    expect(parseKeepAliveTimeoutMs(130_000)).toBe(130_000);
    expect(parseHeadersTimeoutMs(undefined, 120_000)).toBe(120_000 + DEFAULT_HEADERS_TIMEOUT_GAP_MS);
    expect(parseHeadersTimeoutMs(1_000, 120_000)).toBe(121_000);
    expect(parseHeadersTimeoutMs(140_000, 120_000)).toBe(140_000);
    expect(parseToolListTimeoutMs(undefined, 20_000)).toBe(5_000);
    expect(parseToolListTimeoutMs(10, 20_000)).toBe(50);
    expect(parseToolListTimeoutMs(50_000, 1_000)).toBe(1_000);
    const cfg = loadConfig({
      masterKeyRaw: "x",
      adminToken: "y",
      keepAliveTimeoutMs: 130_000,
      headersTimeoutMs: 140_000,
      toolListTimeoutMs: 2_500,
    });
    expect(cfg.keepAliveTimeoutMs).toBe(130_000);
    expect(cfg.headersTimeoutMs).toBe(140_000);
    expect(cfg.toolListTimeoutMs).toBe(2_500);
    const defaults = loadConfig({ masterKeyRaw: "x", adminToken: "y" });
    expect(defaults.keepAliveTimeoutMs).toBe(120_000);
    expect(defaults.headersTimeoutMs).toBe(125_000);
    expect(defaults.toolListTimeoutMs).toBe(5_000);
  });

  it("sets keepAliveTimeout and headersTimeout on the listening server", async () => {
    const fake = { keepAliveTimeout: 5_000, headersTimeout: 60_000 };
    applyHttpServerTimeouts(fake, 130_000, 140_000);
    expect(fake).toEqual({ keepAliveTimeout: 130_000, headersTimeout: 140_000 });

    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-http-"));
    dirs.push(dir);
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: "timeout-admin",
      host: "127.0.0.1",
      port: 0,
      allowPrivateUrls: true,
      workspaceName: "default",
      keepAliveTimeoutMs: 130_000,
      headersTimeoutMs: 140_000,
    });
    const gw = await startServer(cfg);
    closers.push(() => gw.close());
    expect(gw.keepAliveTimeoutMs).toBe(130_000);
    expect(gw.headersTimeoutMs).toBe(140_000);
    const health = await fetch(`${gw.url}/health`);
    expect(health.status).toBe(200);
  });
});

describe("tools/list fan-out", () => {
  it("keeps /health under a 3s probe while a hung backend is listed", async () => {
    const fast = mockUpstream({});
    const hung = mockUpstream({ hangList: true });
    closers.push(() => fast.close(), () => hung.close());
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-stall-"));
    dirs.push(dir);
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: "stall-admin",
      host: "127.0.0.1",
      port: 0,
      allowPrivateUrls: true,
      workspaceName: "default",
      toolListTimeoutMs: 1_500,
    });
    const gw = await startServer(cfg);
    closers.push(() => gw.close());
    const ws = gw.store.ensureWorkspace("default").id;
    gw.store.createBackend(ws, { slug: "fast", transport: "streamable-http", url: await fast.url, enabled: true });
    gw.store.createBackend(ws, { slug: "hung", transport: "streamable-http", url: await hung.url, enabled: true });

    const stop = { v: false };
    const watching = watchHealth(gw.url, stop);
    await new Promise((r) => setTimeout(r, 30));
    const t0 = Date.now();
    const names = (await gw.pool.listNamespacedTools(ws)).map((tool) => tool.name);
    const wall = Date.now() - t0;
    stop.v = true;
    const samples = await watching;

    expect(names).toEqual(["fast__echo"]);
    expect(wall).toBeLessThan(1_500 + 800);
    expect(samples.length).toBeGreaterThan(0);
    expect(samples.every((ms) => ms >= 0 && ms < 3_000)).toBe(true);
    const health = gw.pool.toolListHealth(ws);
    expect(health.find((row) => row.slug === "fast")?.status).toBe("ready");
    expect(health.find((row) => row.slug === "hung")?.status).toBe("degraded");

    const againAt = Date.now();
    const again = (await gw.pool.listNamespacedTools(ws)).map((tool) => tool.name);
    expect(again).toEqual(["fast__echo"]);
    expect(Date.now() - againAt).toBeLessThan(500);
    expect(fast.lists()).toBe(1);
  }, 20_000);

  it("returns partial results and does not let a slow backend hold the others past the cap", async () => {
    const fast = mockUpstream({});
    const slow = mockUpstream({ delayMs: 5_000 });
    closers.push(() => fast.close(), () => slow.close());
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-cap-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default").id;
    store.createBackend(ws, { slug: "fast", transport: "streamable-http", url: await fast.url, enabled: true });
    store.createBackend(ws, { slug: "slow", transport: "streamable-http", url: await slow.url, enabled: true });
    const pool = poolFor(store, 400);

    const t0 = Date.now();
    const names = (await pool.listNamespacedTools(ws)).map((tool) => tool.name);
    const wall = Date.now() - t0;
    expect(names).toEqual(["fast__echo"]);
    expect(wall).toBeLessThan(1_200);
    expect(wall).toBeGreaterThanOrEqual(400);
    expect(pool.toolListHealth(ws).find((row) => row.slug === "slow")?.status).toBe("degraded");
    expect(pool.toolListHealth(ws).find((row) => row.slug === "fast")?.status).toBe("ready");
  }, 20_000);

  it("serves a cached list without another upstream tools/list, and refreshes when the client cache is cleared", async () => {
    let generation = 0;
    const upstream = mockUpstream({
      tools: () => [
        { name: generation === 0 ? "echo" : "other", description: "t", inputSchema: { type: "object" as const } },
      ],
    });
    closers.push(() => upstream.close());
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-cache-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default").id;
    const backend = store.createBackend(ws, {
      slug: "up",
      transport: "streamable-http",
      url: await upstream.url,
      enabled: true,
    });
    const pool = poolFor(store);

    expect((await pool.listNamespacedTools(ws)).map((tool) => tool.name)).toEqual(["up__echo"]);
    expect(upstream.lists()).toBe(1);
    expect((await pool.listNamespacedTools(ws)).map((tool) => tool.name)).toEqual(["up__echo"]);
    expect(upstream.lists()).toBe(1);

    const entry = (pool as unknown as { pool: Map<string, { fetchedAt: number }> }).pool.get(backend.id);
    expect(entry).toBeTruthy();
    entry!.fetchedAt = 0;
    expect((await pool.listNamespacedTools(ws)).map((tool) => tool.name)).toEqual(["up__echo"]);
    expect(upstream.lists()).toBe(2);

    generation = 1;
    pool.invalidate(backend.id);
    expect((await pool.listNamespacedTools(ws)).map((tool) => tool.name)).toEqual(["up__other"]);
    expect(upstream.lists()).toBe(3);
  });

  it("drops cached tools when the backend allowlist changes", async () => {
    const upstream = mockUpstream({
      tools: () => [
        { name: "echo", description: "e", inputSchema: { type: "object" as const } },
        { name: "other", description: "o", inputSchema: { type: "object" as const } },
      ],
    });
    closers.push(() => upstream.close());
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-allow-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default").id;
    const backend = store.createBackend(ws, {
      slug: "up",
      transport: "streamable-http",
      url: await upstream.url,
      enabled: true,
    });
    const pool = poolFor(store);
    expect((await pool.listNamespacedTools(ws)).map((tool) => tool.name).sort()).toEqual(["up__echo", "up__other"]);
    store.updateBackend(ws, backend.id, { toolAllowlist: ["other"] });
    expect((await pool.listNamespacedTools(ws)).map((tool) => tool.name)).toEqual(["up__other"]);
  });

  it("warms the cache in the background so the next list does not fetch", async () => {
    const upstream = mockUpstream({});
    closers.push(() => upstream.close());
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-warm-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default").id;
    store.createBackend(ws, { slug: "up", transport: "streamable-http", url: await upstream.url, enabled: true });
    const pool = poolFor(store);
    await pool.warmToolLists();
    expect(upstream.lists()).toBe(1);
    expect(pool.toolListHealth(ws)).toEqual([
      expect.objectContaining({ slug: "up", status: "ready" }),
    ]);
    await pool.listNamespacedTools(ws);
    expect(upstream.lists()).toBe(1);
  });

  it("lists a large output-schema catalog without missing the health probe", async () => {
    const fat = mockUpstream({ tools: () => fatTools(550) });
    closers.push(() => fat.close());
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-fat-"));
    dirs.push(dir);
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: "fat-admin",
      host: "127.0.0.1",
      port: 0,
      allowPrivateUrls: true,
      workspaceName: "default",
    });
    const gw = await startServer(cfg);
    closers.push(() => gw.close());
    const ws = gw.store.ensureWorkspace("default").id;
    gw.store.createBackend(ws, { slug: "fat", transport: "streamable-http", url: await fat.url, enabled: true });

    const stop = { v: false };
    const watching = watchHealth(gw.url, stop);
    await new Promise((r) => setTimeout(r, 30));
    const names = await gw.pool.listNamespacedTools(ws);
    stop.v = true;
    const samples = await watching;

    expect(names).toHaveLength(550);
    expect(names[0]?.name).toBe("fat__tool_0");
    expect(samples.length).toBeGreaterThan(0);
    expect(samples.every((ms) => ms >= 0 && ms < 3_000)).toBe(true);
  }, 30_000);
});
