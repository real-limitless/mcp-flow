import { mkdtempSync, rmSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import { connectStdioCommand } from "../src/mcp/runners/stdio.js";
import { UpstreamPool } from "../src/mcp/upstream.js";

const master = Buffer.alloc(32, 7).toString("base64");
const dirs: string[] = [];

afterEach(async () => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

/**
 * Minimal MCP stdio server script (JSON-RPC over stdin/stdout).
 * Uses only Node built-ins.
 */
function writeFixtureServer(dir: string): string {
  const path = join(dir, "fixture-mcp.mjs");
  const code = `
import { createInterface } from "node:readline";
const rl = createInterface({ input: process.stdin });
function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\\n");
}
rl.on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "fixture", version: "1.0.0" },
      },
    });
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    return;
  }
  if (msg.method === "notifications/initialized") return;
  if (msg.method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        tools: [{
          name: "ping",
          description: "ping",
          inputSchema: { type: "object", properties: {} },
        }],
      },
    });
    return;
  }
  if (msg.method === "tools/call") {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        content: [{ type: "text", text: "pong" }],
      },
    });
    return;
  }
  if (msg.method === "ping") {
    send({ jsonrpc: "2.0", id: msg.id, result: {} });
  }
});
`;
  writeFileSync(path, code);
  chmodSync(path, 0o755);
  return path;
}

describe("stdio connect errors", () => {
  it("includes child stderr in the thrown error", async () => {
    await expect(
      connectStdioCommand({
        command: [
          process.execPath,
          "-e",
          "process.stderr.write('boom-stdio'); process.exit(1)",
        ],
        env: {},
      }),
    ).rejects.toThrow(/boom-stdio/);
  });
});

describe("central-sandbox stdio", () => {
  it("lists and calls tools via StdioClientTransport", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-stdio-"));
    dirs.push(dir);
    const script = writeFixtureServer(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    const be = store.createBackend(ws.id, {
      slug: "fix",
      transport: "stdio",
      command: [process.execPath, script],
      enabled: true,
      placement: { mode: "central-sandbox" },
    });
    expect(be.placement.mode).toBe("central-sandbox");

    const pool = new UpstreamPool(store);
    try {
      const tools = await pool.listNamespacedTools(ws.id);
      expect(tools.map((t) => t.name)).toContain("fix__ping");
      const result = await pool.callTool(ws.id, "fix__ping", {});
      expect(result.isError).toBeFalsy();
      expect(JSON.stringify(result)).toContain("pong");
    } finally {
      await pool.closeAll();
      store.close();
    }
  }, 30_000);
});
