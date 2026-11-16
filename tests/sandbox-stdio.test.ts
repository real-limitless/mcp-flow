import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import {
  buildStdioEnv,
  connectStdioCommand,
  isNpxCacheCorruption,
  isNpxLikeCommand,
  resolveNpmCacheDir,
} from "../src/mcp/runners/stdio.js";
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

describe("npx cache isolation", () => {
  it("detects npx extract corruption", () => {
    expect(isNpxLikeCommand(["npx", "-y", "one-search-mcp"])).toBe(true);
    expect(isNpxLikeCommand(["/usr/bin/npx", "-y", "pkg"])).toBe(true);
    expect(isNpxLikeCommand(["node", "server.js"])).toBe(false);
    expect(
      isNpxCacheCorruption(
        `Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/home/node/.npm/_npx/abc/node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js'`,
      ),
    ).toBe(true);
    expect(isNpxCacheCorruption("ENOTEMPTY: directory not empty, rmdir '/home/node/.npm/_npx'")).toBe(
      true,
    );
    expect(isNpxCacheCorruption("upstream 401")).toBe(false);
  });

  it("points stdio env at a volume-backed npm cache", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-data-"));
    dirs.push(dir);
    const prevData = process.env.MCP_FLOW_DATA_DIR;
    const prevNpm = process.env.MCP_FLOW_NPM_CACHE;
    delete process.env.MCP_FLOW_NPM_CACHE;
    process.env.MCP_FLOW_DATA_DIR = dir;
    try {
      expect(resolveNpmCacheDir()).toBe(join(dir, "npm-cache"));
      const env = buildStdioEnv({});
      expect(env.npm_config_cache).toBe(join(dir, "npm-cache"));
      expect(env.npm_config_yes).toBe("true");
    } finally {
      if (prevData === undefined) delete process.env.MCP_FLOW_DATA_DIR;
      else process.env.MCP_FLOW_DATA_DIR = prevData;
      if (prevNpm === undefined) delete process.env.MCP_FLOW_NPM_CACHE;
      else process.env.MCP_FLOW_NPM_CACHE = prevNpm;
    }
  });

  it("retries npx once after a corrupt extract", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-npx-"));
    dirs.push(dir);
    const cache = join(dir, "cache");
    const fixture = writeFixtureServer(dir);
    const npx = join(dir, "npx");
    const countFile = join(dir, "count");
    writeFileSync(
      npx,
      `#!/usr/bin/env node
const { spawn } = require("child_process");
const { readFileSync, writeFileSync } = require("fs");
const stamp = ${JSON.stringify(countFile)};
const fixture = ${JSON.stringify(fixture)};
let n = 0;
try { n = Number(readFileSync(stamp, "utf8")); } catch { n = 0; }
n += 1;
writeFileSync(stamp, String(n));
if (n === 1) {
  console.error("Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/home/node/.npm/_npx/x/node_modules/@modelcontextprotocol/sdk/dist/esm/server/mcp.js'");
  process.exit(1);
}
const child = spawn(process.execPath, [fixture], { stdio: "inherit" });
child.on("exit", (code) => process.exit(code ?? 1));
`,
    );
    chmodSync(npx, 0o755);
    const result = await connectStdioCommand({
      command: [npx, "-y", "one-search-mcp"],
      env: { npm_config_cache: cache },
    });
    expect(result.tools.map((t) => t.name)).toContain("ping");
    await result.client.close();
  }, 20_000);
});

describe("python cache isolation", () => {
  const keys = [
    "MCP_FLOW_DATA_DIR",
    "MCP_FLOW_UV_CACHE",
    "MCP_FLOW_UV_TOOL_DIR",
    "MCP_FLOW_UV_PYTHON_DIR",
    "MCP_FLOW_PIP_CACHE",
    "MCP_FLOW_PYTHONUSERBASE",
  ] as const;

  function save(): Map<string, string | undefined> {
    return new Map(keys.map((key) => [key, process.env[key]]));
  }

  function restore(prev: Map<string, string | undefined>): void {
    for (const [key, value] of prev) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }

  it("points stdio env at volume-backed uv and pip dirs", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-py-"));
    dirs.push(dir);
    const prev = save();
    for (const key of keys) {
      if (key !== "MCP_FLOW_DATA_DIR") delete process.env[key];
    }
    process.env.MCP_FLOW_DATA_DIR = dir;
    try {
      const env = buildStdioEnv({});
      expect(env.UV_CACHE_DIR).toBe(join(dir, "uv-cache"));
      expect(env.UV_TOOL_DIR).toBe(join(dir, "uv-tools"));
      expect(env.UV_PYTHON_INSTALL_DIR).toBe(join(dir, "uv-python"));
      expect(env.PIP_CACHE_DIR).toBe(join(dir, "pip-cache"));
      expect(env.PYTHONUSERBASE).toBe(join(dir, "pip-user"));
      expect(env.UV_LINK_MODE).toBe("copy");
      for (const path of [
        env.UV_CACHE_DIR,
        env.UV_TOOL_DIR,
        env.UV_PYTHON_INSTALL_DIR,
        env.PIP_CACHE_DIR,
        env.PYTHONUSERBASE,
      ]) {
        expect(existsSync(path)).toBe(true);
      }
      expect(env.PATH?.split(delimiter)[0]).toBe(join(dir, "pip-user", "bin"));
    } finally {
      restore(prev);
    }
  });

  it("honors a backend UV_CACHE_DIR and keeps the user bin on PATH", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-py-"));
    dirs.push(dir);
    const prev = save();
    for (const key of keys) delete process.env[key];
    process.env.MCP_FLOW_DATA_DIR = dir;
    const custom = join(dir, "custom-uv");
    try {
      const env = buildStdioEnv({
        UV_CACHE_DIR: custom,
        UV_LINK_MODE: "hardlink",
        PATH: "/usr/bin",
      });
      expect(env.UV_CACHE_DIR).toBe(custom);
      expect(existsSync(custom)).toBe(true);
      expect(env.UV_LINK_MODE).toBe("hardlink");
      expect(env.PATH?.split(delimiter)).toEqual([join(dir, "pip-user", "bin"), "/usr/bin"]);
    } finally {
      restore(prev);
    }
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
