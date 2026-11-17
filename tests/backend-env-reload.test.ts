import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";

const master = Buffer.alloc(32, 7).toString("base64");
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function echoScript(dir: string): string {
  const path = join(dir, "echo-env.mjs");
  writeFileSync(
    path,
    `import { createInterface } from "node:readline";
const rl = createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === "initialize") {
    send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "echo", version: "1" } } });
    return;
  }
  if (msg.method === "notifications/initialized") return;
  if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo_env", description: "env", inputSchema: { type: "object", properties: {} } }] } });
    return;
  }
  if (msg.method === "tools/call") {
    send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: process.env.DEMO_VALUE || "" }] } });
  }
});
`,
  );
  return path;
}

describe("backend env edits", () => {
  it("uses the new value on the next tools/call without restarting the gateway", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-env-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    const backend = store.createBackend(ws.id, {
      slug: "echo",
      transport: "stdio",
      command: [process.execPath, echoScript(dir)],
      env: { DEMO_VALUE: "one" },
      enabled: true,
      placement: { mode: "central-sandbox" },
    });
    const pool = new UpstreamPool(store);
    try {
      const first = await pool.callTool(ws.id, "echo__echo_env", {});
      expect(JSON.stringify(first.content)).toContain("one");
      store.updateBackend(ws.id, backend.id, { env: { DEMO_VALUE: "two" }, envMode: "replace" });
      const second = await pool.callTool(ws.id, "echo__echo_env", {});
      expect(JSON.stringify(second.content)).toContain("two");
      expect(JSON.stringify(second.content)).not.toContain("one");
    } finally {
      await pool.closeAll();
      store.close();
    }
  }, 30_000);
});
