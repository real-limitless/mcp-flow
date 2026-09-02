import { describe, expect, it } from "vitest";
import {
  connectOci,
  containerRuntime,
  containerRuntimeAvailable,
  ociRunArgs,
} from "../src/mcp/runners/oci.js";

const fixtureMcp = `
import { createInterface } from "node:readline";
const rl = createInterface({ input: process.stdin });
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\\n"); }
rl.on("line", (line) => {
  let msg; try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === "initialize") {
    send({ jsonrpc: "2.0", id: msg.id, result: {
      protocolVersion: "2024-11-05", capabilities: { tools: {} },
      serverInfo: { name: "fixture-oci", version: "1.0.0" },
    }});
    return;
  }
  if (msg.method === "notifications/initialized") return;
  if (msg.method === "tools/list") {
    send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{
      name: "ping", description: "ping", inputSchema: { type: "object", properties: {} },
    }]}});
    return;
  }
  if (msg.method === "tools/call") {
    send({ jsonrpc: "2.0", id: msg.id, result: {
      content: [{ type: "text", text: "pong-oci" }],
    }});
    return;
  }
  if (msg.method === "ping") send({ jsonrpc: "2.0", id: msg.id, result: {} });
});
`.trim();

describe("edge-sandbox OCI args", () => {
  it("builds docker/podman run for an image", () => {
    const args = ociRunArgs({
      image: "ghcr.io/example/mcp:latest",
      command: ["node", "server.js"],
      env: { TOKEN: "x" },
      sandbox: { memory: "256m", cpus: "0.5", networkMode: "none" },
    });
    expect(args).toEqual([
      "run",
      "-i",
      "--rm",
      "--network",
      "none",
      "--memory",
      "256m",
      "--cpus",
      "0.5",
      "-e",
      "TOKEN=x",
      "ghcr.io/example/mcp:latest",
      "node",
      "server.js",
    ]);
  });
});

describe("edge-sandbox OCI runtime", () => {
  it("lists and calls tools inside a container", async () => {
    if (process.env.MCP_FLOW_CONTAINER_RUNTIME === undefined) {
      process.env.MCP_FLOW_CONTAINER_RUNTIME = "podman";
    }
    if (!(await containerRuntimeAvailable())) {
      return;
    }
    const run = await connectOci({
      image: "docker.io/library/node:22-alpine",
      command: ["node", "--input-type=module", "-e", fixtureMcp],
      env: {},
      sandbox: { networkMode: "none" },
    });
    try {
      expect(run.tools.map((t) => t.name)).toContain("ping");
      const result = await run.client.callTool({ name: "ping", arguments: {} });
      expect(JSON.stringify(result)).toContain("pong-oci");
    } finally {
      await run.client.close().catch(() => undefined);
    }
  }, 120_000);

  it("reports the runtime name", () => {
    expect(containerRuntime().length).toBeGreaterThan(0);
  });
});
