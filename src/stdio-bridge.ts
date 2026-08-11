/**
 * Stdio bridge: harness talks stdio MCP; we proxy tools to HTTP /mcp.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

export interface StdioBridgeOptions {
  url: string;
  apiKey: string;
}

export async function runStdioBridge(opts: StdioBridgeOptions): Promise<void> {
  const remote = new Client(
    { name: "mcp-flow-stdio", version: "0.1.0" },
    { capabilities: {} },
  );

  const transport = new StreamableHTTPClientTransport(new URL(opts.url), {
    requestInit: {
      headers: {
        Authorization: `Bearer ${opts.apiKey}`,
      },
    },
  });

  await remote.connect(transport);

  const server = new Server(
    { name: "mcp-flow-stdio", version: "0.1.0" },
    { capabilities: { tools: { listChanged: true } } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const result = await remote.listTools();
    return result;
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const result = await remote.callTool({
      name: request.params.name,
      arguments: request.params.arguments ?? {},
    });
    return result as CallToolResult;
  });

  const stdio = new StdioServerTransport();
  await server.connect(stdio);

  const shutdown = async () => {
    try {
      await server.close();
    } catch {
      /* ignore */
    }
    try {
      await remote.close();
    } catch {
      /* ignore */
    }
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}
