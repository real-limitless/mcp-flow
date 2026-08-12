import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

export interface StdioRunResult {
  client: Client;
  transport: Transport;
  tools: Tool[];
  /** Extra cleanup (e.g. kill container) */
  dispose?: () => Promise<void>;
}

/**
 * Spawn a local stdio MCP via command[0] + args, with sealed env injected.
 */
export async function connectStdioCommand(opts: {
  command: string[];
  env: Record<string, string>;
  cwd?: string;
}): Promise<StdioRunResult> {
  if (!opts.command.length) {
    throw new Error("stdio command is empty");
  }
  const [cmd, ...args] = opts.command;
  const transport = new StdioClientTransport({
    command: cmd!,
    args,
    env: { ...getDefaultEnvironment(), ...opts.env },
    cwd: opts.cwd,
    stderr: "pipe",
  });

  const client = new Client(
    { name: "mcp-flow-stdio", version: "0.1.0" },
    { capabilities: {} },
  );
  await client.connect(transport);
  const listed = await client.listTools();
  return {
    client,
    transport,
    tools: listed.tools ?? [],
  };
}
