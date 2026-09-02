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
  dispose?: () => Promise<void>;
}

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
    env: {
      ...getDefaultEnvironment(),
      PATH: process.env.PATH ?? "",
      HOME: process.env.HOME ?? "",
      npm_config_yes: "true",
      npm_config_update_notifier: "false",
      ...opts.env,
    },
    cwd: opts.cwd,
    stderr: "pipe",
  });

  const errBuf: string[] = [];
  transport.stderr?.on("data", (chunk: Buffer | string) => {
    const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    errBuf.push(s);
    process.stderr.write(s);
  });

  const client = new Client(
    { name: "mcp-flow-stdio", version: "0.1.0" },
    { capabilities: {} },
  );
  try {
    await client.connect(transport);
    const listed = await client.listTools();
    return {
      client,
      transport,
      tools: listed.tools ?? [],
    };
  } catch (err) {
    const tail = errBuf.join("").trim().slice(-8000);
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(tail ? `${msg}\n--- stderr ---\n${tail}` : msg);
  }
}

export type { Transport, Tool };
