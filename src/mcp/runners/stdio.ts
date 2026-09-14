import { mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

/** Volume-backed npm cache so Docker overlayfs does not corrupt npx extracts. */
export function resolveNpmCacheDir(): string {
  const explicit = process.env.MCP_FLOW_NPM_CACHE?.trim();
  if (explicit) return explicit;
  const data = process.env.MCP_FLOW_DATA_DIR?.trim();
  if (data) return join(data, "npm-cache");
  return join(tmpdir(), "mcp-flow-npm-cache");
}

export function isNpxLikeCommand(command: string[]): boolean {
  const base = (command[0] ?? "").replace(/\\/g, "/").split("/").pop() ?? "";
  return /^(npx|npm)(\.cmd)?$/i.test(base);
}

export function isNpxCacheCorruption(message: string): boolean {
  return (
    /ERR_MODULE_NOT_FOUND|ENOTEMPTY|ENOENT/i.test(message) &&
    /node_modules|_npx|Cannot find module/i.test(message)
  );
}

export function npxExtractStore(cacheDir: string): string {
  return join(cacheDir, "_npx");
}

export function clearNpxExtractStore(cacheDir: string): void {
  rmSync(npxExtractStore(cacheDir), { recursive: true, force: true });
}

export function buildStdioEnv(
  extra: Record<string, string> = {},
): Record<string, string> {
  const cache = extra.npm_config_cache?.trim() || resolveNpmCacheDir();
  mkdirSync(cache, { recursive: true });
  return {
    ...getDefaultEnvironment(),
    PATH: process.env.PATH ?? "",
    HOME: process.env.HOME ?? "",
    npm_config_yes: "true",
    npm_config_update_notifier: "false",
    npm_config_fund: "false",
    npm_config_audit: "false",
    ...extra,
    npm_config_cache: cache,
  };
}

async function connectOnce(
  command: string[],
  env: Record<string, string>,
  cwd?: string,
): Promise<StdioRunResult> {
  const [cmd, ...args] = command;
  const transport = new StdioClientTransport({
    command: cmd!,
    args,
    env,
    cwd,
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
    try {
      await client.close();
    } catch {
      /* ignore */
    }
    const tail = errBuf.join("").trim().slice(-8000);
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(tail ? `${msg}\n--- stderr ---\n${tail}` : msg);
  }
}

export async function connectStdioCommand(opts: {
  command: string[];
  env: Record<string, string>;
  cwd?: string;
}): Promise<StdioRunResult> {
  if (!opts.command.length) {
    throw new Error("stdio command is empty");
  }
  const env = buildStdioEnv(opts.env);
  try {
    return await connectOnce(opts.command, env, opts.cwd);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!isNpxLikeCommand(opts.command) || !isNpxCacheCorruption(msg)) {
      throw err;
    }
    const cache = env.npm_config_cache || resolveNpmCacheDir();
    console.error(
      `[mcp-flow] npx extract looks corrupt (${msg.split("\n")[0]}); clearing ${npxExtractStore(cache)} and retrying`,
    );
    clearNpxExtractStore(cache);
    return await connectOnce(opts.command, env, opts.cwd);
  }
}

export type { Transport, Tool };
