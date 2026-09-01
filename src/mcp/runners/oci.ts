import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { SandboxConfig } from "../../types.js";
import { connectStdioCommand, type StdioRunResult } from "./stdio.js";

export function containerRuntime(): string {
  return process.env.MCP_FLOW_CONTAINER_RUNTIME?.trim() || "docker";
}

/**
 * Run an OCI image as a stdio MCP: `docker/podman run -i --rm … image [cmd…]`
 * Attaches via StdioClientTransport to the container process.
 */
export async function connectOci(opts: {
  image: string;
  command?: string[] | null;
  env: Record<string, string>;
  sandbox?: SandboxConfig | null;
}): Promise<StdioRunResult> {
  const runtime = containerRuntime();
  const args: string[] = ["run", "-i", "--rm"];

  const net = opts.sandbox?.networkMode ?? "bridge";
  args.push("--network", net);

  if (opts.sandbox?.memory) {
    args.push("--memory", opts.sandbox.memory);
  }
  if (opts.sandbox?.cpus) {
    args.push("--cpus", opts.sandbox.cpus);
  }

  for (const [k, v] of Object.entries(opts.env)) {
    args.push("-e", `${k}=${v}`);
  }

  args.push(opts.image);
  if (opts.command?.length) {
    args.push(...opts.command);
  }

  // Use StdioClientTransport with docker/podman as the command
  return connectStdioCommand({
    command: [runtime, ...args],
    env: {},
  });
}

/** Quick check whether the container runtime is available */
export async function containerRuntimeAvailable(): Promise<boolean> {
  const runtime = containerRuntime();
  return new Promise((resolve) => {
    const child = spawn(runtime, ["version"], {
      stdio: "ignore",
    });
    child.on("error", () => resolve(false));
    child.on("exit", (code) => resolve(code === 0));
  });
}

export type { Transport, Tool, Client };
