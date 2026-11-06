#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdirSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const cwd = process.env.MCP_SHELL_CWD || "/repos";
mkdirSync(cwd, { recursive: true });

const server = new McpServer({
  name: "mcp-flow-shell",
  version: "0.1.0",
});

server.tool(
  "bash",
  "Run a shell command. cwd is the repos root (/repos). Use for gh, git, npm, etc.",
  {
    command: z.string(),
    timeout_ms: z.number().optional(),
  },
  async ({ command, timeout_ms }) => {
    const timeout = Math.min(Math.max(timeout_ms ?? 60_000, 1000), 300_000);
    try {
      const out = await new Promise((resolve, reject) => {
        const child = spawn("sh", ["-c", command], {
          cwd,
          env: process.env,
          stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (d) => {
          stdout += String(d);
          if (stdout.length > 200_000) stdout = stdout.slice(-200_000);
        });
        child.stderr?.on("data", (d) => {
          stderr += String(d);
          if (stderr.length > 200_000) stderr = stderr.slice(-200_000);
        });
        const t = setTimeout(() => {
          child.kill("SIGKILL");
          reject(new Error(`timed out after ${timeout}ms`));
        }, timeout);
        child.on("error", (e) => {
          clearTimeout(t);
          reject(e);
        });
        child.on("close", (code) => {
          clearTimeout(t);
          resolve(
            [`exit ${code ?? "?"}`, stdout && `stdout:\n${stdout}`, stderr && `stderr:\n${stderr}`]
              .filter(Boolean)
              .join("\n"),
          );
        });
      });
      return { content: [{ type: "text", text: out }] };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return {
        isError: true,
        content: [{ type: "text", text: msg }],
      };
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
