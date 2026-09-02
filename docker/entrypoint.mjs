#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";

const DATA = process.env.MCP_FLOW_DATA_DIR || "/data";
const SECRETS = `${DATA}/secrets.env`;

function nonempty(v) {
  return typeof v === "string" && v.trim() !== "";
}

function parseEnvFile(text) {
  const out = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i === -1) continue;
    let v = t.slice(i + 1);
    if (
      (v.startsWith('"') && v.endsWith('"')) ||
      (v.startsWith("'") && v.endsWith("'"))
    ) {
      v = v.slice(1, -1);
    }
    out[t.slice(0, i)] = v;
  }
  return out;
}

mkdirSync(DATA, { recursive: true });
const file = existsSync(SECRETS)
  ? parseEnvFile(readFileSync(SECRETS, "utf8"))
  : {};

if (!nonempty(process.env.MCP_FLOW_MASTER_KEY) && nonempty(file.MCP_FLOW_MASTER_KEY)) {
  process.env.MCP_FLOW_MASTER_KEY = file.MCP_FLOW_MASTER_KEY;
}
if (!nonempty(process.env.MCP_FLOW_ADMIN_TOKEN) && nonempty(file.MCP_FLOW_ADMIN_TOKEN)) {
  process.env.MCP_FLOW_ADMIN_TOKEN = file.MCP_FLOW_ADMIN_TOKEN;
}

let generated = false;
if (!nonempty(process.env.MCP_FLOW_MASTER_KEY)) {
  process.env.MCP_FLOW_MASTER_KEY = randomBytes(32).toString("base64");
  generated = true;
}
if (!nonempty(process.env.MCP_FLOW_ADMIN_TOKEN)) {
  process.env.MCP_FLOW_ADMIN_TOKEN = randomBytes(32).toString("hex");
  generated = true;
}

if (!existsSync(SECRETS) || generated) {
  writeFileSync(
    SECRETS,
    [
      `MCP_FLOW_MASTER_KEY=${process.env.MCP_FLOW_MASTER_KEY}`,
      `MCP_FLOW_ADMIN_TOKEN=${process.env.MCP_FLOW_ADMIN_TOKEN}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  console.error("mcp-flow: wrote /data/secrets.env (values not logged)");
}
writeFileSync(`${DATA}/admin.token`, `${process.env.MCP_FLOW_ADMIN_TOKEN}\n`, {
  mode: 0o600,
});

process.env.MCP_FLOW_HOST ||= "0.0.0.0";
process.env.MCP_FLOW_PORT ||= "8787";
process.env.MCP_FLOW_DB_PATH ||= "/data/mcp-flow.db";

const args = process.argv.slice(2);
const verb = args[0] || "serve";

if (verb === "bootstrap") {
  const { runBootstrap } = await import("./bootstrap.mjs");
  await runBootstrap();
  process.exit(0);
}

if (verb === "edge") {
  const tokenPath = `${DATA}/device-token.txt`;
  const deadline = Date.now() + 90_000;
  while (!existsSync(tokenPath) && Date.now() < deadline) {
    console.error("mcp-flow edge: waiting for /data/device-token.txt");
    await new Promise((r) => setTimeout(r, 1000));
  }
  if (!existsSync(tokenPath)) {
    console.error("mcp-flow edge: /data/device-token.txt missing — start bootstrap first");
    process.exit(1);
  }
  const token = readFileSync(tokenPath, "utf8").trim();
  const rest = args.slice(1);
  if (!rest.includes("--url") && !process.env.MCP_FLOW_URL) {
    rest.push("--url", "http://mcp-flow:8787");
  }
  if (!rest.includes("--token")) rest.push("--token", token);
  await execCli(["edge", ...rest]);
  process.exit(0);
}

await execCli(args.length ? args : ["serve"]);

function execCli(cliArgs) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["/app/dist/cli.js", ...cliArgs], {
      stdio: "inherit",
      env: process.env,
      cwd: "/app",
    });
    const forward = (sig) => {
      if (!child.killed) child.kill(sig);
    };
    process.on("SIGTERM", () => forward("SIGTERM"));
    process.on("SIGINT", () => forward("SIGINT"));
    child.on("error", reject);
    child.on("exit", (code, signal) => {
      if (signal) process.exit(1);
      resolve(code ?? 1);
      process.exit(code ?? 1);
    });
  });
}
