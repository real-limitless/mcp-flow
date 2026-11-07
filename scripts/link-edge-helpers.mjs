#!/usr/bin/env node
// Put shell-mcp and github-mcp on PATH without compiling TypeScript.
// Root: node scripts/link-edge-helpers.mjs
// Also: node scripts/link-edge-helpers.mjs --bind-missing /path/from/the/node/error
import { chmodSync, lstatSync, mkdirSync, symlinkSync, unlinkSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const helpers = {
  "shell-mcp": join(root, "docker", "shell-mcp.mjs"),
  "github-mcp": join(root, "docker", "github-mcp.sh"),
  "shell-mcp.mjs": join(root, "docker", "shell-mcp.mjs"),
  "github-mcp.sh": join(root, "docker", "github-mcp.sh"),
};

function link(dest, target) {
  mkdirSync(dirname(dest), { recursive: true });
  try {
    lstatSync(dest);
    unlinkSync(dest);
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
  }
  symlinkSync(target, dest);
}

const binDir = process.env.MCP_FLOW_BIN_DIR || "/usr/local/bin";
for (const name of ["shell-mcp", "github-mcp"]) {
  const target = helpers[name];
  chmodSync(target, 0o755);
  link(join(binDir, name), target);
  console.error(`linked ${join(binDir, name)} -> ${target}`);
}

const flag = process.argv.indexOf("--bind-missing");
if (flag !== -1) {
  const missing = process.argv[flag + 1];
  if (!missing) {
    console.error("mcp-flow: --bind-missing needs the path from the Node error");
    process.exit(1);
  }
  const key = basename(missing);
  const target = helpers[key];
  if (!target) {
    console.error(`mcp-flow: ${key} is not a shell-mcp or github-mcp helper`);
    process.exit(1);
  }
  link(missing, target);
  console.error(`linked ${missing} -> ${target}`);
}
