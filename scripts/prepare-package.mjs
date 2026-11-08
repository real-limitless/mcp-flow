import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TSC_REL = join("node_modules", "typescript", "lib", "tsc.js");

/**
 * `npm install -g` and a root shell with NODE_ENV=production pass config that
 * would make a nested install global or omit devDependencies. The compiler
 * must land in this checkout.
 */
export function localInstallEnv(base = process.env) {
  const env = { ...base };
  delete env.npm_config_global;
  delete env.npm_config_prefix;
  delete env.npm_config_production;
  delete env.npm_config_omit;
  if (env.NODE_ENV === "production") delete env.NODE_ENV;
  return env;
}

function run(command, args, env = process.env) {
  const result = spawnSync(command, args, {
    stdio: "inherit",
    env,
    shell: process.platform === "win32",
  });
  if (result.error) {
    console.error(result.error.message);
    return 1;
  }
  return result.status === 0 ? 0 : (result.status ?? 1);
}

export function ensureTypescript(env = process.env) {
  if (existsSync(TSC_REL)) return 0;
  console.error("mcp-flow: installing the TypeScript compiler into this checkout");
  const status = run(
    "npm",
    ["install", "--include=dev", "--ignore-scripts", "--no-audit", "--no-fund"],
    localInstallEnv(env),
  );
  if (status !== 0 || !existsSync(TSC_REL)) {
    console.error(
      "mcp-flow: typescript is still missing. From the checkout run: npm install --include=dev",
    );
    return status || 1;
  }
  return 0;
}

function copyAdmin() {
  const src = "src/admin";
  if (!existsSync(src)) {
    console.error("mcp-flow: src/admin is missing");
    return 1;
  }
  const dest = "dist/admin";
  mkdirSync(dest, { recursive: true });
  for (const name of readdirSync(src)) {
    const from = join(src, name);
    if (!statSync(from).isFile()) continue;
    cpSync(from, join(dest, name));
  }
  return 0;
}

export function buildPackage(env = process.env) {
  const ready = ensureTypescript(env);
  if (ready !== 0) return ready;
  const compiled = run(process.execPath, [TSC_REL, "-p", "tsconfig.json"], env);
  if (compiled !== 0) return compiled;
  return copyAdmin();
}

function main() {
  const requireSources = process.argv.includes("--build");
  const hasSources = existsSync("src/cli.ts") && existsSync("tsconfig.json");
  if (!hasSources) {
    if (requireSources) {
      console.error("mcp-flow: src/cli.ts and tsconfig.json are required to build");
      process.exit(1);
    }
    process.exit(0);
  }
  process.exit(buildPackage(process.env));
}

const invokedDirectly =
  process.argv[1] &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (invokedDirectly) main();
