import { existsSync } from "node:fs";
import { basename, delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export type HelperName = "shell-mcp" | "github-mcp";

export interface ResolveHelperOptions {
  exists?: (path: string) => boolean;
  pathEnv?: string;
  execPath?: string;
  shellBin?: string;
  helperFile?: (name: HelperName) => string;
}

/** `docker/<helper>` next to the mcp-flow package that is running this process. */
export function installedHelperFile(name: HelperName): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const file = name === "shell-mcp" ? "shell-mcp.mjs" : "github-mcp.sh";
  // src/mcp/runners and dist/mcp/runners are both three levels below the package root.
  return join(here, "..", "..", "..", "docker", file);
}

function helperFromToken(token: string): HelperName | null {
  const base = basename(token.replaceAll("\\", "/"));
  if (base === "shell-mcp" || base === "shell-mcp.mjs") return "shell-mcp";
  if (base === "github-mcp" || base === "github-mcp.sh") return "github-mcp";
  return null;
}

function isNodeBin(token: string): boolean {
  const base = basename(token.replaceAll("\\", "/")).toLowerCase();
  return base === "node" || base === "nodejs" || base === "node.exe" || base === "nodejs.exe";
}

const CONTAINER_RUNTIMES = new Set(["docker", "podman", "nerdctl"]);

export function isContainerRuntime(token: string): boolean {
  const base = basename(token.replaceAll("\\", "/")).toLowerCase();
  return CONTAINER_RUNTIMES.has(base);
}

function findHelperToken(command: string[]): { helper: HelperName; index: number } | null {
  for (let i = 0; i < command.length; i++) {
    const helper = helperFromToken(command[i] ?? "");
    if (helper) return { helper, index: i };
  }
  return null;
}

/**
 * Command to send to another machine or into a container. A checkout path such as
 * docker/shell-mcp.mjs is only valid on the machine that stored it, so the
 * receiver gets the PATH name shell-mcp / github-mcp.
 */
export function portableHelperCommand(command: string[]): {
  command: string[];
  rewritten: boolean;
  helper: HelperName | null;
} {
  const found = findHelperToken(command);
  if (!found) return { command, rewritten: false, helper: null };
  const token = command[found.index] ?? "";
  if (token === found.helper) return { command, rewritten: false, helper: found.helper };
  const next = command.slice();
  next[found.index] = found.helper;
  const launcher = found.index - 1;
  if (launcher >= 0 && isNodeBin(next[launcher] ?? "")) next.splice(launcher, 1);
  return { command: next, rewritten: true, helper: found.helper };
}

export function resolveSpawnCommand(
  command: string[],
  opts: ResolveHelperOptions = {},
): { command: string[]; rewritten: boolean; helper: HelperName | null } {
  const head = command[0] ?? "";
  if (isContainerRuntime(head)) return portableHelperCommand(command);
  return resolveInstalledHelperCommand(command, opts);
}

function onPath(name: string, pathEnv: string, exists: (path: string) => boolean): boolean {
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    if (exists(join(dir, name))) return true;
  }
  return false;
}

/**
 * Launch the shell-mcp / github-mcp that ships with this install when a stored
 * command points at a checkout path this machine does not have, or when the
 * bare command is not on PATH (root services often have a short PATH).
 * A path that exists is left unchanged.
 */
export function resolveInstalledHelperCommand(
  command: string[],
  opts: ResolveHelperOptions = {},
): { command: string[]; rewritten: boolean; helper: HelperName | null } {
  const exists = opts.exists ?? existsSync;
  const pathEnv = opts.pathEnv ?? process.env.PATH ?? "";
  const execPath = opts.execPath ?? process.execPath;
  const shellBin = opts.shellBin ?? "/bin/sh";
  const helperFile = opts.helperFile ?? installedHelperFile;

  const found = findHelperToken(command);
  if (!found) return { command, rewritten: false, helper: null };
  const helper = found.helper;
  const token = command[found.index] ?? "";

  const isPathToken = token.includes("/") || token.includes("\\") || token.endsWith(".mjs") || token.endsWith(".sh");
  if (!isPathToken) {
    if (onPath(token, pathEnv, exists)) return { command, rewritten: false, helper };
  } else if (exists(token)) {
    return { command, rewritten: false, helper };
  }

  const file = helperFile(helper);
  const argsAfter = command.slice(found.index + 1);
  if (!exists(file)) {
    if (!isPathToken) return { command, rewritten: false, helper };
    return { command: [helper, ...argsAfter], rewritten: true, helper };
  }
  if (helper === "shell-mcp") {
    return { command: [execPath, file, ...argsAfter], rewritten: true, helper };
  }
  return { command: [shellBin, file, ...argsAfter], rewritten: true, helper };
}
