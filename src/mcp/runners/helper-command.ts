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

  const head = command[0] ?? "";
  const scriptIndex = isNodeBin(head) && command.length > 1 ? 1 : 0;
  const token = command[scriptIndex] ?? "";
  const helper = helperFromToken(token);
  if (!helper) return { command, rewritten: false, helper: null };

  const isPathToken = token.includes("/") || token.includes("\\") || token.endsWith(".mjs") || token.endsWith(".sh");
  if (!isPathToken) {
    if (onPath(token, pathEnv, exists)) return { command, rewritten: false, helper };
  } else if (exists(token)) {
    return { command, rewritten: false, helper };
  }

  const file = helperFile(helper);
  const argsAfter = command.slice(scriptIndex + 1);
  if (!exists(file)) {
    if (!isPathToken) return { command, rewritten: false, helper };
    return { command: [helper, ...argsAfter], rewritten: true, helper };
  }
  if (helper === "shell-mcp") {
    return { command: [execPath, file, ...argsAfter], rewritten: true, helper };
  }
  return { command: [shellBin, file, ...argsAfter], rewritten: true, helper };
}
