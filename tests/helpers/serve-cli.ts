/**
 * Spawn the real CLI (`serve`) from an isolated working directory: the gateway resolves its catalog
 * from the cwd (defaultCatalogDir), so tests never read or write the repo's catalog/ (QA v5.5 ask).
 */
import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const REPO = resolve(__dirname, "..", "..");

/** node argv for `src/cli.ts serve ...` with absolute paths (works from any cwd). */
export function cliServeArgs(...extra: string[]): string[] {
  return ["--import", pathToFileURL(join(REPO, "node_modules", "tsx", "dist", "loader.mjs")).href, join(REPO, "src", "cli.ts"), "serve", ...extra];
}

/** <dir>/cwd with an empty catalog/ inside: the cwd to spawn `serve` in. */
export function isolatedServeCwd(dir: string): string {
  const cwd = join(dir, "cwd");
  mkdirSync(join(cwd, "catalog"), { recursive: true });
  return cwd;
}
