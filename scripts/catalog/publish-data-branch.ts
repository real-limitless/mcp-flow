#!/usr/bin/env tsx
/**
 * Push local factory catalog shards to origin/catalog-data (for GitHub Pages).
 *
 *   npm run catalog:publish-data
 *   npm run catalog:publish-data -- --dry-run
 *   npm run catalog:publish-data -- --release   # also refresh catalog-latest tarball release
 *
 * Requires: catalog/index.json + catalog/entries/, git push access to origin.
 * Does NOT touch main — only force-updates the catalog-data branch.
 */
import { existsSync, mkdirSync, cpSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { parseArgs } from "node:util";

const root = process.cwd();
const catalogDir = process.env.CATALOG_DIR || join(root, "catalog");

const { values } = parseArgs({
  options: {
    "dry-run": { type: "boolean", default: false },
    release: { type: "boolean", default: false },
    remote: { type: "string", default: "origin" },
    message: { type: "string" },
    help: { type: "boolean", default: false },
  },
});

if (values.help) {
  console.log(`Usage: publish-data-branch [--dry-run] [--release] [--remote origin] [--message msg]`);
  process.exit(0);
}

function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; inherit?: boolean } = {},
): string {
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd ?? root,
    encoding: "utf8",
    stdio: opts.inherit ? "inherit" : "pipe",
  });
  if (r.status !== 0) {
    const err = (r.stderr || r.stdout || "").trim();
    throw new Error(`${cmd} ${args.join(" ")} failed: ${err || r.status}`);
  }
  return (r.stdout || "").trim();
}

const indexPath = join(catalogDir, "index.json");
const metaPath = join(catalogDir, "meta.json");
const entriesPath = join(catalogDir, "entries");

if (!existsSync(indexPath) || !existsSync(entriesPath)) {
  console.error(
    "missing catalog/index.json or catalog/entries — run factory sync/enrich first",
  );
  process.exit(1);
}

let count = "?";
try {
  const meta = JSON.parse(readFileSync(metaPath, "utf8")) as {
    counts?: { total?: number };
  };
  count = String(meta.counts?.total ?? "?");
} catch {
  /* ignore */
}

const msg =
  values.message ||
  `catalog-data: local factory publish ${new Date().toISOString()} · ${count} entries`;

const work = join(tmpdir(), `mcp-flow-catalog-data-${process.pid}`);
rmSync(work, { recursive: true, force: true });
mkdirSync(join(work, "entries"), { recursive: true });
cpSync(indexPath, join(work, "index.json"));
if (existsSync(metaPath)) cpSync(metaPath, join(work, "meta.json"));
cpSync(entriesPath, join(work, "entries"), { recursive: true });

const entryFiles = run("bash", [
  "-c",
  `find entries -name '*.json' | wc -l`,
], { cwd: work });

console.log(
  JSON.stringify(
    {
      catalogDir,
      work,
      entries: entryFiles.trim(),
      remote: values.remote,
      dryRun: values.dryRun,
      release: values.release,
      message: msg,
    },
    null,
    2,
  ),
);

if (values.dryRun) {
  console.log("dry-run: not pushing");
  process.exit(0);
}

run("git", ["init"], { cwd: work });
run("git", ["checkout", "-b", "catalog-data"], { cwd: work });
run("git", ["config", "user.name", "mcp-flow-catalog"], { cwd: work });
run(
  "git",
  ["config", "user.email", "mcp-flow-catalog@users.noreply.github.com"],
  { cwd: work },
);
run("git", ["add", "-A"], { cwd: work });
run("git", ["commit", "-m", msg], { cwd: work });

const remoteUrl = run("git", ["remote", "get-url", values.remote ?? "origin"]);
run("git", ["remote", "add", "origin", remoteUrl], { cwd: work });
run("git", ["push", "-f", "origin", "catalog-data"], {
  cwd: work,
  inherit: true,
});

rmSync(work, { recursive: true, force: true });
console.log("pushed origin/catalog-data");

if (values.release) {
  run("npm", ["run", "catalog:bundle"], { inherit: true });
  const tag = "catalog-latest";
  spawnSync("gh", ["release", "delete", tag, "-y"], { cwd: root });
  run("git", ["tag", "-f", tag]);
  run("git", ["push", "-f", "origin", `refs/tags/${tag}`], { inherit: true });
  run(
    "gh",
    [
      "release",
      "create",
      tag,
      "dist/catalog-bundle.tgz",
      "--title",
      "Catalog data (latest)",
      "--notes",
      "Sharded catalog from local factory publish. Branch: catalog-data.",
      "--latest=false",
    ],
    { inherit: true },
  );
  console.log("updated release catalog-latest");
}

console.log(
  "Next: GitHub Actions pages workflow will pick this up on next run, or:\n  gh workflow run pages.yml",
);
