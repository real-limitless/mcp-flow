#!/usr/bin/env tsx
/**
 * Push local factory catalog shards to origin/catalog-data (for GitHub Pages).
 *
 *   npm run catalog:publish-data
 *   npm run catalog:publish-data -- --dry-run
 *   npm run catalog:publish-data -- --release
 */
import { existsSync, mkdirSync, cpSync, rmSync, readFileSync, writeFileSync } from "node:fs";
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
  console.log(
    `Usage: publish-data-branch [--dry-run] [--release] [--remote origin] [--message msg]`,
  );
  process.exit(0);
}

function run(
  cmd: string,
  args: string[],
  opts: { cwd?: string; inherit?: boolean; env?: NodeJS.ProcessEnv } = {},
): string {
  const r = spawnSync(cmd, args, {
    cwd: opts.cwd ?? root,
    encoding: "utf8",
    stdio: opts.inherit ? "inherit" : "pipe",
    env: { ...process.env, ...opts.env, GIT_TERMINAL_PROMPT: "0" },
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0) {
    const err = (r.stderr || r.stdout || "").trim();
    throw new Error(
      `${cmd} ${args.slice(0, 4).join(" ")}… failed (${r.status}): ${err.slice(0, 2000)}`,
    );
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

console.error("copying catalog shards…");
cpSync(indexPath, join(work, "index.json"));
if (existsSync(metaPath)) cpSync(metaPath, join(work, "meta.json"));
// Prefer cp -a for speed/size with many files
const cpr = spawnSync("cp", ["-a", `${entriesPath}/.`, join(work, "entries")], {
  encoding: "utf8",
});
if (cpr.status !== 0) {
  cpSync(entriesPath, join(work, "entries"), { recursive: true });
}

const entryFiles = run("bash", ["-c", "find entries -name '*.json' | wc -l"], {
  cwd: work,
});

console.log(
  JSON.stringify(
    {
      catalogDir,
      entries: Number(entryFiles.trim()),
      remote: values.remote,
      dryRun: Boolean(values["dry-run"]),
      release: Boolean(values.release),
      message: msg,
    },
    null,
    2,
  ),
);

if (values["dry-run"]) {
  console.log("dry-run: not pushing");
  rmSync(work, { recursive: true, force: true });
  process.exit(0);
}

console.error("git init + commit…");
run("git", ["init", "-q"], { cwd: work });
run("git", ["checkout", "-q", "-b", "catalog-data"], { cwd: work });
run("git", ["config", "user.name", "mcp-flow-catalog"], { cwd: work });
run(
  "git",
  ["config", "user.email", "mcp-flow-catalog@users.noreply.github.com"],
  { cwd: work },
);
// Quieter add for tens of thousands of files
run("git", ["-c", "core.safecrlf=false", "add", "-A"], { cwd: work });
// Avoid printing every path: use --quiet where supported
const commit = spawnSync(
  "git",
  ["commit", "-q", "-m", msg],
  { cwd: work, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 },
);
if (commit.status !== 0) {
  throw new Error(`git commit failed: ${(commit.stderr || commit.stdout || "").slice(0, 1500)}`);
}

const remoteUrl = run("git", ["remote", "get-url", values.remote ?? "origin"]);
run("git", ["remote", "add", "origin", remoteUrl], { cwd: work });

console.error("pushing origin/catalog-data (force)…");
// Increase http buffer for large push
run(
  "git",
  [
    "-c",
    "http.postBuffer=524288000",
    "push",
    "-f",
    "origin",
    "catalog-data",
  ],
  { cwd: work, inherit: true },
);

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
  "Next: gh workflow run pages.yml   # redeploy site from catalog-data",
);
