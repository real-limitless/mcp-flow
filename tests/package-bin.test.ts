import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function read(rel: string): string {
  return readFileSync(resolve(root, rel), "utf8");
}

describe("npm package bins", () => {
  const pkg = JSON.parse(read("package.json")) as {
    name: string;
    version: string;
    bin: Record<string, string>;
    files: string[];
    scripts: Record<string, string>;
  };
  const lock = JSON.parse(read("package-lock.json")) as {
    packages: { "": { bin?: Record<string, string> } };
  };

  it("exposes mcp-flow, shell-mcp, and github-mcp", () => {
    expect(pkg.name).toBe("mcp-flow");
    expect(pkg.version).toBe("0.1.0");
    expect(pkg.bin).toEqual({
      "mcp-flow": "./dist/cli.js",
      "shell-mcp": "./docker/shell-mcp.mjs",
      "github-mcp": "./docker/github-mcp.sh",
    });
    expect(lock.packages[""].bin).toEqual({
      "github-mcp": "docker/github-mcp.sh",
      "mcp-flow": "dist/cli.js",
      "shell-mcp": "docker/shell-mcp.mjs",
    });
  });

  it("packs the built CLI, helper scripts, and prepare guard", () => {
    expect(pkg.files).toEqual(
      expect.arrayContaining([
        "dist",
        "docker/shell-mcp.mjs",
        "docker/github-mcp.sh",
        "scripts/prepare-package.mjs",
      ]),
    );
    expect(pkg.scripts.prepare).toBe("node scripts/prepare-package.mjs");
    expect(pkg.scripts.build).toContain("tsc");
    expect(read("scripts/prepare-package.mjs")).toContain("npm");
    expect(read("scripts/prepare-package.mjs")).toContain("src/cli.ts");
  });

  it("gives each bin a shebang", () => {
    expect(read("src/cli.ts").startsWith("#!/usr/bin/env node\n")).toBe(true);
    expect(read("docker/shell-mcp.mjs").startsWith("#!/usr/bin/env node\n")).toBe(true);
    expect(read("docker/github-mcp.sh").startsWith("#!/bin/sh\n")).toBe(true);
  });

  it("matches the edge image PATH links", () => {
    const dockerfile = read("Dockerfile");
    expect(dockerfile).toContain(
      "ln -sf /app/docker/shell-mcp.mjs /usr/local/bin/shell-mcp",
    );
    expect(dockerfile).toContain(
      "ln -sf /app/docker/github-mcp.sh /usr/local/bin/github-mcp",
    );
    expect(dockerfile).toContain("COPY scripts/prepare-package.mjs");
  });

  it("skips the build when the TypeScript sources are not in the tree", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-prepare-"));
    const result = spawnSync(
      process.execPath,
      [resolve(root, "scripts/prepare-package.mjs")],
      { cwd: dir, encoding: "utf8" },
    );
    expect(result.status).toBe(0);
    expect(existsSync(join(dir, "dist"))).toBe(false);
  });

  it("documents global install and PATH command names", () => {
    const readme = read("README.md");
    const agents = read("AGENTS.md");
    expect(readme).toContain("npm install -g mcp-flow");
    expect(readme).toContain("npm install -g .");
    expect(readme).toContain("shell-mcp");
    expect(readme).toContain("github-mcp");
    expect(agents).toContain("shell-mcp");
    expect(agents).toContain("github-mcp");
  });
});
