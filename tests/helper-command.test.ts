import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  installedHelperFile,
  portableHelperCommand,
  resolveInstalledHelperCommand,
  resolveSpawnCommand,
} from "../src/mcp/runners/helper-command.js";

const installedShell = "/usr/lib/node_modules/mcp-flow/docker/shell-mcp.mjs";
const installedGithub = "/usr/lib/node_modules/mcp-flow/docker/github-mcp.sh";
const missingCheckout = "/opt/checkout/docker/shell-mcp.mjs";

function resolve(
  command: string[],
  exists: (path: string) => boolean,
  pathEnv = ["/usr/bin", "/bin"].join(delimiter),
) {
  return resolveInstalledHelperCommand(command, {
    exists,
    pathEnv,
    execPath: "/usr/bin/node",
    shellBin: "/bin/sh",
    helperFile: (name) => (name === "shell-mcp" ? installedShell : installedGithub),
  });
}

describe("installed helper command", () => {
  it("ships shell-mcp.mjs next to this package", () => {
    const file = installedHelperFile("shell-mcp");
    expect(file.endsWith(`${join("docker", "shell-mcp.mjs")}`)).toBe(true);
    expect(existsSync(file)).toBe(true);
  });

  it("replaces a missing checkout path with the installed helper", () => {
    const exists = (path: string) => path === installedShell || path === installedGithub;
    const shell = resolve(["node", missingCheckout], exists);
    expect(shell.rewritten).toBe(true);
    expect(shell.command).toEqual(["/usr/bin/node", installedShell]);

    const direct = resolve([missingCheckout], exists);
    expect(direct.command).toEqual(["/usr/bin/node", installedShell]);

    const github = resolve(["/opt/checkout/docker/github-mcp.sh"], exists);
    expect(github.command).toEqual(["/bin/sh", installedGithub]);
  });

  it("keeps a checkout path that exists on this machine", () => {
    const present = "/opt/checkout/docker/shell-mcp.mjs";
    const resolved = resolve(["node", present], (path) => path === present || path === installedShell);
    expect(resolved.rewritten).toBe(false);
    expect(resolved.command).toEqual(["node", present]);
  });

  it("keeps a bare command that is already on PATH", () => {
    const pathEnv = ["/usr/local/bin", "/usr/bin"].join(delimiter);
    const resolved = resolve(
      ["shell-mcp"],
      (path) => path === join("/usr/local/bin", "shell-mcp"),
      pathEnv,
    );
    expect(resolved.rewritten).toBe(false);
    expect(resolved.command).toEqual(["shell-mcp"]);
  });

  it("uses the installed helper when root's PATH does not include the bin", () => {
    const resolved = resolve(["shell-mcp"], (path) => path === installedShell);
    expect(resolved.rewritten).toBe(true);
    expect(resolved.command).toEqual(["/usr/bin/node", installedShell]);
  });

  it("leaves unrelated stdio commands alone", () => {
    const command = ["npx", "-y", "some-mcp"];
    const resolved = resolve(command, () => false);
    expect(resolved.rewritten).toBe(false);
    expect(resolved.command).toEqual(command);
  });

  it("sends a checkout path to another machine as the PATH name", () => {
    expect(portableHelperCommand(["node", missingCheckout]).command).toEqual(["shell-mcp"]);
    expect(
      portableHelperCommand([
        "docker",
        "run",
        "-i",
        "--rm",
        "ghcr.io/example/mcp:latest",
        "node",
        "/opt/checkout/docker/shell-mcp.mjs",
      ]).command,
    ).toEqual(["docker", "run", "-i", "--rm", "ghcr.io/example/mcp:latest", "shell-mcp"]);
    expect(portableHelperCommand(["/usr/bin/env", "node", "/opt/checkout/docker/github-mcp.sh"]).command).toEqual([
      "/usr/bin/env",
      "github-mcp",
    ]);
  });

  it("rewrites a helper path inside a container argv instead of using a host file", () => {
    const resolved = resolveSpawnCommand(
      ["docker", "run", "--rm", "ghcr.io/example/edge:local", "node", missingCheckout],
      {
        exists: () => true,
        execPath: "/usr/bin/node",
        helperFile: () => installedShell,
      },
    );
    expect(resolved.command).toEqual([
      "docker",
      "run",
      "--rm",
      "ghcr.io/example/edge:local",
      "shell-mcp",
    ]);
  });

  it("falls back to the PATH name when the install has no helper file", () => {
    const resolved = resolveInstalledHelperCommand(["node", missingCheckout], {
      exists: () => false,
      execPath: "/usr/bin/node",
      helperFile: () => "/missing/docker/shell-mcp.mjs",
    });
    expect(resolved.command).toEqual(["shell-mcp"]);
  });
});

describe("link edge helpers", () => {
  it("symlinks shell-mcp onto a bin dir and onto a missing checkout path", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-link-"));
    const bin = join(dir, "bin");
    const missing = join(dir, "missing", "docker", "shell-mcp.mjs");
    const script = join(dirname(fileURLToPath(import.meta.url)), "..", "scripts", "link-edge-helpers.mjs");
    const result = spawnSync(process.execPath, [script, "--bind-missing", missing], {
      cwd: dir,
      env: { ...process.env, MCP_FLOW_BIN_DIR: bin },
      encoding: "utf8",
    });
    expect(result.status, `${script}\n${result.stderr || result.stdout}`).toBe(0);
    expect(readlinkSync(join(bin, "shell-mcp"))).toContain("shell-mcp.mjs");
    expect(readlinkSync(join(bin, "github-mcp"))).toContain("github-mcp.sh");
    expect(readlinkSync(missing)).toContain("shell-mcp.mjs");
  });
});
