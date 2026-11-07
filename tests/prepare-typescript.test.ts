import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { localInstallEnv } from "../scripts/prepare-package.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const prepareScript = resolve(root, "scripts/prepare-package.mjs");

describe("checkout build without a global tsc", () => {
  it("drops global and production config before installing the compiler", () => {
    const env = localInstallEnv({
      PATH: "/usr/bin",
      NODE_ENV: "production",
      npm_config_global: "true",
      npm_config_prefix: "/usr/local",
      npm_config_omit: "dev",
      npm_config_production: "true",
      npm_config_registry: "https://registry.npmjs.org/",
    });
    expect(env.NODE_ENV).toBeUndefined();
    expect(env.npm_config_global).toBeUndefined();
    expect(env.npm_config_prefix).toBeUndefined();
    expect(env.npm_config_omit).toBeUndefined();
    expect(env.npm_config_production).toBeUndefined();
    expect(env.npm_config_registry).toBe("https://registry.npmjs.org/");
    expect(env.PATH).toBe("/usr/bin");
  });

  it("installs typescript locally when the compiler file is missing", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-prepare-tsc-"));
    const bin = join(dir, "bin");
    mkdirSync(bin);
    const argsFile = join(dir, "npm-args");
    const envFile = join(dir, "npm-env");
    const npm = join(bin, "npm");
    writeFileSync(
      npm,
      `#!/bin/sh
printf '%s\\n' "$*" > "${argsFile}"
printenv > "${envFile}"
mkdir -p node_modules/typescript/lib
cat > node_modules/typescript/lib/tsc.js << 'EOF'
process.exit(0);
EOF
`,
    );
    chmodSync(npm, 0o755);
    mkdirSync(join(dir, "src/admin"), { recursive: true });
    writeFileSync(join(dir, "src/cli.ts"), "export {}\n");
    writeFileSync(join(dir, "src/admin/index.html"), "<html></html>\n");
    writeFileSync(join(dir, "tsconfig.json"), "{}\n");

    const result = spawnSync(process.execPath, [prepareScript, "--build"], {
      cwd: dir,
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
        NODE_ENV: "production",
        npm_config_global: "true",
        npm_config_prefix: "/usr/local",
        npm_config_omit: "dev",
      },
    });

    expect(result.status).toBe(0);
    expect(readFileSync(argsFile, "utf8")).toContain(
      "install --include=dev --ignore-scripts --no-audit --no-fund",
    );
    const recorded = readFileSync(envFile, "utf8");
    expect(recorded).not.toMatch(/^npm_config_global=/m);
    expect(recorded).not.toMatch(/^npm_config_prefix=/m);
    expect(recorded).not.toMatch(/^NODE_ENV=production$/m);
    expect(readFileSync(join(dir, "dist/admin/index.html"), "utf8")).toContain("<html>");
  });
});
