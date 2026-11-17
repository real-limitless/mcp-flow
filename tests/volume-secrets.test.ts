import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyVolumeSecrets } from "../src/volume-secrets.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("volume secrets", () => {
  it("fills an empty master key from secrets.env and leaves a set value alone", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-secrets-"));
    dirs.push(dir);
    writeFileSync(join(dir, "secrets.env"), "MCP_FLOW_MASTER_KEY=from-file\nMCP_FLOW_ADMIN_TOKEN=token-file\n");
    const env: NodeJS.ProcessEnv = { MCP_FLOW_DATA_DIR: dir, MCP_FLOW_MASTER_KEY: "", MCP_FLOW_ADMIN_TOKEN: "already" };
    applyVolumeSecrets(env);
    expect(env.MCP_FLOW_MASTER_KEY).toBe("from-file");
    expect(env.MCP_FLOW_ADMIN_TOKEN).toBe("already");
  });
});