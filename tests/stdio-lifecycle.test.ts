import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import type { BackendRecord } from "../src/types.js";

const master = Buffer.alloc(32, 7).toString("base64");
const dirs: string[] = [];
const spawnDirs: string[] = [];

function cmdline(pid: number): string {
  try {
    return readFileSync(`/proc/${pid}/cmdline`).toString().replaceAll("\0", " ");
  } catch {
    return "";
  }
}

function procStat(pid: number): { state: string; pgrp: number } | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const rest = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
    const state = rest[0];
    const pgrp = Number(rest[2]);
    if (!state || !Number.isInteger(pgrp)) return null;
    return { state, pgrp };
  } catch {
    return null;
  }
}

function livingInGroup(pgid: number): number[] {
  const out: number[] = [];
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    const pid = Number(name);
    const stat = procStat(pid);
    if (stat && stat.pgrp === pgid && stat.state !== "Z") out.push(pid);
  }
  return out;
}

function killFixtureGroup(pid: number): void {
  if (!Number.isInteger(pid) || pid <= 1) return;
  const members = livingInGroup(pid);
  const owned = members.some(
    (member) =>
      cmdline(member).includes("fixture-mcp") ||
      cmdline(member).includes("setInterval"),
  );
  if (!owned && !cmdline(pid).includes("fixture-mcp")) return;
  try {
    process.kill(-pid, "SIGKILL");
  } catch {
    /* already gone */
  }
}

afterEach(() => {
  for (const dir of spawnDirs.splice(0)) {
    let names: string[] = [];
    try {
      names = readdirSync(dir);
    } catch {
      names = [];
    }
    for (const name of names) {
      const pid = Number(name);
      if (Number.isInteger(pid)) killFixtureGroup(pid);
    }
  }
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function writeForkingServer(dir: string, spawnDir: string, listFile: string): string {
  const path = join(dir, "fixture-mcp.mjs");
  const code = `import { createInterface } from "node:readline";
import { spawn } from "node:child_process";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";

const spawnDir = ${JSON.stringify(spawnDir)};
const listFile = ${JSON.stringify(listFile)};
mkdirSync(spawnDir, { recursive: true });
const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1e9)"], {
  stdio: "ignore",
});
writeFileSync(
  spawnDir + "/" + String(process.pid),
  JSON.stringify({ pid: process.pid, child: child.pid }) + "\\n",
);

const rl = createInterface({ input: process.stdin });
function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\\n");
}
async function handle(msg) {
  if (msg.method === "initialize") {
    await new Promise((resolve) => setTimeout(resolve, 200));
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "fixture", version: "1.0.0" },
      },
    });
    return;
  }
  if (msg.method === "notifications/initialized") return;
  if (msg.method === "tools/list") {
    appendFileSync(listFile, "1\\n");
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        tools: [{
          name: "ping",
          description: "ping",
          inputSchema: { type: "object", properties: {} },
        }],
      },
    });
    return;
  }
  if (msg.method === "tools/call") {
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: { content: [{ type: "text", text: "pong" }] },
    });
    return;
  }
  if (msg.method === "ping") {
    send({ jsonrpc: "2.0", id: msg.id, result: {} });
  }
}
rl.on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  void handle(msg);
});
`;
  writeFileSync(path, code);
  return path;
}

function writeExitServer(dir: string, spawnDir: string): string {
  const path = join(dir, "fixture-exit.mjs");
  const code = `import { mkdirSync, writeFileSync } from "node:fs";
mkdirSync(${JSON.stringify(spawnDir)}, { recursive: true });
writeFileSync(${JSON.stringify(spawnDir)} + "/" + String(process.pid), "1");
process.exit(1);
`;
  writeFileSync(path, code);
  return path;
}

interface PoolHarness {
  getClient(backend: BackendRecord): Promise<{ fetchedAt: number }>;
}

function harness(pool: UpstreamPool): PoolHarness {
  return pool as unknown as PoolHarness;
}

function setupPool(script: string, spawnDir: string): {
  pool: UpstreamPool;
  store: Store;
  workspaceId: string;
  backend: BackendRecord;
} {
  const dir = dirs[dirs.length - 1]!;
  const store = new Store(join(dir, "t.db"), master);
  const ws = store.ensureWorkspace("default");
  store.createBackend(ws.id, {
    slug: "fix",
    transport: "stdio",
    command: [process.execPath, script],
    enabled: true,
    placement: { mode: "central-sandbox" },
  });
  const backend = store.getBackend(ws.id, "fix");
  if (!backend) throw new Error("backend missing");
  spawnDirs.push(spawnDir);
  return { pool: new UpstreamPool(store), store, workspaceId: ws.id, backend };
}

function marker(spawnDir: string): { pid: number; child: number } {
  const names = readdirSync(spawnDir);
  expect(names).toHaveLength(1);
  return JSON.parse(readFileSync(join(spawnDir, names[0]!), "utf8")) as {
    pid: number;
    child: number;
  };
}

function listCount(listFile: string): number {
  try {
    return readFileSync(listFile, "utf8").split("\n").filter(Boolean).length;
  } catch {
    return 0;
  }
}

async function until(pred: () => boolean, ms: number): Promise<boolean> {
  const started = Date.now();
  while (Date.now() - started < ms) {
    if (pred()) return true;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return pred();
}

describe("stdio process lifecycle", () => {
  it("uses one spawn for parallel getClient calls on the same backend", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const listFile = join(dir, "lists");
    const script = writeForkingServer(dir, spawnDir, listFile);
    const { pool, store, backend } = setupPool(script, spawnDir);
    try {
      const clients = await Promise.all(
        Array.from({ length: 8 }, () => harness(pool).getClient(backend)),
      );
      expect(new Set(clients).size).toBe(1);
      expect(readdirSync(spawnDir)).toHaveLength(1);
      const info = marker(spawnDir);
      expect(procStat(info.child)?.pgrp).toBe(info.pid);
      expect(livingInGroup(info.pid)).toEqual(
        expect.arrayContaining([info.pid, info.child]),
      );
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("refreshes tools on the open client without spawning", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const listFile = join(dir, "lists");
    const script = writeForkingServer(dir, spawnDir, listFile);
    const { pool, store, workspaceId, backend } = setupPool(script, spawnDir);
    try {
      const entry = await harness(pool).getClient(backend);
      expect(listCount(listFile)).toBe(1);
      expect(readdirSync(spawnDir)).toHaveLength(1);
      const cached = await pool.listNamespacedTools(workspaceId);
      expect(cached.map((tool) => tool.name)).toContain("fix__ping");
      expect(listCount(listFile)).toBe(1);

      entry.fetchedAt = 0;
      const refreshed = await pool.listNamespacedTools(workspaceId);
      expect(refreshed.map((tool) => tool.name)).toContain("fix__ping");
      expect(listCount(listFile)).toBe(2);
      expect(readdirSync(spawnDir)).toHaveLength(1);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("close leaves no descendant processes", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const listFile = join(dir, "lists");
    const script = writeForkingServer(dir, spawnDir, listFile);
    const { pool, store, backend } = setupPool(script, spawnDir);
    try {
      await harness(pool).getClient(backend);
      const info = marker(spawnDir);
      expect(procStat(info.pid)?.pgrp).toBe(info.pid);
      expect(procStat(info.child)?.pgrp).toBe(info.pid);
      expect(livingInGroup(info.pid).length).toBeGreaterThanOrEqual(2);

      await pool.closeAll();

      const gone = await until(
        () =>
          procStat(info.pid) === null &&
          procStat(info.child) === null &&
          livingInGroup(info.pid).length === 0,
        4_000,
      );
      expect(gone).toBe(true);
    } finally {
      store.close();
    }
  });

  it("clears a failed connect so a later getClient can spawn again", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writeExitServer(dir, spawnDir);
    const { pool, store, workspaceId } = setupPool(script, spawnDir);
    try {
      await expect(pool.listNamespacedTools(workspaceId)).resolves.toEqual([]);
      expect(readdirSync(spawnDir)).toHaveLength(1);
      await expect(pool.listNamespacedTools(workspaceId)).resolves.toEqual([]);
      expect(readdirSync(spawnDir)).toHaveLength(2);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });
});
