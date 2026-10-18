import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { STDIO_GROUP_KILL_BUDGET_MS } from "../src/mcp/runners/stdio.js";
import {
  INFLIGHT_CLOSE_DEADLINE_MS,
  UpstreamPool,
  type UpstreamPoolOptions,
} from "../src/mcp/upstream.js";
import { SHUTDOWN_BUDGET_MS, SHUTDOWN_DRAIN_MS, startServer } from "../src/server.js";
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

function writePlainServer(
  dir: string,
  spawnDir: string,
  name: string,
  ignoreTerm = false,
): string {
  const path = join(dir, name);
  const code = `import { createInterface } from "node:readline";
import { mkdirSync, writeFileSync } from "node:fs";
${ignoreTerm ? 'process.on("SIGTERM", () => {});' : ""}
const spawnDir = ${JSON.stringify(spawnDir)};
mkdirSync(spawnDir, { recursive: true });
writeFileSync(spawnDir + "/" + String(process.pid), "1");
const rl = createInterface({ input: process.stdin });
function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\\n");
}
rl.on("line", (line) => {
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  if (msg.method === "initialize") {
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
    send({
      jsonrpc: "2.0",
      id: msg.id,
      result: {
        tools: [
          { name: "ping", description: "ping", inputSchema: { type: "object", properties: {} } },
          { name: "bad", description: "bad", inputSchema: { type: "object", properties: {} } },
          { name: "die", description: "die", inputSchema: { type: "object", properties: {} } },
        ],
      },
    });
    return;
  }
  if (msg.method === "tools/call" && msg.params && msg.params.name === "bad") {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: "bad args" } });
    return;
  }
  if (msg.method === "tools/call" && msg.params && msg.params.name === "die") {
    process.exit(1);
  }
  if (msg.method === "tools/call") {
    send({ jsonrpc: "2.0", id: msg.id, result: { content: [{ type: "text", text: "pong" }] } });
    return;
  }
  if (msg.method === "ping") send({ jsonrpc: "2.0", id: msg.id, result: {} });
});
`;
  writeFileSync(path, code);
  return path;
}

function alivePids(spawnDir: string): number[] {
  let names: string[] = [];
  try {
    names = readdirSync(spawnDir);
  } catch {
    return [];
  }
  const out: number[] = [];
  for (const name of names) {
    const pid = Number(name);
    const stat = procStat(pid);
    if (stat && stat.state !== "Z") out.push(pid);
  }
  return out;
}

function poolSize(pool: UpstreamPool): number {
  return (pool as unknown as { pool: Map<string, unknown> }).pool.size;
}

function writeHungServer(dir: string, spawnDir: string): string {
  const path = join(dir, "fixture-hung.mjs");
  const code = `import { mkdirSync, writeFileSync } from "node:fs";
process.on("SIGTERM", () => {});
const spawnDir = ${JSON.stringify(spawnDir)};
mkdirSync(spawnDir, { recursive: true });
writeFileSync(spawnDir + "/" + String(process.pid), "1");
setInterval(() => {}, 1e9);
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

function setupPool(script: string, spawnDir: string, poolOpts: UpstreamPoolOptions = {}): {
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
  return { pool: new UpstreamPool(store, poolOpts), store, workspaceId: ws.id, backend };
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

  it("clears a failed connect so a later getClient can spawn again (after the crash backoff)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writeExitServer(dir, spawnDir);
    const { pool, store, workspaceId } = setupPool(script, spawnDir, { crashBackoffMs: 200 });
    try {
      await expect(pool.listNamespacedTools(workspaceId)).resolves.toEqual([]);
      expect(readdirSync(spawnDir)).toHaveLength(1);
      // QA v5.5: inside the backoff window there is no respawn
      await expect(pool.listNamespacedTools(workspaceId)).resolves.toEqual([]);
      expect(readdirSync(spawnDir)).toHaveLength(1);
      await new Promise((r) => setTimeout(r, 250));
      await expect(pool.listNamespacedTools(workspaceId)).resolves.toEqual([]);
      expect(readdirSync(spawnDir)).toHaveLength(2);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("does not respawn on a tool error, and reconnects after the process exits", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "calls.mjs");
    const { pool, store, workspaceId, backend } = setupPool(script, spawnDir);
    try {
      await harness(pool).getClient(backend);
      expect(alivePids(spawnDir)).toHaveLength(1);
      const bad = await pool.callTool(workspaceId, "fix__bad", {});
      expect(bad.isError).toBe(true);
      expect(readdirSync(spawnDir)).toHaveLength(1);
      expect(alivePids(spawnDir)).toHaveLength(1);

      const tested = await pool.testBackend(backend);
      expect(tested.ok).toBe(true);
      expect(readdirSync(spawnDir)).toHaveLength(1);

      await pool.callTool(workspaceId, "fix__die", {});
      const gone = await until(() => alivePids(spawnDir).length === 0, 2_000);
      expect(gone).toBe(true);
      const tools = await pool.listNamespacedTools(workspaceId);
      expect(tools.map((tool) => tool.name)).toContain("fix__ping");
      expect(alivePids(spawnDir)).toHaveLength(1);
      expect(readdirSync(spawnDir)).toHaveLength(2);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("keeps stdio children within the backend count under 16-way connect/disconnect", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "plain.mjs");
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    for (const slug of ["aa", "bb"]) {
      store.createBackend(ws.id, {
        slug,
        transport: "stdio",
        command: [process.execPath, script],
        enabled: true,
        placement: { mode: "central-sandbox" },
      });
    }
    spawnDirs.push(spawnDir);
    const pool = new UpstreamPool(store);
    const backends = ["aa", "bb"].map((slug) => store.getBackend(ws.id, slug)!);
    try {
      await pool.listNamespacedTools(ws.id);
      expect(alivePids(spawnDir)).toHaveLength(2);
      expect(poolSize(pool)).toBe(2);
      let peak = alivePids(spawnDir).length;
      const timer = setInterval(() => {
        peak = Math.max(peak, alivePids(spawnDir).length, poolSize(pool));
      }, 10);
      try {
        await Promise.all(
          Array.from({ length: 16 }, async () => {
            for (let n = 0; n < 3; n++) {
              await pool.listNamespacedTools(ws.id);
              for (const backend of backends) pool.invalidate(backend.id);
            }
          }),
        );
      } finally {
        clearInterval(timer);
      }
      await pool.listNamespacedTools(ws.id);
      expect(peak).toBeLessThanOrEqual(backends.length);
      expect(alivePids(spawnDir).length).toBeLessThanOrEqual(backends.length);
      expect(poolSize(pool)).toBeLessThanOrEqual(backends.length);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("kills a hung initialize at the close deadline", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writeHungServer(dir, spawnDir);
    const { pool, store, workspaceId } = setupPool(script, spawnDir);
    const listed = pool.listNamespacedTools(workspaceId);
    try {
      const spawned = await until(() => alivePids(spawnDir).length === 1, 2_000);
      expect(spawned).toBe(true);
      const started = Date.now();
      await Promise.all([pool.closeAll(), listed]);
      const elapsed = Date.now() - started;
      expect(elapsed).toBeGreaterThanOrEqual(INFLIGHT_CLOSE_DEADLINE_MS);
      expect(elapsed).toBeLessThan(
        INFLIGHT_CLOSE_DEADLINE_MS + STDIO_GROUP_KILL_BUDGET_MS + 1_000,
      );
      expect(alivePids(spawnDir)).toHaveLength(0);
      expect(poolSize(pool)).toBe(0);
      await expect(listed).resolves.toEqual([]);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });
});

describe("shutdown budget", () => {
  it("finishes within 10s when a stdio child ignores SIGTERM", async () => {
    expect(SHUTDOWN_BUDGET_MS).toBeLessThanOrEqual(10_000);
    expect(SHUTDOWN_DRAIN_MS).toBeLessThanOrEqual(7_000);
    expect(STDIO_GROUP_KILL_BUDGET_MS).toBeLessThan(2_000);
    expect(SHUTDOWN_DRAIN_MS + STDIO_GROUP_KILL_BUDGET_MS).toBeLessThanOrEqual(
      SHUTDOWN_BUDGET_MS,
    );
    expect(
      SHUTDOWN_DRAIN_MS +
        INFLIGHT_CLOSE_DEADLINE_MS +
        STDIO_GROUP_KILL_BUDGET_MS,
    ).toBeLessThanOrEqual(SHUTDOWN_BUDGET_MS);

    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-stop-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "ignore-term.mjs", true);
    spawnDirs.push(spawnDir);
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: "shutdown-budget-token",
      host: "127.0.0.1",
      port: 0,
      allowPrivateUrls: true,
    });
    const running = await startServer(cfg);
    const ws = running.store.ensureWorkspace("default");
    running.store.createBackend(ws.id, {
      slug: "fix",
      transport: "stdio",
      command: [process.execPath, script],
      enabled: true,
      placement: { mode: "central-sandbox" },
    });
    const backend = running.store.getBackend(ws.id, "fix");
    await (
      running.pool as unknown as {
        getClient(b: BackendRecord): Promise<unknown>;
      }
    ).getClient(backend!);
    expect(alivePids(spawnDir)).toHaveLength(1);
    const started = Date.now();
    await running.close();
    const elapsed = Date.now() - started;
    expect(elapsed).toBeLessThan(SHUTDOWN_BUDGET_MS);
    const gone = await until(() => alivePids(spawnDir).length === 0, 1_000);
    expect(gone).toBe(true);
  });
});
