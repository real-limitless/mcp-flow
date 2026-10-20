import { spawn } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { isLiving, STDIO_GROUP_KILL_BUDGET_MS } from "../src/mcp/runners/stdio.js";
import {
  INFLIGHT_CLOSE_DEADLINE_MS,
  UpstreamPool,
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
  const readLog = join(dir, "reads");
  const code = `import { createInterface } from "node:readline";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
${ignoreTerm ? 'process.on("SIGTERM", () => {});' : ""}
const spawnDir = ${JSON.stringify(spawnDir)};
const readLog = ${JSON.stringify(readLog)};
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
          { name: "ack", description: "ack", inputSchema: { type: "object", properties: {} } },
        ],
      },
    });
    return;
  }
  if (msg.method === "tools/call") {
    appendFileSync(readLog, String(msg.params && msg.params.name) + "\\n");
  }
  if (msg.method === "tools/call" && msg.params && msg.params.name === "bad") {
    send({ jsonrpc: "2.0", id: msg.id, error: { code: -32602, message: "bad args" } });
    return;
  }
  if (msg.method === "tools/call" && msg.params && msg.params.name === "die") {
    process.exit(1);
  }
  if (msg.method === "tools/call" && msg.params && msg.params.name === "ack") {
    const note = JSON.stringify({
      jsonrpc: "2.0",
      method: "notifications/progress",
      params: { progressToken: msg.id, progress: 1 },
    }) + "\\n";
    process.stdout.write(note, () => process.exit(0));
    return;
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

function resultText(result: { content?: Array<{ text?: string }> }): string {
  return (result.content ?? []).map((block) => block.text ?? "").join("\n");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface PoolEntry {
  dead: boolean;
  client: {
    callTool: (params: {
      name: string;
      arguments?: Record<string, unknown>;
    }) => Promise<unknown>;
  };
  transport: {
    send: (message: unknown, options?: unknown) => Promise<void>;
  };
}

function poolEntry(pool: UpstreamPool, backendId: string): PoolEntry | undefined {
  return (pool as unknown as { pool: Map<string, PoolEntry> }).pool.get(backendId);
}

function readNames(dir: string): string[] {
  try {
    return readFileSync(join(dir, "reads"), "utf8").split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

function entryPid(entry: PoolEntry): number {
  const pid = (entry.transport as { pid?: number | null }).pid;
  if (pid == null) throw new Error("stdio transport has no pid");
  return pid;
}

function rpcMethod(message: unknown): string | undefined {
  if (!message || typeof message !== "object" || !("method" in message)) return undefined;
  const method = (message as { method?: unknown }).method;
  return typeof method === "string" ? method : undefined;
}

function holdZombie(): Promise<{ pid: number; stop: () => void }> {
  const child = spawn(
    "python3",
    [
      "-c",
      "import os,sys,time\npid=os.fork()\nif pid==0:\n os._exit(0)\nsys.stdout.write(str(pid)+'\\n')\nsys.stdout.flush()\ntime.sleep(60)\n",
    ],
    { stdio: ["ignore", "pipe", "ignore"] },
  );
  return new Promise((resolve, reject) => {
    let buf = "";
    const timer = setTimeout(() => reject(new Error("zombie pid missing")), 2_000);
    child.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    child.stdout?.on("data", (chunk: Buffer) => {
      buf += chunk.toString();
      const line = buf.split("\n")[0] ?? "";
      if (!/^\d+$/.test(line)) return;
      clearTimeout(timer);
      resolve({
        pid: Number(line),
        stop: () => {
          child.kill("SIGKILL");
        },
      });
    });
  });
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
      expect(bad.sent).toBe(true);
      expect(readdirSync(spawnDir)).toHaveLength(1);
      expect(alivePids(spawnDir)).toHaveLength(1);

      const tested = await pool.testBackend(backend);
      expect(tested.ok).toBe(true);
      expect(readdirSync(spawnDir)).toHaveLength(1);

      const died = await pool.callTool(workspaceId, "fix__die", {});
      expect(died.sent).toBe(false);
      expect(resultText(died)).toMatch(/connection closed/i);
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

  it("respawns the next call after the stdio process is killed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "kill-between.mjs");
    const { pool, store, workspaceId } = setupPool(script, spawnDir);
    try {
      const first = await pool.callTool(workspaceId, "fix__ping", {});
      expect(first.sent).toBe(true);
      expect(resultText(first)).toBe("pong");
      expect(readdirSync(spawnDir)).toHaveLength(1);
      const pid = alivePids(spawnDir)[0];
      expect(pid).toBeTypeOf("number");
      process.kill(pid!, "SIGKILL");
      const dropped = await until(
        () => poolSize(pool) === 0 && alivePids(spawnDir).length === 0,
        2_000,
      );
      expect(dropped).toBe(true);
      const again = await pool.callTool(workspaceId, "fix__ping", {
        note: "respawn-note-placeholder",
      });
      expect(again.sent).toBe(true);
      expect(resultText(again)).toBe("pong");
      expect(readdirSync(spawnDir)).toHaveLength(2);
      expect(alivePids(spawnDir)).toHaveLength(1);
      expect(alivePids(spawnDir)[0]).not.toBe(pid);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("marks a pre-write Not connected rejection as unsent and respawns", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "prewrite.mjs");
    const { pool, store, workspaceId, backend } = setupPool(script, spawnDir);
    try {
      await pool.callTool(workspaceId, "fix__ping", {});
      const entry = poolEntry(pool, backend.id);
      expect(entry).toBeTruthy();
      entry!.transport.send = async () => {
        throw new Error("Not connected");
      };
      const blocked = await pool.callTool(workspaceId, "fix__ping", {
        note: "kill-note-placeholder",
      });
      expect(blocked.sent).toBe(false);
      expect(resultText(blocked)).toMatch(/Not connected/);
      expect(resultText(blocked)).not.toContain("kill-note-placeholder");
      const dropped = await until(() => poolSize(pool) === 0, 2_000);
      expect(dropped).toBe(true);
      const again = await pool.callTool(workspaceId, "fix__ping", {});
      expect(again.sent).toBe(true);
      expect(resultText(again)).toBe("pong");
      expect(readdirSync(spawnDir).length).toBeGreaterThanOrEqual(2);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("does not mark a resolved write as sent when the child never answers", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "written.mjs");
    const { pool, store, workspaceId, backend } = setupPool(script, spawnDir);
    try {
      await pool.callTool(workspaceId, "fix__ping", {});
      const entry = poolEntry(pool, backend.id);
      expect(entry).toBeTruthy();
      entry!.client.callTool = async () => {
        await entry!.transport.send({ jsonrpc: "2.0", id: 99, method: "ping" });
        throw new Error("Connection closed");
      };
      const written = await pool.callTool(workspaceId, "fix__ping", {
        note: "written-note-placeholder",
      });
      expect(written.sent).toBe(false);
      expect(resultText(written)).toMatch(/connection closed/i);
      const again = await pool.callTool(workspaceId, "fix__ping", {});
      expect(again.sent).toBe(true);
      expect(resultText(again)).toBe("pong");
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("does not report Not connected as sent in the kill race window", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "race.mjs");
    const { pool, store, workspaceId } = setupPool(script, spawnDir);
    try {
      const primed = await pool.callTool(workspaceId, "fix__ping", {});
      expect(primed.sent).toBe(true);
      expect(resultText(primed)).toBe("pong");
      for (const delay of [0, 1, 5, 20]) {
        const living = alivePids(spawnDir);
        expect(living.length).toBeGreaterThan(0);
        const pid = living[living.length - 1]!;
        process.kill(pid, "SIGKILL");
        if (delay) await sleep(delay);
        const outcome = await pool.callTool(workspaceId, "fix__ping", {
          note: "race-secret-placeholder",
        });
        const text = resultText(outcome);
        if (/not connected|connection closed/i.test(text)) expect(outcome.sent).toBe(false);
        if (outcome.sent) expect(text).toBe("pong");
        if (!outcome.sent) expect(text).not.toContain("race-secret-placeholder");
        if (outcome.sent && text === "pong") continue;
        const dropped = await until(() => poolSize(pool) === 0, 2_000);
        expect(dropped).toBe(true);
        const next = await pool.callTool(workspaceId, "fix__ping", {});
        expect(next.sent).toBe(true);
        expect(resultText(next)).toBe("pong");
      }
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("respawns instead of writing to a zombie stdio process", async () => {
    const held = await holdZombie();
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "zombie.mjs");
    const { pool, store, workspaceId, backend } = setupPool(script, spawnDir);
    try {
      expect(isLiving(held.pid)).toBe(false);
      expect(() => process.kill(held.pid, 0)).not.toThrow();
      await pool.callTool(workspaceId, "fix__ping", {});
      const entry = poolEntry(pool, backend.id);
      expect(entry).toBeTruthy();
      const original = entryPid(entry!);
      Object.defineProperty(entry!.transport, "pid", {
        configurable: true,
        get: () => held.pid,
      });
      expect((entry!.transport as { pid?: number | null }).pid).toBe(held.pid);
      const outcome = await pool.callTool(workspaceId, "fix__ping", {
        note: "zombie-placeholder",
      });
      expect(resultText(outcome)).toBe("pong");
      expect(outcome.sent).toBe(true);
      expect(readdirSync(spawnDir)).toHaveLength(2);
      const living = alivePids(spawnDir);
      expect(living).toHaveLength(1);
      expect(living[0]).not.toBe(original);
    } finally {
      held.stop();
      await pool.closeAll();
      store.close();
    }
  });

  it("does not mark a call sent when the child is killed before the write", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "before-write.mjs");
    const { pool, store, workspaceId, backend } = setupPool(script, spawnDir);
    try {
      await pool.callTool(workspaceId, "fix__ping", {});
      expect(readNames(dir)).toEqual(["ping"]);
      const entry = poolEntry(pool, backend.id);
      expect(entry).toBeTruthy();
      const pid = entryPid(entry!);
      const realSend = entry!.transport.send.bind(entry!.transport);
      entry!.transport.send = async (message, options) => {
        if (rpcMethod(message) !== "tools/call") return realSend(message, options);
        process.kill(pid, "SIGKILL");
        let sawZ = false;
        const started = Date.now();
        while (Date.now() - started < 1_000) {
          if (procStat(pid)?.state === "Z") {
            sawZ = true;
            break;
          }
        }
        expect(sawZ).toBe(true);
        await realSend(message, options).catch(() => undefined);
        return undefined;
      };
      const outcome = await pool.callTool(workspaceId, "fix__ping", {
        note: "before-write-placeholder",
      });
      expect(outcome.sent).toBe(false);
      expect(resultText(outcome)).not.toBe("pong");
      expect(resultText(outcome)).not.toContain("before-write-placeholder");
      expect(readNames(dir)).toEqual(["ping"]);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("does not mark a call sent when the child is killed during the write", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "during-write.mjs");
    const { pool, store, workspaceId, backend } = setupPool(script, spawnDir);
    try {
      await pool.callTool(workspaceId, "fix__ping", {});
      expect(readNames(dir)).toEqual(["ping"]);
      const entry = poolEntry(pool, backend.id);
      expect(entry).toBeTruthy();
      const pid = entryPid(entry!);
      process.kill(pid, "SIGSTOP");
      const stopped = await until(() => procStat(pid)?.state === "T", 2_000);
      expect(stopped).toBe(true);
      const realSend = entry!.transport.send.bind(entry!.transport);
      entry!.transport.send = async (message, options) => {
        if (rpcMethod(message) !== "tools/call") return realSend(message, options);
        const pending = realSend(message, options);
        process.kill(pid, "SIGKILL");
        await pending.catch(() => undefined);
        return undefined;
      };
      const outcome = await pool.callTool(workspaceId, "fix__ping", {
        note: "during-write-placeholder",
      });
      expect(outcome.sent).toBe(false);
      expect(resultText(outcome)).not.toBe("pong");
      expect(resultText(outcome)).not.toContain("during-write-placeholder");
      expect(readNames(dir)).toEqual(["ping"]);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("does not mark a call sent when the child is killed after send resolves", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "after-send.mjs");
    const { pool, store, workspaceId, backend } = setupPool(script, spawnDir);
    try {
      await pool.callTool(workspaceId, "fix__ping", {});
      expect(readNames(dir)).toEqual(["ping"]);
      const entry = poolEntry(pool, backend.id);
      expect(entry).toBeTruthy();
      const pid = entryPid(entry!);
      process.kill(pid, "SIGSTOP");
      const stopped = await until(() => procStat(pid)?.state === "T", 2_000);
      expect(stopped).toBe(true);
      const realSend = entry!.transport.send.bind(entry!.transport);
      entry!.transport.send = async (message, options) => {
        if (rpcMethod(message) !== "tools/call") return realSend(message, options);
        await realSend(message, options);
        process.kill(pid, "SIGKILL");
        return undefined;
      };
      const outcome = await pool.callTool(workspaceId, "fix__ping", {
        note: "after-send-placeholder",
      });
      expect(outcome.sent).toBe(false);
      expect(resultText(outcome)).not.toBe("pong");
      expect(resultText(outcome)).not.toContain("after-send-placeholder");
      expect(readNames(dir)).toEqual(["ping"]);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

  it("marks a call sent when the child acknowledged before it exited", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "after-ack.mjs");
    const { pool, store, workspaceId } = setupPool(script, spawnDir);
    try {
      const outcome = await pool.callTool(workspaceId, "fix__ack", {
        note: "ack-note-placeholder",
      });
      expect(outcome.sent).toBe(true);
      expect(resultText(outcome)).toMatch(/connection closed/i);
      const again = await pool.callTool(workspaceId, "fix__ping", {});
      expect(again.sent).toBe(true);
      expect(resultText(again)).toBe("pong");
    } finally {
      await pool.closeAll();
      store.close();
    }
  });
});

describe("stdio death audit", () => {
  it("records a respawned call and collapses a pre-write rejection", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "audit-kill.mjs");
    spawnDirs.push(spawnDir);
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: "stdio-death-audit-token",
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
    expect(backend).toBeTruthy();
    const created = running.store.createApiKey(ws.id, "stdio-death");
    const client = new Client({ name: "stdio-death", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${running.url}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${created.token}` } },
      }),
    );
    const textOf = (result: { content: Array<{ text?: string }> }): string =>
      result.content.map((block) => block.text ?? "").join("\n");
    try {
      const first = await client.callTool({
        name: "fix__ping",
        arguments: { note: "between-note-placeholder" },
      });
      expect(textOf(first)).toBe("pong");
      const pid = alivePids(spawnDir)[0];
      expect(pid).toBeTypeOf("number");
      process.kill(pid!, "SIGKILL");
      const dropped = await until(
        () => poolSize(running.pool) === 0 && alivePids(spawnDir).length === 0,
        2_000,
      );
      expect(dropped).toBe(true);
      const again = await client.callTool({
        name: "fix__ping",
        arguments: { note: "respawn-note-placeholder" },
      });
      expect(textOf(again)).toBe("pong");

      const entry = poolEntry(running.pool, backend!.id);
      expect(entry).toBeTruthy();
      entry!.transport.send = async () => {
        throw new Error("Not connected");
      };
      const secret = "race-secret-placeholder";
      const blocked = await client.callTool({
        name: "fix__ping",
        arguments: { note: secret },
      });
      expect(textOf(blocked)).toBe("tool not found");
      expect(textOf(blocked)).not.toMatch(/not connected/i);
      expect(textOf(blocked)).not.toContain(secret);

      const recovered = await client.callTool({
        name: "fix__ping",
        arguments: { note: "after-race-placeholder" },
      });
      expect(textOf(recovered)).toBe("pong");

      const calls = running.store
        .listAudit(ws.id, { limit: 50 })
        .filter((event) => event.action === "tools/call");
      const blob = JSON.stringify(calls);
      expect(blob).toContain("between-note-placeholder");
      expect(blob).toContain("respawn-note-placeholder");
      expect(blob).toContain("after-race-placeholder");
      expect(blob).not.toContain(secret);
      const collapsed = calls.filter((event) => {
        const args = (event.detail as { arguments?: { arguments?: unknown } } | null)
          ?.arguments;
        return args?.arguments === "[redacted]";
      });
      expect(collapsed.length).toBeGreaterThanOrEqual(1);
      for (const event of collapsed) {
        expect(JSON.stringify(event.detail)).not.toContain(secret);
      }
    } finally {
      await client.close();
      await running.close();
    }
  }, 30_000);

  it("keeps acknowledged args and collapses a kill during the write", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-life-"));
    dirs.push(dir);
    const spawnDir = join(dir, "spawns");
    const script = writePlainServer(dir, spawnDir, "audit-windows.mjs");
    spawnDirs.push(spawnDir);
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: "stdio-window-audit-token",
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
    expect(backend).toBeTruthy();
    const created = running.store.createApiKey(ws.id, "stdio-windows");
    const client = new Client({ name: "stdio-windows", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${running.url}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${created.token}` } },
      }),
    );
    const textOf = (result: { content: Array<{ text?: string }> }): string =>
      result.content.map((block) => block.text ?? "").join("\n");
    try {
      const acked = await client.callTool({
        name: "fix__ack",
        arguments: { note: "ack-note-placeholder" },
      });
      expect(textOf(acked)).toMatch(/connection closed/i);
      const ping = await client.callTool({
        name: "fix__ping",
        arguments: { note: "after-ack-placeholder" },
      });
      expect(textOf(ping)).toBe("pong");

      const unread = [
        "before-write-placeholder",
        "during-write-placeholder",
        "after-send-placeholder",
      ] as const;
      for (const [index, note] of unread.entries()) {
        const primed = await client.callTool({
          name: "fix__ping",
          arguments: { note: `window-live-${index}` },
        });
        expect(textOf(primed)).toBe("pong");
        const beforeReads = readNames(dir).length;
        const entry = poolEntry(running.pool, backend!.id);
        expect(entry).toBeTruthy();
        const pid = entryPid(entry!);
        const realSend = entry!.transport.send.bind(entry!.transport);
        if (index === 0) {
          entry!.transport.send = async (message, options) => {
            if (rpcMethod(message) !== "tools/call") return realSend(message, options);
            process.kill(pid, "SIGKILL");
            const started = Date.now();
            let sawZ = false;
            while (Date.now() - started < 1_000) {
              if (procStat(pid)?.state === "Z") {
                sawZ = true;
                break;
              }
            }
            expect(sawZ).toBe(true);
            await realSend(message, options).catch(() => undefined);
            return undefined;
          };
        } else {
          process.kill(pid, "SIGSTOP");
          const stopped = await until(() => procStat(pid)?.state === "T", 2_000);
          expect(stopped).toBe(true);
          entry!.transport.send = async (message, options) => {
            if (rpcMethod(message) !== "tools/call") return realSend(message, options);
            const pending = realSend(message, options);
            if (index === 2) await pending;
            process.kill(pid, "SIGKILL");
            await pending.catch(() => undefined);
            return undefined;
          };
        }
        const blocked = await client.callTool({
          name: "fix__ping",
          arguments: { note },
        });
        expect(textOf(blocked)).toBe("tool not found");
        expect(textOf(blocked)).not.toContain(note);
        expect(readNames(dir)).toHaveLength(beforeReads);
      }

      const calls = running.store
        .listAudit(ws.id, { limit: 50 })
        .filter((event) => event.action === "tools/call");
      const blob = JSON.stringify(calls);
      expect(blob).toContain("ack-note-placeholder");
      expect(blob).toContain("after-ack-placeholder");
      for (const note of unread) expect(blob).not.toContain(note);
    } finally {
      await client.close();
      await running.close();
    }
  }, 30_000);
});

describe("shutdown budget", () => {
  it("finishes within 10s when a stdio child ignores SIGTERM", async () => {
    expect(SHUTDOWN_BUDGET_MS).toBeLessThanOrEqual(10_000);
    expect(SHUTDOWN_DRAIN_MS).toBeLessThanOrEqual(8_000);
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
