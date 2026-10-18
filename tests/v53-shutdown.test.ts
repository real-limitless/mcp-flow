/**
 * QA v5.3 blockers (V53-F1..F3, headroom), modelled on /workspace/mcp-flow-qa/v5.3/shutdown-test.mjs
 * and crash-orphan-repro.mts: a real `serve` process gets real signals; stdio backends spawn a
 * grandchild so process-group reaping is observable. Tokens are minted at runtime, never printed.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { startServer, type RunningServer } from "../src/server.js";
import type { BackendRecord } from "../src/types.js";

const REPO = resolve(__dirname, "..");
const MASTER = Buffer.alloc(32, 9).toString("base64");
const tmp: string[] = [];
const procs: ChildProcess[] = [];
const cleanups: Array<() => Promise<void>> = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function procStat(pid: number): { state: string; pgrp: number } | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const rest = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
    return { state: rest[0]!, pgrp: Number(rest[2]) };
  } catch {
    return null;
  }
}
const alive = (pid: number) => { const s = procStat(pid); return s !== null && s.state !== "Z"; };

interface Marker { pid: number; child: number }
function markers(spawnDir: string): Marker[] {
  let names: string[] = [];
  try { names = readdirSync(spawnDir); } catch { return []; }
  return names.map((n) => JSON.parse(readFileSync(join(spawnDir, n), "utf8")) as Marker);
}
/** Every backend leader and grandchild ever spawned for this test that is still running. */
function survivors(spawnDir: string): number[] {
  return markers(spawnDir).flatMap((m) => [m.pid, m.child]).filter(alive);
}
async function until(pred: () => boolean, ms: number): Promise<boolean> {
  const t = Date.now();
  while (Date.now() - t < ms) { if (pred()) return true; await sleep(20); }
  return pred();
}

afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  for (const p of procs.splice(0)) if (p.exitCode === null && p.signalCode === null) p.kill("SIGKILL");
  for (const d of tmp) {
    for (const m of markers(join(d, "spawns"))) for (const pid of [m.child, m.pid]) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
  }
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

/**
 * Raw JSON-RPC stdio MCP server. argv: <spawnDir> [modes], modes "+"-joined:
 * ignore-term (leader ignores SIGTERM), hang-init-on-respawn (2nd+ spawn never answers initialize).
 * Spawns one grandchild in its own process group (inherited), like npx -> sh -> node.
 */
function writeBackend(dir: string): string {
  const path = join(dir, "fixture-mcp-v53.mjs");
  writeFileSync(path, `import { createInterface } from "node:readline";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
const [, , spawnDir, mode = ""] = process.argv;
const modes = new Set(mode.split("+"));
if (modes.has("ignore-term")) process.on("SIGTERM", () => {});
mkdirSync(spawnDir, { recursive: true });
const flag = spawnDir + "/../respawn.flag";
const hang = modes.has("hang-init-on-respawn") && existsSync(flag);
writeFileSync(flag, "1");
const gc = spawn(process.execPath, ["-e", "process.on('SIGTERM',()=>{});setInterval(()=>{},1e9)"], { stdio: "ignore" });
writeFileSync(spawnDir + "/" + process.pid, JSON.stringify({ pid: process.pid, child: gc.pid }));
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
const ok = (id, text) => send({ jsonrpc: "2.0", id, result: { content: [{ type: "text", text }] } });
createInterface({ input: process.stdin }).on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    if (hang) return;
    return send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "v53", version: "1" } } });
  }
  if (m.method === "tools/list") {
    return send({ jsonrpc: "2.0", id: m.id, result: { tools: ["echo", "slow", "hang", "crash"].map((name) => ({ name, inputSchema: { type: "object" } })) } });
  }
  if (m.method === "tools/call") {
    const a = m.params.arguments ?? {};
    switch (m.params.name) {
      case "echo": return ok(m.id, "echo");
      case "slow": return void setTimeout(() => ok(m.id, "slow:" + a.ms), Number(a.ms ?? 1000));
      case "hang": return;
      case "crash": ok(m.id, "crashing"); return void setTimeout(() => process.exit(3), 5);
    }
  }
  if (m.method === "ping") send({ jsonrpc: "2.0", id: m.id, result: {} });
});
`);
  return path;
}

async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  return port;
}

/** Seed a DB with n stdio backends (s1..sn) and a legacy key with all projects. */
function seed(n: number, modes: string[] = []) {
  const d = mkdtempSync(join(tmpdir(), "v53-")); tmp.push(d);
  const spawnDir = join(d, "spawns"); mkdirSync(spawnDir);
  const script = writeBackend(d);
  const dbPath = join(d, "t.db");
  const store = new Store(dbPath, MASTER);
  const ws = store.ensureWorkspace("default").id;
  for (let i = 1; i <= n; i++) {
    store.createBackend(ws, { slug: `s${i}`, transport: "stdio", command: [process.execPath, script, spawnDir, modes[i - 1] ?? ""], enabled: true, placement: { mode: "central-sandbox" } });
  }
  const legacy = store.createApiKey(ws, "legacy", { projects: ["*"] } as never).token;
  store.close();
  return { d, dbPath, spawnDir, script, legacy, ws };
}

/** The real CLI (`serve`), with real signal handling, in one node process. */
async function serve(dbPath: string, env: Record<string, string> = {}) {
  const port = await freePort();
  const p = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", "serve"], {
    cwd: REPO,
    env: { ...process.env, MCP_FLOW_DB_PATH: dbPath, MCP_FLOW_MASTER_KEY: MASTER, MCP_FLOW_ADMIN_TOKEN: randomBytes(24).toString("hex"), MCP_FLOW_PORT: String(port), MCP_FLOW_HOST: "127.0.0.1", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  procs.push(p);
  let log = "";
  p.stderr!.on("data", (b) => (log += b)); p.stdout!.on("data", (b) => (log += b));
  const exited = new Promise<{ code: number | null; at: number }>((r) => p.on("exit", (code) => r({ code, at: Date.now() })));
  const t = Date.now();
  while (!/listening on/.test(log)) {
    if (Date.now() - t > 20_000 || p.exitCode !== null) throw new Error(`serve did not start: ${log.slice(-400)}`);
    await sleep(25);
  }
  return { p, port, exited, log: () => log };
}

async function mcpClient(port: number, token: string): Promise<Client> {
  const c = new Client({ name: "v53", version: "1" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
  cleanups.push(() => c.close());
  return c;
}
const text = (r: unknown) => String((r as { content?: Array<{ text?: string }> }).content?.[0]?.text ?? "");
const call = (c: Client, name: string, args: Record<string, unknown> = {}) =>
  c.callTool({ name, arguments: args }, undefined, { timeout: 60_000 }).then(text, (e: Error) => `ERR ${e.message.slice(0, 60)}`);

describe("V53-F1 second signal: ignored, cleanup continues, process groups reaped", () => {
  for (const second of ["SIGTERM", "SIGINT"] as const) {
    it(`SIGTERM then ${second}: exit 0 and no backend or grandchild survives`, async () => {
      const w = seed(2, ["", "ignore-term"]);
      const s = await serve(w.dbPath);
      const c = await mcpClient(s.port, w.legacy);
      expect(await call(c, "s1__echo")).toBe("echo");
      expect(await call(c, "s2__echo")).toBe("echo");
      expect(markers(w.spawnDir)).toHaveLength(2);
      expect(survivors(w.spawnDir)).toHaveLength(4);
      s.p.kill("SIGTERM");
      await sleep(30);
      s.p.kill(second);
      await sleep(30);
      s.p.kill(second);
      const done = await s.exited;
      expect(done.code).toBe(0);
      expect(s.log()).toMatch(/again during shutdown; ignored/);
      expect(await until(() => survivors(w.spawnDir).length === 0, 1_000)).toBe(true);
    }, 30_000);
  }
});

describe("V53-F1 forceStop kills the stdio process groups", () => {
  it("forceStop SIGKILLs every spawned group (leader that ignores SIGTERM and its grandchild)", async () => {
    const w = seed(2, ["", "ignore-term"]);
    const cfg = loadConfig({ dbPath: w.dbPath, masterKeyRaw: MASTER, adminToken: randomBytes(24).toString("hex"), host: "127.0.0.1", port: await freePort(), allowPrivateUrls: true });
    const gw: RunningServer = await startServer(cfg);
    cleanups.push(() => gw.close());
    const getClient = (gw.pool as unknown as { getClient(b: BackendRecord): Promise<unknown> }).getClient.bind(gw.pool);
    await getClient(gw.store.getBackend(w.ws, "s1")!);
    await getClient(gw.store.getBackend(w.ws, "s2")!);
    expect(survivors(w.spawnDir)).toHaveLength(4);
    gw.forceStop();
    expect(await until(() => survivors(w.spawnDir).length === 0, 500)).toBe(true);
  });
});
