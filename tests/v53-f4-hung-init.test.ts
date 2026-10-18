/**
 * QA V53-F4 (v5.3 + v5.4 hung-init-block.mjs): one stdio backend that never answers initialize made
 * every agent call to a healthy backend in the same project wait ~60 s (60065 / 60055 ms). Now:
 * bounded per-backend init timeout, agent calls resolve against their own backend only, listings wait
 * a bounded time per backend, and the stuck backend gets a typed backend_unavailable refusal.
 * Tokens are minted at runtime and never printed; no mf_sess_ ids are minted.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  DEFAULT_BACKEND_INIT_HARD_TIMEOUT_MS,
  DEFAULT_BACKEND_INIT_TIMEOUT_MS,
  loadConfig,
  parseBackendInitHardTimeoutMs,
  parseBackendInitTimeoutMs,
  timeoutEnvWarning,
} from "../src/config.js";
import { Store } from "../src/db/store.js";
import { BackendUnavailableError, backoffMs, UpstreamPool, type UpstreamPoolOptions } from "../src/mcp/upstream.js";
import { ToolListChangedNotificationSchema } from "@modelcontextprotocol/sdk/types.js";
import { saveRuleVersion } from "../src/policy/rule-input.js";
import type { BackendRecord } from "../src/types.js";

const REPO = resolve(__dirname, "..");
const MASTER = Buffer.alloc(32, 11).toString("base64");
const tmp: string[] = [];
const procs: ChildProcess[] = [];
const cleanups: Array<() => Promise<void>> = [];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function alive(pid: number): boolean {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/)[0] !== "Z";
  } catch {
    return false;
  }
}
interface Marker { pid: number; child: number; name: string }
function markers(spawnDir: string, name?: string): Marker[] {
  let names: string[] = [];
  try { names = readdirSync(spawnDir); } catch { return []; }
  return names.map((n) => JSON.parse(readFileSync(join(spawnDir, n), "utf8")) as Marker).filter((m) => !name || m.name === name);
}
const survivors = (spawnDir: string, name?: string) => markers(spawnDir, name).flatMap((m) => [m.pid, m.child]).filter(alive);
async function until(pred: () => boolean, ms: number): Promise<boolean> {
  const t = Date.now();
  while (Date.now() - t < ms) { if (pred()) return true; await sleep(20); }
  return pred();
}

afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  for (const p of procs.splice(0)) if (p.exitCode === null && p.signalCode === null) p.kill("SIGKILL");
  for (const d of tmp) for (const m of markers(join(d, "spawns"))) for (const pid of [m.child, m.pid]) { try { process.kill(pid, "SIGKILL"); } catch { /* gone */ } }
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

/** Raw JSON-RPC stdio MCP server. argv: <spawnDir> <name> [mode]; mode: hang-init | exit-init | slow-init:<ms> | hang-relist. One grandchild. */
function writeBackend(dir: string): string {
  const path = join(dir, "fixture-mcp-f4.mjs");
  writeFileSync(path, `import { createInterface } from "node:readline";
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
const [, , spawnDir, name, mode = ""] = process.argv;
mkdirSync(spawnDir, { recursive: true });
const gc = spawn(process.execPath, ["-e", "setInterval(()=>{},1e9)"], { stdio: "ignore" });
writeFileSync(spawnDir + "/" + process.pid, JSON.stringify({ pid: process.pid, child: gc.pid, name }));
const slow = mode.startsWith("slow-init:") ? Number(mode.slice(10)) : 0;
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
createInterface({ input: process.stdin }).on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") {
    if (mode === "hang-init") return;
    if (mode === "exit-init") process.exit(3);
    const reply = () => send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name, version: "1" } } });
    return void (slow ? setTimeout(reply, slow) : reply());
  }
  if (m.method === "tools/list" && mode === "hang-relist" && globalThis.listed) return;
  if (m.method === "tools/list") globalThis.listed = true;
  if (m.method === "tools/list") return send({ jsonrpc: "2.0", id: m.id, result: { tools: [{ name: "echo", inputSchema: { type: "object" } }] } });
  if (m.method === "tools/call") return send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: name + ":echo:" + (m.params.arguments?.v ?? "") }] } });
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

/** As QA's seed.ts: backends s1..sn, project p1, bot agent key + legacy key, allow-all rule. */
function seed(modes: string[]) {
  const d = mkdtempSync(join(tmpdir(), "v53f4-")); tmp.push(d);
  const spawnDir = join(d, "spawns"); mkdirSync(spawnDir);
  const script = writeBackend(d);
  const dbPath = join(d, "t.db");
  const store = new Store(dbPath, MASTER);
  const ws = store.ensureWorkspace("default").id;
  const slugs = modes.map((_, i) => `s${i + 1}`);
  slugs.forEach((slug, i) => store.createBackend(ws, { slug, transport: "stdio", command: [process.execPath, script, spawnDir, slug, modes[i]!], enabled: true, placement: { mode: "central-sandbox" } } as never));
  store.createProject(ws, { slug: "p1", title: "P1", backendSlugs: slugs });
  const id = store.identity;
  const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
  const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  const botToken = id.createKey({ agentId: bot, createdBy: chen }).token;
  saveRuleVersion(store.db, { ruleId: `rule_${randomBytes(12).toString("hex")}`, workspaceId: ws, createdBy: chen, description: "f4 allow", effect: "allow", matchTools: ["*"] });
  const legacy = store.createApiKey(ws, "legacy", { projects: ["*"] } as never).token;
  store.close();
  return { dbPath, spawnDir, script, botToken, legacy, ws };
}

async function serve(dbPath: string, env: Record<string, string>) {
  const port = await freePort();
  const p = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", "serve"], {
    cwd: REPO,
    env: { ...process.env, MCP_FLOW_DB_PATH: dbPath, MCP_FLOW_MASTER_KEY: MASTER, MCP_FLOW_ADMIN_TOKEN: randomBytes(24).toString("hex"), MCP_FLOW_PORT: String(port), MCP_FLOW_HOST: "127.0.0.1", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  procs.push(p);
  let log = "";
  p.stderr!.on("data", (b) => (log += b)); p.stdout!.on("data", (b) => (log += b));
  const exited = new Promise<number | null>((r) => p.on("exit", (code) => r(code)));
  const t = Date.now();
  while (!/listening on/.test(log)) {
    if (Date.now() - t > 20_000 || p.exitCode !== null) throw new Error(`serve did not start: ${log.slice(-400)}`);
    await sleep(25);
  }
  return { p, port, exited, log: () => log };
}

async function mcpClient(port: number, token: string, project: boolean): Promise<Client> {
  const c = new Client({ name: "v53f4", version: "1" });
  await c.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${token}` } } }));
  cleanups.push(() => c.close());
  if (project) await c.callTool({ name: "mf_use_project", arguments: { project: "p1", mintSessionToken: false } }, undefined, { timeout: 15_000 });
  return c;
}
const text = (r: unknown) => String((r as { content?: Array<{ text?: string }> }).content?.[0]?.text ?? "");
async function timed(c: Client, name: string, args: Record<string, unknown> = {}) {
  const t = Date.now();
  const r = await c.callTool({ name, arguments: args }, undefined, { timeout: 120_000 }).then(text, (e: Error) => `ERR ${e.message}`);
  return { r, ms: Date.now() - t };
}

describe("V53-F4 QA repro: one backend never initializes", () => {
  it("agent calls to the healthy backend do not wait; the stuck one gets a typed backend_unavailable; listing is bounded", async () => {
    const INIT = 2000;
    const w = seed(["", "hang-init"]);
    // a truly hung init: the hard ceiling (here = the caller wait) kills it and starts the backoff
    const s = await serve(w.dbPath, { MCP_FLOW_BACKEND_INIT_TIMEOUT_MS: String(INIT), MCP_FLOW_BACKEND_INIT_HARD_TIMEOUT_MS: String(INIT) });
    const c = await mcpClient(s.port, w.botToken, true);

    // QA: 60065 ms then 60055 ms
    const a1 = await timed(c, "s1__echo", { v: 1 });
    const a2 = await timed(c, "s1__echo", { v: 2 });
    expect(a1.r).toBe("s1:echo:1");
    expect(a2.r).toBe("s1:echo:2");
    expect(a1.ms).toBeLessThan(1_500);
    expect(a2.ms).toBeLessThan(500);

    // the stuck backend: typed refusal within the init timeout, never dispatched
    const b1 = await timed(c, "s2__echo", { v: 1 });
    const p1 = JSON.parse(b1.r) as Record<string, unknown>;
    expect(p1).toMatchObject({ reason: "backend_unavailable", backend: "s2", tool: "s2__echo" });
    expect(Number(p1.retry_after_ms)).toBeGreaterThan(0);
    expect(b1.ms).toBeLessThan(INIT + 2_500);
    // during the cooldown it fails at once and does not respawn
    expect(await until(() => /backend s2 did not initialize within the 2000 ms hard ceiling/.test(s.log()), 3_000)).toBe(true);
    const spawnsBefore = markers(w.spawnDir, "s2").length;
    const b2 = await timed(c, "s2__echo", { v: 2 });
    expect(JSON.parse(b2.r)).toMatchObject({ reason: "backend_unavailable", backend: "s2" });
    expect(b2.ms).toBeLessThan(500);
    expect(markers(w.spawnDir, "s2")).toHaveLength(spawnsBefore);
    // the timed-out spawn and its grandchild are gone
    expect(await until(() => survivors(w.spawnDir, "s2").length === 0, 2_000)).toBe(true);

    // tools/list stays bounded and still lists the healthy backend
    const t = Date.now();
    const listed = await c.listTools(undefined, { timeout: 60_000 });
    expect(Date.now() - t).toBeLessThan(INIT + 1_000);
    const names = listed.tools.map((x) => x.name);
    expect(names).toContain("s1__echo");
    expect(names).not.toContain("s2__echo");

    // legacy key (bypasses the enforcer): healthy backend fast, stuck one returns a clear error
    const lc = await mcpClient(s.port, w.legacy, false);
    const l1 = await timed(lc, "s1__echo", { v: 3 });
    expect(l1.r).toBe("s1:echo:3");
    expect(l1.ms).toBeLessThan(500);
    const l2 = await timed(lc, "s2__echo", { v: 4 });
    expect(l2.r).toMatch(/backend_unavailable/);
    expect(l2.ms).toBeLessThan(500);

    s.p.kill("SIGTERM");
    expect(await s.exited).toBe(0);
    expect(await until(() => survivors(w.spawnDir).length === 0, 1_500)).toBe(true);
    expect(s.log()).toMatch(/backend s2 did not initialize within the 2000 ms hard ceiling; stopped it; next attempt in \d+ ms \(failure 1\)/);

    const db = new DatabaseSync(w.dbPath);
    try {
      const rows = db.prepare(`SELECT event_type, policy_decision, final_outcome, result_status, error_code, backend_slug FROM mcpflow_call_audit WHERE tool = 's2__echo' ORDER BY audit_id`).all();
      expect(rows).toEqual([
        { event_type: "decision", policy_decision: "deny", final_outcome: null, result_status: null, error_code: "backend_unavailable", backend_slug: "s2" },
        { event_type: "completion", policy_decision: null, final_outcome: "error", result_status: "not_dispatched", error_code: "backend_unavailable", backend_slug: "s2" },
        { event_type: "decision", policy_decision: "deny", final_outcome: null, result_status: null, error_code: "backend_unavailable", backend_slug: "s2" },
        { event_type: "completion", policy_decision: null, final_outcome: "error", result_status: "not_dispatched", error_code: "backend_unavailable", backend_slug: "s2" },
      ]);
    } finally {
      db.close();
    }
  }, 60_000);
});

describe("V53-F4 pool: init timeout, cooldown, bounded listing", () => {
  function pool(modes: string[], opts: UpstreamPoolOptions) {
    const w = seed(modes);
    const store = new Store(w.dbPath, MASTER);
    const p = new UpstreamPool(store, opts);
    cleanups.push(async () => { await p.closeAll(); store.close(); });
    const backend = (slug: string) => store.getBackend(w.ws, slug) as BackendRecord;
    return { ...w, store, p, backend };
  }

  it("after the cooldown the stuck backend is tried again (one new spawn), then fails typed again; the backoff doubles", async () => {
    const x = pool(["hang-init"], { initTimeoutMs: 3000, initHardTimeoutMs: 1000, stuckCooldownMs: 600 });
    const t = Date.now();
    await expect(x.p.listBackendTools(x.ws, x.backend("s1"))).rejects.toMatchObject({ code: "backend_unavailable", cause_: "init_timeout" });
    expect(Date.now() - t).toBeLessThan(2_500);
    await expect(x.p.listBackendTools(x.ws, x.backend("s1"))).rejects.toMatchObject({ cause_: "cooling_down" });
    expect(markers(x.spawnDir)).toHaveLength(1);
    await sleep(700);
    await expect(x.p.listBackendTools(x.ws, x.backend("s1"))).rejects.toBeInstanceOf(BackendUnavailableError);
    expect(markers(x.spawnDir)).toHaveLength(2);
    expect(await until(() => survivors(x.spawnDir).length === 0, 2_000)).toBe(true);
    // second consecutive hard-ceiling failure: 2x the first backoff, so no tight respawn loop
    const err = (await x.p.listBackendTools(x.ws, x.backend("s1")).catch((e) => e)) as BackendUnavailableError;
    expect(err.cause_).toBe("cooling_down");
    expect(err.retryAfterMs).toBeGreaterThan(900);
    expect(markers(x.spawnDir)).toHaveLength(2);
  }, 20_000);

  it("a slow but healthy backend is left out of a listing that cannot wait, then appears; no cooldown", async () => {
    const x = pool(["", "slow-init:900"], { initTimeoutMs: 3000, listWaitMs: 300 });
    const t = Date.now();
    const first = (await x.p.listNamespacedTools(x.ws)).map((n) => n.name);
    expect(Date.now() - t).toBeLessThan(800);
    expect(first).toEqual(["s1__echo"]);
    expect(await until(() => markers(x.spawnDir, "s2").length === 1, 1_000)).toBe(true);
    await sleep(1_000);
    const later = (await x.p.listNamespacedTools(x.ws)).map((n) => n.name);
    expect(later).toEqual(["s1__echo", "s2__echo"]);
    expect(markers(x.spawnDir, "s2")).toHaveLength(1); // the first connect was kept, not respawned
  }, 20_000);

  it("an open client that stops answering tools/list is retired (group killed) and fails typed, not waited on", async () => {
    const x = pool(["hang-relist"], { initTimeoutMs: 800, stuckCooldownMs: 5_000 });
    expect((await x.p.listBackendTools(x.ws, x.backend("s1"))).map((n) => n.name)).toEqual(["s1__echo"]);
    const entry = (x.p as unknown as { pool: Map<string, { fetchedAt: number }> }).pool.get(x.backend("s1").id)!;
    entry.fetchedAt = 0; // tool cache expired
    const t = Date.now();
    await expect(x.p.listBackendTools(x.ws, x.backend("s1"))).rejects.toMatchObject({ code: "backend_unavailable", cause_: "init_timeout" });
    expect(Date.now() - t).toBeLessThan(1_800);
    expect(await until(() => survivors(x.spawnDir).length === 0, 2_000)).toBe(true);
    await expect(x.p.listBackendTools(x.ws, x.backend("s1"))).rejects.toMatchObject({ cause_: "cooling_down" });
  }, 20_000);

  it("a call routed to one backend never waits for another backend that is stuck", async () => {
    const x = pool(["", "hang-init"], { initTimeoutMs: 3000 });
    void x.p.listNamespacedTools(x.ws); // starts both connects
    const t = Date.now();
    const tools = await x.p.listBackendTools(x.ws, x.backend("s1"));
    expect(tools.map((n) => n.name)).toEqual(["s1__echo"]);
    expect(Date.now() - t).toBeLessThan(1_000);
  }, 20_000);
});

describe("QA v5.5 item 1: slow cold start keeps its spawn; crash / hung init back off", () => {
  function pool(modes: string[], opts: UpstreamPoolOptions = {}) {
    const w = seed(modes);
    const store = new Store(w.dbPath, MASTER);
    const p = new UpstreamPool(store, opts);
    const changed: string[] = [];
    p.onToolsChanged((_ws, slug) => changed.push(slug));
    cleanups.push(async () => { await p.closeAll(); store.close(); });
    const backend = (slug: string) => store.getBackend(w.ws, slug) as BackendRecord;
    return { ...w, store, p, backend, changed };
  }

  it("a 25 s cold start (default 20 s caller wait) eventually serves calls with ONE spawn, no kill / respawn churn", async () => {
    const x = pool(["slow-init:25000"]); // defaults: caller wait 20 s, hard ceiling 300 s
    const t0 = Date.now();
    const first = (await x.p.listBackendTools(x.ws, x.backend("s1")).catch((e) => e)) as BackendUnavailableError;
    expect(first).toBeInstanceOf(BackendUnavailableError);
    expect(first.cause_).toBe("starting");
    expect(first.retryAfterMs).toBeGreaterThan(0);
    const waited = Date.now() - t0;
    expect(waited).toBeGreaterThanOrEqual(19_500);
    expect(waited).toBeLessThan(21_500);
    // callers after the wait fail fast while init continues in the background
    const t1 = Date.now();
    await expect(x.p.listBackendTools(x.ws, x.backend("s1"))).rejects.toMatchObject({ cause_: "starting" });
    expect(Date.now() - t1).toBeLessThan(200);
    expect(survivors(x.spawnDir, "s1").length).toBeGreaterThan(0); // the spawn was NOT killed
    let okAt = 0;
    while (Date.now() - t0 < 32_000) {
      const r = await x.p.listBackendTools(x.ws, x.backend("s1")).catch(() => null);
      if (r) {
        expect(r.map((n) => n.name)).toEqual(["s1__echo"]);
        okAt = Date.now() - t0;
        break;
      }
      await sleep(500);
    }
    expect(okAt).toBeGreaterThan(24_000);
    expect(okAt).toBeLessThan(27_500);
    expect(markers(x.spawnDir, "s1")).toHaveLength(1);
    expect(x.p.spawnCount.get(x.backend("s1").id)).toBe(1);
    expect(x.changed).toEqual(["s1"]); // late arrival announced once (-> tools/list_changed)
    const r = await x.p.callTool(x.ws, "s1__echo", { v: 7 });
    expect(r.isError).toBeFalsy();
  }, 45_000);

  it("scaled: callers stop waiting at the soft timeout, the init finishes at 1.5 s and is pooled (no respawn)", async () => {
    const x = pool(["slow-init:1500"], { initTimeoutMs: 500 });
    await expect(x.p.listBackendTools(x.ws, x.backend("s1"))).rejects.toMatchObject({ cause_: "starting" });
    expect(await until(() => x.changed.length === 1, 3_000)).toBe(true);
    expect((await x.p.listBackendTools(x.ws, x.backend("s1"))).map((n) => n.name)).toEqual(["s1__echo"]);
    expect(markers(x.spawnDir, "s1")).toHaveLength(1);
  }, 20_000);

  it("a backend that exits during init is respawned with exponential backoff (bounded, typed), never in a tight loop", async () => {
    const x = pool(["exit-init"], { crashBackoffMs: 200, crashBackoffMaxMs: 800 });
    const causes = new Set<string>();
    const t0 = Date.now();
    while (Date.now() - t0 < 2_500) {
      const e = await x.p.listBackendTools(x.ws, x.backend("s1")).catch((err) => err);
      causes.add(e instanceof BackendUnavailableError ? e.cause_ : "raw");
      await sleep(20);
    }
    // attempts at ~0, 0.2, 0.6, 1.4, 2.2 s => at most 5 (6 with timing slack) instead of ~100
    const n = markers(x.spawnDir, "s1").length;
    expect(n).toBeGreaterThanOrEqual(3);
    expect(n).toBeLessThanOrEqual(6);
    expect(causes.has("cooling_down")).toBe(true);
    expect([...causes].every((c) => ["cooling_down", "init_failed"].includes(c))).toBe(true); // always typed for agents
    expect(backoffMs(1, 200, 800)).toBe(200);
    expect(backoffMs(3, 200, 800)).toBe(800);
    expect(backoffMs(9, 200, 800)).toBe(800);
  }, 20_000);
});

describe("QA v5.5 item 2: notifications/tools/list_changed when a late backend's tools arrive", () => {
  it("a client that listed before the slow backend was ready gets list_changed, then sees its tools", async () => {
    const w = seed(["", "slow-init:3000"]);
    const s = await serve(w.dbPath, { MCP_FLOW_BACKEND_INIT_TIMEOUT_MS: "1000" });
    const c = await mcpClient(s.port, w.botToken, true);
    const got: number[] = [];
    c.setNotificationHandler(ToolListChangedNotificationSchema, () => {
      got.push(Date.now());
    });
    const t = Date.now();
    const early = (await c.listTools(undefined, { timeout: 30_000 })).tools.map((x) => x.name);
    expect(Date.now() - t).toBeLessThan(2_500);
    expect(early).toContain("s1__echo");
    expect(early).not.toContain("s2__echo");
    expect(await until(() => got.length > 0, 8_000)).toBe(true);
    const later = (await c.listTools(undefined, { timeout: 30_000 })).tools.map((x) => x.name);
    expect(later).toContain("s2__echo");
    expect((await timed(c, "s2__echo", { v: 5 })).r).toBe("s2:echo:5");
    expect(markers(w.spawnDir, "s2")).toHaveLength(1);
    s.p.kill("SIGTERM");
    expect(await s.exited).toBe(0);
  }, 40_000);
});

describe("V53-F4 config", () => {
  it("MCP_FLOW_BACKEND_INIT_TIMEOUT_MS: default 20 s, clamped to 1..120 s", () => {
    expect(DEFAULT_BACKEND_INIT_TIMEOUT_MS).toBe(20_000);
    expect(parseBackendInitTimeoutMs(undefined)).toBe(20_000);
    expect(parseBackendInitTimeoutMs("abc")).toBe(20_000);
    expect(parseBackendInitTimeoutMs("5")).toBe(1_000);
    expect(parseBackendInitTimeoutMs("500000")).toBe(120_000);
    expect(parseBackendInitTimeoutMs("7500")).toBe(7_500);
    // QA v5.5: the hard ceiling (default 300 s, never below the caller wait, max 30 min)
    expect(DEFAULT_BACKEND_INIT_HARD_TIMEOUT_MS).toBe(300_000);
    expect(parseBackendInitHardTimeoutMs(undefined, 20_000)).toBe(300_000);
    expect(parseBackendInitHardTimeoutMs("1000", 20_000)).toBe(20_000);
    expect(parseBackendInitHardTimeoutMs("9999999", 20_000)).toBe(1_800_000);
    expect(parseBackendInitHardTimeoutMs("60000", 20_000)).toBe(60_000);
    // QA v5.5 note: invalid / clamped values are warned about, valid ones are not
    expect(timeoutEnvWarning("X", "abc", 20_000)).toMatch(/not a number; using 20000 ms/);
    expect(timeoutEnvWarning("X", "0", 1_000)).toMatch(/out of range/);
    expect(timeoutEnvWarning("X", "7500", 7_500)).toBeNull();
    expect(timeoutEnvWarning("X", undefined, 20_000)).toBeNull();
    const prev = process.env.MCP_FLOW_BACKEND_INIT_TIMEOUT_MS;
    process.env.MCP_FLOW_BACKEND_INIT_TIMEOUT_MS = "3000";
    try {
      expect(loadConfig({ masterKeyRaw: "x", adminToken: "y" } as never).backendInitTimeoutMs).toBe(3_000);
    } finally {
      if (prev === undefined) delete process.env.MCP_FLOW_BACKEND_INIT_TIMEOUT_MS; else process.env.MCP_FLOW_BACKEND_INIT_TIMEOUT_MS = prev;
    }
  });
});
