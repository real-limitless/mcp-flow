/** QA V51-F1: SIGTERM/SIGINT drains in-flight calls (bounded grace), then records leftovers as unknown. */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_SHUTDOWN_GRACE_MS, MAX_SHUTDOWN_GRACE_MS, loadConfig, parseShutdownGraceMs } from "../src/config.js";
import { HELD_CALLER_WAIT_MAX_MS, SHUTDOWN_BUDGET_MS, SHUTDOWN_CLOSE_RESERVE_MS, heldCallerWaitMs, installSignalHandlers, startServer, type RunningServer } from "../src/server.js";
import type { CallContext } from "../src/policy/engine.js";

const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function boot(graceMs: number) {
  const d = mkdtempSync(join(tmpdir(), "drain-")); tmp.push(d);
  const dbPath = join(d, "t.db");
  const cfg = loadConfig({ dbPath, masterKeyRaw: Buffer.alloc(32, 8).toString("base64"), adminToken: "drain-admin", host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default", shutdownGraceMs: graceMs });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const gw: RunningServer = await startServer(cfg);
  cleanups.push(() => gw.close());
  const ws = gw.store.ensureWorkspace("default").id;
  const id = gw.store.identity;
  const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
  const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
  const botKey = id.createKey({ agentId: bot, createdBy: chen }).keyId;
  const db = gw.store.db;
  const rid = `rule_${randomBytes(12).toString("hex")}`;
  db.exec("BEGIN IMMEDIATE;");
  db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, ws, chen);
  db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, created_by) VALUES (?,1,'t','["slow"]','allow',?)`).run(rid, chen);
  db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
  db.exec("COMMIT;");
  const ctx: CallContext = { workspaceId: ws, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null, projectId: "p1", backendSlug: "gh", tool: "slow", qualifiedTool: "gh__slow", placement: "remote", deviceId: null };
  return { gw, dbPath, ctx };
}

function slowCall(gw: RunningServer, ctx: CallContext, ms: number) {
  const state = { started: false, finished: false };
  const p = gw.store.policy.enforce({ ctx, args: { ms }, dispatch: async () => { state.started = true; await sleep(ms); state.finished = true; return { content: [{ type: "text" as const, text: "done" }] }; } });
  return { p, state };
}

function inspect(dbPath: string) {
  const ro = new DatabaseSync(dbPath);
  try {
    return {
      completions: ro.prepare(`SELECT final_outcome, result_status, error_code FROM mcpflow_call_audit WHERE event_type='completion' AND tool IN ('slow','gh__slow') ORDER BY audit_id`).all(),
      shutdown: ro.prepare(`SELECT detail_json FROM audit_events WHERE action='policy.shutdown'`).all().map((r) => JSON.parse(String((r as { detail_json: string }).detail_json))),
    };
  } finally {
    ro.close();
  }
}

describe("QA V51-F1 shutdown drain", () => {
  it("config: grace defaults to 8000 ms, configurable, clamped below the 10 s stop timeout", () => {
    expect(DEFAULT_SHUTDOWN_GRACE_MS).toBe(8000);
    expect(parseShutdownGraceMs(undefined)).toBe(8000);
    expect(parseShutdownGraceMs("abc")).toBe(8000);
    expect(parseShutdownGraceMs("2500")).toBe(2500);
    expect(parseShutdownGraceMs("60000")).toBe(8000);
    expect(parseShutdownGraceMs("9000")).toBe(8000);
    expect(MAX_SHUTDOWN_GRACE_MS).toBe(8000);
    expect(parseShutdownGraceMs("-5")).toBe(0);
    const prev = process.env.MCP_FLOW_SHUTDOWN_GRACE_MS;
    process.env.MCP_FLOW_SHUTDOWN_GRACE_MS = "3000";
    try {
      expect(loadConfig({ masterKeyRaw: "x", adminToken: "y" }).shutdownGraceMs).toBe(3000);
    } finally {
      if (prev === undefined) delete process.env.MCP_FLOW_SHUTDOWN_GRACE_MS; else process.env.MCP_FLOW_SHUTDOWN_GRACE_MS = prev;
    }
  });

  it("budget: max grace + held-caller wait + upstream close reserve fit in the 10 s stop timeout", () => {
    expect(SHUTDOWN_BUDGET_MS).toBe(10_000);
    expect(heldCallerWaitMs(0)).toBe(HELD_CALLER_WAIT_MAX_MS);
    // after a full max-grace drain the held-caller wait shrinks so the close reserve still fits
    expect(heldCallerWaitMs(MAX_SHUTDOWN_GRACE_MS)).toBe(0);
    expect(MAX_SHUTDOWN_GRACE_MS + heldCallerWaitMs(MAX_SHUTDOWN_GRACE_MS) + SHUTDOWN_CLOSE_RESERVE_MS).toBeLessThanOrEqual(SHUTDOWN_BUDGET_MS);
    // default-length drain that ends early leaves the full held-caller wait
    expect(heldCallerWaitMs(3000)).toBe(HELD_CALLER_WAIT_MAX_MS);
    expect(heldCallerWaitMs(SHUTDOWN_BUDGET_MS)).toBe(0);
  });

  it("a call that finishes inside the grace period completes normally (executed/ok, drained:1); new calls are refused", async () => {
    const { gw, dbPath, ctx } = await boot(3000);
    const c = slowCall(gw, ctx, 600);
    for (let i = 0; i < 100 && !c.state.started; i++) await sleep(5);
    const codes: number[] = [];
    const h = installSignalHandlers(gw, { exit: (x) => codes.push(x), signals: [] });
    const t0 = Date.now();
    const stopping = h.handle("SIGTERM");
    await sleep(20);
    // during the drain: a new call is refused cleanly and nothing is dispatched
    let dispatchedLate = false;
    const late = (await gw.store.policy.enforce({ ctx, args: { late: 1 }, dispatch: async () => { dispatchedLate = true; return { content: [] }; } })) as { isError?: boolean; content: Array<{ text: string }> };
    expect(late.isError).toBe(true);
    expect(late.content[0]!.text).toContain("gateway_shutting_down");
    expect(dispatchedLate).toBe(false);
    await stopping;
    const res = (await c.p) as { content: Array<{ text: string }> };
    expect(res.content[0]!.text).toBe("done");
    expect(c.state.finished).toBe(true);
    expect(Date.now() - t0).toBeLessThan(3000);
    expect(codes).toEqual([0]);
    expect(existsSync(`${dbPath}.gateway.lock`)).toBe(false);
    const db = inspect(dbPath);
    expect(db.completions).toEqual([
      { final_outcome: "error", result_status: "not_dispatched", error_code: "gateway_shutting_down" }, // refused first
      { final_outcome: "executed", result_status: "ok", error_code: null }, // then the drained call
    ]);
    expect(db.shutdown).toHaveLength(1);
    expect(db.shutdown[0]).toMatchObject({ drained: 1, unknown: 0, reason: "SIGTERM", grace_ms: 3000 });
  });

  it("a call still running when the grace period ends is recorded once as outcome unknown (shutdown_unknown); its late finish writes nothing", async () => {
    const { gw, dbPath, ctx } = await boot(300);
    const c = slowCall(gw, ctx, 1500);
    for (let i = 0; i < 100 && !c.state.started; i++) await sleep(5);
    const codes: number[] = [];
    const h = installSignalHandlers(gw, { exit: (x) => codes.push(x), signals: [] });
    const t0 = Date.now();
    await h.handle("SIGINT");
    expect(Date.now() - t0).toBeLessThan(1400); // bounded by the grace, not the call
    expect(codes).toEqual([0]);
    expect(c.state.finished).toBe(false);
    let db = inspect(dbPath);
    expect(db.completions).toEqual([{ final_outcome: "error", result_status: "error", error_code: "shutdown_unknown" }]);
    expect(db.shutdown[0]).toMatchObject({ drained: 0, unknown: 1, reason: "SIGINT", grace_ms: 300 });
    await c.p.catch(() => {}); // the backend finishes later; the DB is closed, nothing more is written
    db = inspect(dbPath);
    expect(db.completions).toHaveLength(1);
  });

  it("second signal during the drain: in-flight recorded unknown immediately, lock released, exit 1", async () => {
    const { gw, dbPath, ctx } = await boot(5000);
    const c = slowCall(gw, ctx, 1500);
    for (let i = 0; i < 100 && !c.state.started; i++) await sleep(5);
    const codes: number[] = [];
    const h = installSignalHandlers(gw, { exit: (x) => codes.push(x), signals: [] });
    void h.handle("SIGTERM");
    await sleep(50);
    await h.handle("SIGTERM");
    expect(codes).toEqual([1]);
    expect(existsSync(`${dbPath}.gateway.lock`)).toBe(false);
    const db = inspect(dbPath);
    expect(db.completions).toEqual([{ final_outcome: "error", result_status: "error", error_code: "shutdown_unknown" }]);
    expect(db.shutdown.some((d) => d.forced === true && d.unknown === 1)).toBe(true);
    await c.p.catch(() => {});
  });
});
