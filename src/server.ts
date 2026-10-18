import type { Duplex } from "node:stream";
import { createPendingCallNotifier } from "./policy/push-notify.js";
import { createAdaptorServer } from "@hono/node-server";
import type { WebSocket } from "ws";
import { WebSocketServer } from "ws";
import { createApp } from "./api/app.js";
import type { Config } from "./config.js";
import { DEFAULT_SHUTDOWN_GRACE_MS, MAX_SHUTDOWN_GRACE_MS, requireSecrets } from "./config.js";
import { Store } from "./db/store.js";
import { acquireGatewayLock } from "./db/gateway-lock.js";
import { EdgeHub } from "./edge/hub.js";
import { encodeMsg, newMsgId } from "./edge/protocol.js";
import { EdgeRouter } from "./edge/router.js";
import { STDIO_GROUP_KILL_BUDGET_MS, killLiveStdioSync } from "./mcp/runners/stdio.js";
import { INFLIGHT_CLOSE_DEADLINE_MS, UpstreamPool } from "./mcp/upstream.js";

/** Docker's 10 s stop timeout: drain + upstream close (connect deadline + process-group kill) fit inside. */
export const SHUTDOWN_BUDGET_MS = 10_000;
/** Default in-flight drain (MCP_FLOW_SHUTDOWN_GRACE_MS default); see config.ts for the clamp. */
export const SHUTDOWN_DRAIN_MS = Math.min(
  DEFAULT_SHUTDOWN_GRACE_MS,
  SHUTDOWN_BUDGET_MS - STDIO_GROUP_KILL_BUDGET_MS - INFLIGHT_CLOSE_DEADLINE_MS,
);

/** Time reserved after the drain for pool.closeAll(): in-flight connect deadline + process-group kill. */
export const SHUTDOWN_CLOSE_RESERVE_MS = INFLIGHT_CLOSE_DEADLINE_MS + STDIO_GROUP_KILL_BUDGET_MS;
/** Held callers get at most this long to receive their 'cancelled' answer. */
export const HELD_CALLER_WAIT_MAX_MS = 1000;
/** V53: unused stop budget kept in the worst case (QA v5.3 measured ~160 ms with grace 8000). */
export const SHUTDOWN_HEADROOM_MS = 1000;
/** Allowance for work outside the timed steps (audit writes, recovery, socket and DB close). */
export const SHUTDOWN_OVERHEAD_ALLOWANCE_MS = 500;
/** Worst case by construction: max grace, no held-caller wait left, full close reserve. */
export const SHUTDOWN_WORST_CASE_MS = MAX_SHUTDOWN_GRACE_MS + SHUTDOWN_CLOSE_RESERVE_MS + SHUTDOWN_OVERHEAD_ALLOWANCE_MS;
if (SHUTDOWN_WORST_CASE_MS + SHUTDOWN_HEADROOM_MS > SHUTDOWN_BUDGET_MS) {
  throw new Error("shutdown constants leave less than SHUTDOWN_HEADROOM_MS of the stop budget");
}

/**
 * How long shutdown may still wait for held callers, given the time already spent: never more than
 * HELD_CALLER_WAIT_MAX_MS, and never into the time reserved for closing upstreams.
 */
export function heldCallerWaitMs(elapsedMs: number): number {
  return Math.max(0, Math.min(HELD_CALLER_WAIT_MAX_MS, SHUTDOWN_BUDGET_MS - SHUTDOWN_CLOSE_RESERVE_MS - SHUTDOWN_OVERHEAD_ALLOWANCE_MS - SHUTDOWN_HEADROOM_MS - elapsedMs));
}

export interface RunningServer {
  store: Store;
  pool: UpstreamPool;
  edgeHub: EdgeHub;
  edgeRouter: EdgeRouter;
  close: () => Promise<void>;
  /**
   * QA V5-F2: graceful stop (SIGTERM/SIGINT). Stops accepting, closes this process's open holds
   * durably (pending -> cancelled, approved-undispatched -> abandoned, in-flight -> unknown; audited
   * as policy.shutdown), then close(): DB closed and lock released. Idempotent.
   */
  shutdown: (reason: string) => Promise<void>;
  /**
   * Last-resort synchronous stop (not wired to signals; V53-F1): SIGKILL every stdio process group,
   * record in-flight calls as unknown, close the DB, release the lock.
   */
  forceStop: () => void;
  url: string;
}

/**
 * QA V5-F2: SIGTERM / SIGINT -> gw.shutdown() then exit(0) (exit(1) if shutdown failed).
 * V53-F1 (as on DEVELOPMENT 83382388): a second signal while shutting down is ignored and cleanup
 * continues, so stdio backends and their process groups are still reaped. The shutdown is
 * bounded by the 10 s budget on its own. Returns { handle, remove } (handle for tests).
 */
export function installSignalHandlers(
  gw: RunningServer,
  opts: { exit?: (code: number) => void; signals?: NodeJS.Signals[] } = {},
): { handle: (sig: NodeJS.Signals) => Promise<void>; remove: () => void } {
  const exit = opts.exit ?? ((code: number) => process.exit(code));
  const signals = opts.signals ?? ["SIGTERM", "SIGINT"];
  let stopping = false;
  const handle = async (sig: NodeJS.Signals) => {
    if (stopping) {
      console.error(`[mcp-flow] ${sig} again during shutdown; ignored, still cleaning up (bounded by the 10 s budget)`);
      return;
    }
    stopping = true;
    console.error(`[mcp-flow] ${sig}: shutting down (closing holds, DB and lock)`);
    try {
      await gw.shutdown(sig);
      exit(0);
    } catch (err) {
      console.error(`[mcp-flow] shutdown failed: ${(err as Error).message}`);
      exit(1);
    }
  };
  const listener = (sig: NodeJS.Signals) => void handle(sig);
  for (const s of signals) process.on(s, listener);
  return { handle, remove: () => { for (const s of signals) process.off(s, listener); } };
}

export interface StartOptions {
  /** R3-2: called when the DB lock is lost while serving. Default: log, stop accepting, exit(70). */
  onLockLost?: (reason: string) => void;
  lockHeartbeatMs?: number;
  /** Test hook: runs after the lock is taken and the DB is open, before the pre-recovery ownership check. */
  afterLock?: () => void;
}

export async function startServer(cfg: Config, opts: StartOptions = {}): Promise<RunningServer> {
  requireSecrets(cfg);
  // R2-4: exactly one gateway process per DB (recovery below assumes it); a second one refuses to start
  let stopServing: () => void = () => {};
  const lock = await acquireGatewayLock(cfg.dbPath, {
    heartbeatMs: opts.lockHeartbeatMs,
    onLost: (reason) => {
      console.error(`[mcp-flow] FATAL: lost the gateway DB lock (${reason}); another gateway owns this database. Stopping.`);
      stopServing();
      if (opts.onLockLost) opts.onLockLost(reason);
      else process.exit(70);
    },
  });
  let store: Store;
  try {
    store = new Store(cfg.dbPath, cfg.masterKeyRaw, { policyDevKeyRaw: cfg.policyDevKeyRaw, journalSizeLimitBytes: cfg.journalSizeLimitBytes, rateLimitPerMin: cfg.rateLimitPerMin });
  } catch (err) {
    lock?.release();
    throw err;
  }

  // R4-3: log the resolved cutover flag
  console.error(`[mcp-flow] MCP_FLOW_REFUSE_LEGACY_MCP_KEYS resolved to ${cfg.refuseLegacyMcpKeys ? "ON (legacy keys refused on /mcp)" : "OFF (legacy keys accepted on /mcp)"}`);
  opts.afterLock?.();
  // R4-1: re-check ownership right before recovery (a concurrent starter may have replaced our lock)
  if (lock && !lock.owned()) {
    lock.release();
    store.close();
    throw new Error(`lost the gateway DB lock ${lock.path} before recovery; another gateway owns this database`);
  }

  // Security T2.5 R-1: close out holds orphaned by the previous process (single gateway per DB).
  try {
    const rec = store.policy.recoverOrphans();
    if (rec.cancelled + rec.abandoned + rec.unknown > 0) {
      console.error(`[mcp-flow] recovered orphaned holds: ${JSON.stringify({ cancelled: rec.cancelled, abandoned: rec.abandoned, unknown: rec.unknown })}`);
      // R2-7: one row per affected workspace, with that workspace's own counts
      for (const [workspaceId, counts] of Object.entries(rec.byWorkspace)) {
        store.writeAudit({ workspaceId, keyId: null, action: "policy.recover", detail: { ...counts } });
      }
    }
  } catch (err) {
    console.error(`[mcp-flow] orphan recovery failed: ${(err as Error).message}`);
  }
  store.ensureWorkspace(cfg.workspaceName);
  // raw approval arguments must not outlive a decision made while no gate was waiting
  store.sweepResolvedSealedApprovalArgs();
  const pool = new UpstreamPool(store, { initTimeoutMs: cfg.backendInitTimeoutMs, initHardTimeoutMs: cfg.backendInitHardTimeoutMs });
  const edgeHub = new EdgeHub(store);
  const edgeRouter = new EdgeRouter(store, edgeHub);
  pool.setEdgeRouter(edgeRouter);

  const app = createApp(store, cfg, pool, { edgeHub, edgeRouter });

  // QA V51-F1: once shutdown starts, requests on still-open connections are refused cleanly (503)
  let draining = false;
  const nodeServer = createAdaptorServer({
    fetch: (req: Request, ...rest: unknown[]) =>
      draining
        ? new Response(JSON.stringify({ error: "shutting_down", message: "The gateway is shutting down; retry after it restarts." }), {
            status: 503, headers: { "content-type": "application/json", "retry-after": "5", connection: "close" },
          })
        : (app.fetch as (r: Request, ...a: unknown[]) => Response | Promise<Response>)(req, ...rest),
    hostname: cfg.host,
    port: cfg.port,
  });

  // V53-F2: count in-flight HTTP requests so shutdown drains every call, including legacy-key
  // /mcp calls that never pass through the policy enforcer. Long-lived GET event streams are not
  // work in flight and are not counted.
  let httpInflight = 0;
  const httpIdleWaiters = new Set<() => void>();
  nodeServer.on("request", (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => {
    if (req.method === "GET" && String(req.headers.accept ?? "").includes("text/event-stream")) return;
    httpInflight++;
    res.once("close", () => {
      httpInflight--;
      if (httpInflight === 0) for (const wake of [...httpIdleWaiters]) wake();
    });
  });
  /** Resolves true when no HTTP request is in flight, or false after ms. */
  const httpDrain = (ms: number): Promise<boolean> =>
    httpInflight === 0
      ? Promise.resolve(true)
      : new Promise<boolean>((resolve) => {
          const wake = () => { clearTimeout(timer); httpIdleWaiters.delete(wake); resolve(true); };
          const timer = setTimeout(() => { httpIdleWaiters.delete(wake); resolve(httpInflight === 0); }, Math.max(0, ms));
          httpIdleWaiters.add(wake);
        });

  const wss = new WebSocketServer({ noServer: true });
  // R3-2 self-fencing: stop accepting new HTTP/WS work immediately when the lock is lost
  stopServing = () => {
    try {
      nodeServer.close();
      (nodeServer as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
    } catch {
      /* already closed */
    }
  };

  nodeServer.on(
    "upgrade",
    (req: import("node:http").IncomingMessage, socket: Duplex, head: Buffer) => {
      const host = req.headers.host ?? "localhost";
      const url = new URL(req.url ?? "/", `http://${host}`);
      if (url.pathname !== "/v1/edge/connect") {
        socket.destroy();
        return;
      }
      const auth = req.headers.authorization;
      const m = auth ? /^Bearer\s+(.+)$/i.exec(auth) : null;
      const token = m?.[1]?.trim();
      if (!token) {
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }
      const device = store.authenticateDevice(token);
      if (!device) {
        socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
        socket.destroy();
        return;
      }
      wss.handleUpgrade(req, socket, head, (ws: WebSocket) => {
        edgeHub.attach(device.deviceId, device.workspaceId, {
          send: (data) => {
            if (ws.readyState === ws.OPEN) ws.send(data);
          },
          close: () => ws.close(),
        });
        ws.send(
          encodeMsg({
            v: 1,
            id: newMsgId(),
            type: "hello_ok",
            deviceId: device.deviceId,
            payload: { name: device.name },
          }),
        );
        ws.on("message", (data) => {
          edgeHub.handleMessage(device.deviceId, String(data));
        });
        ws.on("close", () => {
          edgeHub.detach(device.deviceId);
        });
      });
    },
  );

  await new Promise<void>((resolve, reject) => {
    nodeServer.listen(cfg.port, cfg.host, () => resolve());
    nodeServer.once("error", reject);
  });

  const addr = nodeServer.address();
  const port =
    typeof addr === "object" && addr ? addr.port : cfg.port;
  const url = `http://${cfg.host === "0.0.0.0" ? "127.0.0.1" : cfg.host}:${port}`;

  console.error(`mcp-flow listening on ${url}`);
  console.error(`  MCP:    ${url}/mcp`);
  console.error(`  Admin:  ${url}/v1/*  (Bearer admin token)`);
  console.error(`  Edge:   ws://…/v1/edge/connect`);
  console.error(`  UI:     ${url}/admin/`);
  console.error(`  Health: ${url}/health`);

  // T2.4: approver notification on one channel (Web Push)
  store.policy.setNotifier(createPendingCallNotifier(store, { approveBaseUrl: cfg.publicUrl ?? null }));

  // Timeout = deny even for holds whose waiter is gone (restart, crash): sweep overdue pending calls.
  const sweeper = setInterval(() => {
    try {
      store.policy.sweepExpired();
      store.policy.purgeResults();
    } catch (err) {
      console.error(`[mcp-flow] pending sweeper: ${(err as Error).message}`);
    }
  }, 30_000);
  sweeper.unref();

  let closing: Promise<void> | undefined;
  let shuttingDown: Promise<void> | undefined;
  const running: RunningServer = {
    store,
    pool,
    edgeHub,
    edgeRouter,
    url,
    close: () => (closing ??= (async () => {
      clearInterval(sweeper);
      edgeHub.closeAll();
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      await pool.closeAll();
      store.close();
      lock?.release();
      await new Promise<void>((resolve, reject) => {
        nodeServer.close((err) => (err && (err as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING" ? reject(err) : resolve()));
      });
    })()),
    forceStop: () => {
      draining = true;
      try {
        killLiveStdioSync();
      } catch (err) {
        console.error(`[mcp-flow] forced stop: process-group kill failed: ${(err as Error).message}`);
      }
      if (!lock || lock.owned()) {
        for (const [workspaceId, unknown] of Object.entries(store.policy.markInflightUnknown())) {
          store.writeAudit({ workspaceId, keyId: null, action: "policy.shutdown", detail: { forced: true, unknown } });
        }
      }
      try {
        store.close();
      } catch {
        /* already closed */
      }
      lock?.release();
    },
    shutdown: (reason: string) => (shuttingDown ??= (async () => {
      const shutdownStarted = Date.now();
      // QA V51-F1: drain instead of cut.
      // 1) stop accepting: no new connections; new requests on open connections get 503; new calls refused
      draining = true;
      nodeServer.close();
      (nodeServer as unknown as { closeIdleConnections?: () => void }).closeIdleConnections?.();
      if (!lock || lock.owned()) {
        try {
          // 2) holds not yet dispatched: pending -> cancelled, approved-undispatched -> abandoned
          const holds = store.policy.beginShutdown();
          // 3) dispatched calls: bounded grace, then any still running -> outcome unknown + completion row
          const graceMs = cfg.shutdownGraceMs ?? DEFAULT_SHUTDOWN_GRACE_MS;
          console.error(`[mcp-flow] draining ${store.policy.inflightCount()} in-flight call(s), ${httpInflight} HTTP request(s), grace ${graceMs} ms`);
          // V53-F2: enforcer calls and in-flight HTTP requests (legacy-key calls bypass the enforcer)
          // drain concurrently inside the same grace window, so the HTTP drain adds no time.
          const [drain, httpDrained] = await Promise.all([store.policy.drain(graceMs), httpDrain(graceMs)]);
          if (!httpDrained) console.error(`[mcp-flow] ${httpInflight} HTTP request(s) still open after the grace; closing them`);
          // 4) anything else left open (e.g. tracked outcomes) is closed out as on restart
          const rest = store.policy.recoverOrphans();
          const per: Record<string, { cancelled: number; abandoned: number; drained: number; unknown: number }> = {};
          const slot = (ws: string) => (per[ws] ??= { cancelled: 0, abandoned: 0, drained: 0, unknown: 0 });
          for (const [ws, c] of Object.entries(holds.byWorkspace)) { slot(ws).cancelled += c.cancelled; slot(ws).abandoned += c.abandoned; slot(ws).unknown += c.unknown; }
          for (const [ws, c] of Object.entries(drain.byWorkspace)) { slot(ws).drained += c.drained; slot(ws).unknown += c.unknown; }
          for (const [ws, c] of Object.entries(rest.byWorkspace)) { slot(ws).cancelled += c.cancelled; slot(ws).abandoned += c.abandoned; slot(ws).unknown += c.unknown; }
          for (const [workspaceId, counts] of Object.entries(per)) {
            store.writeAudit({ workspaceId, keyId: null, action: "policy.shutdown", detail: { ...counts, grace_ms: graceMs, reason } });
          }
          const tot = Object.values(per).reduce((a, c) => ({ cancelled: a.cancelled + c.cancelled, abandoned: a.abandoned + c.abandoned, drained: a.drained + c.drained, unknown: a.unknown + c.unknown }), { cancelled: 0, abandoned: 0, drained: 0, unknown: 0 });
          console.error(`[mcp-flow] shutdown: ${JSON.stringify(tot)}`);
          // 5) let held callers receive their 'cancelled' answer before connections are closed
          // capped to what is left of the 10 s budget after reserving time for the upstream close
          const waitUntil = Date.now() + heldCallerWaitMs(Date.now() - shutdownStarted);
          while (store.policy.waiterCount() > 0 && Date.now() < waitUntil) await new Promise((r) => setTimeout(r, 25));
          const flush = Math.min(50, Math.max(0, waitUntil - Date.now()));
          if (flush > 0) await new Promise((r) => setTimeout(r, flush));
        } catch (err) {
          console.error(`[mcp-flow] shutdown drain failed: ${(err as Error).message}`);
        }
      }
      (nodeServer as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
      await running.close();
    })()),
  };
  return running;
}
