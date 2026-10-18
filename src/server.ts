import type { Duplex } from "node:stream";
import { createPendingCallNotifier } from "./policy/push-notify.js";
import { createAdaptorServer } from "@hono/node-server";
import type { WebSocket } from "ws";
import { WebSocketServer } from "ws";
import { createApp } from "./api/app.js";
import type { Config } from "./config.js";
import { DEFAULT_SHUTDOWN_GRACE_MS, requireSecrets } from "./config.js";
import { Store } from "./db/store.js";
import { acquireGatewayLock } from "./db/gateway-lock.js";
import { EdgeHub } from "./edge/hub.js";
import { encodeMsg, newMsgId } from "./edge/protocol.js";
import { EdgeRouter } from "./edge/router.js";
import { STDIO_GROUP_KILL_BUDGET_MS } from "./mcp/runners/stdio.js";
import { INFLIGHT_CLOSE_DEADLINE_MS, UpstreamPool } from "./mcp/upstream.js";

/** Docker's 10 s stop timeout: drain + upstream close (connect deadline + process-group kill) fit inside. */
export const SHUTDOWN_BUDGET_MS = 10_000;
/** Default in-flight drain (MCP_FLOW_SHUTDOWN_GRACE_MS default); see config.ts for the clamp. */
export const SHUTDOWN_DRAIN_MS = Math.min(
  DEFAULT_SHUTDOWN_GRACE_MS,
  SHUTDOWN_BUDGET_MS - STDIO_GROUP_KILL_BUDGET_MS - INFLIGHT_CLOSE_DEADLINE_MS,
);

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
  /** Second signal during shutdown: record in-flight calls as unknown, close DB, release lock (sync). */
  forceStop: () => void;
  url: string;
}

/**
 * QA V5-F2: SIGTERM / SIGINT -> gw.shutdown() then exit(0) (exit(1) if shutdown failed).
 * A second signal while shutting down exits(1) immediately. Returns { handle, remove } (handle for tests).
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
      console.error(`[mcp-flow] ${sig} again during shutdown; exiting now (in-flight calls recorded as unknown)`);
      try {
        gw.forceStop();
      } catch (err) {
        console.error(`[mcp-flow] forced stop failed: ${(err as Error).message}`);
      }
      return exit(1);
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
    store = new Store(cfg.dbPath, cfg.masterKeyRaw, { policyDevKeyRaw: cfg.policyDevKeyRaw });
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
  const pool = new UpstreamPool(store);
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
          console.error(`[mcp-flow] draining ${store.policy.inflightCount()} in-flight call(s), grace ${graceMs} ms`);
          const drain = await store.policy.drain(graceMs);
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
          for (let i = 0; i < 40 && store.policy.waiterCount() > 0; i++) await new Promise((r) => setTimeout(r, 25));
          await new Promise((r) => setTimeout(r, 50));
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
