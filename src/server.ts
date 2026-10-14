import type { Duplex } from "node:stream";
import { createAdaptorServer } from "@hono/node-server";
import type { WebSocket } from "ws";
import { WebSocketServer } from "ws";
import { createApp } from "./api/app.js";
import type { Config } from "./config.js";
import { requireSecrets } from "./config.js";
import { Store } from "./db/store.js";
import { EdgeHub } from "./edge/hub.js";
import { encodeMsg, newMsgId } from "./edge/protocol.js";
import { EdgeRouter } from "./edge/router.js";
import { STDIO_GROUP_KILL_BUDGET_MS } from "./mcp/runners/stdio.js";
import { INFLIGHT_CLOSE_DEADLINE_MS, UpstreamPool } from "./mcp/upstream.js";

/** Stop accepting and let in-flight requests finish, then close upstreams. */
export const SHUTDOWN_BUDGET_MS = 10_000;
export const SHUTDOWN_DRAIN_MS = Math.min(
  8_000,
  SHUTDOWN_BUDGET_MS -
    STDIO_GROUP_KILL_BUDGET_MS -
    INFLIGHT_CLOSE_DEADLINE_MS,
);

export interface RunningServer {
  store: Store;
  pool: UpstreamPool;
  edgeHub: EdgeHub;
  edgeRouter: EdgeRouter;
  close: () => Promise<void>;
  url: string;
}

export async function startServer(cfg: Config): Promise<RunningServer> {
  requireSecrets(cfg);
  const store = new Store(cfg.dbPath, cfg.masterKeyRaw, { policyDevKeyRaw: cfg.policyDevKeyRaw });
  store.ensureWorkspace(cfg.workspaceName);
  const pool = new UpstreamPool(store);
  const edgeHub = new EdgeHub(store);
  const edgeRouter = new EdgeRouter(store, edgeHub);
  pool.setEdgeRouter(edgeRouter);

  const app = createApp(store, cfg, pool, { edgeHub, edgeRouter });

  const nodeServer = createAdaptorServer({
    fetch: app.fetch,
    hostname: cfg.host,
    port: cfg.port,
  });

  const wss = new WebSocketServer({ noServer: true });

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

  let closed = false;
  return {
    store,
    pool,
    edgeHub,
    edgeRouter,
    url,
    close: async () => {
      if (closed) return;
      closed = true;
      const started = Date.now();
      const left = () =>
        Math.max(0, SHUTDOWN_BUDGET_MS - (Date.now() - started));
      const wait = (ms: number) =>
        new Promise<void>((resolve) => setTimeout(resolve, ms));

      edgeHub.closeAll();
      const edgeClosed = new Promise<void>((resolve) => wss.close(() => resolve()));
      // Stop accepting. Drain in-flight HTTP for up to 8s, inside the 10s budget.
      let drained = false;
      const drain = new Promise<void>((resolve) => {
        nodeServer.close(() => {
          drained = true;
          resolve();
        });
      });
      const drainBudget = Math.min(SHUTDOWN_DRAIN_MS, left());
      await Promise.race([drain, wait(drainBudget)]);
      await edgeClosed;

      // Process-group kill is bounded below the time left after the drain.
      await pool.closeAll();
      store.close();
      if (!drained) await Promise.race([drain, wait(left())]);
    },
  };
}
