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
import { UpstreamPool } from "./mcp/upstream.js";

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
  const store = new Store(cfg.dbPath, cfg.masterKeyRaw);
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

  return {
    store,
    pool,
    edgeHub,
    edgeRouter,
    url,
    close: async () => {
      edgeHub.closeAll();
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      await pool.closeAll();
      store.close();
      await new Promise<void>((resolve, reject) => {
        nodeServer.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
