import { serve } from "@hono/node-server";
import type { Config } from "./config.js";
import { requireSecrets } from "./config.js";
import { Store } from "./db/store.js";
import { createApp } from "./api/app.js";
import { UpstreamPool } from "./mcp/upstream.js";

export interface RunningServer {
  store: Store;
  pool: UpstreamPool;
  close: () => Promise<void>;
  url: string;
}

export async function startServer(cfg: Config): Promise<RunningServer> {
  requireSecrets(cfg);
  const store = new Store(cfg.dbPath, cfg.masterKeyRaw);
  store.ensureWorkspace(cfg.workspaceName);
  const pool = new UpstreamPool(store);
  const app = createApp(store, cfg, pool);

  const server = serve({
    fetch: app.fetch,
    hostname: cfg.host,
    port: cfg.port,
  });

  const url = `http://${cfg.host === "0.0.0.0" ? "127.0.0.1" : cfg.host}:${cfg.port}`;

  console.error(`mcp-flow listening on ${url}`);
  console.error(`  MCP:    ${url}/mcp`);
  console.error(`  Admin:  ${url}/v1/*  (Bearer admin token)`);
  console.error(`  Health: ${url}/health`);

  return {
    store,
    pool,
    url,
    close: async () => {
      await pool.closeAll();
      store.close();
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    },
  };
}
