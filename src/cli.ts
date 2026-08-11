#!/usr/bin/env node
import { Command } from "commander";
import { loadConfig, requireSecrets } from "./config.js";
import { Store } from "./db/store.js";
import { UpstreamPool } from "./mcp/upstream.js";
import { startServer } from "./server.js";
import { runStdioBridge } from "./stdio-bridge.js";
import { parseHeaderFlags } from "./headers.js";
import { assertSafeUrl } from "./ssrf.js";
import { DEFAULT_PLACEMENT } from "./types.js";

const program = new Command();

program
  .name("mcp-flow")
  .description("Self-hosted MCP workspace gateway")
  .version("0.1.0");

program
  .command("serve")
  .description("Run HTTP API + /mcp gateway")
  .option("-p, --port <port>", "listen port")
  .option("-H, --host <host>", "listen host")
  .option("--db <path>", "sqlite path")
  .action(async (opts: { port?: string; host?: string; db?: string }) => {
    const cfg = loadConfig({
      port: opts.port ? Number(opts.port) : undefined,
      host: opts.host,
      dbPath: opts.db,
    });
    await startServer(cfg);
  });

program
  .command("stdio")
  .description("Stdio shim → remote mcp-flow /mcp")
  .option("--url <url>", "MCP endpoint URL", process.env.MCP_FLOW_URL)
  .option("--api-key <key>", "agent API key", process.env.MCP_FLOW_API_KEY)
  .action(async (opts: { url?: string; apiKey?: string }) => {
    const url = opts.url;
    const apiKey = opts.apiKey;
    if (!url || !apiKey) {
      console.error(
        "stdio requires --url (or MCP_FLOW_URL) and --api-key (or MCP_FLOW_API_KEY)",
      );
      process.exit(1);
    }
    await runStdioBridge({ url, apiKey });
  });

program
  .command("tui")
  .description("Interactive TUI to manage upstream MCPs and API keys")
  .option("--db <path>", "sqlite path")
  .action(async (opts: { db?: string }) => {
    const cfg = loadConfig({ dbPath: opts.db });
    if (!cfg.masterKeyRaw) {
      console.error("MCP_FLOW_MASTER_KEY is required");
      process.exit(1);
    }
    const { runTui } = await import("./tui/app.js");
    await runTui(cfg);
  });

function openStore(db?: string): { store: Store; workspaceId: string } {
  const cfg = loadConfig({ dbPath: db });
  if (!cfg.masterKeyRaw) {
    throw new Error("MCP_FLOW_MASTER_KEY is required");
  }
  const store = new Store(cfg.dbPath, cfg.masterKeyRaw);
  const ws = store.ensureWorkspace(cfg.workspaceName);
  return { store, workspaceId: ws.id };
}

const keyCmd = program.command("key").description("Manage agent API keys");

keyCmd
  .command("create")
  .description("Mint an agent API key (secret shown once)")
  .requiredOption("-n, --name <name>", "key name")
  .option("--db <path>", "sqlite path")
  .action((opts: { name: string; db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      const created = store.createApiKey(workspaceId, opts.name);
      console.log(JSON.stringify({ key: created }, null, 2));
    } finally {
      store.close();
    }
  });

keyCmd
  .command("list")
  .description("List API keys (no secrets)")
  .option("--db <path>", "sqlite path")
  .action((opts: { db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      console.log(JSON.stringify({ keys: store.listApiKeys(workspaceId) }, null, 2));
    } finally {
      store.close();
    }
  });

keyCmd
  .command("revoke")
  .description("Revoke an API key by id")
  .argument("<id>", "key id")
  .option("--db <path>", "sqlite path")
  .action((id: string, opts: { db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      const ok = store.revokeApiKey(workspaceId, id);
      if (!ok) {
        console.error("not found or already revoked");
        process.exit(1);
      }
      console.log(JSON.stringify({ ok: true }));
    } finally {
      store.close();
    }
  });

const backendCmd = program
  .command("backend")
  .description("Manage upstream MCP backends");

backendCmd
  .command("add")
  .description("Add a remote MCP backend")
  .requiredOption("--slug <slug>", "stable slug (namespaced as slug__tool)")
  .option("--title <title>", "display title")
  .option("--url <url>", "remote MCP URL")
  .option(
    "--transport <kind>",
    "streamable-http | sse",
    "streamable-http",
  )
  .option(
    "--header <name=value>",
    "HTTP header (repeatable). Name=value or Name: value — sealed at rest",
    (v: string, acc: string[]) => {
      acc.push(v);
      return acc;
    },
    [] as string[],
  )
  .option("--enable", "enable immediately", false)
  .option("--db <path>", "sqlite path")
  .action(
    async (opts: {
      slug: string;
      title?: string;
      url?: string;
      transport: string;
      header: string[];
      enable?: boolean;
      db?: string;
    }) => {
      const cfg = loadConfig({ dbPath: opts.db });
      requireSecrets(cfg);
      if (opts.url) {
        await assertSafeUrl(opts.url, cfg.allowPrivateUrls);
      }
      let headers: Record<string, string> = {};
      try {
        headers = parseHeaderFlags(opts.header);
      } catch (err) {
        console.error(err instanceof Error ? err.message : err);
        process.exit(1);
      }
      const store = new Store(cfg.dbPath, cfg.masterKeyRaw);
      try {
        const ws = store.ensureWorkspace(cfg.workspaceName);
        const backend = store.createBackend(ws.id, {
          slug: opts.slug,
          title: opts.title,
          url: opts.url,
          transport: opts.transport as "streamable-http" | "sse",
          headers: Object.keys(headers).length ? headers : undefined,
          enabled: Boolean(opts.enable),
          placement: { ...DEFAULT_PLACEMENT },
        });
        console.log(JSON.stringify({ backend }, null, 2));
      } finally {
        store.close();
      }
    },
  );

backendCmd
  .command("headers")
  .description("Merge or replace sealed upstream HTTP headers")
  .argument("<idOrSlug>", "backend id or slug")
  .option(
    "--header <name=value>",
    "header to set (repeatable; Name=value or Name: value)",
    (v: string, acc: string[]) => {
      acc.push(v);
      return acc;
    },
    [] as string[],
  )
  .option("--replace", "replace all headers instead of merge", false)
  .option("--clear", "remove all sealed headers", false)
  .option("--db <path>", "sqlite path")
  .action(
    (
      idOrSlug: string,
      opts: { header: string[]; replace?: boolean; clear?: boolean; db?: string },
    ) => {
      const { store, workspaceId } = openStore(opts.db);
      try {
        if (opts.clear) {
          const backend = store.updateBackend(workspaceId, idOrSlug, {
            headers: null,
          });
          if (!backend) {
            console.error("not found");
            process.exit(1);
          }
          console.log(JSON.stringify({ backend }, null, 2));
          return;
        }
        if (!opts.header.length) {
          const names = store.listBackendHeaderNames(workspaceId, idOrSlug);
          if (!names) {
            console.error("not found");
            process.exit(1);
          }
          console.log(
            JSON.stringify(
              { headerNames: names, note: "values are sealed and never listed" },
              null,
              2,
            ),
          );
          return;
        }
        let partial: Record<string, string>;
        try {
          partial = parseHeaderFlags(opts.header);
        } catch (err) {
          console.error(err instanceof Error ? err.message : err);
          process.exit(1);
        }
        const backend = opts.replace
          ? store.updateBackend(workspaceId, idOrSlug, { headers: partial })
          : store.mergeBackendHeaders(workspaceId, idOrSlug, partial);
        if (!backend) {
          console.error("not found");
          process.exit(1);
        }
        console.log(JSON.stringify({ backend }, null, 2));
      } finally {
        store.close();
      }
    },
  );

backendCmd
  .command("list")
  .description("List backends (secrets redacted)")
  .option("--db <path>", "sqlite path")
  .action((opts: { db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      console.log(
        JSON.stringify({ backends: store.listBackends(workspaceId) }, null, 2),
      );
    } finally {
      store.close();
    }
  });

backendCmd
  .command("enable")
  .description("Enable a backend")
  .argument("<idOrSlug>", "backend id or slug")
  .option("--db <path>", "sqlite path")
  .action((idOrSlug: string, opts: { db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      const backend = store.updateBackend(workspaceId, idOrSlug, {
        enabled: true,
      });
      if (!backend) {
        console.error("not found");
        process.exit(1);
      }
      console.log(JSON.stringify({ backend }, null, 2));
    } finally {
      store.close();
    }
  });

backendCmd
  .command("disable")
  .description("Disable a backend")
  .argument("<idOrSlug>", "backend id or slug")
  .option("--db <path>", "sqlite path")
  .action((idOrSlug: string, opts: { db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      const backend = store.updateBackend(workspaceId, idOrSlug, {
        enabled: false,
      });
      if (!backend) {
        console.error("not found");
        process.exit(1);
      }
      console.log(JSON.stringify({ backend }, null, 2));
    } finally {
      store.close();
    }
  });

backendCmd
  .command("test")
  .description("Connectivity + tools/list smoke test")
  .argument("<idOrSlug>", "backend id or slug")
  .option("--db <path>", "sqlite path")
  .action(async (idOrSlug: string, opts: { db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    const pool = new UpstreamPool(store);
    try {
      const backend = store.getBackend(workspaceId, idOrSlug);
      if (!backend) {
        console.error("not found");
        process.exit(1);
      }
      const result = await pool.testBackend(backend);
      console.log(JSON.stringify(result, null, 2));
      if (!result.ok) process.exit(2);
    } finally {
      await pool.closeAll();
      store.close();
    }
  });

backendCmd
  .command("rm")
  .description("Delete a backend")
  .argument("<idOrSlug>", "backend id or slug")
  .option("--db <path>", "sqlite path")
  .action((idOrSlug: string, opts: { db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      const ok = store.deleteBackend(workspaceId, idOrSlug);
      if (!ok) {
        console.error("not found");
        process.exit(1);
      }
      console.log(JSON.stringify({ ok: true }));
    } finally {
      store.close();
    }
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
