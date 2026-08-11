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
  .option(
    "--scope-prefix <prefix>",
    "tool name prefix allowlist (repeatable), e.g. yh-finance__",
    (v: string, acc: string[]) => {
      acc.push(v);
      return acc;
    },
    [] as string[],
  )
  .option("--db <path>", "sqlite path")
  .action((opts: { name: string; scopePrefix: string[]; db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      const scopes = opts.scopePrefix.length
        ? { toolPrefixAllowlist: opts.scopePrefix }
        : null;
      const created = store.createApiKey(workspaceId, opts.name, scopes);
      store.writeAudit({
        workspaceId,
        action: "key.create",
        detail: { keyId: created.id, scopes },
      });
      console.log(JSON.stringify({ key: created }, null, 2));
    } finally {
      store.close();
    }
  });

keyCmd
  .command("scopes")
  .description("Set tool prefix scopes on a key (empty clears)")
  .argument("<id>", "key id")
  .option(
    "--scope-prefix <prefix>",
    "tool name prefix (repeatable)",
    (v: string, acc: string[]) => {
      acc.push(v);
      return acc;
    },
    [] as string[],
  )
  .option("--clear", "remove all scopes (full access)", false)
  .option("--db <path>", "sqlite path")
  .action(
    (
      id: string,
      opts: { scopePrefix: string[]; clear?: boolean; db?: string },
    ) => {
      const { store, workspaceId } = openStore(opts.db);
      try {
        const scopes = opts.clear
          ? null
          : opts.scopePrefix.length
            ? { toolPrefixAllowlist: opts.scopePrefix }
            : null;
        if (!opts.clear && !opts.scopePrefix.length) {
          console.error("pass --scope-prefix and/or --clear");
          process.exit(1);
        }
        const key = store.updateApiKeyScopes(workspaceId, id, scopes);
        if (!key) {
          console.error("not found");
          process.exit(1);
        }
        store.writeAudit({
          workspaceId,
          action: "key.update",
          detail: { keyId: id, scopes },
        });
        console.log(JSON.stringify({ key }, null, 2));
      } finally {
        store.close();
      }
    },
  );

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

const catalogCmd = program
  .command("catalog")
  .description("Official registry gallery (P1b)");

catalogCmd
  .command("sync")
  .description("Pull registry → catalog/entries/*.json + index.json")
  .option("--max-pages <n>", "page cap (default 5; 0 = all)", "5")
  .option("--dir <path>", "catalog directory")
  .action(async (opts: { maxPages?: string; dir?: string }) => {
    const { defaultCatalogDir, syncCatalog } = await import(
      "./catalog/sync.js"
    );
    const catalogDir = opts.dir ?? defaultCatalogDir();
    const maxPages = Number(opts.maxPages ?? "5");
    const result = await syncCatalog({
      catalogDir,
      maxPages: maxPages === 0 ? 0 : maxPages,
      latestOnly: true,
    });
    console.log(
      JSON.stringify(
        {
          meta: result.meta,
          storage: result.storage,
          indexPath: result.indexPath,
          entriesDir: result.galleryPath,
        },
        null,
        2,
      ),
    );
  });

catalogCmd
  .command("show")
  .description("Show one full gallery entry (sharded file or local)")
  .argument("[id]", "gallery id (registry server.name)")
  .option("--dir <path>", "catalog directory")
  .option("--pretty", "human-readable dossier (readme + tools)", false)
  .option("--enrich", "run enrich pipeline before show", false)
  .action(
    async (
      id: string | undefined,
      opts: { dir?: string; pretty?: boolean; enrich?: boolean },
    ) => {
      const { defaultCatalogDir, loadLocalIndex } = await import(
        "./catalog/sync.js"
      );
      const { readEntryFile, loadAllEntries } = await import(
        "./catalog/shard.js"
      );
      const catalogDir = opts.dir ?? defaultCatalogDir();

      if (!id?.trim()) {
        const samples = loadLocalIndex(catalogDir)
          .slice(0, 5)
          .map((e) => e.id);
        console.error("Usage: mcp-flow catalog show <id> [--pretty] [--enrich]");
        console.error("");
        console.error("  id = registry server.name (stable allowlist key)");
        console.error("");
        console.error("Examples:");
        console.error(
          '  npx mcp-flow catalog show "ai.agentlookups/overassessed" --pretty',
        );
        console.error(
          '  npx mcp-flow catalog enrich "ai.agentlookups/overassessed"',
        );
        console.error("  npx mcp-flow catalog search github   # find ids");
        if (samples.length) {
          console.error("");
          console.error("Sample ids from local index:");
          for (const s of samples) console.error(`  ${s}`);
        }
        process.exit(1);
      }

      if (opts.enrich) {
        const { runEnrich } = await import("./catalog/enrich/run-enrich.js");
        await runEnrich({
          id,
          opts: { catalogDir, enrichReadme: true, enrichTools: true },
        });
      }

      const entry =
        readEntryFile(catalogDir, id) ??
        loadAllEntries(catalogDir).find((e) => e.id === id);
      if (!entry) {
        console.error(`not found: ${id}`);
        console.error('Tip: npx mcp-flow catalog search "<keywords>"');
        console.error('Or:  npx mcp-flow catalog enrich "<id>"');
        process.exit(1);
      }
      if (opts.pretty) {
        const { formatEntryPretty } = await import(
          "./catalog/enrich/run-enrich.js"
        );
        console.log(formatEntryPretty(entry));
        return;
      }
      console.log(JSON.stringify({ entry }, null, 2));
    },
  );

catalogCmd
  .command("enrich")
  .description("Normalize + fetch README + probe tools/list for one server")
  .argument("<id>", "gallery id")
  .option("--dir <path>", "catalog directory")
  .option("--no-readme", "skip README stage")
  .option("--no-tools", "skip tools/list stage")
  .option("--pretty", "print dossier after", false)
  .action(
    async (
      id: string,
      opts: {
        dir?: string;
        readme?: boolean;
        tools?: boolean;
        pretty?: boolean;
      },
    ) => {
      const { defaultCatalogDir } = await import("./catalog/sync.js");
      const { runEnrich, formatEntryPretty } = await import(
        "./catalog/enrich/run-enrich.js"
      );
      const catalogDir = opts.dir ?? defaultCatalogDir();
      const result = await runEnrich({
        id,
        opts: {
          catalogDir,
          enrichReadme: opts.readme !== false,
          enrichTools: opts.tools !== false,
          log: (m) => console.error(m),
        },
      });
      if (opts.pretty) {
        console.log(formatEntryPretty(result.entry));
      } else {
        console.log(
          JSON.stringify(
            {
              entry: result.entry,
              stages: result.stages,
              errors: result.errors,
            },
            null,
            2,
          ),
        );
      }
    },
  );

catalogCmd
  .command("search")
  .description("Search live registry or local gallery")
  .argument("<query>", "search string")
  .option("--local", "local gallery only", false)
  .option("--dir <path>", "catalog directory")
  .action(async (query: string, opts: { local?: boolean; dir?: string }) => {
    const {
      defaultCatalogDir,
      filterLocalGallery,
      loadLocalGallery,
      searchRegistryLive,
    } = await import("./catalog/sync.js");
    const catalogDir = opts.dir ?? defaultCatalogDir();
    if (opts.local) {
      const entries = filterLocalGallery(loadLocalGallery(catalogDir), query);
      console.log(JSON.stringify({ entries, source: "local" }, null, 2));
      return;
    }
    try {
      const entries = await searchRegistryLive(query, { limit: 25 });
      console.log(JSON.stringify({ entries, source: "live" }, null, 2));
    } catch (err) {
      const entries = filterLocalGallery(loadLocalGallery(catalogDir), query);
      console.log(
        JSON.stringify(
          {
            entries,
            source: "local",
            warning: err instanceof Error ? err.message : String(err),
          },
          null,
          2,
        ),
      );
    }
  });

catalogCmd
  .command("install")
  .description("Create remote backend from gallery id")
  .argument("<id>", "gallery id (registry server.name)")
  .option("--slug <slug>", "backend slug override")
  .option("--enable", "enable immediately", false)
  .option(
    "--header <name=value>",
    "sealed header (repeatable)",
    (v: string, acc: string[]) => {
      acc.push(v);
      return acc;
    },
    [] as string[],
  )
  .option("--dir <path>", "catalog directory")
  .option("--db <path>", "sqlite path")
  .action(
    async (
      id: string,
      opts: {
        slug?: string;
        enable?: boolean;
        header: string[];
        dir?: string;
        db?: string;
      },
    ) => {
      const { installFromGallery } = await import("./catalog/install.js");
      const {
        defaultCatalogDir,
        loadLocalGallery,
        searchRegistryLive,
      } = await import("./catalog/sync.js");
      const { parseHeaderFlags } = await import("./headers.js");
      const cfg = loadConfig({ dbPath: opts.db });
      requireSecrets(cfg);
      const catalogDir = opts.dir ?? defaultCatalogDir();
      const { readEntryFile } = await import("./catalog/shard.js");
      let entry =
        readEntryFile(catalogDir, id) ??
        loadLocalGallery(catalogDir).find((e) => e.id === id);
      if (!entry) {
        const live = await searchRegistryLive(id, { limit: 15 });
        entry = live.find((e) => e.id === id) ?? live[0];
      }
      if (!entry) {
        console.error("gallery entry not found");
        process.exit(1);
      }
      const headers = opts.header.length
        ? parseHeaderFlags(opts.header)
        : undefined;
      const store = new Store(cfg.dbPath, cfg.masterKeyRaw);
      try {
        const ws = store.ensureWorkspace(cfg.workspaceName);
        const result = await installFromGallery(store, ws.id, {
          entry,
          slug: opts.slug,
          enable: Boolean(opts.enable),
          headers,
          allowPrivateUrls: cfg.allowPrivateUrls,
        });
        store.writeAudit({
          workspaceId: ws.id,
          action: "catalog.install",
          backendSlug: result.backend.slug,
          detail: { galleryId: entry.id },
        });
        console.log(JSON.stringify(result, null, 2));
      } finally {
        store.close();
      }
    },
  );

program
  .command("audit")
  .description("List recent audit events")
  .option("--limit <n>", "max events", "50")
  .option("--db <path>", "sqlite path")
  .action((opts: { limit?: string; db?: string }) => {
    const { store, workspaceId } = openStore(opts.db);
    try {
      const events = store.listAudit(workspaceId, {
        limit: Number(opts.limit ?? "50"),
      });
      console.log(JSON.stringify({ events }, null, 2));
    } finally {
      store.close();
    }
  });

program
  .command("factory")
  .description("Catalog factory TUI (registry scrape + queue + proxies)")
  .option("--scrape", "headless scrape instead of TUI", false)
  .option("--worker", "run queue worker instead of TUI", false)
  .option("--enqueue", "with --scrape: enqueue jobs", false)
  .option("--max-pages <n>", "scrape page cap")
  .option("--use-proxy", "use proxy for scrape", false)
  .option("--proxy <url>", "fixed proxy URL")
  .action(
    async (opts: {
      scrape?: boolean;
      worker?: boolean;
      enqueue?: boolean;
      maxPages?: string;
      useProxy?: boolean;
      proxy?: string;
    }) => {
      if (opts.worker) {
        const { spawn } = await import("node:child_process");
        const child = spawn(
          "npx",
          ["tsx", "scripts/factory/queue-worker.ts"],
          { stdio: "inherit", cwd: process.cwd() },
        );
        await new Promise<void>((resolve, reject) => {
          child.on("exit", (code) =>
            code === 0 ? resolve() : reject(new Error(`worker exit ${code}`)),
          );
        });
        return;
      }
      if (opts.scrape) {
        const args = ["tsx", "scripts/factory/scrape-registry.ts"];
        if (opts.enqueue) args.push("--enqueue");
        if (opts.maxPages) args.push("--max-pages", opts.maxPages);
        if (opts.useProxy) args.push("--use-proxy");
        if (opts.proxy) args.push("--proxy", opts.proxy);
        const { spawn } = await import("node:child_process");
        const child = spawn("npx", args, {
          stdio: "inherit",
          cwd: process.cwd(),
        });
        await new Promise<void>((resolve, reject) => {
          child.on("exit", (code) =>
            code === 0 ? resolve() : reject(new Error(`scrape exit ${code}`)),
          );
        });
        return;
      }
      const { spawn } = await import("node:child_process");
      const child = spawn("npx", ["tsx", "scripts/factory/tui.ts"], {
        stdio: "inherit",
        cwd: process.cwd(),
      });
      await new Promise<void>((resolve, reject) => {
        child.on("exit", (code) =>
          code === 0 || code === null
            ? resolve()
            : reject(new Error(`factory tui exit ${code}`)),
        );
      });
    },
  );

program
  .command("doctor")
  .description("Check local config / db / listen readiness")
  .option("--db <path>", "sqlite path")
  .action((opts: { db?: string }) => {
    const cfg = loadConfig({ dbPath: opts.db });
    const report: Record<string, unknown> = {
      node: process.version,
      dbPath: cfg.dbPath,
      host: cfg.host,
      port: cfg.port,
      masterKey: Boolean(cfg.masterKeyRaw),
      adminToken: Boolean(cfg.adminToken),
      allowPrivateUrls: cfg.allowPrivateUrls,
    };
    try {
      if (cfg.masterKeyRaw) {
        const store = new Store(cfg.dbPath, cfg.masterKeyRaw);
        const ws = store.ensureWorkspace(cfg.workspaceName);
        report.workspace = ws.name;
        report.backends = store.listBackends(ws.id).length;
        report.keys = store.listApiKeys(ws.id).length;
        store.close();
        report.dbOk = true;
      } else {
        report.dbOk = false;
        report.error = "MCP_FLOW_MASTER_KEY missing";
      }
    } catch (err) {
      report.dbOk = false;
      report.error = err instanceof Error ? err.message : String(err);
    }
    console.log(JSON.stringify(report, null, 2));
    if (!report.dbOk) process.exit(1);
  });

program.parseAsync(process.argv).catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
