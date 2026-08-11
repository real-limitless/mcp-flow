import { Hono } from "hono";
import { cors } from "hono/cors";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { installFromGallery } from "../catalog/install.js";
import { readEntryFile } from "../catalog/shard.js";
import {
  defaultCatalogDir,
  filterLocalGallery,
  filterLocalIndex,
  loadLocalGallery,
  loadLocalIndex,
  searchRegistryLive,
  syncCatalog,
} from "../catalog/sync.js";
import type { McpGalleryEntry } from "../catalog/types.js";
import type { Config } from "../config.js";
import { safeEqualStr } from "../crypto.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import { createGatewayServer } from "../mcp/gateway.js";
import { UpstreamPool } from "../mcp/upstream.js";
import { assertSafeUrl, SsrfError } from "../ssrf.js";
import type {
  ApiKeyScopes,
  AuthContext,
  CreateBackendInput,
  UpdateBackendInput,
} from "../types.js";
import { DEFAULT_PLACEMENT } from "../types.js";

type Variables = {
  auth: AuthContext;
};

function bearer(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(.+)$/i.exec(header.trim());
  return m ? m[1]!.trim() : null;
}

function findEntryById(
  catalogDir: string,
  id: string,
): McpGalleryEntry | undefined {
  const fromFile = readEntryFile(catalogDir, id);
  if (fromFile) return fromFile;
  return loadLocalGallery(catalogDir).find((e) => e.id === id);
}

export function createApp(store: Store, cfg: Config, pool: UpstreamPool) {
  const app = new Hono<{ Variables: Variables }>();
  const catalogDir = defaultCatalogDir(process.cwd());

  app.use(
    "*",
    cors({
      origin: "*",
      allowMethods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
      allowHeaders: [
        "Content-Type",
        "Authorization",
        "mcp-session-id",
        "Last-Event-ID",
        "mcp-protocol-version",
      ],
      exposeHeaders: ["mcp-session-id", "mcp-protocol-version"],
    }),
  );

  app.get("/health", (c) =>
    c.json({ ok: true, service: "mcp-flow", version: "0.1.0" }),
  );

  const admin = new Hono<{ Variables: Variables }>();

  admin.use("*", async (c, next) => {
    const token = bearer(c.req.header("authorization"));
    if (!token || !safeEqualStr(token, cfg.adminToken)) {
      return c.json({ error: "unauthorized" }, 401);
    }
    const ws = store.ensureWorkspace(cfg.workspaceName);
    c.set("auth", { kind: "admin", workspaceId: ws.id });
    await next();
  });

  admin.get("/workspace", (c) => {
    const auth = c.get("auth");
    const ws = store.getWorkspace(auth.workspaceId);
    return c.json({ workspace: ws });
  });

  admin.post("/keys", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json().catch(() => ({}))) as {
      name?: string;
      scopes?: ApiKeyScopes | null;
      toolPrefixAllowlist?: string[];
    };
    const name = body.name?.trim() || "default";
    const scopes: ApiKeyScopes | null =
      body.scopes !== undefined
        ? body.scopes
        : body.toolPrefixAllowlist?.length
          ? { toolPrefixAllowlist: body.toolPrefixAllowlist }
          : null;
    const created = store.createApiKey(auth.workspaceId, name, scopes);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "key.create",
      detail: { keyId: created.id, name: created.name, scopes },
    });
    return c.json({ key: created }, 201);
  });

  admin.get("/keys", (c) => {
    const auth = c.get("auth");
    return c.json({ keys: store.listApiKeys(auth.workspaceId) });
  });

  admin.patch("/keys/:id", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as {
      scopes?: ApiKeyScopes | null;
      toolPrefixAllowlist?: string[] | null;
    };
    let scopes: ApiKeyScopes | null;
    if (body.scopes !== undefined) scopes = body.scopes;
    else if (body.toolPrefixAllowlist !== undefined) {
      scopes =
        body.toolPrefixAllowlist && body.toolPrefixAllowlist.length
          ? { toolPrefixAllowlist: body.toolPrefixAllowlist }
          : null;
    } else {
      return c.json({ error: "scopes or toolPrefixAllowlist required" }, 400);
    }
    const key = store.updateApiKeyScopes(
      auth.workspaceId,
      c.req.param("id"),
      scopes,
    );
    if (!key) return c.json({ error: "not found" }, 404);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "key.update",
      detail: { keyId: key.id, scopes },
    });
    return c.json({ key });
  });

  admin.delete("/keys/:id", (c) => {
    const auth = c.get("auth");
    const ok = store.revokeApiKey(auth.workspaceId, c.req.param("id"));
    if (!ok) return c.json({ error: "not found" }, 404);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "key.revoke",
      detail: { keyId: c.req.param("id") },
    });
    return c.json({ ok: true });
  });

  admin.get("/backends", (c) => {
    const auth = c.get("auth");
    return c.json({ backends: store.listBackends(auth.workspaceId) });
  });

  admin.get("/backends/:id", (c) => {
    const auth = c.get("auth");
    const b = store.getBackendPublic(auth.workspaceId, c.req.param("id"));
    if (!b) return c.json({ error: "not found" }, 404);
    return c.json({ backend: b });
  });

  admin.post("/backends", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as CreateBackendInput;
    if (!body.slug) return c.json({ error: "slug required" }, 400);

    const transport = body.transport ?? "streamable-http";
    if (
      (transport === "streamable-http" || transport === "sse") &&
      body.url
    ) {
      try {
        await assertSafeUrl(body.url, cfg.allowPrivateUrls);
      } catch (err) {
        const msg = err instanceof SsrfError ? err.message : "invalid url";
        return c.json({ error: msg }, 400);
      }
    }

    const placement = body.placement ?? { ...DEFAULT_PLACEMENT };
    if (placement.mode !== "remote") {
      return c.json(
        {
          error: `placement.mode=${placement.mode} not implemented; use remote`,
        },
        400,
      );
    }

    try {
      const backend = store.createBackend(auth.workspaceId, {
        ...body,
        transport,
        placement,
      });
      store.writeAudit({
        workspaceId: auth.workspaceId,
        action: "backend.create",
        backendSlug: backend.slug,
        placement: backend.placement.mode,
      });
      return c.json({ backend }, 201);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        400,
      );
    }
  });

  admin.patch("/backends/:id", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as UpdateBackendInput;

    if (body.url) {
      try {
        await assertSafeUrl(body.url, cfg.allowPrivateUrls);
      } catch (err) {
        const msg = err instanceof SsrfError ? err.message : "invalid url";
        return c.json({ error: msg }, 400);
      }
    }
    if (body.placement && body.placement.mode !== "remote") {
      return c.json(
        {
          error: `placement.mode=${body.placement.mode} not implemented; use remote`,
        },
        400,
      );
    }

    const backend = store.updateBackend(
      auth.workspaceId,
      c.req.param("id"),
      body,
    );
    if (!backend) return c.json({ error: "not found" }, 404);
    pool.invalidate(store.getBackend(auth.workspaceId, backend.id)?.id);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "backend.update",
      backendSlug: backend.slug,
      placement: backend.placement.mode,
    });
    return c.json({ backend });
  });

  admin.delete("/backends/:id", (c) => {
    const auth = c.get("auth");
    const existing = store.getBackend(auth.workspaceId, c.req.param("id"));
    const ok = store.deleteBackend(auth.workspaceId, c.req.param("id"));
    if (!ok) return c.json({ error: "not found" }, 404);
    if (existing) pool.invalidate(existing.id);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "backend.delete",
      backendSlug: existing?.slug,
    });
    return c.json({ ok: true });
  });

  admin.post("/backends/:id/test", async (c) => {
    const auth = c.get("auth");
    const backend = store.getBackend(auth.workspaceId, c.req.param("id"));
    if (!backend) return c.json({ error: "not found" }, 404);
    const result = await pool.testBackend(backend);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "backend.test",
      backendSlug: backend.slug,
      detail: { ok: result.ok, toolCount: result.toolCount },
    });
    return c.json(result, result.ok ? 200 : 502);
  });

  // --- Catalog (P1b) ---
  admin.get("/catalog/search", async (c) => {
    const q = c.req.query("q")?.trim() ?? "";
    const live = c.req.query("live") !== "0";
    let entries: McpGalleryEntry[] = [];
    let source: "live" | "local" | "local-index" = "local";
    try {
      if (live && q) {
        entries = await searchRegistryLive(q, { limit: 25 });
        source = "live";
      } else {
        const index = loadLocalIndex(catalogDir);
        if (index.length) {
          const rows = filterLocalIndex(index, q || "");
          // return index-shaped objects (full description in summary fields)
          entries = rows.map((r) => ({
            id: r.id,
            title: r.title,
            description: r.summary,
            summary: r.summary,
            transport: r.transport,
            flags: r.flags,
            version: r.version,
            status: r.status,
            endpointUrl: r.endpointUrl,
            provenance: "official-registry" as const,
          }));
          source = "local-index";
        } else {
          entries = filterLocalGallery(loadLocalGallery(catalogDir), q || "");
          source = "local";
        }
      }
    } catch (err) {
      const index = loadLocalIndex(catalogDir);
      if (index.length) {
        entries = filterLocalIndex(index, q).map((r) => ({
          id: r.id,
          title: r.title,
          description: r.summary,
          summary: r.summary,
          transport: r.transport,
          flags: r.flags,
          version: r.version,
          status: r.status,
          endpointUrl: r.endpointUrl,
          provenance: "official-registry" as const,
        }));
        source = "local-index";
      } else {
        entries = filterLocalGallery(loadLocalGallery(catalogDir), q);
        source = "local";
      }
      return c.json({
        entries,
        source,
        warning: err instanceof Error ? err.message : String(err),
      });
    }
    return c.json({ entries, source });
  });

  admin.get("/catalog/entries/:id", async (c) => {
    const id = decodeURIComponent(c.req.param("id"));
    let entry = findEntryById(catalogDir, id);
    if (!entry) {
      try {
        const live = await searchRegistryLive(id, { limit: 10 });
        entry = live.find((e) => e.id === id) ?? live[0];
      } catch {
        /* ignore */
      }
    }
    if (!entry) return c.json({ error: "not found" }, 404);
    return c.json({ entry });
  });

  admin.post("/catalog/sync", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json().catch(() => ({}))) as {
      maxPages?: number;
    };
    try {
      const result = await syncCatalog({
        catalogDir,
        maxPages: body.maxPages ?? 5,
        latestOnly: true,
      });
      store.writeAudit({
        workspaceId: auth.workspaceId,
        action: "catalog.sync",
        detail: { total: result.meta.counts.total },
      });
      return c.json({ meta: result.meta });
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        502,
      );
    }
  });

  admin.post("/catalog/install", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as {
      id?: string;
      slug?: string;
      enable?: boolean;
      headers?: Record<string, string>;
      entry?: McpGalleryEntry;
    };

    let entry = body.entry;
    if (!entry && body.id) {
      entry = findEntryById(catalogDir, body.id);
      if (!entry) {
        try {
          const live = await searchRegistryLive(body.id, { limit: 15 });
          entry =
            live.find((e) => e.id === body.id) ??
            (live.length === 1 ? live[0] : undefined);
        } catch {
          /* ignore */
        }
      }
    }
    if (!entry) return c.json({ error: "gallery entry required (id or entry)" }, 400);

    try {
      const result = await installFromGallery(store, auth.workspaceId, {
        entry,
        slug: body.slug,
        enable: body.enable,
        headers: body.headers,
        allowPrivateUrls: cfg.allowPrivateUrls,
      });
      store.writeAudit({
        workspaceId: auth.workspaceId,
        action: "catalog.install",
        backendSlug: result.backend.slug,
        detail: { galleryId: entry.id, warnings: result.warnings },
      });
      return c.json(result, 201);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        400,
      );
    }
  });

  admin.get("/audit", (c) => {
    const auth = c.get("auth");
    const limit = Number(c.req.query("limit") ?? "50");
    const before = c.req.query("before") ?? undefined;
    const events = store.listAudit(auth.workspaceId, { limit, before });
    return c.json({ events });
  });

  app.route("/v1", admin);

  // MCP Streamable HTTP — agent API keys only
  app.all("/mcp", async (c) => {
    const token = bearer(c.req.header("authorization"));
    if (!token) {
      return c.json({ error: "missing bearer token" }, 401);
    }
    const key = store.authenticateApiKey(token);
    if (!key) {
      return c.json({ error: "invalid api key" }, 401);
    }

    const auth: AuthContext = {
      kind: "api_key",
      workspaceId: key.workspaceId,
      keyId: key.keyId,
      keyName: key.keyName,
      scopes: key.scopes,
    };

    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    const server = createGatewayServer(store, pool, auth);
    await server.connect(transport);
    const response = await transport.handleRequest(c.req.raw);

    const cleanup = () => {
      void transport.close().catch(() => undefined);
      void server.close().catch(() => undefined);
    };

    if (!response.body) {
      cleanup();
      return response;
    }

    const reader = response.body.getReader();
    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          if (done) {
            controller.close();
            cleanup();
            return;
          }
          controller.enqueue(value);
        } catch (err) {
          cleanup();
          controller.error(err);
        }
      },
      cancel() {
        void reader.cancel().catch(() => undefined);
        cleanup();
      },
    });

    return new Response(stream, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  });

  app.notFound((c) => c.json({ error: "not found" }, 404));

  return app;
}

export type AppType = ReturnType<typeof createApp>;

export { toPublicBackend };
