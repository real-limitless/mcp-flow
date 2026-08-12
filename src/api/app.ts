import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
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
import type { EdgeHub } from "../edge/hub.js";
import type { EdgeRouter } from "../edge/router.js";
import { clientIp } from "../http/client-ip.js";
import { createGatewayServer } from "../mcp/gateway.js";
import { UpstreamPool } from "../mcp/upstream.js";
import {
  assertBackendShape,
  assertPlacementAllowed,
  PlacementError,
  supportedPlacementModes,
} from "../placement.js";
import { assertSafeUrl, SsrfError } from "../ssrf.js";
import type {
  ApiKeyScopes,
  AuthContext,
  CreateBackendInput,
  DeviceCapabilities,
  TransportKind,
  UpdateBackendInput,
  WorkspacePolicy,
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

function resolveAdminDir(): string | null {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "../admin"),
    join(here, "../../src/admin"),
    join(process.cwd(), "src/admin"),
    join(process.cwd(), "dist/admin"),
    join(process.cwd(), "admin"),
  ];
  for (const dir of candidates) {
    if (existsSync(join(dir, "index.html"))) return dir;
  }
  return null;
}

export function createApp(
  store: Store,
  cfg: Config,
  pool: UpstreamPool,
  edge?: { edgeHub?: EdgeHub | null; edgeRouter?: EdgeRouter | null },
) {
  const app = new Hono<{ Variables: Variables }>();
  const catalogDir = defaultCatalogDir(process.cwd());
  const edgeHub = edge?.edgeHub ?? null;
  const edgeRouter = edge?.edgeRouter ?? null;
  const edgeEnabled = Boolean(edgeHub);

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
    c.json({
      ok: true,
      service: "mcp-flow",
      version: "0.1.0",
      placementModes: supportedPlacementModes({ edgeEnabled }),
    }),
  );

  // Static admin UI (local branch / built package)
  const adminDir = resolveAdminDir();
  app.get("/admin", (c) => c.redirect("/admin/"));
  app.get("/admin/", (c) => {
    if (!adminDir) {
      return c.json(
        {
          error: "admin UI not found",
          hint: "Run from repo: npm run dev  (or npm run build && npm start). npx of an old publish has no /admin.",
        },
        404,
      );
    }
    try {
      const html = readFileSync(join(adminDir, "index.html"), "utf8");
      return c.html(html);
    } catch {
      return c.text("admin UI not found", 404);
    }
  });
  app.get("/admin/app.js", (c) => {
    if (!adminDir) return c.text("not found", 404);
    try {
      const js = readFileSync(join(adminDir, "app.js"), "utf8");
      return c.body(js, 200, {
        "Content-Type": "application/javascript; charset=utf-8",
      });
    } catch {
      return c.text("not found", 404);
    }
  });
  app.get("/admin/styles.css", (c) => {
    if (!adminDir) return c.text("not found", 404);
    try {
      const css = readFileSync(join(adminDir, "styles.css"), "utf8");
      return c.body(css, 200, {
        "Content-Type": "text/css; charset=utf-8",
      });
    } catch {
      return c.text("not found", 404);
    }
  });

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
    return c.json({
      workspace: ws,
      placementModes: supportedPlacementModes({ edgeEnabled }),
    });
  });

  admin.patch("/workspace/policy", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as WorkspacePolicy;
    const ws = store.updateWorkspacePolicy(auth.workspaceId, {
      allowEdgeBare: Boolean(body.allowEdgeBare),
    });
    if (!ws) return c.json({ error: "not found" }, 404);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "workspace.policy",
      detail: { policy: ws.policy },
      ip: clientIp(c),
    });
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
      ip: clientIp(c),
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
      ip: clientIp(c),
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
      ip: clientIp(c),
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

  function validateBackendWrite(
    workspaceId: string,
    transport: TransportKind,
    body: CreateBackendInput | UpdateBackendInput,
    placement = body.placement ?? { ...DEFAULT_PLACEMENT },
  ): string | null {
    try {
      const command =
        "command" in body
          ? body.command
          : undefined;
      const image = "image" in body ? body.image : undefined;
      const url = "url" in body ? body.url : undefined;
      assertBackendShape({
        transport,
        url: url as string | null | undefined,
        image: image as string | null | undefined,
        command: command as string[] | null | undefined,
      });
      const ws = store.getWorkspace(workspaceId);
      const deviceId = placement.deviceId;
      const device = deviceId
        ? store.getDevice(workspaceId, deviceId)
        : null;
      assertPlacementAllowed(placement, {
        transport,
        policy: ws?.policy,
        edgeEnabled,
        deviceExists: Boolean(device),
        deviceBare: Boolean(device?.capabilities.bare),
        deviceSandbox: Boolean(
          device && device.capabilities.sandbox !== "none",
        ),
      });
      return null;
    } catch (err) {
      return err instanceof PlacementError || err instanceof Error
        ? err.message
        : String(err);
    }
  }

  admin.post("/backends", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as CreateBackendInput;
    if (!body.slug) return c.json({ error: "slug required" }, 400);

    const transport = (body.transport ?? "streamable-http") as TransportKind;
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
    const verr = validateBackendWrite(
      auth.workspaceId,
      transport,
      body,
      placement,
    );
    if (verr) return c.json({ error: verr }, 400);

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
        deviceId: backend.placement.deviceId ?? null,
        ip: clientIp(c),
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
    const existing = store.getBackend(auth.workspaceId, c.req.param("id"));
    if (!existing) return c.json({ error: "not found" }, 404);

    if (body.url) {
      try {
        await assertSafeUrl(body.url, cfg.allowPrivateUrls);
      } catch (err) {
        const msg = err instanceof SsrfError ? err.message : "invalid url";
        return c.json({ error: msg }, 400);
      }
    }

    const transport = (body.transport ?? existing.transport) as TransportKind;
    const placement =
      body.placement ??
      (JSON.parse(existing.placementJson) as typeof DEFAULT_PLACEMENT);
    const merged: UpdateBackendInput = {
      ...body,
      url: body.url !== undefined ? body.url : existing.url,
      image: body.image !== undefined ? body.image : existing.image,
      command:
        body.command !== undefined
          ? body.command
          : existing.commandJson
            ? (JSON.parse(existing.commandJson) as string[])
            : null,
    };
    const verr = validateBackendWrite(
      auth.workspaceId,
      transport,
      merged,
      placement,
    );
    if (verr) return c.json({ error: verr }, 400);

    const backend = store.updateBackend(
      auth.workspaceId,
      c.req.param("id"),
      body,
    );
    if (!backend) return c.json({ error: "not found" }, 404);
    pool.invalidate(existing.id);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "backend.update",
      backendSlug: backend.slug,
      placement: backend.placement.mode,
      deviceId: backend.placement.deviceId ?? null,
      ip: clientIp(c),
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
      ip: clientIp(c),
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
      ip: clientIp(c),
    });
    return c.json(result, result.ok ? 200 : 502);
  });

  // Devices
  admin.get("/devices", (c) => {
    const auth = c.get("auth");
    const devices = store.listDevices(auth.workspaceId).map((d) => ({
      ...d,
      status: edgeHub?.isOnline(d.id) ? "online" : d.status,
    }));
    return c.json({ devices });
  });

  admin.post("/devices", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json().catch(() => ({}))) as {
      name?: string;
      tags?: string[];
      capabilities?: DeviceCapabilities;
    };
    const enrolled = store.enrollDevice(auth.workspaceId, {
      name: body.name?.trim() || "edge-device",
      tags: body.tags,
      capabilities: body.capabilities,
    });
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "device.enroll",
      deviceId: enrolled.id,
      detail: { name: enrolled.name },
      ip: clientIp(c),
    });
    return c.json({ device: enrolled }, 201);
  });

  admin.patch("/devices/:id", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as {
      name?: string;
      tags?: string[];
      capabilities?: DeviceCapabilities;
    };
    const device = store.updateDevice(auth.workspaceId, c.req.param("id"), body);
    if (!device) return c.json({ error: "not found" }, 404);
    return c.json({ device });
  });

  admin.delete("/devices/:id", (c) => {
    const auth = c.get("auth");
    const id = c.req.param("id");
    const ok = store.revokeDevice(auth.workspaceId, id);
    if (!ok) return c.json({ error: "not found" }, 404);
    if (edgeHub?.isOnline(id)) edgeHub.detach(id);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      action: "device.revoke",
      deviceId: id,
      ip: clientIp(c),
    });
    return c.json({ ok: true });
  });

  // Catalog
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
        ip: clientIp(c),
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
      env?: Record<string, string>;
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
    if (!entry) {
      return c.json({ error: "gallery entry required (id or entry)" }, 400);
    }

    try {
      const result = await installFromGallery(store, auth.workspaceId, {
        entry,
        slug: body.slug,
        enable: body.enable,
        headers: body.headers,
        env: body.env,
        allowPrivateUrls: cfg.allowPrivateUrls,
      });
      store.writeAudit({
        workspaceId: auth.workspaceId,
        action: "catalog.install",
        backendSlug: result.backend.slug,
        placement: result.backend.placement.mode,
        detail: { galleryId: entry.id, warnings: result.warnings },
        ip: clientIp(c),
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
    const server = createGatewayServer({
      store,
      pool,
      auth,
      edgeHub,
      edgeRouter,
      ip: clientIp(c),
    });
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
