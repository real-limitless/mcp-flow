import { existsSync, readFileSync } from "node:fs";
import { bodyLimit } from "hono/body-limit";
import { registerReadEndpoints } from "./read-endpoints.js";
import { policyApprovalsRouter } from "./policy-approvals.js";
import { callAuditFilterFrom, exportCallAudit, queryCallAudit } from "../audit/call-audit.js";
import {
  acceptClientSessionId,
  agentAuthContext,
  newAgentSessionId,
} from "../identity/auth-context.js";
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
import { globalApprovalWaiters } from "../authz/waiters.js";
import {
  parseAuthzRequirement,
  requirementNeedsMfa,
} from "../authz/types.js";
import { generateTotpSecret, otpauthUrl } from "../authz/totp.js";
import { operatorSubject, verifyOperatorTotp } from "../authz/operator.js";
import { seal, safeEqualStr } from "../crypto.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import type { EdgeHub } from "../edge/hub.js";
import type { EdgeRouter } from "../edge/router.js";
import { clientIp } from "../http/client-ip.js";
import { createGatewayServer } from "../mcp/gateway.js";
import {
  buildScopesFromArgs,
  mergeApiKeyScopes,
} from "../mcp/admin-tools.js";
import { globalSessionProjects } from "../mcp/session-project.js";
import { forgetMcpSession } from "../mcp/session-tools.js";
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
  CreateProjectInput,
  DeviceCapabilities,
  TransportKind,
  UpdateBackendInput,
  UpdateProjectInput,
  WorkspacePolicy,
} from "../types.js";
import { DEFAULT_PLACEMENT, isAdminScopes } from "../types.js";

type Variables = {
  auth: AuthContext;
  /** Set only when the admin caller is a human admin AGENT (not the env token or a legacy scopes.admin key) */
  humanAdmin?: string;
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
  const adminStatic: Record<string, string> = {
    "app.js": "application/javascript; charset=utf-8",
    "sw.js": "application/javascript; charset=utf-8",
    "styles.css": "text/css; charset=utf-8",
    "manifest.webmanifest": "application/manifest+json; charset=utf-8",
    "icon.svg": "image/svg+xml",
    "icon-192.png": "image/png",
    "icon-512.png": "image/png",
  };
  app.get("/admin/:file", (c) => {
    const file = c.req.param("file");
    const type = adminStatic[file];
    if (!type || !adminDir) return c.text("not found", 404);
    try {
      const buf = readFileSync(join(adminDir, file));
      const headers: Record<string, string> = { "Content-Type": type };
      if (file === "sw.js") {
        headers["Cache-Control"] = "no-cache";
        headers["Service-Worker-Allowed"] = "/admin/";
      }
      return c.body(buf, 200, headers);
    } catch {
      return c.text("not found", 404);
    }
  });

  const admin = new Hono<{ Variables: Variables }>();

  admin.use("*", async (c, next) => {
    const token = bearer(c.req.header("authorization"));
    if (!token) return c.json({ error: "unauthorized" }, 401);

    // Break-glass env admin token
    if (cfg.adminToken && safeEqualStr(token, cfg.adminToken)) {
      const ws = store.ensureWorkspace(cfg.workspaceName);
      c.set("auth", { kind: "admin", workspaceId: ws.id });
      await next();
      return;
    }

    // T1.3 agent key or session of a human admin agent (agent.is_admin)
    const agentRes = token.startsWith("mf_sess_")
      ? store.identity.resolveSession(token)
      : store.identity.resolveKey(token, clientIp(c));
    if (agentRes.status === "ok" || agentRes.status === "forbidden") {
      // QA V3-F2: authenticated but not a human admin -> 403 (401 stays for missing/bad tokens)
      if (!agentRes.agent.isAdmin || agentRes.agent.kind !== "human") return c.json({ error: "forbidden" }, 403);
      c.set("auth", agentAuthContext(agentRes.agent, { mcpSessionId: null }));
      c.set("humanAdmin", agentRes.agent.agentId);
      await next();
      return;
    }
    if (agentRes.status !== "unknown") return c.json({ error: "unauthorized" }, 401);

    // Operator agent key (scopes.admin)
    const key = store.authenticateApiKey(token);
    if (key && isAdminScopes(key.scopes)) {
      c.set("auth", {
        kind: "api_key",
        workspaceId: key.workspaceId,
        keyId: key.keyId,
        keyName: key.keyName,
        scopes: key.scopes,
      });
      await next();
      return;
    }
    if (key) return c.json({ error: "forbidden" }, 403); // valid legacy key without scopes.admin

    return c.json({ error: "unauthorized" }, 401);
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
      admin?: boolean;
      projects?: string[];
      defaultProject?: string | null;
      dynamicTools?: boolean;
      dynamicToolsHot?: string[];
    };
    const name = body.name?.trim() || "default";
    let scopes: ApiKeyScopes | null =
      body.scopes !== undefined
        ? body.scopes
        : buildScopesFromArgs({
            admin: body.admin === true,
            toolPrefixAllowlist: body.toolPrefixAllowlist,
            projects: body.projects,
            defaultProject: body.defaultProject ?? undefined,
            dynamicTools: body.dynamicTools === true,
            dynamicToolsHot: body.dynamicToolsHot,
          });
    // Only env admin or existing admin keys reach here — both may grant admin
    if (scopes?.admin !== true && body.admin === true) {
      scopes = { ...(scopes ?? {}), admin: true };
    }
    if (body.projects?.length) {
      scopes = { ...(scopes ?? {}), projects: body.projects.map(String) };
    }
    if (body.defaultProject != null && String(body.defaultProject).trim()) {
      scopes = {
        ...(scopes ?? {}),
        defaultProject: String(body.defaultProject).trim(),
      };
    }
    if (body.dynamicTools === true) {
      scopes = { ...(scopes ?? {}), dynamicTools: true };
    }
    if (body.dynamicToolsHot?.length) {
      scopes = {
        ...(scopes ?? {}),
        dynamicToolsHot: body.dynamicToolsHot.map(String),
      };
    }
    const created = store.createApiKey(auth.workspaceId, name, scopes);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      keyId: auth.keyId,
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
      admin?: boolean;
      projects?: string[] | null;
      defaultProject?: string | null;
      dynamicTools?: boolean;
      dynamicToolsHot?: string[] | null;
    };
    let scopes: ApiKeyScopes | null;
    if (body.scopes !== undefined) scopes = body.scopes;
    else if (
      body.toolPrefixAllowlist !== undefined ||
      body.admin !== undefined ||
      body.projects !== undefined ||
      body.defaultProject !== undefined ||
      body.dynamicTools !== undefined ||
      body.dynamicToolsHot !== undefined
    ) {
      const existing = store
        .listApiKeys(auth.workspaceId)
        .find((k) => k.id === c.req.param("id"));
      scopes = mergeApiKeyScopes(existing?.scopes, {
        admin: body.admin,
        toolPrefixAllowlist: body.toolPrefixAllowlist,
        projects: body.projects,
        defaultProject: body.defaultProject,
        dynamicTools: body.dynamicTools,
        dynamicToolsHot: body.dynamicToolsHot,
      });
    } else {
      return c.json(
        {
          error:
            "scopes, toolPrefixAllowlist, admin, projects, defaultProject, dynamicTools, or dynamicToolsHot required",
        },
        400,
      );
    }
    const key = store.updateApiKeyScopes(
      auth.workspaceId,
      c.req.param("id"),
      scopes,
    );
    if (!key) return c.json({ error: "not found" }, 404);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      keyId: auth.keyId,
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

  registerReadEndpoints(admin, store, pool);

  // T3.3: per-call audit log (mcpflow_call_audit), admin only
  admin.get("/audit/calls", (c) => {
    const auth = c.get("auth");
    const q = c.req.query();
    const filter = callAuditFilterFrom(q);
    const format = q.format;
    if (format === "csv" || format === "json") {
      const out = exportCallAudit(store.db, auth.workspaceId, filter, format, q.max_rows ? Number(q.max_rows) : undefined);
      store.writeAudit({
        workspaceId: auth.workspaceId,
        keyId: auth.keyId,
        action: "audit.export",
        detail: { via: "rest", format, rows: out.rows, truncated: out.truncated },
        ip: clientIp(c),
      });
      return new Response(out.body, {
        headers: {
          "content-type": out.contentType,
          "content-disposition": `attachment; filename="call-audit.${format}"`,
          "x-mcp-flow-truncated": String(out.truncated),
        },
      });
    }
    const page = queryCallAudit(store.db, auth.workspaceId, filter, {
      limit: q.limit ? Number(q.limit) : undefined,
      cursor: q.cursor ? Number(q.cursor) : undefined,
    });
    return c.json({ rows: page.rows, next_cursor: page.nextCursor });
  });

  admin.get("/audit", (c) => {
    const auth = c.get("auth");
    const limit = Number(c.req.query("limit") ?? "50");
    const before = c.req.query("before") ?? undefined;
    const events = store.listAudit(auth.workspaceId, { limit, before });
    return c.json({ events });
  });

  // Projects (collections)
  admin.get("/projects", (c) => {
    const auth = c.get("auth");
    return c.json({ projects: store.listProjects(auth.workspaceId) });
  });

  admin.get("/projects/:id", (c) => {
    const auth = c.get("auth");
    const p = store.getProject(auth.workspaceId, c.req.param("id"));
    if (!p) return c.json({ error: "not found" }, 404);
    return c.json({ project: p });
  });

  admin.post("/projects", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as CreateProjectInput;
    if (!body.slug) return c.json({ error: "slug required" }, 400);
    try {
      const project = store.createProject(auth.workspaceId, body);
      store.writeAudit({
        workspaceId: auth.workspaceId,
        keyId: auth.keyId,
        action: "project.create",
        detail: { slug: project.slug },
        ip: clientIp(c),
      });
      return c.json({ project }, 201);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        400,
      );
    }
  });

  admin.patch("/projects/:id", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json()) as UpdateProjectInput;
    try {
      const project = store.updateProject(
        auth.workspaceId,
        c.req.param("id"),
        body,
      );
      if (!project) return c.json({ error: "not found" }, 404);
      store.writeAudit({
        workspaceId: auth.workspaceId,
        keyId: auth.keyId,
        action: "project.update",
        detail: { slug: project.slug },
        ip: clientIp(c),
      });
      return c.json({ project });
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        400,
      );
    }
  });

  admin.delete("/projects/:id", (c) => {
    const auth = c.get("auth");
    try {
      const existing = store.getProject(auth.workspaceId, c.req.param("id"));
      const ok = store.deleteProject(auth.workspaceId, c.req.param("id"));
      if (!ok) return c.json({ error: "not found" }, 404);
      store.writeAudit({
        workspaceId: auth.workspaceId,
        keyId: auth.keyId,
        action: "project.delete",
        detail: { slug: existing?.slug },
        ip: clientIp(c),
      });
      return c.json({ ok: true });
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        400,
      );
    }
  });

  admin.get("/authz/rules", (c) => {
    const auth = c.get("auth");
    return c.json({ rules: store.listAuthzRules(auth.workspaceId) });
  });

  admin.post("/authz/rules", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    try {
      const rule = store.createAuthzRule(auth.workspaceId, {
        name: String(body.name ?? ""),
        enabled: body.enabled !== false,
        priority: typeof body.priority === "number" ? body.priority : undefined,
        match: (body.match ?? {}) as Record<string, unknown>,
        requirement: parseAuthzRequirement(body.requirement) ?? undefined,
        ttlSeconds: body.ttlSeconds as number | undefined,
        mfaReuseSeconds: body.mfaReuseSeconds as number | undefined,
      });
      return c.json({ rule }, 201);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        400,
      );
    }
  });

  admin.patch("/authz/rules/:id", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    try {
      const rule = store.updateAuthzRule(auth.workspaceId, c.req.param("id"), {
        name: body.name !== undefined ? String(body.name) : undefined,
        enabled: body.enabled !== undefined ? Boolean(body.enabled) : undefined,
        priority: typeof body.priority === "number" ? body.priority : undefined,
        match:
          body.match !== undefined
            ? (body.match as Record<string, unknown>)
            : undefined,
        requirement: parseAuthzRequirement(body.requirement) ?? undefined,
        ttlSeconds: body.ttlSeconds as number | undefined,
        mfaReuseSeconds: body.mfaReuseSeconds as number | undefined,
      });
      if (!rule) return c.json({ error: "not found" }, 404);
      return c.json({ rule });
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        400,
      );
    }
  });

  admin.delete("/authz/rules/:id", (c) => {
    const auth = c.get("auth");
    const ok = store.deleteAuthzRule(auth.workspaceId, c.req.param("id"));
    if (!ok) return c.json({ error: "not found" }, 404);
    return c.json({ ok: true });
  });

  admin.get("/approvals", (c) => {
    const auth = c.get("auth");
    const statusRaw = c.req.query("status");
    const status =
      statusRaw === "pending" ||
      statusRaw === "approved" ||
      statusRaw === "denied" ||
      statusRaw === "expired" ||
      statusRaw === "all"
        ? statusRaw
        : "pending";
    const approvals = store.listApprovals(auth.workspaceId, { status });
    return c.json({
      approvals,
      pendingCount: store.countPendingApprovals(auth.workspaceId),
      waiting: globalApprovalWaiters.workspacePending(auth.workspaceId),
    });
  });

  admin.post("/approvals/:id/decision", async (c) => {
    const auth = c.get("auth");
    const id = c.req.param("id");
    const body = (await c.req.json().catch(() => ({}))) as {
      decision?: string;
      totp?: string;
    };
    const decision =
      body.decision === "approve" || body.decision === "deny"
        ? body.decision
        : null;
    if (!decision) {
      return c.json({ error: 'decision must be "approve" or "deny"' }, 400);
    }

    const approval = store.getApproval(auth.workspaceId, id, { redact: true });
    if (!approval) return c.json({ error: "not found" }, 404);
    if (approval.status !== "pending") {
      return c.json(
        { error: "approval is not pending", status: approval.status },
        409,
      );
    }

    if (decision === "approve" && requirementNeedsMfa(approval.requirement)) {
      const op = operatorSubject(auth);
      const mfa = store.getOperatorMfa(auth.workspaceId, op);
      if (!mfa.enrolled) {
        return c.json(
          {
            error: "enroll MFA first",
            enroll: "/v1/operators/mfa/begin",
          },
          400,
        );
      }
      const totp = String(body.totp ?? "").trim();
      if (!totp) return c.json({ error: "totp required" }, 400);
      const verified = verifyOperatorTotp(
        store,
        auth.workspaceId,
        op,
        totp,
      );
      if (!verified.ok) {
        const status = verified.error === "locked" ? 429 : 401;
        return c.json({ error: verified.error === "locked" ? "totp locked" : "invalid totp" }, status);
      }
    }

    const nextStatus = decision === "approve" ? "approved" : "denied";
    const updated = store.decideApproval(auth.workspaceId, id, {
      status: nextStatus,
      decidedByKeyId: auth.keyId ?? null,
      mfaSatisfied: decision === "approve" && requirementNeedsMfa(approval.requirement),
    });
    if (!updated) {
      return c.json(
        { error: "approval is not pending", status: "expired" },
        409,
      );
    }

    const unblocked = globalApprovalWaiters.resolve(
      id,
      nextStatus === "approved" ? "approved" : "denied",
    );
    store.writeAudit({
      workspaceId: auth.workspaceId,
      keyId: auth.keyId ?? null,
      action: nextStatus === "approved" ? "authz.approve" : "authz.deny",
      tool: approval.tool,
      backendSlug: approval.backendSlug,
      detail: {
        approvalId: id,
        decision: nextStatus,
        unblocked,
        requirement: approval.requirement,
      },
      ip: clientIp(c),
    });
    return c.json({
      approval: store.getApproval(auth.workspaceId, id, { redact: true }),
      unblocked,
    });
  });

  admin.get("/operators/mfa", (c) => {
    const auth = c.get("auth");
    const op = operatorSubject(auth);
    return c.json(store.getOperatorMfa(auth.workspaceId, op));
  });

  admin.post("/operators/mfa/begin", async (c) => {
    const auth = c.get("auth");
    const op = operatorSubject(auth);
    const body = (await c.req.json().catch(() => ({}))) as {
      replace?: boolean;
      totp?: string;
    };
    const current = store.getOperatorMfa(auth.workspaceId, op);
    if (current.enrolled && !body.replace) {
      return c.json(
        {
          error: "already enrolled",
          hint: 'POST with { "replace": true, "totp": "123456" } to rotate',
        },
        409,
      );
    }
    if (current.enrolled && body.replace) {
      const totp = String(body.totp ?? "").trim();
      if (!totp) return c.json({ error: "totp required to replace" }, 400);
      const verified = verifyOperatorTotp(
        store,
        auth.workspaceId,
        op,
        totp,
      );
      if (!verified.ok) {
        const status = verified.error === "locked" ? 429 : 401;
        return c.json({ error: verified.error === "locked" ? "totp locked" : "invalid totp" }, status);
      }
    }
    const { base32 } = generateTotpSecret();
    store.upsertOperatorMfaPending(
      auth.workspaceId,
      op,
      seal(store.masterKey, { base32 }),
    );
    const account =
      auth.kind === "admin"
        ? "env-admin"
        : (auth.keyName ?? auth.keyId ?? "operator");
    return c.json({
      pending: true,
      secret: base32,
      otpauthUrl: otpauthUrl({
        issuer: "mcp-flow",
        account,
        base32,
      }),
    });
  });

  admin.post("/operators/mfa/confirm", async (c) => {
    const auth = c.get("auth");
    const op = operatorSubject(auth);
    const body = (await c.req.json().catch(() => ({}))) as { totp?: string };
    const totp = String(body.totp ?? "").trim();
    if (!totp) return c.json({ error: "totp required" }, 400);
    const verified = verifyOperatorTotp(store, auth.workspaceId, op, totp, {
      requireEnrolled: false,
    });
    if (!verified.ok) {
      if (verified.error === "not_enrolled") {
        return c.json({ error: "call /v1/operators/mfa/begin first" }, 400);
      }
      const status = verified.error === "locked" ? 429 : 401;
      return c.json({ error: verified.error === "locked" ? "totp locked" : "invalid totp" }, status);
    }
    store.markOperatorMfaEnrolled(auth.workspaceId, op);
    return c.json({ enrolled: true });
  });

  admin.post("/operators/mfa/disable", async (c) => {
    const auth = c.get("auth");
    const op = operatorSubject(auth);
    const body = (await c.req.json().catch(() => ({}))) as { totp?: string };
    const current = store.getOperatorMfa(auth.workspaceId, op);
    if (!current.enrolled && !current.pending) {
      return c.json({ ok: true, enrolled: false });
    }
    const totp = String(body.totp ?? "").trim();
    if (current.enrolled) {
      if (!totp) return c.json({ error: "totp required" }, 400);
      const verified = verifyOperatorTotp(store, auth.workspaceId, op, totp);
      if (!verified.ok) {
        const status = verified.error === "locked" ? 429 : 401;
        return c.json({ error: verified.error === "locked" ? "totp locked" : "invalid totp" }, status);
      }
    }
    store.deleteOperatorMfa(auth.workspaceId, op);
    return c.json({ ok: true, enrolled: false });
  });

  admin.get("/push/vapid", (c) => {
    const auth = c.get("auth");
    const vapid = store.getPushVapid(auth.workspaceId);
    return c.json({
      publicKey: vapid.publicKey,
      subject: vapid.subject,
    });
  });

  admin.get("/push/subscriptions", (c) => {
    const auth = c.get("auth");
    return c.json({
      subscriptions: store.listPushSubscriptionsPublic(auth.workspaceId),
    });
  });

  admin.post("/push/subscriptions", async (c) => {
    const auth = c.get("auth");
    const body = (await c.req.json().catch(() => ({}))) as {
      endpoint?: string;
      keys?: { p256dh?: string; auth?: string };
    };
    try {
      const sub = store.upsertPushSubscription({
        workspaceId: auth.workspaceId,
        operatorKeyId: operatorSubject(auth),
        endpoint: String(body.endpoint ?? ""),
        p256dh: String(body.keys?.p256dh ?? ""),
        auth: String(body.keys?.auth ?? ""),
      });
      return c.json({ subscription: sub }, 201);
    } catch (err) {
      return c.json(
        { error: err instanceof Error ? err.message : String(err) },
        400,
      );
    }
  });

  admin.delete("/push/subscriptions/:id", (c) => {
    const auth = c.get("auth");
    const ok = store.deletePushSubscription(auth.workspaceId, c.req.param("id"));
    if (!ok) return c.json({ error: "not found" }, 404);
    return c.json({ ok: true });
  });

  app.post("/v1/approvals/:id/push-decision", async (c) => {
    const id = c.req.param("id");
    const body = (await c.req.json().catch(() => ({}))) as {
      decision?: string;
      token?: string;
    };
    const decision =
      body.decision === "approve" || body.decision === "deny"
        ? body.decision
        : null;
    if (!decision) {
      return c.json({ error: 'decision must be "approve" or "deny"' }, 400);
    }
    const token = String(body.token ?? "").trim();
    if (!token) return c.json({ error: "token required" }, 400);
    const looked = store.lookupPushDecision(id, token);
    if (!looked.ok) {
      const status =
        looked.error === "not_found"
          ? 404
          : looked.error === "not_pending"
            ? 409
            : 401;
      return c.json({ error: looked.error }, status);
    }
    if (
      decision === "approve" &&
      requirementNeedsMfa(looked.approval.requirement)
    ) {
      return c.json(
        {
          error: "mfa_required",
          url: `/admin/#approvals/${id}`,
        },
        400,
      );
    }
    const nextStatus = decision === "approve" ? "approved" : "denied";
    const updated = store.decideApproval(looked.approval.workspaceId, id, {
      status: nextStatus,
      decidedByKeyId: null,
    });
    if (!updated) {
      return c.json({ error: "not_pending", status: "expired" }, 409);
    }
    const unblocked = globalApprovalWaiters.resolve(
      id,
      nextStatus === "approved" ? "approved" : "denied",
    );
    store.writeAudit({
      workspaceId: looked.approval.workspaceId,
      keyId: null,
      action: nextStatus === "approved" ? "authz.approve" : "authz.deny",
      tool: looked.approval.tool,
      backendSlug: looked.approval.backendSlug,
      detail: {
        approvalId: id,
        decision: nextStatus,
        unblocked,
        via: "web_push",
        requirement: looked.approval.requirement,
      },
      ip: clientIp(c),
    });
    return c.json({
      ok: true,
      approval: store.getApproval(looked.approval.workspaceId, id, {
        redact: true,
      }),
      unblocked,
    });
  });

  app.route("/v1/policy/approvals", policyApprovalsRouter(store));
  app.route("/v1", admin);

  // MCP Streamable HTTP — agent API keys or project session tokens
  // Security T2.5 R-3: bound request bodies before anything (auth, progress peek, transport) reads them
  app.use(
    "/mcp",
    bodyLimit({
      maxSize: mcpMaxBodyBytes(),
      onError: (c) => c.json({ jsonrpc: "2.0", error: { code: -32600, message: "request body too large" }, id: null }, 413),
    }),
  );
  app.all("/mcp", async (c) => {
    const token = bearer(c.req.header("authorization"));
    if (!token) {
      return c.json({ error: "missing bearer token" }, 401);
    }

    const mcpSessionId =
      c.req.header("mcp-session-id") ||
      c.req.header("x-mcp-flow-session") ||
      null;

    let auth: AuthContext;

    // T1.3: per-agent identity first (mcpflow_* tables); legacy keys fall through.
    const agentRes = token.startsWith("mf_sess_")
      ? store.identity.resolveSession(token)
      : store.identity.resolveKey(token, clientIp(c));
    if (agentRes.status === "unauthorized") {
      return c.json({ error: "invalid api key" }, 401);
    }
    if (agentRes.status === "forbidden") {
      return c.json({ error: "agent has no permitted projects" }, 403);
    }

    // Security M-5 (cutover flag, default off): legacy shared keys / legacy project sessions refused on /mcp
    if (agentRes.status === "unknown" && cfg.refuseLegacyMcpKeys) {
      const legacy = store.authenticateProjectSession(token) ?? store.authenticateApiKey(token);
      if (legacy) return c.json({ error: "legacy keys are not accepted on /mcp; use an agent key" }, 403);
      return c.json({ error: "invalid api key" }, 401);
    }
    const sess =
      agentRes.status === "unknown" ? store.authenticateProjectSession(token) : null;
    /** Set when the gateway minted a fresh agent session id the client must echo back. */
    let issuedSessionId: string | null = null;
    if (agentRes.status === "ok") {
      const agent = agentRes.agent;
      let agentSid: string;
      if (acceptClientSessionId(agent, mcpSessionId)) {
        agentSid = mcpSessionId!;
      } else {
        agentSid = newAgentSessionId(agent);
        issuedSessionId = agentSid;
      }
      let projectId: string | null = null;
      let projectSlug: string | null = null;
      if (agent.sessionProject) {
        const p = store.getProjectBySlug(agent.workspaceId, agent.sessionProject);
        if (!p) return c.json({ error: "session project not found" }, 403);
        projectId = p.id;
        projectSlug = p.slug;
      } else {
        const sticky = globalSessionProjects.get(agentSid);
        if (
          sticky &&
          sticky.keyId === agent.keyId &&
          agent.effectiveProjects.includes(sticky.projectSlug)
        ) {
          projectId = sticky.projectId;
          projectSlug = sticky.projectSlug;
        }
      }
      auth = agentAuthContext(agent, { mcpSessionId: agentSid, projectId, projectSlug });
    } else if (sess) {
      auth = {
        kind: "project_session",
        workspaceId: sess.workspaceId,
        keyId: sess.keyId,
        keyName: sess.keyName,
        scopes: sess.scopes,
        projectId: sess.projectId,
        projectSlug: sess.projectSlug,
        projectSessionId: sess.projectSessionId,
        mcpSessionId,
      };
    } else {
      const key = store.authenticateApiKey(token);
      if (!key) {
        return c.json({ error: "invalid api key" }, 401);
      }
      // Resolve sticky project from MCP session or key fallback
      const sticky =
        globalSessionProjects.get(mcpSessionId) ||
        (key.keyId
          ? globalSessionProjects.get(`key:${key.keyId}`)
          : null);
      auth = {
        kind: "api_key",
        workspaceId: key.workspaceId,
        keyId: key.keyId,
        keyName: key.keyName,
        scopes: key.scopes,
        mcpSessionId: mcpSessionId || (key.keyId ? `key:${key.keyId}` : null),
        projectId:
          sticky && sticky.keyId === key.keyId ? sticky.projectId : null,
        projectSlug:
          sticky && sticky.keyId === key.keyId ? sticky.projectSlug : null,
      };
    }

    // A tools/call that carries a progressToken gets an SSE response so hold progress
    // notifications can reach the client; everything else keeps plain JSON responses.
    let wantsStream = false;
    if (c.req.method === "POST") {
      try {
        const peek = (await c.req.raw.clone().json()) as unknown;
        const msgs = Array.isArray(peek) ? peek : [peek];
        wantsStream = msgs.some((m) => {
          const msg = m as { method?: string; params?: { _meta?: { progressToken?: unknown } } };
          return msg?.method === "tools/call" && msg.params?._meta?.progressToken !== undefined;
        });
      } catch {
        wantsStream = false;
      }
    }
    const transport = new WebStandardStreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: !wantsStream,
    });
    const server = createGatewayServer({
      store,
      pool,
      auth,
      cfg,
      edgeHub,
      edgeRouter,
      ip: clientIp(c),
      abortSignal: c.req.raw.signal,
      // Security T2.5 H-2: configured origin only, never the request's Host header
      approveBaseUrl: cfg.publicUrl ?? null,
    });
    await server.connect(transport);
    const response = await transport.handleRequest(c.req.raw);
    if (c.req.method === "DELETE") forgetMcpSession(mcpSessionId, auth.keyId);

    const cleanup = () => {
      void transport.close().catch(() => undefined);
      void server.close().catch(() => undefined);
    };

    // Fresh per-client agent session id (T1.1 §3.5); clients echo it as Mcp-Session-Id.
    // Copy headers: the node adaptor may cache the original Response's init.
    const outHeaders = new Headers(response.headers);
    if (issuedSessionId) outHeaders.set("mcp-session-id", issuedSessionId);

    if (!response.body) {
      cleanup();
      return issuedSessionId
        ? new Response(null, {
            status: response.status,
            statusText: response.statusText,
            headers: outHeaders,
          })
        : response;
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
      headers: outHeaders,
    });
  });

  app.notFound((c) => c.json({ error: "not found" }, 404));

  return app;
}

export type AppType = ReturnType<typeof createApp>;

export { toPublicBackend };

/** Max /mcp request body (bytes), MCP_FLOW_MAX_BODY_BYTES, default 4 MiB, clamped 64 KiB..64 MiB. */
export function mcpMaxBodyBytes(): number {
  const n = Number(process.env.MCP_FLOW_MAX_BODY_BYTES ?? "");
  if (Number.isFinite(n) && n >= 65_536 && n <= 67_108_864) return Math.floor(n);
  return 4 * 1024 * 1024;
}
