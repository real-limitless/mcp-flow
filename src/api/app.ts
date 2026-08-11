import { Hono } from "hono";
import { cors } from "hono/cors";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import type { Config } from "../config.js";
import { safeEqualStr } from "../crypto.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import { createGatewayServer } from "../mcp/gateway.js";
import { UpstreamPool } from "../mcp/upstream.js";
import { assertSafeUrl, SsrfError } from "../ssrf.js";
import type {
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

export function createApp(store: Store, cfg: Config, pool: UpstreamPool) {
  const app = new Hono<{ Variables: Variables }>();

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
    const body = (await c.req.json().catch(() => ({}))) as { name?: string };
    const name = body.name?.trim() || "default";
    const created = store.createApiKey(auth.workspaceId, name);
    return c.json({ key: created }, 201);
  });

  admin.get("/keys", (c) => {
    const auth = c.get("auth");
    return c.json({ keys: store.listApiKeys(auth.workspaceId) });
  });

  admin.delete("/keys/:id", (c) => {
    const auth = c.get("auth");
    const ok = store.revokeApiKey(auth.workspaceId, c.req.param("id"));
    if (!ok) return c.json({ error: "not found" }, 404);
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
    pool.invalidate(
      store.getBackend(auth.workspaceId, backend.id)?.id,
    );
    return c.json({ backend });
  });

  admin.delete("/backends/:id", (c) => {
    const auth = c.get("auth");
    const existing = store.getBackend(auth.workspaceId, c.req.param("id"));
    const ok = store.deleteBackend(auth.workspaceId, c.req.param("id"));
    if (!ok) return c.json({ error: "not found" }, 404);
    if (existing) pool.invalidate(existing.id);
    return c.json({ ok: true });
  });

  admin.post("/backends/:id/test", async (c) => {
    const auth = c.get("auth");
    const backend = store.getBackend(auth.workspaceId, c.req.param("id"));
    if (!backend) return c.json({ error: "not found" }, 404);
    const result = await pool.testBackend(backend);
    return c.json(result, result.ok ? 200 : 502);
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

    // Do not close until the body is fully consumed (stateless per-request transport).
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

  // Convenience: never leak secrets in accidental dumps
  app.notFound((c) => c.json({ error: "not found" }, 404));

  return app;
}

export type AppType = ReturnType<typeof createApp>;

// re-export for tests
export { toPublicBackend };
