import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { toolCallAuditDetail } from "../audit/sanitize.js";
import type { Config } from "../config.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import type { EdgeHub } from "../edge/hub.js";
import type { EdgeRouter } from "../edge/router.js";
import { CONTROL_PLANE_MODES, supportedPlacementModes } from "../placement.js";
import type { AuthContext, Project } from "../types.js";
import {
  isAdminScopes,
  keyMayUseProject,
  resolveDefaultProjectSlug,
  toolAllowedByProject,
  toolAllowedByScopes,
} from "../types.js";
import { ADMIN_META_TOOLS, handleAdminTool } from "./admin-tools.js";
import { globalSessionProjects } from "./session-project.js";
import { parseNamespacedTool, UpstreamPool } from "./upstream.js";

const META_TOOLS: Tool[] = [
  {
    name: "mf_list_backends",
    description:
      "List MCP backends in the active project (secrets redacted).",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "mf_list_tools",
    description:
      "List namespaced tools available through mcp-flow (slug__tool) for the active project.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "mf_status",
    description: "Gateway status for the current API key / workspace / project.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "mf_list_projects",
    description:
      "List projects (tool collections) this key may use. Call mf_use_project to switch.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "mf_use_project",
    description:
      "Activate a project for this chat/session. Returns sessionToken (optional bearer) and binds MCP session. Re-list tools after switching.",
    inputSchema: {
      type: "object",
      properties: {
        project: {
          type: "string",
          description: "Project slug (e.g. default, webdevelopment)",
        },
        mintSessionToken: {
          type: "boolean",
          description: "If true, mint short-lived mf_sess_* bound to this project",
        },
      },
      required: ["project"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_current_project",
    description: "Show the active project and its backend membership.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "mf_use_device",
    description:
      "Pin subsequent edge tool calls for this key to a device id (session sticky). Pass empty deviceId to clear.",
    inputSchema: {
      type: "object",
      properties: {
        deviceId: {
          type: "string",
          description: "Device id or empty to clear sticky",
        },
      },
      additionalProperties: false,
    },
  },
];

function textResult(data: unknown, isError = false): CallToolResult {
  return {
    isError,
    content: [
      {
        type: "text",
        text:
          typeof data === "string" ? data : JSON.stringify(data, null, 2),
      },
    ],
  };
}

function filterTools(
  tools: Tool[],
  auth: AuthContext,
  project: Project | null,
): Tool[] {
  return tools.filter(
    (t) =>
      toolAllowedByScopes(t.name, auth.scopes) &&
      toolAllowedByProject(t.name, project),
  );
}

function resolveActiveProject(
  store: Store,
  auth: AuthContext,
): Project | null {
  store.ensureDefaultProject(auth.workspaceId);

  // 1) Explicit project from mf_sess_* or pre-resolved auth
  if (auth.projectId) {
    return store.getProject(auth.workspaceId, auth.projectId);
  }

  // 2) MCP session sticky
  const sticky = globalSessionProjects.get(auth.mcpSessionId);
  if (sticky && sticky.keyId === auth.keyId) {
    return store.getProject(auth.workspaceId, sticky.projectId);
  }

  // 3) Key / workspace default
  const def = store.getDefaultProject(auth.workspaceId);
  const slug = resolveDefaultProjectSlug(auth.scopes, def?.slug ?? null);
  if (slug) {
    const p = store.getProjectBySlug(auth.workspaceId, slug);
    if (p && keyMayUseProject(auth.scopes, p.slug)) return p;
  }
  return def;
}

export interface GatewayDeps {
  store: Store;
  pool: UpstreamPool;
  auth: AuthContext;
  cfg: Config;
  edgeHub?: EdgeHub | null;
  edgeRouter?: EdgeRouter | null;
  /** Client IP for audit */
  ip?: string | null;
}

export function createGatewayServer(deps: GatewayDeps): Server {
  const { store, pool: upstream, auth: ctx, cfg } = deps;
  const ip = deps.ip ?? null;
  const edgeHub = deps.edgeHub ?? null;
  const edgeRouter = deps.edgeRouter ?? null;
  const adminTools = isAdminScopes(ctx.scopes) ? ADMIN_META_TOOLS : [];

  const server = new Server(
    { name: "mcp-flow", version: "0.1.0" },
    { capabilities: { tools: { listChanged: true } } },
  );

  const edgeEnabled = Boolean(edgeHub);

  const activeProject = (): Project | null =>
    resolveActiveProject(store, ctx);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const project = activeProject();
    const upstreamTools = await upstream.listNamespacedTools(ctx.workspaceId);
    const tools: Tool[] = filterTools(
      [
        ...META_TOOLS,
        ...adminTools,
        ...upstreamTools.map(
          ({ upstreamName: _u, backendSlug: _s, backendId: _b, ...tool }) =>
            tool,
        ),
      ],
      ctx,
      project,
    );
    store.writeAudit({
      workspaceId: ctx.workspaceId,
      keyId: ctx.keyId,
      action: "tools/list",
      detail: {
        count: tools.length,
        project: project?.slug ?? null,
      },
      ip,
    });
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    const started = Date.now();
    const project = activeProject();

    if (!toolAllowedByScopes(name, ctx.scopes)) {
      store.writeAudit({
        workspaceId: ctx.workspaceId,
        keyId: ctx.keyId,
        action: "tools/call",
        tool: name,
        detail: toolCallAuditDetail({
          denied: true,
          reason: "scope",
          arguments: args,
          durationMs: Date.now() - started,
        }),
        ip,
      });
      return textResult(`Tool not allowed by API key scopes: ${name}`, true);
    }

    if (!toolAllowedByProject(name, project)) {
      store.writeAudit({
        workspaceId: ctx.workspaceId,
        keyId: ctx.keyId,
        action: "tools/call",
        tool: name,
        detail: toolCallAuditDetail({
          denied: true,
          reason: "project",
          arguments: args,
          durationMs: Date.now() - started,
        }),
        ip,
      });
      return textResult(
        `Tool not in active project (${project?.slug ?? "none"}): ${name}. Use mf_use_project or mf_list_projects.`,
        true,
      );
    }

    const auditCall = (
      result: CallToolResult,
      extra?: {
        meta?: boolean;
        backendSlug?: string | null;
        placement?: string | null;
        deviceId?: string | null;
      },
    ) => {
      store.writeAudit({
        workspaceId: ctx.workspaceId,
        keyId: ctx.keyId,
        action: "tools/call",
        tool: name,
        backendSlug: extra?.backendSlug ?? null,
        placement: extra?.placement ?? null,
        deviceId: extra?.deviceId ?? null,
        detail: toolCallAuditDetail({
          meta: extra?.meta,
          arguments: args,
          result,
          durationMs: Date.now() - started,
        }),
        ip,
      });
    };

    if (name === "mf_list_backends") {
      let backends = store.listBackends(ctx.workspaceId);
      if (project) {
        const allow = new Set(project.backendSlugs);
        backends = backends.filter((b) => allow.has(b.slug));
      }
      const payload = {
        project: project?.slug ?? null,
        backends: backends.map((b) => {
          const deviceId = b.placement.deviceId;
          const device = deviceId
            ? store.getDevice(ctx.workspaceId, deviceId)
            : null;
          return {
            slug: b.slug,
            title: b.title,
            transport: b.transport,
            enabled: b.enabled,
            placement: b.placement,
            hasHeaders: b.hasHeaders,
            hasEnv: b.hasEnv,
            url: b.url,
            runsOn: device
              ? {
                  deviceId: device.id,
                  name: device.name,
                  status: edgeHub?.isOnline(device.id)
                    ? "online"
                    : device.status,
                }
              : b.placement.mode === "central-sandbox"
                ? { host: "central" }
                : b.placement.mode === "remote"
                  ? { host: "remote" }
                  : null,
          };
        }),
      };
      const result = textResult(payload);
      auditCall(result, { meta: true });
      return result;
    }

    if (name === "mf_list_tools") {
      const tools = await upstream.listNamespacedTools(ctx.workspaceId);
      const filtered = tools.filter(
        (t) =>
          toolAllowedByScopes(t.name, ctx.scopes) &&
          toolAllowedByProject(t.name, project),
      );
      const payload = {
        project: project?.slug ?? null,
        tools: filtered.map((t) => ({
          name: t.name,
          description: t.description,
          backend: t.backendSlug,
        })),
      };
      const result = textResult(payload);
      auditCall(result, { meta: true });
      return result;
    }

    if (name === "mf_list_projects") {
      const all = store.listProjects(ctx.workspaceId);
      const projects = all.filter((p) => keyMayUseProject(ctx.scopes, p.slug));
      const payload = {
        active: project
          ? { id: project.id, slug: project.slug, title: project.title }
          : null,
        projects: projects.map((p) => ({
          id: p.id,
          slug: p.slug,
          title: p.title,
          description: p.description,
          backendSlugs: p.backendSlugs,
          isDefault: p.isDefault,
          active: project?.id === p.id,
        })),
      };
      const result = textResult(payload);
      auditCall(result, { meta: true });
      return result;
    }

    if (name === "mf_current_project") {
      const result = textResult({
        project: project
          ? {
              id: project.id,
              slug: project.slug,
              title: project.title,
              backendSlugs: project.backendSlugs,
              isDefault: project.isDefault,
            }
          : null,
        mcpSessionId: ctx.mcpSessionId ?? null,
      });
      auditCall(result, { meta: true });
      return result;
    }

    if (name === "mf_use_project") {
      const slug = String(args.project ?? "")
        .trim()
        .toLowerCase();
      if (!slug) {
        const result = textResult("project slug required", true);
        auditCall(result, { meta: true });
        return result;
      }
      if (!keyMayUseProject(ctx.scopes, slug)) {
        const result = textResult(
          `key cannot use project: ${slug}`,
          true,
        );
        auditCall(result, { meta: true });
        return result;
      }
      const target = store.getProjectBySlug(ctx.workspaceId, slug);
      if (!target) {
        const result = textResult(`project not found: ${slug}`, true);
        auditCall(result, { meta: true });
        return result;
      }
      // Bind MCP session sticky when we have a session id
      const sid =
        ctx.mcpSessionId ||
        (ctx.keyId ? `key:${ctx.keyId}` : null);
      if (sid && ctx.keyId) {
        globalSessionProjects.set(sid, {
          projectId: target.id,
          projectSlug: target.slug,
          keyId: ctx.keyId,
        });
        // mutate auth for remainder of this request
        ctx.projectId = target.id;
        ctx.projectSlug = target.slug;
        if (!ctx.mcpSessionId) ctx.mcpSessionId = sid;
      }

      let sessionToken: string | undefined;
      let sessionMeta: Record<string, unknown> | undefined;
      const mint =
        args.mintSessionToken !== false && Boolean(ctx.keyId);
      if (mint && ctx.keyId) {
        const sess = store.createProjectSession(
          ctx.workspaceId,
          ctx.keyId,
          target.id,
        );
        sessionToken = sess.token;
        sessionMeta = {
          sessionId: sess.id,
          expiresAt: sess.expiresAt,
          token: sess.token,
        };
      }

      store.writeAudit({
        workspaceId: ctx.workspaceId,
        keyId: ctx.keyId,
        action: "project.use",
        detail: {
          project: target.slug,
          mcpSessionId: sid,
          mintedSessionToken: Boolean(sessionToken),
        },
        ip,
      });

      const result = textResult({
        ok: true,
        project: {
          id: target.id,
          slug: target.slug,
          title: target.title,
          backendSlugs: target.backendSlugs,
        },
        mcpSessionId: sid,
        sessionToken: sessionToken ?? null,
        session: sessionMeta ?? null,
        note: sessionToken
          ? "Optional: use sessionToken as Bearer for project-scoped /mcp calls. Re-run tools/list."
          : "Project bound to this session. Re-run tools/list to refresh available tools.",
      });
      auditCall(result, { meta: true });
      return result;
    }

    if (name === "mf_status") {
      const backends = store.listBackends(ctx.workspaceId);
      const enabled = backends.filter((b) => b.enabled);
      const devices = store.listDevices(ctx.workspaceId);
      const online = edgeHub
        ? devices.filter((d) => edgeHub.isOnline(d.id)).length
        : 0;
      const payload = {
        ok: true,
        workspaceId: ctx.workspaceId,
        keyId: ctx.keyId ?? null,
        keyName: ctx.keyName ?? null,
        scopes: ctx.scopes ?? null,
        project: project
          ? { slug: project.slug, backendSlugs: project.backendSlugs }
          : null,
        backends: {
          total: backends.length,
          enabled: enabled.length,
          inProject: project
            ? backends.filter((b) => project.backendSlugs.includes(b.slug))
                .length
            : backends.length,
        },
        devices: {
          total: devices.length,
          online,
        },
        stickyDeviceId: edgeRouter?.sticky.get(ctx.keyId) ?? null,
        placementModesSupported: supportedPlacementModes({ edgeEnabled }),
        policy: store.getWorkspace(ctx.workspaceId)?.policy ?? null,
      };
      const result = textResult(payload);
      auditCall(result, { meta: true });
      return result;
    }

    if (name === "mf_use_device") {
      if (!edgeRouter) {
        const result = textResult("edge routing not enabled", true);
        auditCall(result, { meta: true });
        return result;
      }
      const deviceId = String(args.deviceId ?? "").trim();
      if (!deviceId) {
        if (ctx.keyId) edgeRouter.sticky.clear(ctx.keyId);
        const result = textResult({ ok: true, stickyDeviceId: null });
        auditCall(result, { meta: true });
        return result;
      }
      const d = store.getDevice(ctx.workspaceId, deviceId);
      if (!d) {
        const result = textResult(`device not found: ${deviceId}`, true);
        auditCall(result, { meta: true });
        return result;
      }
      if (ctx.keyId) edgeRouter.sticky.set(ctx.keyId, deviceId);
      const result = textResult({ ok: true, stickyDeviceId: deviceId });
      auditCall(result, { meta: true });
      return result;
    }

    if (name.startsWith("mf_admin_")) {
      if (!isAdminScopes(ctx.scopes)) {
        const result = textResult(`admin key required for ${name}`, true);
        store.writeAudit({
          workspaceId: ctx.workspaceId,
          keyId: ctx.keyId,
          action: "tools/call",
          tool: name,
          detail: toolCallAuditDetail({
            denied: true,
            reason: "admin_required",
            arguments: args,
            durationMs: Date.now() - started,
          }),
          ip,
        });
        return result;
      }
      const result = await handleAdminTool(name, args, {
        store,
        pool: upstream,
        cfg,
        auth: ctx,
        edgeHub,
        ip,
        edgeEnabled,
      });
      auditCall(result, { meta: true });
      return result;
    }

    if (name.startsWith("mf_")) {
      const result = textResult(`Unknown meta tool: ${name}`, true);
      auditCall(result, { meta: true });
      return result;
    }

    const parsed = parseNamespacedTool(name);
    const ctxInfo = upstream.resolveCallContext(ctx.workspaceId, name);
    const result = await upstream.callTool(ctx.workspaceId, name, args);
    auditCall(result, {
      backendSlug: ctxInfo.backendSlug ?? parsed?.slug ?? null,
      placement: ctxInfo.placement,
      deviceId: ctxInfo.deviceId,
    });
    return result;
  });

  return server;
}

export async function smokeListTools(
  store: Store,
  pool: UpstreamPool,
  workspaceId: string,
): Promise<{ tools: string[]; backends: ReturnType<typeof toPublicBackend>[] }> {
  const tools = await pool.listNamespacedTools(workspaceId);
  return {
    tools: tools.map((t) => t.name),
    backends: store.listBackends(workspaceId),
  };
}

export { CONTROL_PLANE_MODES };
