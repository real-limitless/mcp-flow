import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { toolCallAuditDetail } from "../audit/sanitize.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import type { EdgeHub } from "../edge/hub.js";
import type { EdgeRouter } from "../edge/router.js";
import { CONTROL_PLANE_MODES, supportedPlacementModes } from "../placement.js";
import type { AuthContext } from "../types.js";
import { toolAllowedByScopes } from "../types.js";
import { parseNamespacedTool, UpstreamPool } from "./upstream.js";

const META_TOOLS: Tool[] = [
  {
    name: "mf_list_backends",
    description:
      "List MCP backends registered in this workspace (secrets redacted).",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "mf_list_tools",
    description:
      "List namespaced tools available through mcp-flow (slug__tool).",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  {
    name: "mf_status",
    description: "Gateway status for the current API key / workspace.",
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

function filterTools(tools: Tool[], auth: AuthContext): Tool[] {
  return tools.filter((t) => toolAllowedByScopes(t.name, auth.scopes));
}

export interface GatewayDeps {
  store: Store;
  pool: UpstreamPool;
  auth: AuthContext;
  edgeHub?: EdgeHub | null;
  edgeRouter?: EdgeRouter | null;
  /** Client IP for audit */
  ip?: string | null;
}

export function createGatewayServer(deps: GatewayDeps): Server {
  const { store, pool: upstream, auth: ctx } = deps;
  const ip = deps.ip ?? null;
  const edgeHub = deps.edgeHub ?? null;
  const edgeRouter = deps.edgeRouter ?? null;

  const server = new Server(
    { name: "mcp-flow", version: "0.1.0" },
    { capabilities: { tools: { listChanged: true } } },
  );

  const edgeEnabled = Boolean(edgeHub);

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const upstreamTools = await upstream.listNamespacedTools(ctx.workspaceId);
    const tools: Tool[] = filterTools(
      [
        ...META_TOOLS,
        ...upstreamTools.map(
          ({ upstreamName: _u, backendSlug: _s, backendId: _b, ...tool }) =>
            tool,
        ),
      ],
      ctx,
    );
    store.writeAudit({
      workspaceId: ctx.workspaceId,
      keyId: ctx.keyId,
      action: "tools/list",
      detail: { count: tools.length },
      ip,
    });
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    const started = Date.now();

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
      const backends = store.listBackends(ctx.workspaceId).map((b) => {
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
      });
      const payload = { backends };
      const result = textResult(payload);
      auditCall(result, { meta: true });
      return result;
    }

    if (name === "mf_list_tools") {
      const tools = await upstream.listNamespacedTools(ctx.workspaceId);
      const filtered = tools.filter((t) =>
        toolAllowedByScopes(t.name, ctx.scopes),
      );
      const payload = {
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
        backends: {
          total: backends.length,
          enabled: enabled.length,
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
