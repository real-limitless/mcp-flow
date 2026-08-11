import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
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

export function createGatewayServer(
  store: Store,
  pool: UpstreamPool,
  auth: AuthContext,
): Server {
  const server = new Server(
    { name: "mcp-flow", version: "0.1.0" },
    { capabilities: { tools: { listChanged: true } } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    const upstream = await pool.listNamespacedTools(auth.workspaceId);
    const tools: Tool[] = filterTools(
      [
        ...META_TOOLS,
        ...upstream.map(
          ({ upstreamName: _u, backendSlug: _s, backendId: _b, ...tool }) =>
            tool,
        ),
      ],
      auth,
    );
    store.writeAudit({
      workspaceId: auth.workspaceId,
      keyId: auth.keyId,
      action: "tools/list",
      detail: { count: tools.length },
    });
    return { tools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const name = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;

    if (!toolAllowedByScopes(name, auth.scopes)) {
      store.writeAudit({
        workspaceId: auth.workspaceId,
        keyId: auth.keyId,
        action: "tools/call",
        tool: name,
        detail: { denied: true, reason: "scope" },
      });
      return textResult(`Tool not allowed by API key scopes: ${name}`, true);
    }

    if (name === "mf_list_backends") {
      const backends = store
        .listBackends(auth.workspaceId)
        .map((b) => ({
          slug: b.slug,
          title: b.title,
          transport: b.transport,
          enabled: b.enabled,
          placement: b.placement,
          hasHeaders: b.hasHeaders,
          hasEnv: b.hasEnv,
          url: b.url,
        }));
      return textResult({ backends });
    }

    if (name === "mf_list_tools") {
      const tools = await pool.listNamespacedTools(auth.workspaceId);
      const filtered = tools.filter((t) =>
        toolAllowedByScopes(t.name, auth.scopes),
      );
      return textResult({
        tools: filtered.map((t) => ({
          name: t.name,
          description: t.description,
          backend: t.backendSlug,
        })),
      });
    }

    if (name === "mf_status") {
      const backends = store.listBackends(auth.workspaceId);
      const enabled = backends.filter((b) => b.enabled);
      return textResult({
        ok: true,
        workspaceId: auth.workspaceId,
        keyId: auth.keyId ?? null,
        keyName: auth.keyName ?? null,
        scopes: auth.scopes ?? null,
        backends: {
          total: backends.length,
          enabled: enabled.length,
        },
        placementModesSupported: ["remote"],
      });
    }

    if (name.startsWith("mf_")) {
      return textResult(`Unknown meta tool: ${name}`, true);
    }

    const parsed = parseNamespacedTool(name);
    const result = await pool.callTool(auth.workspaceId, name, args);
    store.writeAudit({
      workspaceId: auth.workspaceId,
      keyId: auth.keyId,
      action: "tools/call",
      tool: name,
      backendSlug: parsed?.slug ?? null,
      placement: "remote",
      detail: { isError: Boolean(result.isError) },
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
