import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import type { BackendRecord, Placement } from "../types.js";
import { connectOci } from "./runners/oci.js";
import { connectStdioCommand } from "./runners/stdio.js";
import type { EdgeRouter } from "../edge/router.js";

export interface NamespacedTool extends Tool {
  /** Original upstream tool name */
  upstreamName: string;
  backendSlug: string;
  backendId: string;
}

export function namespaceTool(slug: string, name: string): string {
  return `${slug}__${name}`;
}

export function parseNamespacedTool(
  namespaced: string,
): { slug: string; tool: string } | null {
  const idx = namespaced.indexOf("__");
  if (idx <= 0) return null;
  return {
    slug: namespaced.slice(0, idx),
    tool: namespaced.slice(idx + 2),
  };
}

interface PooledClient {
  backendId: string;
  client: Client;
  transport: Transport;
  tools: Tool[];
  fetchedAt: number;
  dispose?: () => Promise<void>;
  placementMode: string;
  deviceId?: string;
}

const TOOL_CACHE_MS = 30_000;

function parsePlacement(backend: BackendRecord): Placement {
  try {
    return JSON.parse(backend.placementJson) as Placement;
  } catch {
    return { mode: "remote" };
  }
}

export class UpstreamPool {
  private pool = new Map<string, PooledClient>();
  private edgeRouter: EdgeRouter | null = null;

  constructor(private store: Store) {}

  setEdgeRouter(router: EdgeRouter | null): void {
    this.edgeRouter = router;
  }

  async closeAll(): Promise<void> {
    const entries = [...this.pool.values()];
    this.pool.clear();
    await Promise.allSettled(
      entries.map(async (e) => {
        try {
          await e.client.close();
        } catch {
          /* ignore */
        }
        if (e.dispose) {
          try {
            await e.dispose();
          } catch {
            /* ignore */
          }
        }
      }),
    );
  }

  invalidate(backendId?: string): void {
    if (!backendId) {
      void this.closeAll();
      return;
    }
    const e = this.pool.get(backendId);
    if (e) {
      this.pool.delete(backendId);
      void e.client.close().catch(() => undefined);
      if (e.dispose) void e.dispose().catch(() => undefined);
    }
  }

  private async connectRemote(backend: BackendRecord): Promise<PooledClient> {
    if (
      backend.transport !== "streamable-http" &&
      backend.transport !== "sse"
    ) {
      throw new Error(
        `remote placement requires http/sse transport (got ${backend.transport})`,
      );
    }
    if (!backend.url) {
      throw new Error(`backend ${backend.slug} has no url`);
    }

    const headers = this.store.decryptHeaders(backend);
    const url = new URL(backend.url);

    const client = new Client(
      { name: "mcp-flow-upstream", version: "0.1.0" },
      { capabilities: {} },
    );

    let transport: Transport;
    const requestInit: RequestInit = {
      headers: { ...headers },
    };

    if (backend.transport === "sse") {
      transport = new SSEClientTransport(url, { requestInit });
    } else {
      transport = new StreamableHTTPClientTransport(url, { requestInit });
    }

    await client.connect(transport);
    const listed = await client.listTools();
    return {
      backendId: backend.id,
      client,
      transport,
      tools: listed.tools ?? [],
      fetchedAt: Date.now(),
      placementMode: "remote",
    };
  }

  private async connectCentralSandbox(
    backend: BackendRecord,
  ): Promise<PooledClient> {
    const env = this.store.decryptEnv(backend);
    const pub = toPublicBackend(backend);

    if (backend.transport === "stdio") {
      if (!pub.command?.length) {
        throw new Error(`stdio backend ${backend.slug} has no command`);
      }
      const run = await connectStdioCommand({
        command: pub.command,
        env,
      });
      return {
        backendId: backend.id,
        client: run.client,
        transport: run.transport,
        tools: run.tools,
        fetchedAt: Date.now(),
        dispose: run.dispose,
        placementMode: "central-sandbox",
      };
    }

    if (backend.transport === "oci") {
      if (!backend.image) {
        throw new Error(`oci backend ${backend.slug} has no image`);
      }
      const run = await connectOci({
        image: backend.image,
        command: pub.command,
        env,
        sandbox: pub.sandbox,
      });
      return {
        backendId: backend.id,
        client: run.client,
        transport: run.transport,
        tools: run.tools,
        fetchedAt: Date.now(),
        dispose: run.dispose,
        placementMode: "central-sandbox",
      };
    }

    throw new Error(
      `central-sandbox does not support transport ${backend.transport}`,
    );
  }

  private async connect(backend: BackendRecord): Promise<PooledClient> {
    const placement = parsePlacement(backend);
    const mode = placement.mode ?? "remote";

    if (mode === "remote") {
      return this.connectRemote(backend);
    }

    if (mode === "central-sandbox") {
      return this.connectCentralSandbox(backend);
    }

    if (mode === "edge-sandbox" || mode === "edge-bare") {
      if (!this.edgeRouter) {
        throw new Error(
          `placement ${mode} requires edge hub (not configured)`,
        );
      }
      // Edge path uses RPC, not a local pooled client — handled in call/list
      throw new Error(`EDGE_ROUTE:${mode}`);
    }

    throw new Error(`placement ${mode} is not implemented`);
  }

  private async getClient(backend: BackendRecord): Promise<PooledClient> {
    const existing = this.pool.get(backend.id);
    if (existing && Date.now() - existing.fetchedAt < TOOL_CACHE_MS) {
      return existing;
    }
    if (existing) {
      this.pool.delete(backend.id);
      try {
        await existing.client.close();
      } catch {
        /* ignore */
      }
      if (existing.dispose) {
        try {
          await existing.dispose();
        } catch {
          /* ignore */
        }
      }
    }
    const entry = await this.connect(backend);
    this.pool.set(backend.id, entry);
    return entry;
  }

  async listNamespacedTools(workspaceId: string): Promise<NamespacedTool[]> {
    const backends = this.store.listEnabledBackends(workspaceId);
    const out: NamespacedTool[] = [];

    await Promise.all(
      backends.map(async (backend) => {
        const placement = parsePlacement(backend);
        try {
          if (
            placement.mode === "edge-sandbox" ||
            placement.mode === "edge-bare"
          ) {
            if (!this.edgeRouter) return;
            const tools = await this.edgeRouter.listTools(backend);
            const allow = backend.toolAllowlistJson
              ? new Set(JSON.parse(backend.toolAllowlistJson) as string[])
              : null;
            for (const t of tools) {
              if (allow && !allow.has(t.name)) continue;
              out.push({
                ...t,
                name: namespaceTool(backend.slug, t.name),
                description: t.description
                  ? `[${backend.slug}] ${t.description}`
                  : `[${backend.slug}] ${t.name}`,
                upstreamName: t.name,
                backendSlug: backend.slug,
                backendId: backend.id,
              });
            }
            return;
          }

          const pooled = await this.getClient(backend);
          const allow = backend.toolAllowlistJson
            ? new Set(JSON.parse(backend.toolAllowlistJson) as string[])
            : null;
          for (const t of pooled.tools) {
            if (allow && !allow.has(t.name)) continue;
            out.push({
              ...t,
              name: namespaceTool(backend.slug, t.name),
              description: t.description
                ? `[${backend.slug}] ${t.description}`
                : `[${backend.slug}] ${t.name}`,
              upstreamName: t.name,
              backendSlug: backend.slug,
              backendId: backend.id,
            });
          }
        } catch (err) {
          console.error(
            `[mcp-flow] tools/list failed for backend ${backend.slug}:`,
            err instanceof Error ? err.message : err,
          );
        }
      }),
    );

    out.sort((a, b) => a.name.localeCompare(b.name));
    return out;
  }

  async callTool(
    workspaceId: string,
    namespacedName: string,
    args: Record<string, unknown> | undefined,
  ): Promise<CallToolResult> {
    const parsed = parseNamespacedTool(namespacedName);
    if (!parsed) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Invalid tool name (expected slug__tool): ${namespacedName}`,
          },
        ],
      };
    }

    const backend = this.store.getBackend(workspaceId, parsed.slug);
    if (!backend || !backend.enabled) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Backend not found or disabled: ${parsed.slug}`,
          },
        ],
      };
    }

    if (backend.toolAllowlistJson) {
      const allow = new Set(
        JSON.parse(backend.toolAllowlistJson) as string[],
      );
      if (!allow.has(parsed.tool)) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `Tool ${parsed.tool} not on allowlist for ${backend.slug}`,
            },
          ],
        };
      }
    }

    const placement = parsePlacement(backend);

    try {
      if (
        placement.mode === "edge-sandbox" ||
        placement.mode === "edge-bare"
      ) {
        if (!this.edgeRouter) {
          throw new Error("edge hub not configured");
        }
        return await this.edgeRouter.callTool(
          backend,
          parsed.tool,
          args ?? {},
        );
      }

      const pooled = await this.getClient(backend);
      const result = await pooled.client.callTool({
        name: parsed.tool,
        arguments: args ?? {},
      });
      return result as CallToolResult;
    } catch (err) {
      this.invalidate(backend.id);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Upstream error (${backend.slug}): ${
              err instanceof Error ? err.message : String(err)
            }`,
          },
        ],
      };
    }
  }

  /** Placement + device context for audit */
  resolveCallContext(workspaceId: string, namespacedName: string): {
    backendSlug: string | null;
    placement: string | null;
    deviceId: string | null;
  } {
    const parsed = parseNamespacedTool(namespacedName);
    if (!parsed) {
      return { backendSlug: null, placement: null, deviceId: null };
    }
    const backend = this.store.getBackend(workspaceId, parsed.slug);
    if (!backend) {
      return { backendSlug: parsed.slug, placement: null, deviceId: null };
    }
    const placement = parsePlacement(backend);
    return {
      backendSlug: backend.slug,
      placement: placement.mode,
      deviceId: placement.deviceId ?? null,
    };
  }

  async testBackend(backend: BackendRecord): Promise<{
    ok: boolean;
    toolCount?: number;
    tools?: string[];
    error?: string;
    backend: ReturnType<typeof toPublicBackend>;
  }> {
    const pub = toPublicBackend(backend);
    const placement = parsePlacement(backend);
    try {
      if (
        placement.mode === "edge-sandbox" ||
        placement.mode === "edge-bare"
      ) {
        if (!this.edgeRouter) {
          throw new Error("edge hub not configured");
        }
        const tools = await this.edgeRouter.listTools(backend);
        return {
          ok: true,
          toolCount: tools.length,
          tools: tools.map((t) => t.name),
          backend: pub,
        };
      }
      this.invalidate(backend.id);
      const pooled = await this.getClient(backend);
      return {
        ok: true,
        toolCount: pooled.tools.length,
        tools: pooled.tools.map((t) => t.name),
        backend: pub,
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        backend: pub,
      };
    }
  }
}
