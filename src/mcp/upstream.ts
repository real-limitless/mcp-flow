import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Store } from "../db/store.js";
import type { BackendRecord } from "../types.js";
import { toPublicBackend } from "../db/store.js";

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
}

const TOOL_CACHE_MS = 30_000;

export class UpstreamPool {
  private pool = new Map<string, PooledClient>();

  constructor(private store: Store) {}

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
    }
  }

  private async connect(backend: BackendRecord): Promise<PooledClient> {
    try {
      const placement = JSON.parse(backend.placementJson) as { mode?: string };
      if (placement.mode && placement.mode !== "remote") {
        throw new Error(
          `placement ${placement.mode} is not implemented yet (stub remote only)`,
        );
      }
    } catch (err) {
      if (err instanceof Error && err.message.startsWith("placement ")) {
        throw err;
      }
    }

    if (
      backend.transport !== "streamable-http" &&
      backend.transport !== "sse"
    ) {
      throw new Error(
        `transport ${backend.transport} not supported in P1 (remote http/sse only)`,
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
    const entry: PooledClient = {
      backendId: backend.id,
      client,
      transport,
      tools: listed.tools ?? [],
      fetchedAt: Date.now(),
    };
    this.pool.set(backend.id, entry);
    return entry;
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
    }
    return this.connect(backend);
  }

  async listNamespacedTools(workspaceId: string): Promise<NamespacedTool[]> {
    const backends = this.store.listEnabledBackends(workspaceId);
    const out: NamespacedTool[] = [];

    await Promise.all(
      backends.map(async (backend) => {
        if (backend.transport !== "streamable-http" && backend.transport !== "sse") {
          return;
        }
        try {
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
          // Skip failed backends on list; surface via meta status
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

    try {
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

  async testBackend(backend: BackendRecord): Promise<{
    ok: boolean;
    toolCount?: number;
    tools?: string[];
    error?: string;
    backend: ReturnType<typeof toPublicBackend>;
  }> {
    const pub = toPublicBackend(backend);
    try {
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
