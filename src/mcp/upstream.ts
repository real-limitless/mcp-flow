import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import type { BackendRecord, Placement } from "../types.js";
import { connectOci } from "./runners/oci.js";
import {
  armStdioReap,
  connectStdioCommand,
  disarmStdioReap,
  killLiveStdio,
  STDIO_GROUP_KILL_BUDGET_MS,
} from "./runners/stdio.js";
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

/** Re-list tools on the open client after this age. Do not reconnect. */
const TOOL_CACHE_MS = 30_000;

/**
 * How long closeAll waits for an in-flight connect before killing the spawn.
 * 10s shutdown − 8s drain − process-group kill. A slow npx install or a hung
 * initialize cannot stretch shutdown past that budget.
 */
export const INFLIGHT_CLOSE_DEADLINE_MS = Math.max(
  0,
  10_000 - 8_000 - STDIO_GROUP_KILL_BUDGET_MS,
);

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

const TRANSPORT_ERRNO = new Set([
  "ECONNRESET",
  "ECONNREFUSED",
  "EPIPE",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ECONNABORTED",
  "EAI_AGAIN",
]);

/**
 * Socket and stdio disconnects. Not tool errors.
 * JSON-RPC -32000 is also used for ordinary request failures, so the code
 * alone is not enough — the message has to say the connection died.
 */
export function isTransportOrConnectionError(err: unknown): boolean {
  if (typeof err === "string") return transportMessage(err);
  if (!err || typeof err !== "object") return false;
  const code = (err as { code?: unknown }).code;
  if (typeof code === "string") {
    if (TRANSPORT_ERRNO.has(code) || code.startsWith("UND_ERR_")) return true;
  }
  const message = err instanceof Error ? err.message : String(err);
  return transportMessage(message);
}

function transportMessage(message: string): boolean {
  return /connection closed|not connected|econnreset|econnrefused|\bepipe\b|socket hang up|fetch failed|broken pipe|other side closed|process exited/i.test(
    message,
  );
}

function parsePlacement(backend: BackendRecord): Placement {
  try {
    return JSON.parse(backend.placementJson) as Placement;
  } catch {
    return { mode: "remote" };
  }
}

export class UpstreamPool {
  private pool = new Map<string, PooledClient>();
  /** In-flight connect, one per backend. Removed when the attempt settles. */
  private inflight = new Map<string, Promise<PooledClient>>();
  private refreshInflight = new Map<string, Promise<void>>();
  private closingEntries = new WeakMap<PooledClient, Promise<void>>();
  /** Close already started; getClient waits so a replacement cannot overlap. */
  private retiring = new Map<string, Promise<void>>();
  private edgeRouter: EdgeRouter | null = null;
  private closing = false;
  private drain: Promise<void> | null = null;
  /** Bumped by closeAll so a connect that finishes late cannot rejoin the pool. */
  private generation = 0;

  constructor(private store: Store) {}

  setEdgeRouter(router: EdgeRouter | null): void {
    this.edgeRouter = router;
  }

  private closeEntry(entry: PooledClient): Promise<void> {
    const pending = this.closingEntries.get(entry);
    if (pending) return pending;
    const job = (async () => {
      try {
        await entry.client.close();
      } catch {
        /* ignore */
      }
      // V53-F3: Client.close() skips the transport once it has already closed (backend crashed),
      // so close a stdio transport directly too; its group kill is idempotent.
      if (entry.transport instanceof StdioClientTransport) {
        try {
          await entry.transport.close();
        } catch {
          /* ignore */
        }
      }
      if (entry.dispose) {
        try {
          await entry.dispose();
        } catch {
          /* ignore */
        }
      }
    })();
    this.closingEntries.set(entry, job);
    return job;
  }

  async closeAll(): Promise<void> {
    if (this.drain) return this.drain;
    this.drain = this.drainPool().finally(() => {
      this.drain = null;
    });
    return this.drain;
  }

  private async drainPool(): Promise<void> {
    this.closing = true;
    this.generation += 1;
    try {
      const pending = [...this.inflight.values()];
      this.inflight.clear();
      const entries = [...this.pool.values()];
      this.pool.clear();

      let pendingSettled = pending.length === 0;
      const pendingDone = Promise.allSettled(pending).then(() => {
        pendingSettled = true;
      });
      // Close clients we already have while the connect deadline runs.
      const closingKnown = Promise.allSettled(
        entries.map((entry) => this.closeEntry(entry)),
      );

      const stopPending = async () => {
        if (pendingSettled) return;
        await Promise.race([pendingDone, sleep(INFLIGHT_CLOSE_DEADLINE_MS)]);
        if (pendingSettled) return;
        armStdioReap();
        await killLiveStdio();
      };

      await Promise.all([closingKnown, stopPending()]);

      const late = [...this.pool.values()];
      this.pool.clear();
      await Promise.allSettled(late.map((entry) => this.closeEntry(entry)));
    } finally {
      disarmStdioReap();
      this.closing = false;
    }
  }

  invalidate(backendId?: string): void {
    if (!backendId) {
      void this.closeAll();
      return;
    }
    void this.retire(backendId);
  }

  /**
   * Drop a backend and finish closing its client before any replacement spawn.
   * Callers that only need a best-effort drop can ignore the promise; getClient waits.
   */
  private retire(backendId: string): Promise<void> {
    const current = this.retiring.get(backendId);
    if (current) return current;
    const entry = this.pool.get(backendId);
    const pending = this.inflight.get(backendId);
    if (entry) this.pool.delete(backendId);
    if (pending) this.inflight.delete(backendId);
    const job = (async () => {
      if (pending) {
        try {
          const next = await pending;
          if (this.pool.get(backendId) === next) this.pool.delete(backendId);
          if (next !== entry) await this.closeEntry(next);
        } catch {
          /* connect failed; nothing new to keep */
        }
      }
      if (entry) await this.closeEntry(entry);
    })();
    this.retiring.set(backendId, job);
    void job.finally(() => {
      if (this.retiring.get(backendId) === job) this.retiring.delete(backendId);
    });
    return job;
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

    try {
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
    } catch (err) {
      try {
        await client.close();
      } catch {
        /* ignore */
      }
      throw err;
    }
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

  private refreshTools(entry: PooledClient): Promise<void> {
    const current = this.refreshInflight.get(entry.backendId);
    if (current) return current;
    const job = (async () => {
      const listed = await entry.client.listTools();
      entry.tools = listed.tools ?? [];
      entry.fetchedAt = Date.now();
    })();
    this.refreshInflight.set(entry.backendId, job);
    void job.finally(() => {
      if (this.refreshInflight.get(entry.backendId) === job) {
        this.refreshInflight.delete(entry.backendId);
      }
    });
    return job;
  }

  private async connectAndStore(backend: BackendRecord): Promise<PooledClient> {
    const generation = this.generation;
    const entry = await this.connect(backend);
    if (this.closing || generation !== this.generation) {
      await this.closeEntry(entry);
      throw new Error("upstream pool is closing");
    }
    const previous = this.pool.get(backend.id);
    if (previous && previous !== entry) {
      await this.closeEntry(previous);
    }
    if (this.closing) {
      await this.closeEntry(entry);
      throw new Error("upstream pool is closing");
    }
    this.pool.set(backend.id, entry);
    return entry;
  }

  private async getClient(backend: BackendRecord): Promise<PooledClient> {
    const retiring = this.retiring.get(backend.id);
    if (retiring) await retiring;
    if (this.closing) throw new Error("upstream pool is closing");

    const existing = this.pool.get(backend.id);
    if (existing) {
      if (Date.now() - existing.fetchedAt >= TOOL_CACHE_MS) {
        await this.refreshTools(existing);
      }
      return existing;
    }

    const pending = this.inflight.get(backend.id);
    if (pending) return pending;

    const promise = this.connectAndStore(backend);
    this.inflight.set(backend.id, promise);
    try {
      return await promise;
    } finally {
      if (this.inflight.get(backend.id) === promise) {
        this.inflight.delete(backend.id);
      }
    }
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
          if (isTransportOrConnectionError(err)) await this.retire(backend.id);
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
      if (isTransportOrConnectionError(err)) await this.retire(backend.id);
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
      let lastErr: unknown;
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          const pooled = await this.getClient(backend);
          return {
            ok: true,
            toolCount: pooled.tools.length,
            tools: pooled.tools.map((t) => t.name),
            backend: pub,
          };
        } catch (err) {
          lastErr = err;
          if (attempt === 0 && isTransportOrConnectionError(err)) {
            await this.retire(backend.id);
            continue;
          }
          throw err;
        }
      }
      throw lastErr;
    } catch (err) {
      const base = err instanceof Error ? err.message : String(err);
      const hdrs = this.store.decryptHeaders(backend);
      const hasAuth = Object.keys(hdrs).some((k) =>
        /^(authorization|x-api-key)$/i.test(k),
      );
      const hint =
        !hasAuth && /authentication required|unauthorized|\b401\b/i.test(base)
          ? `${base} (no sealed Authorization header — set apiKey or Authorization; Bearer is added automatically)`
          : base;
      return {
        ok: false,
        error: hint,
        backend: pub,
      };
    }
  }
}
