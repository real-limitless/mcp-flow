import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { type Store } from "../db/store.js";
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
import { redactLog } from "../log/redact-lines.js";

export interface NamespacedTool extends Tool {
  /** Original upstream tool name */
  upstreamName: string;
  backendSlug: string;
  backendId: string;
}

export function namespaceTool(slug: string, name: string): string {
  return `${slug}__${name}`;
}

/** tools/call result plus whether a request was sent to the backend. */
export type UpstreamCallResult = CallToolResult & { sent: boolean };

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
  /** Transport closed or failed. The pool entry must not be reused. */
  dead: boolean;
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

/** The SDK rejects with this before Protocol.request writes to the transport. */
function isPreWriteRejection(err: unknown): boolean {
  const message = err instanceof Error ? err.message : String(err);
  return /not connected/i.test(message);
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
  /**
   * Tool names already learned from a tools/list or an open client.
   * Read-only lookups must not connect or spawn a backend.
   */
  private knownNames = new Map<string, Set<string>>();

  constructor(private store: Store) {
    store.onBackendRetired((workspaceId, slug) => {
      this.forgetBackendTools(workspaceId, slug);
    });
  }

  setEdgeRouter(router: EdgeRouter | null): void {
    this.edgeRouter = router;
  }

  private rememberNames(workspaceId: string, names: Iterable<string>): void {
    let known = this.knownNames.get(workspaceId);
    if (!known) {
      known = new Set();
      this.knownNames.set(workspaceId, known);
    }
    for (const name of names) known.add(name);
  }

  private forgetBackendTools(workspaceId: string, slug: string): void {
    const known = this.knownNames.get(workspaceId);
    if (!known) return;
    for (const name of known) {
      if (parseNamespacedTool(name)?.slug === slug) known.delete(name);
    }
  }

  private allowSet(backend: BackendRecord): Set<string> | null {
    if (!backend.toolAllowlistJson) return null;
    try {
      const parsed = JSON.parse(backend.toolAllowlistJson) as unknown;
      if (!Array.isArray(parsed)) return new Set();
      return new Set(parsed.filter((item): item is string => typeof item === "string"));
    } catch {
      return new Set();
    }
  }

  /** Cached name still belongs to an enabled backend and its current allowlist. */
  private nameStillListed(workspaceId: string, name: string): boolean {
    const parsed = parseNamespacedTool(name);
    if (!parsed) return false;
    const backend = this.store.getBackend(workspaceId, parsed.slug);
    if (!backend?.enabled) return false;
    const allow = this.allowSet(backend);
    return !allow || allow.has(parsed.tool);
  }

  /**
   * Namespaced tools this process has already listed or still has open,
   * limited to backends that are enabled now and tools on the current allowlist.
   * Does not connect, refresh, or spawn a backend. Dispatch must not use this.
   */
  knownToolNames(workspaceId: string): ReadonlySet<string> {
    const names = new Set<string>();
    for (const name of this.knownNames.get(workspaceId) ?? []) {
      if (this.nameStillListed(workspaceId, name)) names.add(name);
    }
    for (const backend of this.store.listEnabledBackends(workspaceId)) {
      const pooled = this.pool.get(backend.id);
      if (!pooled) continue;
      const allow = this.allowSet(backend);
      for (const tool of pooled.tools) {
        if (allow && !allow.has(tool.name)) continue;
        names.add(namespaceTool(backend.slug, tool.name));
      }
    }
    return names;
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
        dead: false,
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
        dead: false,
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
        dead: false,
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

  /** Drop the pool entry when its transport closes or the connection fails. */
  private watchTransport(entry: PooledClient): void {
    entry.client.onclose = () => {
      entry.dead = true;
      if (this.pool.get(entry.backendId) === entry) void this.retire(entry.backendId);
    };
    entry.client.onerror = (error: Error) => {
      if (!isTransportOrConnectionError(error)) return;
      entry.dead = true;
      if (this.pool.get(entry.backendId) === entry) void this.retire(entry.backendId);
    };
  }

  /** False when the SDK has already dropped the transport or the stdio process is gone. */
  private transportAlive(entry: PooledClient): boolean {
    if (entry.dead) return false;
    const client = entry.client as Client & { transport?: unknown };
    if (!client.transport) return false;
    const transport = entry.transport as { pid?: number | null };
    if (!("pid" in transport)) return true;
    const pid = transport.pid;
    if (pid == null) return false;
    try {
      process.kill(pid, 0);
    } catch {
      return false;
    }
    return true;
  }

  private async connectAndStore(backend: BackendRecord): Promise<PooledClient> {
    const generation = this.generation;
    const entry = await this.connect(backend);
    this.watchTransport(entry);
    if (this.closing || generation !== this.generation || entry.dead) {
      await this.closeEntry(entry);
      throw new Error(entry.dead ? "Not connected" : "upstream pool is closing");
    }
    const previous = this.pool.get(backend.id);
    if (previous && previous !== entry) {
      await this.closeEntry(previous);
    }
    if (this.closing || entry.dead) {
      await this.closeEntry(entry);
      throw new Error(entry.dead ? "Not connected" : "upstream pool is closing");
    }
    this.pool.set(backend.id, entry);
    return entry;
  }

  private async getClient(backend: BackendRecord): Promise<PooledClient> {
    const retiring = this.retiring.get(backend.id);
    if (retiring) await retiring;
    if (this.closing) throw new Error("upstream pool is closing");

    const existing = this.pool.get(backend.id);
    if (existing && !existing.dead && this.transportAlive(existing)) {
      if (Date.now() - existing.fetchedAt >= TOOL_CACHE_MS) {
        try {
          await this.refreshTools(existing);
        } catch (err) {
          if (this.pool.get(backend.id) === existing) await this.retire(backend.id);
          if (!isTransportOrConnectionError(err)) throw err;
        }
      }
      if (
        this.pool.get(backend.id) === existing &&
        !existing.dead &&
        this.transportAlive(existing)
      ) {
        return existing;
      }
    } else if (existing) {
      await this.retire(backend.id);
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
            redactLog(err),
          );
          if (isTransportOrConnectionError(err)) await this.retire(backend.id);
        }
      }),
    );

    out.sort((a, b) => a.name.localeCompare(b.name));
    this.rememberNames(workspaceId, out.map((tool) => tool.name));
    return out;
  }

  /**
   * Whether slug__tool can be sent to its enabled backend right now.
   * Looks up that backend only. Does not use the audit name cache and does not send a tools/call.
   */
  async toolIsCallable(workspaceId: string, namespacedName: string): Promise<boolean> {
    const parsed = parseNamespacedTool(namespacedName);
    if (!parsed) return false;
    const backend = this.store.getBackend(workspaceId, parsed.slug);
    if (!backend?.enabled) return false;
    const allow = this.allowSet(backend);
    if (allow && !allow.has(parsed.tool)) return false;
    const placement = parsePlacement(backend);
    try {
      if (placement.mode === "edge-sandbox" || placement.mode === "edge-bare") {
        if (!this.edgeRouter) return false;
        const tools = await this.edgeRouter.listTools(backend);
        return tools.some((tool) => tool.name === parsed.tool);
      }
      const pooled = await this.getClient(backend);
      return pooled.tools.some((tool) => tool.name === parsed.tool);
    } catch (err) {
      if (isTransportOrConnectionError(err)) await this.retire(backend.id);
      return false;
    }
  }

  private notSent(text: string): UpstreamCallResult {
    return {
      isError: true,
      sent: false,
      content: [{ type: "text", text }],
    };
  }

  private upstreamError(slug: string, err: unknown, sent: boolean): UpstreamCallResult {
    return {
      isError: true,
      sent,
      content: [
        {
          type: "text",
          text: `Upstream error (${slug}): ${
            err instanceof Error ? err.message : String(err)
          }`,
        },
      ],
    };
  }

  /**
   * Resolve slug__tool on the matching enabled backend and call it.
   * sent is true only after a tools/call request is handed to that backend.
   * Allowlist misses, disabled or deleted backends, and tools that are not
   * listed return sent:false and do not send a request.
   */
  async callTool(
    workspaceId: string,
    namespacedName: string,
    args: Record<string, unknown> | undefined,
  ): Promise<UpstreamCallResult> {
    const parsed = parseNamespacedTool(namespacedName);
    if (!parsed) return this.notSent("tool not found");

    const backend = this.store.getBackend(workspaceId, parsed.slug);
    if (!backend || !backend.enabled) return this.notSent("tool not found");

    const allow = this.allowSet(backend);
    if (allow && !allow.has(parsed.tool)) return this.notSent("tool not found");

    const placement = parsePlacement(backend);

    try {
      if (
        placement.mode === "edge-sandbox" ||
        placement.mode === "edge-bare"
      ) {
        if (!this.edgeRouter) return this.notSent("tool not found");
        let tools;
        try {
          tools = await this.edgeRouter.listTools(backend);
        } catch (err) {
          return this.upstreamError(backend.slug, err, false);
        }
        if (!tools.some((tool) => tool.name === parsed.tool)) {
          return this.notSent("tool not found");
        }
        try {
          const result = await this.edgeRouter.callTool(
            backend,
            parsed.tool,
            args ?? {},
          );
          return { ...result, sent: true };
        } catch (err) {
          return this.upstreamError(backend.slug, err, !isPreWriteRejection(err));
        }
      }

      let pooled;
      try {
        pooled = await this.getClient(backend);
      } catch (err) {
        if (isTransportOrConnectionError(err)) await this.retire(backend.id);
        return this.upstreamError(backend.slug, err, false);
      }
      if (!pooled.tools.some((tool) => tool.name === parsed.tool)) {
        return this.notSent("tool not found");
      }
      if (pooled.dead || !this.transportAlive(pooled)) {
        pooled.dead = true;
        await this.retire(backend.id);
        return this.notSent("tool not found");
      }
      const previousSend = pooled.transport.send;
      const originalSend = previousSend.bind(pooled.transport);
      let wrote = false;
      const wrappedSend = (async (message, options) => {
        const value = await originalSend(message, options);
        wrote = true;
        return value;
      }) as Transport["send"];
      pooled.transport.send = wrappedSend;
      try {
        const result = await pooled.client.callTool({
          name: parsed.tool,
          arguments: args ?? {},
        });
        return { ...(result as CallToolResult), sent: true };
      } catch (err) {
        if (!wrote || isTransportOrConnectionError(err)) {
          pooled.dead = true;
          await this.retire(backend.id);
        }
        return this.upstreamError(backend.slug, err, wrote && !isPreWriteRejection(err));
      } finally {
        if (pooled.transport.send === wrappedSend) pooled.transport.send = previousSend;
      }
    } catch (err) {
      if (isTransportOrConnectionError(err)) await this.retire(backend.id);
      return this.upstreamError(backend.slug, err, false);
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
