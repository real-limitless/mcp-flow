import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_BACKEND_INIT_TIMEOUT_MS } from "../config.js";
import { type Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import type { BackendRecord, Placement } from "../types.js";
import { connectOci } from "./runners/oci.js";
import {
  armStdioReap,
  connectStdioCommand,
  disarmStdioReap,
  isLiving,
  killLiveStdio,
} from "./runners/stdio.js";
import type { EdgeRouter } from "../edge/router.js";
import { redactLog } from "../log/redact-lines.js";
import { createSafeFetch } from "../oauth/fetch.js";
import { getOauthRow } from "../db/oauth-store.js";
import {
  NeedsReauthError,
  StoreOauthProvider,
} from "../oauth/provider.js";

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
 * How long closeAll waits for an in-flight connect before killing the spawn. A slow npx install or a
 * hung initialize cannot stretch shutdown past the budget: 7 s max grace + this + the 1 s group kill
 * leaves >= 1 s of the 10 s stop budget (V53 headroom; asserted in server.ts and tests).
 */
export const INFLIGHT_CLOSE_DEADLINE_MS = 500;

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

function publicUpstreamError(err: unknown): string {
  if (err instanceof NeedsReauthError) return err.message;
  return redactLog(err instanceof Error ? err : String(err));
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

function sameRpcId(left: unknown, right: unknown): boolean {
  if (typeof left === "number" && typeof right === "number") return left === right;
  if (typeof left === "string" && typeof right === "string") return left === right;
  if (
    (typeof left === "number" && typeof right === "string") ||
    (typeof left === "string" && typeof right === "number")
  ) {
    return String(left) === String(right);
  }
  return false;
}

/**
 * The child acknowledged this JSON-RPC id. A resolved stdin write is not
 * enough: the peer can accept the bytes and exit before reading them.
 */
function messageAcksRequest(message: unknown, requestId: string | number): boolean {
  if (!message || typeof message !== "object") return false;
  const msg = message as {
    id?: unknown;
    method?: unknown;
    params?: { progressToken?: unknown };
  };
  if (sameRpcId(msg.id, requestId)) return true;
  return (
    msg.method === "notifications/progress" &&
    sameRpcId(msg.params?.progressToken, requestId)
  );
}

/**
 * V53-F4: a backend that did not finish initialize + tools/list within the init timeout, or is in
 * the fail-fast cooldown after one. Typed so the gateway returns backend_unavailable instead of
 * waiting (QA v5.3/v5.4: one hung backend made every agent call wait ~60 s).
 */
export class BackendUnavailableError extends Error {
  readonly code = "backend_unavailable";
  constructor(
    readonly backendSlug: string,
    readonly cause_: "init_timeout" | "cooling_down",
    readonly retryAfterMs: number,
  ) {
    super(
      cause_ === "init_timeout"
        ? `backend ${backendSlug} did not initialize in time (backend_unavailable)`
        : `backend ${backendSlug} is unavailable after an init timeout; retry in ${retryAfterMs} ms (backend_unavailable)`,
    );
    this.name = "BackendUnavailableError";
  }
}

/** SDK request timeout (McpError RequestTimeout -32001). */
function isRequestTimeout(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  const message = err instanceof Error ? err.message : String(err);
  return code === -32001 || /request timed out/i.test(message);
}

export interface UpstreamPoolOptions {
  /** Bound for a backend's initialize + first tools/list, and for a tools/list refresh (ms). */
  initTimeoutMs?: number;
  /** How long a workspace listing waits for one backend before omitting it from that listing (ms). */
  listWaitMs?: number;
  /** After an init timeout the backend fails fast (no respawn) for this long (ms). */
  stuckCooldownMs?: number;
}

export const DEFAULT_LIST_WAIT_MS = 5_000;
export const DEFAULT_STUCK_COOLDOWN_MS = 30_000;

function parsePlacement(backend: BackendRecord): Placement {
  try {
    return JSON.parse(backend.placementJson) as Placement;
  } catch {
    return { mode: "remote" };
  }
}

export class UpstreamPool {
  private allowPrivateUrls: boolean;
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

  private readonly initTimeoutMs: number;
  private readonly listWaitMs: number;
  private readonly stuckCooldownMs: number;
  /** V53-F4: backendId -> time until which the backend fails fast after an init timeout. */
  private stuckUntil = new Map<string, number>();

  constructor(
    private store: Store,
    opts: UpstreamPoolOptions & { allowPrivateUrls?: boolean } = {},
  ) {
    this.allowPrivateUrls = opts.allowPrivateUrls ?? false;
    this.initTimeoutMs = opts.initTimeoutMs ?? DEFAULT_BACKEND_INIT_TIMEOUT_MS;
    this.listWaitMs = Math.min(opts.listWaitMs ?? DEFAULT_LIST_WAIT_MS, this.initTimeoutMs);
    this.stuckCooldownMs = opts.stuckCooldownMs ?? DEFAULT_STUCK_COOLDOWN_MS;
    store.onBackendRetired((workspaceId, slug) => {
      this.forgetBackendTools(workspaceId, slug);
    });
  }

  private markStuck(backend: BackendRecord): BackendUnavailableError {
    this.stuckUntil.set(backend.id, Date.now() + this.stuckCooldownMs);
    console.error(
      `[mcp-flow] backend ${backend.slug} did not initialize within ${this.initTimeoutMs} ms; failing fast for ${this.stuckCooldownMs} ms`,
    );
    return new BackendUnavailableError(backend.slug, "init_timeout", this.stuckCooldownMs);
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

    const headers = { ...this.store.decryptHeaders(backend) };
    const url = new URL(backend.url);

    const client = new Client(
      { name: "mcp-flow-upstream", version: "0.1.0" },
      { capabilities: {} },
    );

    let transport: Transport;
    const oauth = getOauthRow(this.store.db, backend.id);
    if (oauth) {
      for (const name of Object.keys(headers)) {
        if (name.toLowerCase() === "authorization") delete headers[name];
      }
      const provider = new StoreOauthProvider({
        store: this.store,
        backendId: backend.id,
        workspaceId: backend.workspaceId,
        slug: backend.slug,
        redirectUri: oauth.redirectUri,
        interactive: false,
        allowPrivateUrls: this.allowPrivateUrls,
        onRefreshFailure: (code) => {
          this.store.writeAudit({
            workspaceId: backend.workspaceId,
            action: "oauth.refresh_failure",
            backendSlug: backend.slug,
            detail: { error: code },
          });
        },
      });
      await provider.prepareForConnect();
      const requestInit: RequestInit = { headers };
      const fetch = createSafeFetch(this.allowPrivateUrls);
      // Do not set SSE eventSourceInit: the SDK then skips the bearer token.
      transport =
        backend.transport === "sse"
          ? new SSEClientTransport(url, { authProvider: provider, requestInit, fetch })
          : new StreamableHTTPClientTransport(url, {
              authProvider: provider,
              requestInit,
              fetch,
            });
    } else {
      const requestInit: RequestInit = { headers };
      transport =
        backend.transport === "sse"
          ? new SSEClientTransport(url, { requestInit })
          : new StreamableHTTPClientTransport(url, { requestInit });
    }

    try {
      const opts = { timeout: this.initTimeoutMs };
      await client.connect(transport, opts);
      const listed = await client.listTools(undefined, opts);
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
        timeoutMs: this.initTimeoutMs,
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
        timeoutMs: this.initTimeoutMs,
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
      const listed = await entry.client.listTools(undefined, { timeout: this.initTimeoutMs });
      entry.tools = listed.tools ?? [];
      entry.fetchedAt = Date.now();
    })();
    this.refreshInflight.set(entry.backendId, job);
    // then(f, f), not finally(): a failed refresh (V53-F4 timeout) must not become an unhandled rejection
    const done = () => {
      if (this.refreshInflight.get(entry.backendId) === job) {
        this.refreshInflight.delete(entry.backendId);
      }
    };
    job.then(done, done);
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

  /** False when the SDK has dropped the transport or the stdio process is dead or a zombie. */
  private transportAlive(entry: PooledClient): boolean {
    if (entry.dead) return false;
    const client = entry.client as Client & { transport?: unknown };
    if (!client.transport) return false;
    const transport = entry.transport as { pid?: number | null };
    if (!("pid" in transport)) return true;
    const pid = transport.pid;
    if (pid == null) return false;
    return isLiving(pid);
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
          if (isRequestTimeout(err)) {
            // V53-F4: an open client that stopped answering tools/list is retired, not waited on
            if (this.pool.get(backend.id) === existing) await this.retire(backend.id);
            throw this.markStuck(backend);
          }
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

    // V53-F4: fail fast (no respawn) during the cooldown after an init timeout
    const until = this.stuckUntil.get(backend.id);
    if (until !== undefined) {
      if (Date.now() < until) {
        throw new BackendUnavailableError(backend.slug, "cooling_down", until - Date.now());
      }
      this.stuckUntil.delete(backend.id);
    }

    // The SDK timeouts bound initialize + tools/list; the backstop also covers a spawn that never
    // gets that far. A timed-out attempt is typed so every waiter sees backend_unavailable.
    const promise = (async () => {
      const attempt = this.connectAndStore(backend);
      let timer: ReturnType<typeof setTimeout> | undefined;
      const backstop = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new BackendUnavailableError(backend.slug, "init_timeout", 0)), this.initTimeoutMs + 2_000);
      });
      try {
        return await Promise.race([attempt, backstop]);
      } catch (err) {
        if (err instanceof BackendUnavailableError || isRequestTimeout(err)) {
          // a connect that still succeeds later (backstop case) is pooled and clears the cooldown
          attempt.then(() => this.stuckUntil.delete(backend.id), () => {});
          throw this.markStuck(backend);
        }
        throw err;
      } finally {
        if (timer) clearTimeout(timer);
      }
    })();
    this.inflight.set(backend.id, promise);
    try {
      return await promise;
    } finally {
      if (this.inflight.get(backend.id) === promise) {
        this.inflight.delete(backend.id);
      }
    }
  }

  /** Namespaced, allowlisted tools of one backend. Throws on failure (BackendUnavailableError when stuck). */
  private async toolsOf(backend: BackendRecord): Promise<NamespacedTool[]> {
    const placement = parsePlacement(backend);
    let tools: Tool[];
    if (placement.mode === "edge-sandbox" || placement.mode === "edge-bare") {
      if (!this.edgeRouter) return [];
      tools = await this.edgeRouter.listTools(backend);
    } else {
      tools = (await this.getClient(backend)).tools;
    }
    const allow = backend.toolAllowlistJson
      ? new Set(JSON.parse(backend.toolAllowlistJson) as string[])
      : null;
    const out: NamespacedTool[] = [];
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
    return out;
  }

  /**
   * V53-F4: tools of ONE backend, for routing an agent call. Never waits on other backends.
   * A disabled backend lists nothing. Waits at most the init timeout, then throws
   * BackendUnavailableError (also at once during the cooldown).
   */
  async listBackendTools(workspaceId: string, backend: BackendRecord): Promise<NamespacedTool[]> {
    if (!backend.enabled || backend.workspaceId !== workspaceId) return [];
    try {
      return await this.toolsOf(backend);
    } catch (err) {
      if (err instanceof BackendUnavailableError) throw err;
      if (isTransportOrConnectionError(err)) await this.retire(backend.id);
      throw err;
    }
  }

  /**
   * All enabled backends' tools. V53-F4: each backend gets at most listWaitMs; a backend that is not
   * ready by then (still starting, stuck, or cooling down) is left out of this listing and its
   * connect continues in the background, bounded by the init timeout.
   */
  async listNamespacedTools(workspaceId: string): Promise<NamespacedTool[]> {
    const backends = this.store.listEnabledBackends(workspaceId);
    const out: NamespacedTool[] = [];

    await Promise.all(
      backends.map(async (backend) => {
        const job = this.toolsOf(backend);
        let timer: ReturnType<typeof setTimeout> | undefined;
        const notReady = Symbol("not-ready");
        try {
          const got = await Promise.race([
            job,
            new Promise<typeof notReady>((resolve) => {
              timer = setTimeout(() => resolve(notReady), this.listWaitMs);
            }),
          ]);
          if (got === notReady) {
            job.catch(() => {}); // settles later (pooled, or typed failure); nothing to wait for here
            console.error(`[mcp-flow] tools/list: backend ${backend.slug} not ready after ${this.listWaitMs} ms; omitted from this listing`);
            return;
          }
          out.push(...got);
        } catch (err) {
          console.error(
            `[mcp-flow] tools/list failed for backend ${backend.slug}:`,
            publicUpstreamError(err),
          );
          if (!(err instanceof BackendUnavailableError) && isTransportOrConnectionError(err)) await this.retire(backend.id);
        } finally {
          if (timer) clearTimeout(timer);
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
          text: `Upstream error (${slug}): ${publicUpstreamError(err)}`,
        },
      ],
    };
  }

  /**
   * Resolve slug__tool on the matching enabled backend and call it.
   * sent is true only after that backend acknowledges the tools/call
   * (a response or progress for its request id). A transport write that
   * later fails with Connection closed, and a dead or zombie stdio process,
   * are sent:false. Allowlist misses, disabled or deleted backends, and
   * tools that are not listed return sent:false and do not send a request.
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
      const previousOnMessage = pooled.transport.onmessage;
      const previousSend = pooled.transport.send;
      const originalSend = previousSend.bind(pooled.transport);
      let requestId: string | number | null = null;
      let acknowledged = false;
      const wrappedOnMessage: NonNullable<Transport["onmessage"]> = (message, extra) => {
        if (requestId !== null && messageAcksRequest(message, requestId)) acknowledged = true;
        previousOnMessage?.(message, extra);
      };
      const wrappedSend = (async (message, options) => {
        if (pooled.dead || !this.transportAlive(pooled)) {
          pooled.dead = true;
          throw new Error("Not connected");
        }
        const request = message as { id?: unknown; method?: unknown };
        if (
          request.method === "tools/call" &&
          (typeof request.id === "string" || typeof request.id === "number")
        ) {
          requestId = request.id;
        }
        return originalSend(message, options);
      }) as Transport["send"];
      pooled.transport.onmessage = wrappedOnMessage;
      pooled.transport.send = wrappedSend;
      try {
        const result = await pooled.client.callTool({
          name: parsed.tool,
          arguments: args ?? {},
        });
        return { ...(result as CallToolResult), sent: true };
      } catch (err) {
        if (!acknowledged || isTransportOrConnectionError(err)) {
          pooled.dead = true;
          await this.retire(backend.id);
        }
        return this.upstreamError(backend.slug, err, acknowledged);
      } finally {
        if (pooled.transport.send === wrappedSend) pooled.transport.send = previousSend;
        if (pooled.transport.onmessage === wrappedOnMessage) {
          pooled.transport.onmessage = previousOnMessage;
        }
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
    const pub =
      this.store.getBackendPublic(backend.workspaceId, backend.id) ??
      toPublicBackend(backend);
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
      const base = publicUpstreamError(err);
      const hdrs = this.store.decryptHeaders(backend);
      const hasAuth = Object.keys(hdrs).some((k) =>
        /^(authorization|x-api-key)$/i.test(k),
      );
      const oauth = Boolean(getOauthRow(this.store.db, backend.id));
      const hint =
        !oauth &&
        !hasAuth &&
        /authentication required|unauthorized|\b401\b/i.test(base)
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
