import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { DEFAULT_BACKEND_INIT_HARD_TIMEOUT_MS, DEFAULT_BACKEND_INIT_TIMEOUT_MS } from "../config.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import type { BackendRecord, Placement } from "../types.js";
import { connectOci } from "./runners/oci.js";
import {
  armStdioReap,
  connectStdioCommand,
  disarmStdioReap,
  killLiveStdio,
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

function transportMessage(message: string): boolean {
  return /connection closed|not connected|econnreset|econnrefused|\bepipe\b|socket hang up|fetch failed|broken pipe|other side closed|process exited/i.test(
    message,
  );
}

/**
 * V53-F4: a backend that did not finish initialize + tools/list within the init timeout, or is in
 * the fail-fast cooldown after one. Typed so the gateway returns backend_unavailable instead of
 * waiting (QA v5.3/v5.4: one hung backend made every agent call wait ~60 s).
 */
export type BackendUnavailableCause =
  /** still initializing past the caller wait; the init continues in the background */
  | "starting"
  /** the attempt hit the hard ceiling and was killed; backing off */
  | "init_timeout"
  /** the process exited / errored during init; backing off */
  | "init_failed"
  /** in the backoff window after init_timeout / init_failed */
  | "cooling_down";

export class BackendUnavailableError extends Error {
  readonly code = "backend_unavailable";
  constructor(
    readonly backendSlug: string,
    readonly cause_: BackendUnavailableCause,
    readonly retryAfterMs: number,
  ) {
    super(
      cause_ === "starting"
        ? `backend ${backendSlug} is still starting; retry in ${retryAfterMs} ms (backend_unavailable)`
        : cause_ === "init_timeout"
          ? `backend ${backendSlug} did not initialize in time (backend_unavailable)`
          : cause_ === "init_failed"
            ? `backend ${backendSlug} failed to start; retry in ${retryAfterMs} ms (backend_unavailable)`
            : `backend ${backendSlug} is unavailable after a failed start; retry in ${retryAfterMs} ms (backend_unavailable)`,
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
  /**
   * How long a caller waits for a backend that is still starting (ms), and the bound for a
   * tools/list refresh on an open client. Past it the caller gets backend_unavailable ("starting");
   * the init itself is NOT cut off (QA v5.5: a 25 s cold start must come up, not loop).
   */
  initTimeoutMs?: number;
  /** Absolute ceiling for one init attempt (ms); past it the spawn is killed and the backend backs off. */
  initHardTimeoutMs?: number;
  /** How long a workspace listing waits for one backend before omitting it from that listing (ms). */
  listWaitMs?: number;
  /** First backoff after a hard-ceiling timeout (ms); doubles per consecutive failure up to stuckBackoffMaxMs. */
  stuckCooldownMs?: number;
  stuckBackoffMaxMs?: number;
  /** First backoff after a process exit / error during init (ms); doubles up to crashBackoffMaxMs. */
  crashBackoffMs?: number;
  crashBackoffMaxMs?: number;
}

export const DEFAULT_LIST_WAIT_MS = 5_000;
export const DEFAULT_STUCK_COOLDOWN_MS = 30_000;
export const DEFAULT_STUCK_BACKOFF_MAX_MS = 600_000;
export const DEFAULT_CRASH_BACKOFF_MS = 1_000;
export const DEFAULT_CRASH_BACKOFF_MAX_MS = 60_000;
/** retry_after_ms suggested to a caller that gave up on a backend that is still starting. */
export const STARTING_RETRY_MS = 5_000;

/** Exponential backoff: base * 2^(failures-1), capped. */
export function backoffMs(failures: number, base: number, max: number): number {
  return Math.min(max, base * 2 ** Math.min(Math.max(failures, 1) - 1, 30));
}

interface BackendHealth {
  failures: number;
  until: number;
  cause: "init_timeout" | "init_failed";
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

  private readonly initTimeoutMs: number;
  private readonly initHardTimeoutMs: number;
  private readonly listWaitMs: number;
  private readonly stuckCooldownMs: number;
  private readonly stuckBackoffMaxMs: number;
  private readonly crashBackoffMs: number;
  private readonly crashBackoffMaxMs: number;
  /** QA v5.5: backendId -> consecutive init failures and the end of the current backoff window. */
  private health = new Map<string, BackendHealth>();
  /** Start time of the in-flight init attempt (callers wait until start + initTimeoutMs at most). */
  private attemptStart = new Map<string, number>();
  /** Backends whose current attempt was given up on by a caller or omitted from a listing. */
  private lateAttempt = new Set<string>();
  private toolsChangedListeners = new Set<(workspaceId: string, backendSlug: string) => void>();
  /** Last record seen per pooled backend id (workspace + slug for tools-changed events). */
  private backendRecords = new Map<string, BackendRecord>();
  /** Number of init attempts started per backend id (tests / diagnostics). */
  readonly spawnCount = new Map<string, number>();

  constructor(
    private store: Store,
    opts: UpstreamPoolOptions = {},
  ) {
    this.initTimeoutMs = opts.initTimeoutMs ?? DEFAULT_BACKEND_INIT_TIMEOUT_MS;
    // config clamps hard >= soft; a pool built with hard < soft simply fails callers at the hard ceiling
    this.initHardTimeoutMs = opts.initHardTimeoutMs ?? Math.max(this.initTimeoutMs, DEFAULT_BACKEND_INIT_HARD_TIMEOUT_MS);
    this.listWaitMs = Math.min(opts.listWaitMs ?? DEFAULT_LIST_WAIT_MS, this.initTimeoutMs);
    this.stuckCooldownMs = opts.stuckCooldownMs ?? DEFAULT_STUCK_COOLDOWN_MS;
    this.stuckBackoffMaxMs = Math.max(this.stuckCooldownMs, opts.stuckBackoffMaxMs ?? DEFAULT_STUCK_BACKOFF_MAX_MS);
    this.crashBackoffMs = opts.crashBackoffMs ?? DEFAULT_CRASH_BACKOFF_MS;
    this.crashBackoffMaxMs = Math.max(this.crashBackoffMs, opts.crashBackoffMaxMs ?? DEFAULT_CRASH_BACKOFF_MAX_MS);
  }

  /**
   * QA v5.5 item 2: subscribe to "this backend's tools changed" (a late init finished, or a refresh
   * returned a different tool set). The gateway turns it into notifications/tools/list_changed.
   */
  onToolsChanged(fn: (workspaceId: string, backendSlug: string) => void): () => void {
    this.toolsChangedListeners.add(fn);
    return () => {
      this.toolsChangedListeners.delete(fn);
    };
  }

  private emitToolsChanged(backend: BackendRecord): void {
    for (const fn of [...this.toolsChangedListeners]) {
      try {
        fn(backend.workspaceId, backend.slug);
      } catch {
        /* a listener failure never affects the pool */
      }
    }
  }

  /** Record a failed init attempt; returns the typed error for the caller that owned it. */
  private recordFailure(backend: BackendRecord, cause: "init_timeout" | "init_failed"): BackendUnavailableError {
    const failures = (this.health.get(backend.id)?.failures ?? 0) + 1;
    const delay =
      cause === "init_timeout"
        ? backoffMs(failures, this.stuckCooldownMs, this.stuckBackoffMaxMs)
        : backoffMs(failures, this.crashBackoffMs, this.crashBackoffMaxMs);
    this.health.set(backend.id, { failures, until: Date.now() + delay, cause });
    console.error(
      cause === "init_timeout"
        ? `[mcp-flow] backend ${backend.slug} did not initialize within the ${this.initHardTimeoutMs} ms hard ceiling; stopped it; next attempt in ${delay} ms (failure ${failures})`
        : `[mcp-flow] backend ${backend.slug} failed during init; next attempt in ${delay} ms (failure ${failures})`,
    );
    return new BackendUnavailableError(backend.slug, cause, delay);
  }

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
    // QA v5.5 note: no backoff / attempt state survives closeAll
    this.health.clear();
    this.attemptStart.clear();
    this.lateAttempt.clear();
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
      // QA v5.5: the attempt itself is bounded by the hard ceiling; callers stop waiting much earlier
      const opts = { timeout: this.initHardTimeoutMs };
      await client.connect(transport, opts);
      const listed = await client.listTools(undefined, opts);
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
        timeoutMs: this.initHardTimeoutMs,
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
        timeoutMs: this.initHardTimeoutMs,
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
      const listed = await entry.client.listTools(undefined, { timeout: this.initTimeoutMs });
      const names = (t: Tool[]) => t.map((x) => x.name).sort().join("\n");
      const changed = names(entry.tools) !== names(listed.tools ?? []);
      entry.tools = listed.tools ?? [];
      entry.fetchedAt = Date.now();
      const backend = this.backendRecords.get(entry.backendId);
      if (changed && backend && this.pool.get(entry.backendId) === entry) this.emitToolsChanged(backend);
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
        try {
          await this.refreshTools(existing);
        } catch (err) {
          if (!isRequestTimeout(err)) throw err;
          // V53-F4: an open client that stopped answering tools/list is retired, not waited on
          void this.retire(backend.id);
          throw this.recordFailure(backend, "init_timeout");
        }
      }
      return existing;
    }

    let pending = this.inflight.get(backend.id);
    if (!pending) {
      // QA v5.5: fail fast (no respawn) inside the backoff window after a failed attempt
      const h = this.health.get(backend.id);
      if (h && Date.now() < h.until) {
        throw new BackendUnavailableError(backend.slug, "cooling_down", h.until - Date.now());
      }
      pending = this.startAttempt(backend);
    }
    return this.waitForAttempt(backend, pending);
  }

  /**
   * One init attempt, shared by every caller. It runs until it succeeds, the process exits/errors
   * (backoff 1 s, 2 s, ... 60 s) or the hard ceiling (killed; backoff 30 s, 60 s, ... 10 min).
   * Callers giving up never cut it short (QA v5.5 item 1).
   */
  private startAttempt(backend: BackendRecord): Promise<PooledClient> {
    const generation = this.generation;
    this.spawnCount.set(backend.id, (this.spawnCount.get(backend.id) ?? 0) + 1);
    this.backendRecords.set(backend.id, backend);
    const promise = (async () => {
      const attempt = this.connectAndStore(backend);
      let timer: ReturnType<typeof setTimeout> | undefined;
      // backstop for a spawn that never reaches the SDK request timeouts
      const backstop = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new BackendUnavailableError(backend.slug, "init_timeout", 0)), this.initHardTimeoutMs + 2_000);
      });
      try {
        const entry = await Promise.race([attempt, backstop]);
        this.health.delete(backend.id);
        if (this.lateAttempt.delete(backend.id)) this.emitToolsChanged(backend);
        return entry;
      } catch (err) {
        this.lateAttempt.delete(backend.id);
        if (this.closing || generation !== this.generation) throw err; // shutdown, not a backend failure
        if (err instanceof BackendUnavailableError || isRequestTimeout(err)) {
          // backstop case: a connect that still succeeds later is pooled and clears the backoff
          attempt.then(
            () => {
              this.health.delete(backend.id);
              this.emitToolsChanged(backend);
            },
            () => {},
          );
          throw this.recordFailure(backend, "init_timeout");
        }
        this.recordFailure(backend, "init_failed");
        throw err;
      } finally {
        if (timer) clearTimeout(timer);
      }
    })();
    this.inflight.set(backend.id, promise);
    this.attemptStart.set(backend.id, Date.now());
    const done = () => {
      if (this.inflight.get(backend.id) === promise) {
        this.inflight.delete(backend.id);
        this.attemptStart.delete(backend.id);
      }
    };
    promise.then(done, done);
    return promise;
  }

  /** Wait for the shared attempt, but never past attempt start + initTimeoutMs. */
  private async waitForAttempt(backend: BackendRecord, attempt: Promise<PooledClient>): Promise<PooledClient> {
    const started = this.attemptStart.get(backend.id) ?? Date.now();
    const remaining = started + this.initTimeoutMs - Date.now();
    const giveUp = (): never => {
      attempt.catch(() => {}); // settles later: pooled (then list_changed) or a recorded failure
      if (!this.lateAttempt.has(backend.id)) {
        this.lateAttempt.add(backend.id);
        console.error(
          `[mcp-flow] backend ${backend.slug} still initializing after ${this.initTimeoutMs} ms; callers get backend_unavailable while it continues (hard ceiling ${this.initHardTimeoutMs} ms)`,
        );
      }
      const hardLeft = Math.max(1, started + this.initHardTimeoutMs - Date.now());
      throw new BackendUnavailableError(backend.slug, "starting", Math.min(STARTING_RETRY_MS, hardLeft));
    };
    if (remaining <= 0) return giveUp();
    const notReady = Symbol("not-ready");
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const got = await Promise.race([
        attempt,
        new Promise<typeof notReady>((resolve) => {
          timer = setTimeout(() => resolve(notReady), remaining);
        }),
      ]);
      if (got === notReady) return giveUp();
      return got;
    } finally {
      if (timer) clearTimeout(timer);
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
      // QA v5.5: an init that exited / errored is typed for agents too (not "unknown_tool")
      const h = this.health.get(backend.id);
      if (h?.cause === "init_failed" && Date.now() < h.until) {
        throw new BackendUnavailableError(backend.slug, "init_failed", h.until - Date.now());
      }
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
            // QA v5.5 item 2: when this backend's init finishes, clients get tools/list_changed
            if (this.inflight.has(backend.id)) this.lateAttempt.add(backend.id);
            console.error(`[mcp-flow] tools/list: backend ${backend.slug} not ready after ${this.listWaitMs} ms; omitted from this listing`);
            return;
          }
          out.push(...got);
        } catch (err) {
          console.error(
            `[mcp-flow] tools/list failed for backend ${backend.slug}:`,
            redactLog(err),
          );
          if (!(err instanceof BackendUnavailableError) && isTransportOrConnectionError(err)) await this.retire(backend.id);
        } finally {
          if (timer) clearTimeout(timer);
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
