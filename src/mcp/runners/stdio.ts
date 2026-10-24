import { spawn, type ChildProcess } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
  type StdioServerParameters,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { PassThrough } from "node:stream";
import { redactSecrets } from "../../audit/sanitize.js";
import { lineRedactor, redactLog } from "../../log/redact-lines.js";

export interface StdioRunResult {
  client: Client;
  transport: Transport;
  tools: Tool[];
  dispose?: () => Promise<void>;
}

/** Volume-backed npm cache so Docker overlayfs does not corrupt npx extracts. */
export function resolveNpmCacheDir(): string {
  const explicit = process.env.MCP_FLOW_NPM_CACHE?.trim();
  if (explicit) return explicit;
  const data = process.env.MCP_FLOW_DATA_DIR?.trim();
  if (data) return join(data, "npm-cache");
  return join(tmpdir(), "mcp-flow-npm-cache");
}

export function isNpxLikeCommand(command: string[]): boolean {
  const base = (command[0] ?? "").replace(/\\/g, "/").split("/").pop() ?? "";
  return /^(npx|npm)(\.cmd)?$/i.test(base);
}

export function isNpxCacheCorruption(message: string): boolean {
  return (
    /ERR_MODULE_NOT_FOUND|ENOTEMPTY|ENOENT/i.test(message) &&
    /node_modules|_npx|Cannot find module/i.test(message)
  );
}

export function npxExtractStore(cacheDir: string): string {
  return join(cacheDir, "_npx");
}

export function clearNpxExtractStore(cacheDir: string): void {
  rmSync(npxExtractStore(cacheDir), { recursive: true, force: true });
}

export function buildStdioEnv(
  extra: Record<string, string> = {},
): Record<string, string> {
  const cache = extra.npm_config_cache?.trim() || resolveNpmCacheDir();
  mkdirSync(cache, { recursive: true });
  return {
    ...getDefaultEnvironment(),
    PATH: process.env.PATH ?? "",
    HOME: process.env.HOME ?? "",
    npm_config_yes: "true",
    npm_config_update_notifier: "false",
    npm_config_fund: "false",
    npm_config_audit: "false",
    ...extra,
    npm_config_cache: cache,
  };
}

/** SIGTERM grace before SIGKILL. Kept under 2s so an 8s request drain still fits in a 10s shutdown. */
export const STDIO_GROUP_KILL_GRACE_MS = 1_000;
const STDIO_GROUP_KILL_FOLLOWUP_MS = 250;
export const STDIO_GROUP_KILL_BUDGET_MS =
  STDIO_GROUP_KILL_GRACE_MS + STDIO_GROUP_KILL_FOLLOWUP_MS;

interface ProcStat {
  state: string;
  ppid: number;
  pgrp: number;
}

function procStat(pid: number): ProcStat | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const rest = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
    const state = rest[0];
    const ppid = Number(rest[1]);
    const pgrp = Number(rest[2]);
    if (!state || !Number.isInteger(ppid) || !Number.isInteger(pgrp)) return null;
    return { state, ppid, pgrp };
  } catch {
    return null;
  }
}

export function isLiving(pid: number): boolean {
  if (process.platform === "linux") {
    const stat = procStat(pid);
    return stat !== null && stat.state !== "Z";
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Non-zombie members of a process group. The leader's pid is the pgid. */
function livingGroupMembers(pgid: number): number[] {
  if (process.platform !== "linux") return isLiving(pgid) ? [pgid] : [];
  let names: string[];
  try {
    names = readdirSync("/proc");
  } catch {
    return isLiving(pgid) ? [pgid] : [];
  }
  const out: number[] = [];
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue;
    const pid = Number(name);
    const stat = procStat(pid);
    if (stat && stat.pgrp === pgid && stat.state !== "Z") out.push(pid);
  }
  return out;
}

function signalTree(pid: number, signal: NodeJS.Signals, group: boolean): void {
  if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) return;
  const target = group ? -pid : pid;
  try {
    process.kill(target, signal);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (!group || (code !== "ESRCH" && code !== "EINVAL" && code !== "EPERM")) {
      return;
    }
    try {
      process.kill(pid, signal);
    } catch {
      /* already gone */
    }
  }
}

/**
 * SIGTERM the process (and, when it leads a group, every member), then
 * SIGKILL anything still running after the grace period.
 */
async function killProcessGroup(
  pid: number,
  group = process.platform !== "win32",
): Promise<void> {
  if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) return;
  if (group && process.platform === "linux") {
    const stat = procStat(pid);
    // A live pid that is not our child is not the session we spawned.
    if (stat && (stat.ppid !== process.pid || stat.pgrp !== pid)) return;
  }
  const lingering = () =>
    group ? livingGroupMembers(pid).length > 0 : isLiving(pid);
  signalTree(pid, "SIGTERM", group);
  const started = Date.now();
  while (lingering() && Date.now() - started < STDIO_GROUP_KILL_GRACE_MS) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  if (!lingering()) return;
  signalTree(pid, "SIGKILL", group);
  const killedAt = Date.now();
  while (lingering() && Date.now() - killedAt < STDIO_GROUP_KILL_FOLLOWUP_MS) {
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

interface StdioInternals {
  _process?: ChildProcess;
  _serverParams: StdioServerParameters;
  _stderrStream: PassThrough | null;
  _readBuffer: { append(chunk: Buffer): void };
  processReadBuffer(): void;
  onerror?: (error: Error) => void;
  onclose?: () => void;
}

/**
 * Stdio transport that starts the backend in its own session and tears down
 * the whole process group. The SDK close path only signals the direct child,
 * which leaves grandchildren (shell and node under npm/npx) running.
 */
const liveStdio = new Set<GroupedStdioClientTransport>();
let stdioReapArmed = false;

/** While armed, a spawn closes itself. closeAll sets this at the connect deadline. */
export function armStdioReap(): void {
  stdioReapArmed = true;
}

export function disarmStdioReap(): void {
  stdioReapArmed = false;
}

/** Close every stdio transport that has spawned but may not be in the pool yet. */
export async function killLiveStdio(): Promise<void> {
  await Promise.allSettled([...liveStdio].map((transport) => transport.close()));
}

class GroupedStdioClientTransport extends StdioClientTransport {
  private groupClose: Promise<void> | null = null;
  private leaderPid: number | null = null;
  private tracked = false;
  private retired = false;

  private track(): void {
    if (this.retired || this.tracked) return;
    this.tracked = true;
    liveStdio.add(this);
    if (stdioReapArmed) void this.close();
  }

  override start(): Promise<void> {
    const self = this as unknown as StdioInternals;
    if (self._process) {
      throw new Error(
        "StdioClientTransport already started! If using Client class, note that connect() calls start() automatically.",
      );
    }
    const detached = process.platform !== "win32";
    return new Promise((resolve, reject) => {
      const params = self._serverParams;
      const child = spawn(params.command, params.args ?? [], {
        env: {
          ...getDefaultEnvironment(),
          ...params.env,
        },
        stdio: ["pipe", "pipe", params.stderr ?? "inherit"],
        shell: false,
        windowsHide: process.platform === "win32",
        cwd: params.cwd,
        detached,
      });
      self._process = child;
      if (detached && child.pid) this.leaderPid = child.pid;
      if (child.pid) this.track();
      child.on("error", (error: Error) => {
        reject(error);
        self.onerror?.(error);
      });
      child.on("spawn", () => {
        this.track();
        resolve();
      });
      child.on("close", () => {
        self._process = undefined;
        self.onclose?.();
      });
      child.stdin?.on("error", (error: Error) => {
        self.onerror?.(error);
      });
      child.stdout?.on("data", (chunk: Buffer) => {
        try {
          self._readBuffer.append(chunk);
          self.processReadBuffer();
        } catch (error) {
          self.onerror?.(error instanceof Error ? error : new Error(String(error)));
          void this.close();
        }
      });
      child.stdout?.on("error", (error: Error) => {
        self.onerror?.(error);
      });
      if (self._stderrStream && child.stderr) {
        child.stderr.pipe(self._stderrStream);
      }
    });
  }

  override async close(): Promise<void> {
    this.retired = true;
    liveStdio.delete(this);
    if (this.groupClose) return this.groupClose;
    this.groupClose = (async () => {
      const pid = this.leaderPid;
      this.leaderPid = null;
      if (pid) await killProcessGroup(pid, true);
      await super.close();
    })();
    return this.groupClose;
  }
}

/** Redacted backend stderr kept for an init error (characters). */
const STDERR_TAIL_KEEP = 12_000;
/** Backend stderr included in an init error (characters). */
const STDERR_TAIL_MAX = 8_000;

/**
 * Keeps the last `keep` characters written. Memory is bounded at about 2x keep: the trim runs
 * after a write, so the buffer can briefly exceed 2x keep by one write (a write can be a whole
 * line: up to maxPending (64 KiB) plus one incoming chunk, about 128 KiB). When older text was
 * dropped, text() starts after the first line break of the kept window, so a cut-off line
 * fragment (too short to look like key body) never reaches the second redaction pass. The
 * buffer only ever holds the tail redactor's output, never raw stderr.
 */
export function boundedTail(keep: number): { write: (s: string) => void; text: () => string } {
  let buf = "";
  let dropped = false;
  return {
    write: (s: string) => {
      buf += s;
      if (buf.length > 2 * keep) {
        buf = buf.slice(-keep);
        dropped = true;
      }
    },
    text: () => {
      if (!dropped && buf.length <= keep) return buf;
      const t = buf.slice(-keep);
      const nl = t.indexOf("\n");
      return nl < 0 ? t : t.slice(nl + 1); // one long line: no line run to cut into
    },
  };
}

/**
 * Init-error stderr tail from the tail redactor's output (lineRedactor with keepEndMarker and
 * no line-count reset): redacted again as a whole, then cut to STDERR_TAIL_MAX.
 * - A block whose BEGIN streamed past is already [redacted] line by line (fail closed to the
 *   end of the stream when it never closes).
 * - A stray END (its BEGIN never appeared) is still present as a bare marker, so this pass
 *   redacts the key-body run the line redactor had already written before the END arrived.
 */
export function stderrTailForError(redacted: string): string {
  return redactSecrets(redacted.trim()).slice(-STDERR_TAIL_MAX);
}

async function connectOnce(
  command: string[],
  env: Record<string, string>,
  cwd?: string,
): Promise<StdioRunResult> {
  const [cmd, ...args] = command;
  const transport = new GroupedStdioClientTransport({
    command: cmd!,
    args,
    env,
    cwd,
    stderr: "pipe",
  });

  // backend stderr is passed through to ours, redacted line by line. Lines already printed
  // cannot be taken back: key-body lines before a stray END (no BEGIN seen) stay on live
  // stderr; the init-error tail below does redact them (see stderrTailForError).
  const passthrough = lineRedactor((s) => process.stderr.write(s));
  // the tail kept for the init error is redacted as it streams (the whole stream, with the
  // key-block state carried across lines), and only the redacted text is capped, so a cut can
  // never drop a BEGIN marker and expose the key lines after it. A private key block left open
  // is redacted to the end of the stream (no line-count reset here).
  const errTail = boundedTail(STDERR_TAIL_KEEP);
  const tailRedactor = lineRedactor(errTail.write, undefined, Infinity, { keepEndMarker: true });
  let initDone = false; // the tail is only used for an init error
  transport.stderr?.on("data", (chunk: Buffer | string) => {
    const s = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    passthrough.push(s);
    if (!initDone) tailRedactor.push(s);
  });
  transport.stderr?.on("end", () => passthrough.flush());
  transport.stderr?.on("close", () => passthrough.flush());

  const client = new Client(
    { name: "mcp-flow-stdio", version: "0.1.0" },
    { capabilities: {} },
  );
  try {
    await client.connect(transport);
    const listed = await client.listTools();
    initDone = true;
    return {
      client,
      transport,
      tools: listed.tools ?? [],
    };
  } catch (err) {
    try {
      await client.close();
    } catch {
      /* ignore */
    }
    passthrough.flush();
    tailRedactor.flush();
    const tail = stderrTailForError(errTail.text());
    const msg = redactLog(err);
    throw new Error(tail ? `${msg}\n--- stderr ---\n${tail}` : msg);
  }
}

export async function connectStdioCommand(opts: {
  command: string[];
  env: Record<string, string>;
  cwd?: string;
}): Promise<StdioRunResult> {
  if (!opts.command.length) {
    throw new Error("stdio command is empty");
  }
  const env = buildStdioEnv(opts.env);
  try {
    return await connectOnce(opts.command, env, opts.cwd);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!isNpxLikeCommand(opts.command) || !isNpxCacheCorruption(msg)) {
      throw err;
    }
    const cache = env.npm_config_cache || resolveNpmCacheDir();
    console.error(
      `[mcp-flow] npx extract looks corrupt (${redactLog(msg.split("\n")[0])}); clearing ${npxExtractStore(cache)} and retrying`,
    );
    clearNpxExtractStore(cache);
    return await connectOnce(opts.command, env, opts.cwd);
  }
}

export type { Transport, Tool };
