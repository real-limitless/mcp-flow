import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { parseRateLimitPerMin } from "./policy/rate-limit.js";

export interface Config {
  host: string;
  port: number;
  dbPath: string;
  masterKeyRaw: string;
  adminToken: string;
  allowPrivateUrls: boolean;
  workspaceName: string;
  /** DEV ONLY key material for key pepper / args encryption / args_hash (until SecOPS keys land) */
  policyDevKeyRaw?: string;
  /**
   * Public origin for links sent to humans (approve links in Web Push etc.), from MCP_FLOW_PUBLIC_URL.
   * Never derived from request headers (Security T2.5 H-2). Unset = no absolute links are sent.
   */
  publicUrl?: string | null;
  /**
   * Security M-5 (cutover): refuse legacy shared keys and legacy project sessions on /mcp, so only
   * T1.3 agent keys/sessions (which go through policy + call audit) can call tools.
   * MCP_FLOW_REFUSE_LEGACY_MCP_KEYS=true. Default OFF; turning it on is a cutover step that needs Chen.
   */
  refuseLegacyMcpKeys?: boolean;
  /**
   * QA V51-F1: on SIGTERM/SIGINT, how long dispatched calls may finish before they are recorded as
   * outcome unknown. MCP_FLOW_SHUTDOWN_GRACE_MS, default 8000, clamped to 0..8000 so the drain plus
   * the upstream close (connect deadline + process-group kill, about 2 s) fits inside Docker's default
   * 10 s stop timeout.
   */
  shutdownGraceMs?: number;
  /**
   * PM: PRAGMA journal_size_limit, from MCP_FLOW_JOURNAL_SIZE_LIMIT_MB (whole MiB, default 64, clamped
   * 1..4096; unset/invalid = default). Bounds the WAL file kept on disk after checkpoints.
   */
  journalSizeLimitBytes: number;
  /**
   * PM: per-agent tools/call rate limit (token bucket, in memory), MCP_FLOW_RATE_LIMIT_PER_MIN.
   * Whole calls per minute per agent_id; 0 or unset = off (default).
   */
  rateLimitPerMin?: number;
  /**
   * V53-F4: bound for a backend's initialize + first tools/list (MCP_FLOW_BACKEND_INIT_TIMEOUT_MS,
   * default 20000, clamped 1000..120000). A backend past it is closed and fails fast for a cooldown.
   */
  backendInitTimeoutMs?: number;
}

/**
 * V53 headroom: max grace 7000 ms, so the worst case (full grace + connect deadline + process-group
 * kill + overhead) leaves >= 1 s of the 10 s Docker stop budget (see SHUTDOWN_HEADROOM_MS in server.ts).
 */
export const DEFAULT_SHUTDOWN_GRACE_MS = 7000;
export const MAX_SHUTDOWN_GRACE_MS = 7000;

export function parseShutdownGraceMs(raw: string | number | undefined | null): number {
  const n = typeof raw === "number" ? raw : raw == null || String(raw).trim() === "" ? NaN : Number(raw);
  if (!Number.isFinite(n)) return DEFAULT_SHUTDOWN_GRACE_MS;
  return Math.min(MAX_SHUTDOWN_GRACE_MS, Math.max(0, Math.floor(n)));
}

export const DEFAULT_BACKEND_INIT_TIMEOUT_MS = 20_000;
export const MIN_BACKEND_INIT_TIMEOUT_MS = 1_000;
export const MAX_BACKEND_INIT_TIMEOUT_MS = 120_000;

export function parseBackendInitTimeoutMs(raw: string | number | undefined | null): number {
  const n = typeof raw === "number" ? raw : raw == null || String(raw).trim() === "" ? NaN : Number(raw);
  if (!Number.isFinite(n)) return DEFAULT_BACKEND_INIT_TIMEOUT_MS;
  return Math.min(MAX_BACKEND_INIT_TIMEOUT_MS, Math.max(MIN_BACKEND_INIT_TIMEOUT_MS, Math.floor(n)));
}

export const DEFAULT_JOURNAL_SIZE_LIMIT_MB = 64;
const MAX_JOURNAL_SIZE_LIMIT_MB = 4096;

/** MCP_FLOW_JOURNAL_SIZE_LIMIT_MB -> bytes: whole MiB, clamped 1..4096; unset/invalid -> 64 MiB. */
export function parseJournalSizeLimitBytes(raw: string | number | undefined | null): number {
  const s = raw == null ? "" : String(raw).trim();
  const n = s === "" || !/^\d+$/.test(s) ? NaN : Number(s);
  const mb = Number.isSafeInteger(n) ? Math.min(MAX_JOURNAL_SIZE_LIMIT_MB, Math.max(1, n)) : DEFAULT_JOURNAL_SIZE_LIMIT_MB;
  return mb * 1024 * 1024;
}

/** R4-3: `true` (any case) or `1` is on; anything else (unset, false, 0, yes, typos) is off. */
export function parseBoolFlag(raw: string | undefined | null): boolean {
  const v = (raw ?? "").trim();
  return v === "1" || v.toLowerCase() === "true";
}

/** Validate MCP_FLOW_PUBLIC_URL: https origin (http only for localhost), no path/query/credentials. */
export function parsePublicUrl(raw: string | undefined | null): string | null {
  if (!raw) return null;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("MCP_FLOW_PUBLIC_URL is not a valid URL");
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) {
    throw new Error("MCP_FLOW_PUBLIC_URL must be https (http only for localhost)");
  }
  if (u.username || u.password || u.search || u.hash || (u.pathname && u.pathname !== "/")) {
    throw new Error("MCP_FLOW_PUBLIC_URL must be a bare origin, e.g. https://mcp-flow.example");
  }
  return u.origin;
}

function env(name: string, fallback?: string): string | undefined {
  const v = process.env[name];
  if (v === undefined || v === "") return fallback;
  return v;
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const dbPath = resolve(
    overrides.dbPath ?? env("MCP_FLOW_DB_PATH", "./data/mcp-flow.db")!,
  );
  mkdirSync(dirname(dbPath), { recursive: true });

  const masterKeyRaw =
    overrides.masterKeyRaw ?? env("MCP_FLOW_MASTER_KEY") ?? "";
  const adminToken = overrides.adminToken ?? env("MCP_FLOW_ADMIN_TOKEN") ?? "";

  return {
    host: overrides.host ?? env("MCP_FLOW_HOST", "127.0.0.1")!,
    port: overrides.port ?? Number(env("MCP_FLOW_PORT", "8787")),
    dbPath,
    masterKeyRaw,
    adminToken,
    allowPrivateUrls:
      overrides.allowPrivateUrls ??
      env("MCP_FLOW_ALLOW_PRIVATE_URLS", "false") === "true",
    workspaceName:
      overrides.workspaceName ?? env("MCP_FLOW_WORKSPACE_NAME", "default")!,
    policyDevKeyRaw:
      overrides.policyDevKeyRaw ?? env("MCP_FLOW_POLICY_DEV_KEY"),
    publicUrl:
      overrides.publicUrl !== undefined ? parsePublicUrl(overrides.publicUrl) : parsePublicUrl(env("MCP_FLOW_PUBLIC_URL")),
    refuseLegacyMcpKeys:
      overrides.refuseLegacyMcpKeys ?? parseBoolFlag(env("MCP_FLOW_REFUSE_LEGACY_MCP_KEYS")),
    shutdownGraceMs: parseShutdownGraceMs(overrides.shutdownGraceMs ?? env("MCP_FLOW_SHUTDOWN_GRACE_MS")),
    journalSizeLimitBytes: overrides.journalSizeLimitBytes ?? parseJournalSizeLimitBytes(env("MCP_FLOW_JOURNAL_SIZE_LIMIT_MB")),
    rateLimitPerMin: overrides.rateLimitPerMin ?? parseRateLimitPerMin(env("MCP_FLOW_RATE_LIMIT_PER_MIN")),
    backendInitTimeoutMs: parseBackendInitTimeoutMs(overrides.backendInitTimeoutMs ?? env("MCP_FLOW_BACKEND_INIT_TIMEOUT_MS")),
  };
}

export function requireSecrets(cfg: Config): void {
  if (!cfg.masterKeyRaw) {
    throw new Error(
      "MCP_FLOW_MASTER_KEY is required (openssl rand -base64 32)",
    );
  }
  if (!cfg.adminToken) {
    throw new Error(
      "MCP_FLOW_ADMIN_TOKEN is required (openssl rand -hex 32)",
    );
  }
}
