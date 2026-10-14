import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

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
