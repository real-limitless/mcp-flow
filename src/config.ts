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
