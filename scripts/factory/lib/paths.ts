import { existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** scripts/factory */
export const FACTORY_ROOT = resolve(HERE, "..");
/** repo root */
export const REPO_ROOT = resolve(FACTORY_ROOT, "../..");
export const CATALOG_DIR = join(REPO_ROOT, "catalog");
export const JOBS = join(FACTORY_ROOT, ".jobs");
export const QUEUE_DIR = join(JOBS, "queue");
export const SCANS_DIR = join(JOBS, "scans");
export const PROXIES_DIR = join(JOBS, "proxies");
export const SETTINGS_PATH = join(JOBS, "settings.json");
export const WORKER_LOG = join(JOBS, "worker.log");
export const WORKER_PID = join(JOBS, "worker.pid");
export const PROXIES_LIST = join(PROXIES_DIR, "proxies.txt");
export const PROXIES_HEALTH = join(PROXIES_DIR, "health.json");

export function ensureJobsDirs(): void {
  for (const d of [JOBS, QUEUE_DIR, SCANS_DIR, PROXIES_DIR]) {
    mkdirSync(d, { recursive: true });
  }
  if (!existsSync(CATALOG_DIR)) {
    mkdirSync(CATALOG_DIR, { recursive: true });
  }
}

export const DEFAULT_SETTINGS = {
  maxPages: 10,
  pageLimit: 100,
  latestOnly: true,
  concurrency: 2,
  preferRemoteOnly: false,
  useProxy: false,
  proxy: "",
  proxyListUrl: "https://databay.com/free-proxy-list/socks5.txt",
  proxyProbeLimit: 20,
  proxyProbeTimeout: 8,
  registryUrl: "https://registry.modelcontextprotocol.io/v0.1/servers",
  remoteProbe: false,
  search: "",
  /** Full enrich pipeline */
  enrichReadme: true,
  enrichTools: true,
  toolsTimeoutMs: 15_000,
  readmeMaxBytes: 200_000,
  readmeRefreshDays: 30,
  toolsRefreshDays: 14,
} as const;

export type FactorySettings = {
  -readonly [K in keyof typeof DEFAULT_SETTINGS]: (typeof DEFAULT_SETTINGS)[K];
};
