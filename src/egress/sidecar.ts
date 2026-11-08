import net from "node:net";
import type { Placement, SandboxConfig, SidecarHealth } from "../types.js";

/**
 * Named sidecar (VPN) egress. A backend uses this only when an operator
 * selected the connection. Nothing here is inferred from the process environment.
 */
export interface EgressProxy {
  connectionId: string;
  slug: string;
  displayName: string;
  kind: "tailscale" | "generic";
  httpProxyUrl: string | null;
  socksProxyUrl: string | null;
  scope: "gateway" | "device";
  deviceId: string | null;
}

export class SidecarError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SidecarError";
  }
}

/** Selected connection cannot be used. Callers must not fall back to the normal network. */
export class SidecarUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SidecarUnavailableError";
  }
}

const LOOPBACK_NO_PROXY = ["localhost", "127.0.0.1", "::1"];

/** Env vars a selected connection owns. User values for these keys do not pick a different path. */
const OWNED_ENV = [
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "http_proxy",
  "https_proxy",
  "ALL_PROXY",
  "all_proxy",
  "SOCKS_PROXY",
  "socks_proxy",
  "NODE_USE_ENV_PROXY",
  "NO_PROXY",
  "no_proxy",
] as const;

export function connectionRequested(value: string | null | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

/**
 * socks5:// asks the client to resolve DNS locally, which misses MagicDNS.
 * socks5h:// sends the hostname to the proxy.
 */
export function socksRemoteDns(url: string | null | undefined): string | null {
  if (!url) return null;
  if (/^socks5:\/\//i.test(url)) return `socks5h://${url.slice("socks5://".length)}`;
  return url;
}

export function parseProxyUrl(raw: string, role: "http" | "socks"): string {
  const text = raw.trim();
  if (!text) throw new SidecarError(`${role === "http" ? "HTTP" : "SOCKS"} proxy URL is empty`);
  if (/\s/.test(text)) throw new SidecarError("proxy URLs cannot contain whitespace");
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new SidecarError(`invalid ${role} proxy URL`);
  }
  if (url.username || url.password) {
    throw new SidecarError("proxy URLs cannot include credentials");
  }
  const protocol = url.protocol.toLowerCase();
  if (role === "http" && protocol !== "http:" && protocol !== "https:") {
    throw new SidecarError("HTTP proxy must be an http or https URL");
  }
  if (role === "socks" && protocol !== "socks5:" && protocol !== "socks5h:") {
    throw new SidecarError("SOCKS proxy must be a socks5 or socks5h URL");
  }
  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!host) throw new SidecarError("proxy URL is missing a host");
  if (host === "metadata.google.internal" || host === "metadata.goog") {
    throw new SidecarError("proxy host is not allowed");
  }
  return text;
}

/**
 * Proxy environment for one backend process.
 * HTTP_PROXY / HTTPS_PROXY are what Node (NODE_USE_ENV_PROXY=1) and Axios use.
 * ALL_PROXY is socks5h so MagicDNS is resolved by the sidecar, not Docker DNS.
 * When a connection is selected, a sealed HTTP_PROXY on the backend does not win.
 */
export function applySidecarEnv(
  base: Record<string, string>,
  egress: EgressProxy | null,
): Record<string, string> {
  if (!egress) return base;
  const http = egress.httpProxyUrl;
  const socks = socksRemoteDns(egress.socksProxyUrl);
  if (!http && !socks) {
    throw new SidecarUnavailableError(
      `backend sidecar ${egress.slug} has no proxy endpoint`,
    );
  }
  const next: Record<string, string> = { ...base };
  for (const key of OWNED_ENV) delete next[key];
  if (http) {
    next.HTTP_PROXY = http;
    next.HTTPS_PROXY = http;
    next.http_proxy = http;
    next.https_proxy = http;
  }
  if (socks) {
    next.ALL_PROXY = socks;
    next.all_proxy = socks;
    next.SOCKS_PROXY = socks;
    next.socks_proxy = socks;
  }
  next.NODE_USE_ENV_PROXY = "1";
  const noProxy = mergeNoProxy(base.NO_PROXY ?? base.no_proxy);
  next.NO_PROXY = noProxy;
  next.no_proxy = noProxy;
  return next;
}

export function mergeNoProxy(existing: string | undefined): string {
  const parts = (existing ?? "")
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0 && part !== "*");
  for (const item of LOOPBACK_NO_PROXY) {
    if (!parts.includes(item)) parts.push(item);
  }
  return parts.join(",");
}

/**
 * Central-sandbox containers need to resolve the sidecar's Docker DNS name.
 * An explicit sandbox network mode is kept. Edge processes do not use this.
 */
export function ociNetworkMode(
  sandbox: SandboxConfig | null | undefined,
  egress: EgressProxy | null,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const explicit = sandbox?.networkMode?.trim();
  if (explicit) return explicit;
  if (!egress || egress.scope !== "gateway") return "bridge";
  return env.MCP_FLOW_EGRESS_NETWORK?.trim() || "mcp-flow";
}

export function assertEgressPlacement(
  egress: EgressProxy,
  placement: Placement,
  backendSlug: string,
): void {
  const edge = placement.mode === "edge-sandbox" || placement.mode === "edge-bare";
  if (edge) {
    if (egress.scope !== "device" || !egress.deviceId || egress.deviceId !== placement.deviceId) {
      throw new SidecarUnavailableError(
        `backend ${backendSlug} must use a sidecar connection on the same device`,
      );
    }
    return;
  }
  if (egress.scope !== "gateway") {
    throw new SidecarUnavailableError(
      `backend ${backendSlug} can only use a gateway sidecar connection`,
    );
  }
}

function defaultPort(protocol: string): number {
  if (protocol === "https:") return 443;
  if (protocol === "http:") return 80;
  return 1080;
}

function tcpOpen(proxyUrl: string, timeoutMs: number): Promise<boolean> {
  let url: URL;
  try {
    url = new URL(proxyUrl);
  } catch {
    return Promise.resolve(false);
  }
  const port = url.port ? Number(url.port) : defaultPort(url.protocol);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return Promise.resolve(false);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (!host) return Promise.resolve(false);
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const finish = (ok: boolean) => {
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

/** Online means a configured proxy port accepted a TCP connection. */
export async function probeSidecarHealth(
  row: { httpProxy: string | null; socksProxy: string | null },
  timeoutMs = 500,
): Promise<SidecarHealth> {
  const urls = [row.httpProxy, row.socksProxy].filter((url): url is string => Boolean(url));
  if (!urls.length) return "unknown";
  const results = await Promise.all(urls.map((url) => tcpOpen(url, timeoutMs)));
  return results.some(Boolean) ? "online" : "offline";
}

export async function withSidecarHealth<T extends { httpProxy: string | null; socksProxy: string | null; health: SidecarHealth }>(
  rows: T[],
  timeoutMs = 500,
): Promise<T[]> {
  return Promise.all(
    rows.map(async (row) => ({
      ...row,
      health: await probeSidecarHealth(row, timeoutMs),
    })),
  );
}
