import { isIP } from "node:net";
import { lookup } from "node:dns/promises";

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.goog",
]);

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function isPrivateIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::1") return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // ULA
  if (lower.startsWith("fe80")) return true; // link-local
  // IPv4-mapped
  if (lower.startsWith(":ffff:")) {
    const v4 = lower.slice(7);
    if (isIP(v4) === 4) return isPrivateIpv4(v4);
  }
  return false;
}

export function isPrivateIp(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) return isPrivateIpv4(ip);
  if (v === 6) return isPrivateIpv6(ip);
  return false;
}

export class SsrfError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfError";
  }
}

/**
 * Validate a backend URL before storing or connecting.
 * When allowPrivate is false, blocks private/link-local/metadata targets.
 */
export async function assertSafeUrl(
  urlStr: string,
  allowPrivate: boolean,
): Promise<URL> {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    throw new SsrfError("invalid URL");
  }

  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new SsrfError("only http(s) URLs are allowed");
  }

  if (url.username || url.password) {
    throw new SsrfError("URLs with embedded credentials are not allowed");
  }

  const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (BLOCKED_HOSTNAMES.has(host)) {
    if (!allowPrivate) {
      throw new SsrfError(`blocked hostname: ${host}`);
    }
    return url;
  }

  const ipVersion = isIP(host);
  if (ipVersion) {
    if (!allowPrivate && isPrivateIp(host)) {
      throw new SsrfError(`private IP not allowed: ${host}`);
    }
    return url;
  }

  if (allowPrivate) return url;

  // Resolve and reject if any answer is private
  try {
    const results = await lookup(host, { all: true });
    for (const r of results) {
      if (isPrivateIp(r.address)) {
        throw new SsrfError(
          `hostname resolves to private IP (${r.address}); set MCP_FLOW_ALLOW_PRIVATE_URLS=true to allow`,
        );
      }
    }
  } catch (err) {
    if (err instanceof SsrfError) throw err;
    throw new SsrfError(`DNS lookup failed for ${host}`);
  }

  return url;
}
