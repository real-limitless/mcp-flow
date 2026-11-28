import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";

export const PORTAL_COOKIE = "mf_portal";
export const OAUTH_STATE_COOKIE = "mf_oauth_state";

const ABSOLUTE_SEC = 8 * 60 * 60;
const STATE_SEC = 10 * 60;

export function portalCookieSecure(origin: string): boolean {
  return origin.startsWith("https://");
}

export function readPortalCookie(c: Context): string | null {
  const value = getCookie(c, PORTAL_COOKIE);
  return value && value.length > 0 ? value : null;
}

export function readStateCookie(c: Context): string | null {
  const value = getCookie(c, OAUTH_STATE_COOKIE);
  return value && value.length > 0 ? value : null;
}

export function writePortalCookie(c: Context, token: string, secure: boolean, maxAge = ABSOLUTE_SEC): void {
  setCookie(c, PORTAL_COOKIE, token, {
    httpOnly: true,
    path: "/",
    sameSite: "Strict",
    secure,
    maxAge,
  });
}

export function clearPortalCookie(c: Context, secure: boolean): void {
  deleteCookie(c, PORTAL_COOKIE, { path: "/", secure, sameSite: "Strict" });
}

export function writeStateCookie(c: Context, state: string, secure: boolean): void {
  setCookie(c, OAUTH_STATE_COOKIE, state, {
    httpOnly: true,
    path: "/",
    sameSite: "Lax",
    secure,
    maxAge: STATE_SEC,
  });
}

export function clearStateCookie(c: Context, secure: boolean): void {
  deleteCookie(c, OAUTH_STATE_COOKIE, { path: "/", secure, sameSite: "Lax" });
}

/** Browser Origin is this host. A reverse proxy often rewrites the request URL, not the Host header. */
export function originHostMatches(origin: string, hostHeader: string): boolean {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return false;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return false;
  const host = hostHeader.split(",")[0]?.trim().toLowerCase() ?? "";
  if (!host || /[/\\\s]/.test(host)) return false;
  return host === url.host.toLowerCase() || host === url.hostname.toLowerCase();
}

function headerFirst(value: string | null | undefined): string {
  return value?.split(",")[0]?.trim() ?? "";
}

/**
 * Whether the browser connection is HTTPS, so Set-Cookie may carry Secure.
 * A TLS proxy makes Node's request URL http. The Google callback's Origin is
 * accounts.google.com, which is not this site's scheme. A same-site Origin
 * wins. Otherwise an https request URL, a Host that matches the public https
 * origin, or X-Forwarded-Host plus X-Forwarded-Proto when they match that origin.
 */
export function portalCookieIsSecure(input: {
  origin?: string | null;
  requestOrigin: string;
  publicUrl: string;
  forwardedProto?: string | null;
  forwardedHost?: string | null;
  host?: string | null;
}): boolean {
  const requestOrigin = input.requestOrigin.trim();
  const pub = publicOrigin(input.publicUrl);
  const host = headerFirst(input.host);
  const origin = input.origin?.trim() ?? "";
  if (origin.startsWith("http://") || origin.startsWith("https://")) {
    const sameSite =
      origin === requestOrigin ||
      (pub !== "" && origin === pub) ||
      (host !== "" && originHostMatches(origin, host));
    if (sameSite) return origin.startsWith("https://");
  }
  if (requestOrigin.startsWith("https://")) return true;
  if (pub.startsWith("https://")) {
    if (host && originHostMatches(pub, host)) return true;
    const forwardedHost = headerFirst(input.forwardedHost);
    const forwardedProto = headerFirst(input.forwardedProto).toLowerCase();
    if (forwardedProto === "https" && forwardedHost && originHostMatches(pub, forwardedHost)) return true;
  }
  return false;
}

export function publicOrigin(publicUrl: string): string {
  const raw = publicUrl.trim();
  if (!raw) return "";
  try {
    return new URL(raw).origin;
  } catch {
    return "";
  }
}

/**
 * Cookie-authenticated mutations. The browser Origin may be the public site
 * while Node sees an internal http URL behind a proxy. Allow the request
 * origin, the configured public origin, and an Origin whose host is the Host
 * header. A cross-site page cannot set that Host.
 */
export function cookieMutationError(
  c: Context,
  requestOrigin: string,
  extraOrigins: string[] = [],
): string | null {
  if (c.req.method === "GET" || c.req.method === "HEAD") return null;
  if (c.req.header("x-mcp-flow-request") !== "1") return "csrf";
  const origin = c.req.header("origin")?.trim();
  if (!origin) return null;
  const allowed = new Set([requestOrigin, ...extraOrigins].filter(Boolean));
  if (allowed.has(origin)) return null;
  const host = c.req.header("host");
  if (host && originHostMatches(origin, host)) return null;
  return "origin";
}
