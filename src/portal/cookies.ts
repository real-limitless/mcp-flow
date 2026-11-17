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

/** Cookie-authenticated mutations. Origin is checked only when the browser sent one. */
export function cookieMutationError(
  c: Context,
  requestOrigin: string,
): string | null {
  if (c.req.method === "GET" || c.req.method === "HEAD") return null;
  if (c.req.header("x-mcp-flow-request") !== "1") return "csrf";
  const origin = c.req.header("origin");
  if (origin && origin !== requestOrigin) return "origin";
  return null;
}
