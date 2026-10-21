import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import { assertSafeUrl, SsrfError } from "../ssrf.js";

const MAX_HOPS = 5;

function requestUrl(input: string | URL): string {
  return typeof input === "string" ? input : input.href;
}

/**
 * Fetch that refuses private or non-https targets unless private URLs are allowed,
 * and re-checks every redirect hop. Authorization is dropped when the origin changes.
 */
export function createSafeFetch(allowPrivate: boolean): FetchLike {
  return async (input, init) => {
    let current = requestUrl(input);
    let method = init?.method ?? "GET";
    let body = init?.body;
    let headers = init?.headers;
    for (let hop = 0; hop < MAX_HOPS; hop++) {
      const parsed = await assertSafeUrl(current, allowPrivate);
      if (!allowPrivate && parsed.protocol !== "https:") {
        throw new SsrfError("https required for OAuth endpoints");
      }
      const res = await fetch(current, {
        ...init,
        method,
        headers,
        body,
        redirect: "manual",
      });
      if (res.status < 300 || res.status >= 400) return toGlobalResponse(res);
      const loc = res.headers.get("location");
      await res.body?.cancel().catch(() => undefined);
      if (!loc) return res;
      const next = new URL(loc, current);
      if (next.origin !== parsed.origin) {
        headers = stripAuthorization(headers);
      }
      current = next.href;
      if (res.status === 301 || res.status === 302 || res.status === 303) {
        method = "GET";
        body = undefined;
      }
    }
    throw new SsrfError("too many redirects");
  };
}

/**
 * Node's fetch Response is not always `instanceof` the global Response the MCP SDK checks
 * (`parseErrorResponse` then treats the response as a string). Rebuild without buffering.
 */
function toGlobalResponse(res: Response): Response {
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: res.headers,
  });
}

function stripAuthorization(headers: RequestInit["headers"]): Headers {
  const next = new Headers(headers);
  next.delete("authorization");
  return next;
}
