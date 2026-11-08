import http from "node:http";
import https from "node:https";
import { Readable } from "node:stream";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { FetchLike } from "@modelcontextprotocol/sdk/shared/transport.js";
import { SocksProxyAgent } from "socks-proxy-agent";
import { ProxyAgent, fetch as undiciFetch } from "undici";
import {
  SidecarUnavailableError,
  socksRemoteDns,
  type EgressProxy,
} from "../egress/sidecar.js";
import { assertSafeUrl, SsrfError } from "../ssrf.js";

const MAX_HOPS = 5;

const httpDispatchers = new Map<string, ProxyAgent>();
const socksAgents = new Map<string, SocksProxyAgent>();

function requestUrl(input: string | URL): string {
  return typeof input === "string" ? input : input.href;
}

export interface SafeFetchOptions {
  /** When set, this fetch dials through that connection and does not fall back. */
  egress?: EgressProxy | null;
  /**
   * Require https. Default matches the historical OAuth rule: required unless
   * private URLs are allowed. Remote MCP over a sidecar may be plain http.
   */
  requireHttps?: boolean;
}

/**
 * Fetch that refuses private or non-https targets unless private URLs are allowed,
 * and re-checks every redirect hop. Authorization is dropped when the origin changes.
 * A selected sidecar connection is the only reason this uses a proxy.
 */
export function createSafeFetch(
  allowPrivate: boolean,
  options: SafeFetchOptions = {},
): FetchLike {
  const egress = options.egress ?? null;
  const requireHttps = options.requireHttps ?? !allowPrivate;
  const viaSidecar = Boolean(egress);
  return async (input, init) => {
    let current = requestUrl(input);
    let method = init?.method ?? "GET";
    let body = init?.body;
    let headers = init?.headers;
    for (let hop = 0; hop < MAX_HOPS; hop++) {
      const parsed = await assertSafeUrl(current, allowPrivate, { viaSidecar });
      if (requireHttps && parsed.protocol !== "https:") {
        throw new SsrfError("https required for OAuth endpoints");
      }
      const res = egress
        ? await fetchViaSidecar(current, { ...init, method, headers, body, redirect: "manual" }, egress)
        : await fetch(current, {
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

function httpDispatcher(proxyUrl: string): ProxyAgent {
  let agent = httpDispatchers.get(proxyUrl);
  if (!agent) {
    agent = new ProxyAgent(proxyUrl);
    httpDispatchers.set(proxyUrl, agent);
  }
  return agent;
}

function socksAgent(proxyUrl: string): SocksProxyAgent {
  let agent = socksAgents.get(proxyUrl);
  if (!agent) {
    agent = new SocksProxyAgent(proxyUrl);
    socksAgents.set(proxyUrl, agent);
  }
  return agent;
}

async function fetchViaSidecar(
  url: string,
  init: RequestInit,
  egress: EgressProxy,
): Promise<Response> {
  if (egress.httpProxyUrl) {
    const res = await undiciFetch(url, {
      method: init.method,
      headers: init.headers,
      body: init.body as never,
      redirect: "manual",
      signal: init.signal ?? undefined,
      dispatcher: httpDispatcher(egress.httpProxyUrl),
    });
    return toGlobalResponse(res as unknown as Response);
  }
  const socks = socksRemoteDns(egress.socksProxyUrl);
  if (!socks) {
    throw new SidecarUnavailableError(
      `backend sidecar ${egress.slug} has no proxy endpoint`,
    );
  }
  return fetchViaSocks(url, init, socks);
}

function headersToNode(headers: RequestInit["headers"]): Record<string, string> {
  const out: Record<string, string> = {};
  new Headers(headers).forEach((value, key) => {
    out[key] = value;
  });
  return out;
}

function fetchViaSocks(urlStr: string, init: RequestInit, proxy: string): Promise<Response> {
  const url = new URL(urlStr);
  const lib = url.protocol === "http:" ? http : https;
  const agent = socksAgent(proxy);
  return new Promise((resolve, reject) => {
    const req = lib.request(
      url,
      {
        method: init.method,
        headers: headersToNode(init.headers),
        agent,
      },
      (res) => {
        resolve(responseFromNode(res));
      },
    );
    const onAbort = () => {
      req.destroy(new Error("aborted"));
    };
    if (init.signal) {
      if (init.signal.aborted) {
        onAbort();
        reject(new Error("aborted"));
        return;
      }
      init.signal.addEventListener("abort", onAbort, { once: true });
      req.on("close", () => init.signal?.removeEventListener("abort", onAbort));
    }
    req.on("error", reject);
    sendBody(req, init.body).catch((err) => {
      const error = err instanceof Error ? err : new Error(String(err));
      req.destroy(error);
      reject(error);
    });
  });
}

async function sendBody(req: ClientRequest, body: RequestInit["body"]): Promise<void> {
  if (body == null) {
    req.end();
    return;
  }
  if (typeof body === "string" || body instanceof URLSearchParams) {
    req.end(body.toString());
    return;
  }
  if (body instanceof Uint8Array) {
    req.end(body);
    return;
  }
  if (body instanceof ArrayBuffer) {
    req.end(Buffer.from(body));
    return;
  }
  if (typeof Blob !== "undefined" && body instanceof Blob) {
    req.end(Buffer.from(await body.arrayBuffer()));
    return;
  }
  const reader = (body as ReadableStream<Uint8Array>).getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) req.write(value);
    }
  } finally {
    req.end();
  }
}

function responseFromNode(res: IncomingMessage): Response {
  const headers = new Headers();
  for (const [key, value] of Object.entries(res.headers)) {
    if (value == null) continue;
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
    } else {
      headers.append(key, value);
    }
  }
  return new Response(Readable.toWeb(res) as ReadableStream, {
    status: res.statusCode ?? 500,
    statusText: res.statusMessage,
    headers,
  });
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
