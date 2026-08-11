import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { ProxyAgent, fetch as undiciFetch } from "undici";

export interface HttpGetOptions {
  timeout?: number;
  proxy?: string;
  headers?: Record<string, string>;
}

function isSocks(proxy: string): boolean {
  return /^socks/i.test(proxy);
}

async function getViaSocks(
  urlStr: string,
  proxy: string,
  opts: HttpGetOptions,
): Promise<{ status: number; text: string }> {
  const { SocksProxyAgent } = await import("socks-proxy-agent");
  const agent = new SocksProxyAgent(proxy);
  const url = new URL(urlStr);
  const lib = url.protocol === "http:" ? httpRequest : httpsRequest;
  const timeout = opts.timeout ?? 30_000;

  return new Promise((resolve, reject) => {
    const req = lib(
      url,
      {
        method: "GET",
        agent,
        headers: {
          Accept: "application/json, text/plain, */*",
          ...(opts.headers ?? {}),
        },
        timeout,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c as Buffer));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            text: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`timeout after ${timeout}ms`));
    });
    req.end();
  });
}

export async function httpGetText(
  url: string,
  opts: HttpGetOptions = {},
): Promise<string> {
  const timeout = opts.timeout ?? 30_000;
  const proxy = opts.proxy?.trim();

  if (proxy && isSocks(proxy)) {
    const { status, text } = await getViaSocks(url, proxy, opts);
    if (status < 200 || status >= 300) {
      throw new Error(`HTTP ${status} for ${url}`);
    }
    return text;
  }

  if (proxy) {
    const dispatcher = new ProxyAgent(proxy);
    const res = await undiciFetch(url, {
      dispatcher,
      headers: opts.headers,
      signal: AbortSignal.timeout(timeout),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
    return await res.text();
  }

  const res = await fetch(url, {
    headers: opts.headers,
    signal: AbortSignal.timeout(timeout),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return await res.text();
}

export async function httpGetJson<T = unknown>(
  url: string,
  opts: HttpGetOptions = {},
): Promise<T> {
  const text = await httpGetText(url, {
    ...opts,
    headers: {
      Accept: "application/json",
      ...(opts.headers ?? {}),
    },
  });
  return JSON.parse(text) as T;
}
