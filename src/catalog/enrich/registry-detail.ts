import type { RegistryListItem } from "../normalize.js";
import { DEFAULT_REGISTRY_URL } from "../types.js";

/**
 * GET /v0.1/servers/{serverName}/versions/latest
 * serverName must be URL-encoded (slash → %2F).
 */
export async function fetchRegistryDetail(
  serverName: string,
  opts: {
    registryBase?: string;
    fetchImpl?: typeof fetch;
    proxyGetJson?: (url: string) => Promise<unknown>;
  } = {},
): Promise<RegistryListItem | null> {
  const base = (opts.registryBase ?? DEFAULT_REGISTRY_URL).replace(
    /\/servers\/?$/,
    "",
  );
  const encoded = encodeURIComponent(serverName);
  const url = `${base}/servers/${encoded}/versions/latest`;

  try {
    if (opts.proxyGetJson) {
      const body = await opts.proxyGetJson(url);
      return body as RegistryListItem;
    }
    const fetchImpl = opts.fetchImpl ?? fetch;
    const res = await fetchImpl(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) return null;
    return (await res.json()) as RegistryListItem;
  } catch {
    return null;
  }
}
