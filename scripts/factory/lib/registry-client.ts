import type { RegistryListItem } from "../../../src/catalog/normalize.js";
import { httpGetJson } from "./http-util.js";
import { ProxyPool } from "./proxy-pool.js";
import type { FactorySettings } from "./paths.js";
import { resolveProxyUrl } from "./settings.js";

export interface PageResult {
  items: RegistryListItem[];
  nextCursor?: string;
}

export class RegistryClient {
  constructor(
    private settings: FactorySettings,
    private pool?: ProxyPool,
  ) {}

  private pickProxy(): string | undefined {
    if (!this.settings.useProxy) {
      return resolveProxyUrl(this.settings);
    }
    const fixed = resolveProxyUrl(this.settings);
    if (fixed) return fixed;
    return this.pool?.pick();
  }

  async fetchPage(opts: {
    cursor?: string;
    limit?: number;
    search?: string;
  }): Promise<PageResult> {
    const u = new URL(this.settings.registryUrl);
    u.searchParams.set("limit", String(opts.limit ?? this.settings.pageLimit));
    if (opts.cursor) u.searchParams.set("cursor", opts.cursor);
    if (opts.search) u.searchParams.set("search", opts.search);

    const proxy = this.pickProxy();
    try {
      const body = await httpGetJson<{
        servers?: RegistryListItem[];
        metadata?: { nextCursor?: string };
      }>(u.toString(), { timeout: 45_000, proxy });
      if (proxy) this.pool?.reportOk(proxy);
      return {
        items: body.servers ?? [],
        nextCursor: body.metadata?.nextCursor,
      };
    } catch (err) {
      if (proxy) this.pool?.reportFail(proxy);
      throw err;
    }
  }

  async *paginate(opts: {
    maxPages?: number;
    search?: string;
    onPage?: (n: number, count: number) => void;
  } = {}): AsyncGenerator<RegistryListItem[], void, unknown> {
    let cursor: string | undefined;
    let pages = 0;
    const maxPages = opts.maxPages ?? this.settings.maxPages;

    for (;;) {
      if (maxPages > 0 && pages >= maxPages) break;
      const { items, nextCursor } = await this.fetchPage({
        cursor,
        search: opts.search || this.settings.search || undefined,
      });
      pages++;
      opts.onPage?.(pages, items.length);
      if (items.length) yield items;
      if (!nextCursor || !items.length) break;
      cursor = nextCursor;
    }
  }
}
