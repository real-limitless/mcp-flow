import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { httpGetText } from "./http-util.js";
import { PROXIES_DIR, PROXIES_HEALTH, PROXIES_LIST } from "./paths.js";

const DEFAULT_PROXY_URL =
  "https://databay.com/free-proxy-list/socks5.txt";

const LINE_RE =
  /^(?:(?<scheme>socks5h?|socks4|https?):\/\/)?(?<host>\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9.-]+):(?<port>\d{2,5})\s*$/i;

const HEALTH_URLS = [
  "https://registry.modelcontextprotocol.io/v0.1/servers?limit=1",
  "https://httpbin.org/ip",
];

function nowIso(): string {
  return new Date().toISOString();
}

export class ProxyPool {
  private alive: string[] = [];
  private dead = new Set<string>();
  private failCounts = new Map<string, number>();

  constructor() {
    mkdirSync(PROXIES_DIR, { recursive: true });
    this.loadHealth();
  }

  private loadHealth(): void {
    if (!existsSync(PROXIES_HEALTH)) return;
    try {
      const data = JSON.parse(readFileSync(PROXIES_HEALTH, "utf8")) as {
        alive?: string[];
        dead?: string[];
        failCounts?: Record<string, number>;
      };
      this.alive = data.alive ?? [];
      this.dead = new Set(data.dead ?? []);
      this.failCounts = new Map(
        Object.entries(data.failCounts ?? {}).map(([k, v]) => [k, Number(v)]),
      );
    } catch {
      /* ignore */
    }
  }

  saveHealth(): void {
    mkdirSync(PROXIES_DIR, { recursive: true });
    writeFileSync(
      PROXIES_HEALTH,
      `${JSON.stringify(
        {
          alive: this.alive,
          dead: [...this.dead].sort(),
          failCounts: Object.fromEntries(this.failCounts),
          updatedAt: nowIso(),
          counts: {
            alive: this.alive.length,
            dead: this.dead.size,
            listed: this.listedProxies().length,
          },
        },
        null,
        2,
      )}\n`,
      "utf8",
    );
  }

  parseProxyLines(
    text: string,
    defaultScheme = "socks5",
  ): string[] {
    const out: string[] = [];
    for (const line of text.split(/\r?\n/)) {
      const t = line.trim();
      if (!t || t.startsWith("#")) continue;
      const m = LINE_RE.exec(t);
      if (!m?.groups) continue;
      let scheme = (m.groups.scheme || defaultScheme).toLowerCase();
      if (scheme === "socks5") scheme = "socks5h";
      out.push(`${scheme}://${m.groups.host}:${m.groups.port}`);
    }
    return [...new Set(out)];
  }

  listedProxies(): string[] {
    if (!existsSync(PROXIES_LIST)) return [];
    return this.parseProxyLines(readFileSync(PROXIES_LIST, "utf8"));
  }

  async refresh(
    listUrl = DEFAULT_PROXY_URL,
    proxyForFetch?: string,
  ): Promise<number> {
    const text = await httpGetText(listUrl, {
      timeout: 30_000,
      proxy: proxyForFetch,
    });
    const proxies = this.parseProxyLines(text);
    const body =
      "# proxy list (host:port)\n" +
      proxies.map((p) => p.replace(/^[a-z0-9]+:\/\//i, "")).join("\n") +
      "\n";
    writeFileSync(PROXIES_LIST, body, "utf8");
    return proxies.length;
  }

  addProxy(proxy: string): void {
    const parsed = this.parseProxyLines(proxy.trim());
    if (!parsed.length) {
      throw new Error(`Invalid proxy: ${proxy}`);
    }
    const existing = this.listedProxies();
    const merged = [...new Set([...existing, ...parsed])];
    const body =
      "# proxy list\n" +
      merged.map((p) => p.replace(/^[a-z0-9]+:\/\//i, "")).join("\n") +
      "\n";
    writeFileSync(PROXIES_LIST, body, "utf8");
  }

  async probeOne(proxyUrl: string, timeout = 10_000): Promise<boolean> {
    for (const health of HEALTH_URLS) {
      try {
        await httpGetText(health, { timeout, proxy: proxyUrl });
        return true;
      } catch {
        /* try next */
      }
    }
    return false;
  }

  async healthCheck(opts: {
    limit?: number;
    timeout?: number;
  } = {}): Promise<{ alive: number; dead: number; tested: number }> {
    const limit = opts.limit ?? 20;
    const timeout = (opts.timeout ?? 8) * 1000;
    const listed = this.listedProxies();
    const sample = listed.slice(0, limit);
    const alive: string[] = [];
    const dead: string[] = [];

    // sequential to avoid stampede; small limit
    for (const p of sample) {
      const ok = await this.probeOne(p, timeout);
      if (ok) {
        alive.push(p);
        this.failCounts.delete(p);
      } else {
        dead.push(p);
        this.failCounts.set(p, (this.failCounts.get(p) ?? 0) + 1);
      }
    }

    this.alive = alive;
    for (const d of dead) this.dead.add(d);
    // keep previously alive that weren't tested
    for (const a of this.alive) this.dead.delete(a);
    this.saveHealth();
    return { alive: alive.length, dead: dead.length, tested: sample.length };
  }

  pick(): string | undefined {
    if (this.alive.length) {
      return this.alive[Math.floor(Math.random() * this.alive.length)];
    }
    const listed = this.listedProxies().filter((p) => !this.dead.has(p));
    if (!listed.length) return undefined;
    return listed[Math.floor(Math.random() * listed.length)];
  }

  reportOk(proxyUrl: string): void {
    this.failCounts.delete(proxyUrl);
    if (!this.alive.includes(proxyUrl)) this.alive.push(proxyUrl);
    this.dead.delete(proxyUrl);
  }

  reportFail(proxyUrl: string): void {
    const n = (this.failCounts.get(proxyUrl) ?? 0) + 1;
    this.failCounts.set(proxyUrl, n);
    if (n >= 3) {
      this.dead.add(proxyUrl);
      this.alive = this.alive.filter((p) => p !== proxyUrl);
    }
  }

  summary(): {
    listed: number;
    alive: number;
    dead: number;
    sampleAlive: string[];
  } {
    return {
      listed: this.listedProxies().length,
      alive: this.alive.length,
      dead: this.dead.size,
      sampleAlive: this.alive.slice(0, 5),
    };
  }
}
