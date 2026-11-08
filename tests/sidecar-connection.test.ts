import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import {
  applySidecarEnv,
  ociNetworkMode,
  socksRemoteDns,
} from "../src/egress/sidecar.js";
import type { EgressProxy } from "../src/egress/sidecar.js";
import { ociRunArgs } from "../src/mcp/runners/oci.js";
import { createSafeFetch } from "../src/oauth/fetch.js";
import { assertSafeUrl, SsrfError } from "../src/ssrf.js";

const master = Buffer.alloc(32, 9).toString("base64");
const dirs: string[] = [];

function openStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-sc-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), master);
}

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function proxy(partial: Partial<EgressProxy> & Pick<EgressProxy, "slug">): EgressProxy {
  return {
    connectionId: partial.connectionId ?? `sc_${partial.slug}`,
    slug: partial.slug,
    displayName: partial.displayName ?? partial.slug,
    kind: partial.kind ?? "tailscale",
    httpProxyUrl: partial.httpProxyUrl ?? null,
    socksProxyUrl: partial.socksProxyUrl ?? null,
    scope: partial.scope ?? "gateway",
    deviceId: partial.deviceId ?? null,
  };
}

describe("sidecar catalog", () => {
  it("adds the connection column and leaves backends on the normal path", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const cols = store.db.prepare(`PRAGMA table_info(backends)`).all() as Array<{ name: string }>;
    expect(cols.map((col) => col.name)).toContain("connection_id");
    const applied = store.db
      .prepare(`SELECT id FROM mcpflow_schema_migrations WHERE id = ?`)
      .get("0020_sidecar_connections");
    expect(applied).toBeTruthy();
    const backend = store.createBackend(ws.id, {
      slug: "plain",
      url: "https://mcp.example.com/mcp",
      enabled: false,
    });
    expect(backend.connectionId).toBeNull();
    expect(backend.connection).toBeNull();
    expect(store.egressFor(store.getBackend(ws.id, "plain")!)).toBeNull();
    store.close();
  });

  it("names connections, assigns one, and refuses the other network", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const office = store.createSidecar(ws.id, {
      slug: "office",
      displayName: "Office",
      kind: "tailscale",
      httpProxy: "http://office-sidecar:1055",
      socksProxy: "socks5://office-sidecar:1056",
    });
    const lab = store.createSidecar(ws.id, {
      slug: "lab",
      displayName: "Lab",
      kind: "generic",
      httpProxy: "http://lab-sidecar:1055",
    });
    const renamed = store.updateSidecar(ws.id, "office", { displayName: "Office tailnet" });
    expect(renamed?.displayName).toBe("Office tailnet");
    expect(renamed?.slug).toBe("office");

    const backend = store.createBackend(ws.id, {
      slug: "remote",
      url: "https://mcp.example.com/mcp",
      connectionId: "office",
    });
    expect(backend.connectionId).toBe(office.id);
    expect(backend.connection).toMatchObject({ slug: "office", displayName: "Office tailnet" });
    const egress = store.egressFor(store.getBackend(ws.id, "remote")!)!;
    expect(egress.httpProxyUrl).toBe("http://office-sidecar:1055");
    expect(egress.slug).not.toBe(lab.slug);

    const cleared = store.updateBackend(ws.id, "remote", { connectionId: null });
    expect(cleared?.connectionId).toBeNull();
    expect(store.egressFor(store.getBackend(ws.id, "remote")!)).toBeNull();

    store.updateBackend(ws.id, "remote", { connectionId: lab.id });
    expect(store.egressFor(store.getBackend(ws.id, "remote")!)?.slug).toBe("lab");
    expect(() => store.deleteSidecar(ws.id, "lab")).toThrow(/assigned to 1 backend/);
    store.updateBackend(ws.id, "remote", { connectionId: null });
    expect(store.deleteSidecar(ws.id, "lab")).toBe(true);
    expect(() =>
      store.createBackend(ws.id, {
        slug: "missing",
        url: "https://mcp.example.com/mcp",
        connectionId: "nope",
      }),
    ).toThrow(/not found/);
    store.close();
  });

  it("keeps a device connection off gateway backends and the reverse", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const device = store.enrollDevice(ws.id, { name: "edge" });
    const gateway = store.createSidecar(ws.id, {
      slug: "gateway-net",
      displayName: "Gateway",
      kind: "tailscale",
      httpProxy: "http://tailscale:1055",
    });
    const local = store.createSidecar(ws.id, {
      slug: "edge-net",
      displayName: "Edge",
      kind: "tailscale",
      scope: "device",
      deviceId: device.id,
      httpProxy: "http://127.0.0.1:1055",
    });
    expect(() =>
      store.createBackend(ws.id, {
        slug: "remote",
        url: "https://mcp.example.com/mcp",
        connectionId: local.slug,
      }),
    ).toThrow(/gateway sidecar/);
    expect(() =>
      store.createBackend(ws.id, {
        slug: "edge",
        transport: "stdio",
        command: ["echo"],
        placement: { mode: "edge-bare", deviceId: device.id },
        connectionId: gateway.id,
      }),
    ).toThrow(/same device/);
    const other = store.enrollDevice(ws.id, { name: "other" });
    expect(() =>
      store.createBackend(ws.id, {
        slug: "edge",
        transport: "stdio",
        command: ["echo"],
        placement: { mode: "edge-sandbox", deviceId: other.id },
        connectionId: local.id,
      }),
    ).toThrow(/same device/);
    const ok = store.createBackend(ws.id, {
      slug: "edge",
      transport: "stdio",
      command: ["echo"],
      placement: { mode: "edge-bare", deviceId: device.id },
      connectionId: local.slug,
    });
    expect(ok.connection?.slug).toBe("edge-net");
    store.updateSidecar(ws.id, gateway.id, { enabled: false });
    expect(() =>
      store.updateBackend(ws.id, "edge", { connectionId: gateway.id }),
    ).toThrow(/disabled/);
    store.close();
  });

  it("refreshes seed endpoints and keeps a renamed display name", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const raw = JSON.stringify([
      {
        slug: "tailscale",
        displayName: "Tailscale",
        kind: "tailscale",
        httpProxy: "http://tailscale:1055",
        socksProxy: "socks5://tailscale:1056",
      },
    ]);
    const first = store.seedSidecars(ws.id, raw);
    expect(first.created).toEqual(["tailscale"]);
    store.updateSidecar(ws.id, "tailscale", { displayName: "Office" });
    const next = JSON.stringify([
      {
        slug: "tailscale",
        displayName: "Tailscale",
        kind: "tailscale",
        httpProxy: "http://tailscale:2055",
        socksProxy: "socks5h://tailscale:2056",
      },
    ]);
    const second = store.seedSidecars(ws.id, next);
    expect(second.refreshed).toEqual(["tailscale"]);
    const row = store.getSidecar(ws.id, "tailscale");
    expect(row?.displayName).toBe("Office");
    expect(row?.httpProxy).toBe("http://tailscale:2055");
    expect(row?.socksProxy).toBe("socks5h://tailscale:2056");
    expect(store.listSidecars(ws.id)).toHaveLength(1);
    expect(() => store.seedSidecars(ws.id, "{")).toThrow(/JSON array/);
    store.close();
  });

  it("rejects proxy credentials", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    expect(() =>
      store.createSidecar(ws.id, {
        slug: "bad",
        displayName: "Bad",
        httpProxy: "http://user:secret@tailscale:1055",
      }),
    ).toThrow(/credentials/);
    store.close();
  });
});

describe("sidecar process env", () => {
  it("leaves the environment alone when no connection is selected", () => {
    const base = { PATH: "/usr/bin", HTTP_PROXY: "http://kept.example:1" };
    expect(applySidecarEnv(base, null)).toBe(base);
  });

  it("sets proxy variables for the selected connection only", () => {
    const env = applySidecarEnv(
      { PATH: "/usr/bin", HTTP_PROXY: "http://other.example:1", NO_PROXY: "*" },
      proxy({
        slug: "office",
        httpProxyUrl: "http://tailscale:1055",
        socksProxyUrl: "socks5://tailscale:1056",
      }),
    );
    expect(env.PATH).toBe("/usr/bin");
    expect(env.HTTP_PROXY).toBe("http://tailscale:1055");
    expect(env.HTTPS_PROXY).toBe("http://tailscale:1055");
    expect(env.http_proxy).toBe("http://tailscale:1055");
    expect(env.https_proxy).toBe("http://tailscale:1055");
    expect(env.ALL_PROXY).toBe("socks5h://tailscale:1056");
    expect(env.SOCKS_PROXY).toBe("socks5h://tailscale:1056");
    expect(env.NODE_USE_ENV_PROXY).toBe("1");
    expect(env.NO_PROXY).toBe("localhost,127.0.0.1,::1");
    expect(env.no_proxy).toBe(env.NO_PROXY);
    expect(socksRemoteDns("socks5://tailscale:1056")).toBe("socks5h://tailscale:1056");
    expect(socksRemoteDns("socks5h://tailscale:1056")).toBe("socks5h://tailscale:1056");
  });

  it("joins the compose network only for a gateway connection without an explicit mode", () => {
    const egress = proxy({ slug: "office", scope: "gateway", httpProxyUrl: "http://tailscale:1055" });
    expect(ociNetworkMode(null, null)).toBe("bridge");
    expect(ociNetworkMode(null, egress, { MCP_FLOW_EGRESS_NETWORK: "mcp-flow" })).toBe("mcp-flow");
    expect(ociNetworkMode({ networkMode: "none" }, egress)).toBe("none");
    expect(ociNetworkMode(null, proxy({ slug: "edge", scope: "device", deviceId: "dev_1" }))).toBe(
      "bridge",
    );
    const args = ociRunArgs({
      image: "ghcr.io/example/mcp:latest",
      command: ["server"],
      env: { HTTP_PROXY: "http://tailscale:1055" },
      networkMode: "mcp-flow",
    });
    expect(args).toContain("--network");
    expect(args[args.indexOf("--network") + 1]).toBe("mcp-flow");
    expect(args).toContain("HTTP_PROXY=http://tailscale:1055");
  });
});

describe("sidecar URL policy", () => {
  it("allows MagicDNS failures and tailnet addresses only through a sidecar", async () => {
    await expect(assertSafeUrl("http://magicdns.invalid/mcp", false)).rejects.toBeInstanceOf(
      SsrfError,
    );
    const deferred = await assertSafeUrl("http://magicdns.invalid/mcp", false, {
      viaSidecar: true,
    });
    expect(deferred.hostname).toBe("magicdns.invalid");
    await expect(assertSafeUrl("http://100.64.0.1/mcp", false)).rejects.toThrow(/private IP/);
    await expect(
      assertSafeUrl("http://100.64.0.1/mcp", false, { viaSidecar: true }),
    ).resolves.toBeInstanceOf(URL);
    await expect(
      assertSafeUrl("http://[fd7a:115c:a1e0::1]/mcp", false, { viaSidecar: true }),
    ).resolves.toBeInstanceOf(URL);
    await expect(
      assertSafeUrl("http://10.1.1.1/mcp", false, { viaSidecar: true }),
    ).rejects.toThrow(/private IP/);
    await expect(
      assertSafeUrl("http://metadata.google.internal/mcp", false, { viaSidecar: true }),
    ).rejects.toThrow(/blocked hostname/);
  });
});

function listen(
  onRequest: (req: IncomingMessage, res: ServerResponse) => void,
): Promise<{ port: number; close: () => Promise<void> }> {
  const server = createServer(onRequest);
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("no port");
      resolve({
        port: address.port,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

/** HTTP proxy that records CONNECT targets and answers through the tunnel. */
function proxyListen(body: string, seen: string[]): Promise<{ port: number; close: () => Promise<void> }> {
  const server = createServer();
  server.on("connect", (req, socket) => {
    seen.push(String(req.url ?? ""));
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    let buf = "";
    socket.on("data", (chunk: Buffer) => {
      buf += chunk.toString("utf8");
      if (!buf.includes("\r\n\r\n")) return;
      socket.end(
        `HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`,
      );
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("no port");
      resolve({
        port: address.port,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

describe("sidecar fetch", () => {
  it("sends the hostname to the selected proxy and not to another connection", async () => {
    const seenA: string[] = [];
    const seenB: string[] = [];
    const directHits: string[] = [];
    const a = await proxyListen("a", seenA);
    const b = await proxyListen("b", seenB);
    const direct = await listen((req, res) => {
      directHits.push(req.url ?? "");
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("direct");
    });
    try {
      const fetchA = createSafeFetch(false, {
        requireHttps: false,
        egress: proxy({ slug: "a", httpProxyUrl: `http://127.0.0.1:${a.port}` }),
      });
      const fetchB = createSafeFetch(false, {
        requireHttps: false,
        egress: proxy({ slug: "b", httpProxyUrl: `http://127.0.0.1:${b.port}` }),
      });
      const viaA = await fetchA("http://name-a.invalid/mcp");
      const viaB = await fetchB("http://name-b.invalid/mcp");
      expect(await viaA.text()).toBe("a");
      expect(await viaB.text()).toBe("b");
      expect(seenA.join(" ")).toContain("name-a.invalid");
      expect(seenA.join(" ")).not.toContain("name-b.invalid");
      expect(seenB.join(" ")).toContain("name-b.invalid");
      expect(seenB.join(" ")).not.toContain("name-a.invalid");
      expect(directHits).toEqual([]);

      const plain = await createSafeFetch(true)(`http://127.0.0.1:${direct.port}/plain`);
      expect(await plain.text()).toBe("direct");
      expect(directHits).toEqual(["/plain"]);
      expect(seenA.join(" ")).not.toContain("/plain");
    } finally {
      await a.close();
      await b.close();
      await direct.close();
    }
  });
});

describe("compose sidecar egress", () => {
  it("listens for outbound proxies without publishing them", () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), "..");
    for (const file of ["docker-compose.yml", "docker-compose.dev.yml"]) {
      const text = readFileSync(join(root, file), "utf8");
      expect(text).toContain("TS_OUTBOUND_HTTP_PROXY_LISTEN");
      expect(text).toContain("TS_SOCKS5_SERVER");
      expect(text).toContain("MCP_FLOW_SIDECARS");
      expect(text).toContain("MCP_FLOW_EGRESS_NETWORK");
      expect(text).not.toMatch(/["']1055:1055["']/);
      expect(text).not.toMatch(/["']1056:1056["']/);
    }
    const edge = readFileSync(join(root, "docker-compose.edge.yaml"), "utf8");
    expect(edge).not.toContain("tailscale:");
  });
});
