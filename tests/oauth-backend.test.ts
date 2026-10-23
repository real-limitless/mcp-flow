import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { readOauthSecrets } from "../src/db/oauth-store.js";
import { createSafeFetch } from "../src/oauth/fetch.js";
import { safeOauthMessage, startOauthAuthorization, pollOauthDevice } from "../src/oauth/flow.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { startServer, type RunningServer } from "../src/server.js";

const master = Buffer.alloc(32, 7).toString("base64");
const admin = "oauth-admin-token";
const ACCESS = "oa-access-PLAINTEXT-token-aaa111";
const REFRESH = "oa-refresh-PLAINTEXT-token-bbb222";
const REFRESHED = "oa-access-PLAINTEXT-token-refreshed999";
const DYN_SECRET = "oa-client-PLAINTEXT-secret-ccc333";
const MANUAL_SECRET = "oa-manual-PLAINTEXT-secret-ddd444";

const dirs: string[] = [];
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function closeHttp(server: { close: (cb: (err?: Error) => void) => void; closeAllConnections?: () => void }): Promise<void> {
  server.closeAllConnections?.();
  return new Promise((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

async function readBody(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.setHeader("content-length", Buffer.byteLength(payload));
  res.end(payload);
}

interface MockOpts {
  registration: boolean;
  refresh: "ok" | "invalid";
  codeExpiresIn: number;
}

async function startMock(opts: MockOpts): Promise<{
  url: string;
  counts: { register: number; refresh: number; code: number; revoke: number };
  bearers: string[];
  lastTokenParams: URLSearchParams | null;
  lastBasic: string | null;
  mode: MockOpts;
  close: () => Promise<void>;
}> {
  const counts = { register: 0, refresh: 0, code: 0, revoke: 0 };
  const bearers: string[] = [];
  const mode = { ...opts };
  let lastTokenParams: URLSearchParams | null = null;
  let lastBasic: string | null = null;
  let access = "";
  let port = 0;

  const mcp = () => {
    const server = new McpServer({ name: "oauth-upstream", version: "1.0.0" });
    server.registerTool(
      "echo",
      { description: "Echo", inputSchema: { text: z.string() } },
      async ({ text }) => ({ content: [{ type: "text" as const, text: `echo:${text}` }] }),
    );
    return server;
  };

  const httpServer = createServer(async (req, res) => {
    const pathname = new URL(req.url || "/", `http://127.0.0.1:${port}`).pathname;
    const origin = `http://127.0.0.1:${port}`;
    if (pathname.includes("oauth-protected-resource")) {
      sendJson(res, 200, {
        resource: `${origin}/mcp`,
        authorization_servers: [origin],
        scopes_supported: ["mcp"],
      });
      return;
    }
    if (pathname.includes("oauth-authorization-server")) {
      sendJson(res, 200, {
        issuer: origin,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        ...(mode.registration ? { registration_endpoint: `${origin}/register` } : {}),
        revocation_endpoint: `${origin}/revoke`,
        response_types_supported: ["code"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: [
          "client_secret_basic",
          "client_secret_post",
          "none",
        ],
      });
      return;
    }
    if (req.method === "POST" && pathname === "/register") {
      counts.register += 1;
      const body = JSON.parse(await readBody(req)) as { redirect_uris?: string[] };
      sendJson(res, 201, {
        client_id: "dyn-client",
        client_secret: DYN_SECRET,
        redirect_uris: body.redirect_uris ?? [],
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "client_secret_basic",
        client_name: "mcp-flow",
      });
      return;
    }
    if (req.method === "POST" && pathname === "/token") {
      const raw = await readBody(req);
      const params = new URLSearchParams(raw);
      lastTokenParams = params;
      const basic = req.headers.authorization;
      lastBasic = Array.isArray(basic) ? basic[0]! : basic ?? null;
      if (params.get("grant_type") === "refresh_token") {
        counts.refresh += 1;
        if (mode.refresh === "invalid") {
          sendJson(res, 400, { error: "invalid_grant", error_description: "revoked" });
          return;
        }
        access = REFRESHED;
        sendJson(res, 200, {
          access_token: REFRESHED,
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "oa-refresh-PLAINTEXT-token-rotated",
        });
        return;
      }
      counts.code += 1;
      access = ACCESS;
      sendJson(res, 200, {
        access_token: ACCESS,
        token_type: "Bearer",
          expires_in: mode.codeExpiresIn,
        refresh_token: REFRESH,
        scope: "mcp",
      });
      return;
    }
    if (req.method === "POST" && pathname === "/revoke") {
      counts.revoke += 1;
      res.statusCode = 200;
      res.end();
      return;
    }
    if (req.method === "GET" && pathname === "/mcp") {
      res.statusCode = 405;
      res.end();
      return;
    }
    if (req.method === "POST" && pathname === "/mcp") {
      const header = req.headers.authorization;
      const bearer = Array.isArray(header) ? header[0] : header;
      bearers.push(bearer ?? "");
      if (bearer !== `Bearer ${access}`) {
        res.statusCode = 401;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ error: "unauthorized" }));
        return;
      }
      const raw = await readBody(req);
      const body = raw ? JSON.parse(raw) : undefined;
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      const server = mcp();
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
      res.on("close", () => {
        void transport.close();
        void server.close();
      });
      return;
    }
    res.statusCode = 404;
    res.end("missing");
  });

  await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
  const addr = httpServer.address();
  if (!addr || typeof addr === "string") throw new Error("no addr");
  port = addr.port;
  return {
    url: `http://127.0.0.1:${port}/mcp`,
    counts,
    bearers,
    get lastTokenParams() {
      return lastTokenParams;
    },
    get lastBasic() {
      return lastBasic;
    },
    close: () => closeHttp(httpServer),
    mode,
  };
}

async function boot(allowPrivateUrls = true): Promise<RunningServer & { dbPath: string }> {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-oauth-"));
  dirs.push(dir);
  const dbPath = join(dir, "t.db");
  const cfg = loadConfig({
    dbPath,
    masterKeyRaw: master,
    adminToken: admin,
    host: "127.0.0.1",
    port: 0,
    allowPrivateUrls,
    publicUrl: "",
    workspaceName: "default",
  });
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  cfg.port = (probe.address() as { port: number }).port;
  await closeHttp(probe);
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return Object.assign(running, { dbPath });
}

function authHeaders(): Record<string, string> {
  return {
    Authorization: `Bearer ${admin}`,
    "Content-Type": "application/json",
  };
}

function dbText(dbPath: string): string {
  const parts = [dbPath, `${dbPath}-wal`, `${dbPath}-shm`];
  return parts
    .map((path) => {
      try {
        return readFileSync(path).toString("utf8");
      } catch {
        return "";
      }
    })
    .join("\n");
}

describe("upstream OAuth", () => {
  it("registers, consents with PKCE, calls tools, and keeps secrets sealed", async () => {
    const mock = await startMock({ registration: true, refresh: "ok", codeExpiresIn: 3600 });
    cleanups.push(() => mock.close());
    const gw = await boot();
    const created = await fetch(`${gw.url}/v1/backends`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        slug: "vendor",
        url: mock.url,
        transport: "streamable-http",
        enabled: true,
        auth: { type: "oauth" },
      }),
    });
    expect(created.status).toBe(201);
    const createdBody = (await created.json()) as { backend: { id: string; auth: { status: string } } };
    expect(createdBody.backend.auth.status).toBe("needs_reauth");

    const started = await fetch(`${gw.url}/v1/backends/vendor/oauth/start`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    expect(started.status).toBe(200);
    const startBody = (await started.json()) as {
      authorizationUrl: string;
      redirectUri: string;
    };
    const authUrl = new URL(startBody.authorizationUrl);
    expect(authUrl.searchParams.get("code_challenge_method")).toBe("S256");
    expect(authUrl.searchParams.get("state")!.length).toBeGreaterThan(20);
    expect(authUrl.searchParams.get("code_challenge")!.length).toBeGreaterThan(20);
    expect(startBody.redirectUri).toBe(`${new URL(gw.url).origin}/oauth/callback`);
    expect(mock.counts.register).toBe(1);

    const pending = readOauthSecrets(gw.store.db, gw.store.masterKey, createdBody.backend.id);
    expect(pending?.codeVerifier).toBeTruthy();
    gw.store.db.exec("PRAGMA wal_checkpoint(FULL)");
    expect(dbText(gw.dbPath)).not.toContain(pending!.codeVerifier!);
    expect(dbText(gw.dbPath)).not.toContain(DYN_SECRET);

    const callback = await fetch(
      `${startBody.redirectUri}?code=auth-code-1&state=${encodeURIComponent(authUrl.searchParams.get("state")!)}`,
    );
    expect(await callback.text()).toContain("connected");
    expect(mock.counts.code).toBe(1);
    expect(mock.lastTokenParams?.get("grant_type")).toBe("authorization_code");
    expect(mock.lastTokenParams?.get("code_verifier")!.length).toBeGreaterThan(20);

    const replay = await fetch(
      `${startBody.redirectUri}?code=auth-code-1&state=${encodeURIComponent(authUrl.searchParams.get("state")!)}`,
    );
    expect(await replay.text()).toContain("did not complete");

    const tested = await fetch(`${gw.url}/v1/backends/vendor/test`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    const testBody = (await tested.json()) as { ok: boolean; error?: string; tools?: string[] };
    expect(testBody.ok, testBody.error).toBe(true);
    expect(testBody.tools).toContain("echo");
    expect(mock.bearers.some((b) => b === `Bearer ${ACCESS}`)).toBe(true);

    const listed = await fetch(`${gw.url}/v1/backends`, { headers: authHeaders() });
    const listedText = await listed.text();
    expect(listedText).toContain('"type":"oauth"');
    expect(listedText).toContain('"status":"connected"');
    expect(listedText).not.toContain(ACCESS);
    expect(listedText).not.toContain(REFRESH);
    expect(listedText).not.toContain(DYN_SECRET);

    const audit = await fetch(`${gw.url}/v1/audit`, { headers: authHeaders() });
    const auditText = await audit.text();
    expect(auditText).toContain("oauth.authorize");
    expect(auditText).not.toContain(ACCESS);
    expect(auditText).not.toContain(DYN_SECRET);

    gw.store.db.exec("PRAGMA wal_checkpoint(FULL)");
    const raw = dbText(gw.dbPath);
    expect(raw).not.toContain(ACCESS);
    expect(raw).not.toContain(REFRESH);
    expect(raw).not.toContain(DYN_SECRET);

    const revoked = await fetch(`${gw.url}/v1/backends/vendor/oauth/revoke`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    const revokedBody = (await revoked.json()) as {
      backend: { auth: { status: string; clientId: string | null; hasClientSecret: boolean } };
    };
    expect(revokedBody.backend.auth.status).toBe("needs_reauth");
    expect(revokedBody.backend.auth.clientId).toBe("dyn-client");
    expect(revokedBody.backend.auth.hasClientSecret).toBe(true);
    expect(mock.counts.revoke).toBe(1);
    gw.store.db.exec("PRAGMA wal_checkpoint(FULL)");
    expect(dbText(gw.dbPath)).not.toContain(ACCESS);
  });

  it("refreshes a near-expiry token before the upstream call", async () => {
    const mock = await startMock({ registration: true, refresh: "ok", codeExpiresIn: 30 });
    cleanups.push(() => mock.close());
    const gw = await boot();
    await fetch(`${gw.url}/v1/backends`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        slug: "vendor",
        url: mock.url,
        transport: "streamable-http",
        enabled: true,
        auth: { type: "oauth" },
      }),
    });
    const started = await fetch(`${gw.url}/v1/backends/vendor/oauth/start`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    const startBody = (await started.json()) as { authorizationUrl: string; redirectUri: string };
    const state = new URL(startBody.authorizationUrl).searchParams.get("state");
    await fetch(`${startBody.redirectUri}?code=c1&state=${encodeURIComponent(state!)}`);
    const tested = await fetch(`${gw.url}/v1/backends/vendor/test`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    const testBody = (await tested.json()) as { ok: boolean; error?: string };
    expect(testBody.ok, testBody.error).toBe(true);
    expect(mock.counts.refresh).toBe(1);
    expect(mock.bearers.some((b) => b === `Bearer ${REFRESHED}`)).toBe(true);
  });

  it("marks invalid_grant as needs re-auth and allows consent again", async () => {
    const mock = await startMock({ registration: true, refresh: "invalid", codeExpiresIn: 30 });
    cleanups.push(() => mock.close());
    const gw = await boot();
    const created = await fetch(`${gw.url}/v1/backends`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        slug: "vendor",
        url: mock.url,
        transport: "streamable-http",
        enabled: true,
        auth: { type: "oauth" },
      }),
    });
    const id = ((await created.json()) as { backend: { id: string } }).backend.id;
    const first = await fetch(`${gw.url}/v1/backends/vendor/oauth/start`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    const firstBody = (await first.json()) as { authorizationUrl: string; redirectUri: string };
    const state = new URL(firstBody.authorizationUrl).searchParams.get("state");
    await fetch(`${firstBody.redirectUri}?code=c1&state=${encodeURIComponent(state!)}`);

    const tested = await fetch(`${gw.url}/v1/backends/vendor/test`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    const testBody = (await tested.json()) as { ok: boolean; error?: string };
    expect(testBody.ok).toBe(false);
    expect(testBody.error).toMatch(/re-author/i);

    const audit = await (await fetch(`${gw.url}/v1/audit`, { headers: authHeaders() })).text();
    expect(audit).toContain("oauth.refresh_failure");
    expect(audit).toContain("invalid_grant");
    expect(audit).not.toContain(ACCESS);
    expect(audit).not.toContain(REFRESH);

    const pub = gw.store.getBackendPublic(gw.store.ensureWorkspace("default").id, id);
    expect(pub?.auth.status).toBe("needs_reauth");

    mock.mode.refresh = "ok";
    mock.mode.codeExpiresIn = 3600;
    const again = await fetch(`${gw.url}/v1/backends/vendor/oauth/start`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    expect(again.status).toBe(200);
    const againBody = (await again.json()) as { authorizationUrl: string; redirectUri: string };
    const state2 = new URL(againBody.authorizationUrl).searchParams.get("state");
    const done = await fetch(
      `${againBody.redirectUri}?code=c2&state=${encodeURIComponent(state2!)}`,
    );
    expect(await done.text()).toContain("connected");
    const pub2 = gw.store.getBackendPublic(gw.store.ensureWorkspace("default").id, id);
    expect(pub2?.auth.status).toBe("connected");
    expect(pub2?.id).toBe(id);
  });

  it("uses a manual client and skips dynamic registration", async () => {
    const mock = await startMock({ registration: false, refresh: "ok", codeExpiresIn: 3600 });
    cleanups.push(() => mock.close());
    const gw = await boot();
    await fetch(`${gw.url}/v1/backends`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        slug: "manual",
        url: mock.url,
        transport: "streamable-http",
        enabled: true,
        auth: {
          type: "oauth",
          clientId: "manual-client",
          clientSecret: MANUAL_SECRET,
        },
      }),
    });
    const started = await fetch(`${gw.url}/v1/backends/manual/oauth/start`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    expect(started.status).toBe(200);
    expect(mock.counts.register).toBe(0);
    const startBody = (await started.json()) as { authorizationUrl: string; redirectUri: string };
    const state = new URL(startBody.authorizationUrl).searchParams.get("state");
    await fetch(`${startBody.redirectUri}?code=c1&state=${encodeURIComponent(state!)}`);
    const basic = mock.lastBasic ?? "";
    const decoded = basic.startsWith("Basic ")
      ? Buffer.from(basic.slice(6), "base64").toString("utf8")
      : (mock.lastTokenParams?.get("client_secret") ?? "");
    expect(decoded).toContain(MANUAL_SECRET);
    const listed = await (await fetch(`${gw.url}/v1/backends`, { headers: authHeaders() })).text();
    expect(listed).not.toContain(MANUAL_SECRET);
    gw.store.db.exec("PRAGMA wal_checkpoint(FULL)");
    expect(dbText(gw.dbPath)).not.toContain(MANUAL_SECRET);
  });

  it("tells the admin to enter a client id when registration is not offered", async () => {
    const mock = await startMock({ registration: false, refresh: "ok", codeExpiresIn: 3600 });
    cleanups.push(() => mock.close());
    const gw = await boot();
    await fetch(`${gw.url}/v1/backends`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        slug: "noreg",
        url: mock.url,
        transport: "streamable-http",
        enabled: true,
        auth: { type: "oauth" },
      }),
    });
    const started = await fetch(`${gw.url}/v1/backends/noreg/oauth/start`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}",
    });
    expect(started.status).toBe(400);
    const body = (await started.json()) as { error: string };
    expect(body.error).toMatch(/client id/i);
    expect(mock.counts.register).toBe(0);
  });

  it("rejects OAuth discovery against a private address when private URLs are disabled", async () => {
    const mock = await startMock({ registration: true, refresh: "ok", codeExpiresIn: 3600 });
    cleanups.push(() => mock.close());
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-oauth-ssrf-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    cleanups.push(async () => store.close());
    const ws = store.ensureWorkspace("default");
    const backend = store.createBackend(ws.id, {
      slug: "priv",
      url: mock.url,
      transport: "streamable-http",
      enabled: true,
      auth: { type: "oauth" },
    });
    const record = store.getBackend(ws.id, backend.id)!;
    await expect(
      startOauthAuthorization({
        store,
        backend: record,
        redirectUri: "https://gateway.example/oauth/callback",
        allowPrivateUrls: false,
      }),
    ).rejects.toThrow(/private/i);
  });

  it("rejects OAuth on stdio backends", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-oauth-stdio-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    cleanups.push(async () => store.close());
    const ws = store.ensureWorkspace("default");
    expect(() =>
      store.createBackend(ws.id, {
        slug: "local",
        transport: "stdio",
        command: ["mcp-server"],
        placement: { mode: "central-sandbox" },
        auth: { type: "oauth" },
      }),
    ).toThrow(/OAuth/);
  });

  it("follows a safe redirect and rejects a credential redirect", async () => {
    const landed = createServer((_req, res) => {
      res.end("landed");
    });
    await new Promise<void>((resolve) => landed.listen(0, "127.0.0.1", resolve));
    const landPort = (landed.address() as { port: number }).port;
    cleanups.push(() => closeHttp(landed));

    const hopper = createServer((req, res) => {
      const path = req.url || "/";
      if (path.startsWith("/creds")) {
        res.statusCode = 302;
        res.setHeader("location", `http://user:pass@127.0.0.1:${landPort}/x`);
        res.end();
        return;
      }
      if (path.startsWith("/loop")) {
        res.statusCode = 302;
        res.setHeader("location", "/loop");
        res.end();
        return;
      }
      res.statusCode = 302;
      res.setHeader("location", `http://127.0.0.1:${landPort}/ok`);
      res.end();
    });
    await new Promise<void>((resolve) => hopper.listen(0, "127.0.0.1", resolve));
    const hopPort = (hopper.address() as { port: number }).port;
    cleanups.push(() => closeHttp(hopper));

    const fetchFn = createSafeFetch(true);
    const ok = await fetchFn(`http://127.0.0.1:${hopPort}/go`);
    expect(await ok.text()).toBe("landed");
    await expect(fetchFn(`http://127.0.0.1:${hopPort}/creds`)).rejects.toThrow(/credential/i);
    await expect(fetchFn(`http://127.0.0.1:${hopPort}/loop`)).rejects.toThrow(/redirect/i);
  });

  it("serves a callback error page with no token material", async () => {
    const gw = await boot();
    const res = await fetch(`${gw.url}/oauth/callback?code=secret-code&state=missing`);
    const text = await res.text();
    expect(text).toContain("did not complete");
    expect(text).not.toContain("secret-code");
  });
});

describe("device login when the public redirect is rejected", () => {
  it("keeps the redirect error text instead of collapsing it to server_error", () => {
    const err = new Error(
      "redirect_uri not allowed: https://mcp-flow.z.srl/oauth/callback",
    );
    Object.defineProperty(err, "errorCode", { get: () => "server_error" });
    const message = safeOauthMessage(err);
    expect(message).toContain("redirect_uri not allowed");
    expect(message).not.toBe("OAuth error: server_error");
  });

  it("starts a device grant and polls it without storing the device code in plaintext", async () => {
    const deviceCode = "device-code-PLAINTEXT-should-not-leak";
    const access = "device-access-PLAINTEXT-should-not-leak";
    let polls = 0;
    let port = 0;
    const httpServer = createServer(async (req, res) => {
      const origin = `http://127.0.0.1:${port}`;
      const pathname = new URL(req.url || "/", origin).pathname;
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk as Buffer);
      const raw = Buffer.concat(chunks).toString("utf8");
      const send = (status: number, body: unknown) => {
        const payload = JSON.stringify(body);
        res.statusCode = status;
        res.setHeader("content-type", "application/json");
        res.end(payload);
      };
      if (pathname.includes("oauth-protected-resource")) {
        send(200, {
          resource: `${origin}/mcp`,
          authorization_servers: [origin],
          scopes_supported: ["models:read"],
        });
        return;
      }
      if (pathname.includes("oauth-authorization-server")) {
        send(200, {
          issuer: origin,
          authorization_endpoint: `${origin}/authorize`,
          token_endpoint: `${origin}/token`,
          registration_endpoint: `${origin}/register`,
          device_authorization_endpoint: `${origin}/device`,
          response_types_supported: ["code"],
          grant_types_supported: [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code",
          ],
          code_challenge_methods_supported: ["S256"],
          token_endpoint_auth_methods_supported: ["none"],
        });
        return;
      }
      if (req.method === "POST" && pathname === "/register") {
        const body = JSON.parse(raw) as { redirect_uris?: string[] };
        const redirect = body.redirect_uris?.[0] ?? "";
        if (!redirect.startsWith("http://127.0.0.1")) {
          send(400, {
            error: "invalid_redirect_uri",
            error_description: `redirect_uri not allowed: ${redirect}`,
          });
          return;
        }
        send(201, {
          client_id: "dev-client",
          redirect_uris: body.redirect_uris,
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          token_endpoint_auth_method: "none",
          client_name: "mcp-flow",
        });
        return;
      }
      if (req.method === "POST" && pathname === "/device") {
        send(200, {
          device_code: deviceCode,
          user_code: "ABCD-EFGH",
          verification_uri: `${origin}/verify`,
          verification_uri_complete: `${origin}/verify?user_code=ABCD-EFGH`,
          expires_in: 600,
          interval: 5,
        });
        return;
      }
      if (req.method === "POST" && pathname === "/token") {
        polls += 1;
        if (polls === 1) {
          send(400, { error: "authorization_pending" });
          return;
        }
        send(200, {
          access_token: access,
          token_type: "Bearer",
          expires_in: 3600,
          refresh_token: "device-refresh-PLAINTEXT-should-not-leak",
        });
        return;
      }
      res.statusCode = 404;
      res.end();
    });
    await new Promise<void>((resolve) => httpServer.listen(0, "127.0.0.1", resolve));
    port = (httpServer.address() as { port: number }).port;
    cleanups.push(() => closeHttp(httpServer));

    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-oauth-device-"));
    dirs.push(dir);
    const dbPath = join(dir, "t.db");
    const store = new Store(dbPath, master);
    cleanups.push(async () => store.close());
    const ws = store.ensureWorkspace("default");
    const created = store.createBackend(ws.id, {
      slug: "sway",
      url: `http://127.0.0.1:${port}/mcp`,
      transport: "streamable-http",
      enabled: true,
      auth: { type: "oauth" },
    });
    const backend = store.getBackend(ws.id, created.id)!;
    const started = await startOauthAuthorization({
      store,
      backend,
      redirectUri: "https://mcp-flow.z.srl/oauth/callback",
      allowPrivateUrls: true,
    });
    expect(started.mode).toBe("device");
    expect(started.userCode).toBe("ABCD-EFGH");
    expect(JSON.stringify(started)).not.toContain(deviceCode);
    expect(store.getBackendPublic(ws.id, created.id)?.auth.device?.userCode).toBe(
      "ABCD-EFGH",
    );

    const pending = await pollOauthDevice({
      store,
      backend,
      allowPrivateUrls: true,
    });
    expect(pending).toMatchObject({ status: "pending" });
    const done = await pollOauthDevice({
      store,
      backend,
      allowPrivateUrls: true,
    });
    expect(done.status).toBe("connected");
    expect(store.getBackendPublic(ws.id, created.id)?.auth.status).toBe("connected");
    expect(store.getBackendPublic(ws.id, created.id)?.auth.device).toBeNull();
    store.db.exec("PRAGMA wal_checkpoint(FULL)");
    const raw = dbText(dbPath);
    expect(raw).not.toContain(deviceCode);
    expect(raw).not.toContain(access);
  });
});

describe("oauth pool wiring", () => {
  it("does not open a consent URL from an agent call", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-oauth-pool-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "pending",
      url: "http://127.0.0.1:9/mcp",
      transport: "streamable-http",
      enabled: true,
      auth: { type: "oauth" },
    });
    const pool = new UpstreamPool(store, { allowPrivateUrls: true });
    cleanups.push(async () => {
      await pool.closeAll();
      store.close();
    });
    const result = await pool.callTool(ws.id, "pending__echo", {});
    expect(result.isError).toBe(true);
    const text = result.content?.[0] && "text" in result.content[0] ? result.content[0].text : "";
    expect(text).toMatch(/re-author/i);
  });
});
