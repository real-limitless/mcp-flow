import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTVerifyGetKey } from "jose";
import { createApp } from "../src/api/app.js";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { PortalDirectory, PortalError } from "../src/portal/directory.js";
import { googleSignInWarnings, GOOGLE_TOKEN_URL } from "../src/portal/google.js";
import { PORTAL_SIGNIN_CODES } from "../src/portal/signin-codes.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const ADMIN = "bootstrap-admin-token-0123456789";
const SECRET = "google-client-secret-value";
const AUTH_CODE = "authcode-do-not-log";

async function keys(): Promise<{ privateKey: CryptoKey; jwks: JWTVerifyGetKey }> {
  const pair = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  jwk.kid = "test";
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { privateKey: pair.privateKey, jwks: createLocalJWKSet({ keys: [jwk] }) };
}

function cookiePair(res: Response, name: string): string {
  const all = res.headers.getSetCookie?.() ?? [res.headers.get("set-cookie") ?? ""];
  const line = all.find((item) => item.startsWith(`${name}=`)) ?? "";
  return line.split(";")[0] ?? "";
}

function setCookieLine(res: Response, name: string): string {
  const all = res.headers.getSetCookie?.() ?? [res.headers.get("set-cookie") ?? ""];
  return all.find((item) => item.startsWith(`${name}=`)) ?? "";
}

describe("google sign-in rejections", () => {
  it("names the setup gaps and does not warn when Google is unset", () => {
    expect(googleSignInWarnings({ publicUrl: "https://mcp.example", clientId: "", clientSecretConfigured: false })).toEqual([]);
    const missing = googleSignInWarnings({ publicUrl: "", clientId: "client", clientSecretConfigured: false });
    expect(missing.join("\n")).toMatch(/MCP_FLOW_PUBLIC_URL/);
    expect(missing.join("\n")).toMatch(/MCP_FLOW_GOOGLE_CLIENT_SECRET/);
    expect(missing.join("\n")).not.toMatch(/client-secret/);
  });

  it("keeps every reason code in the sign-in page and leaves OAuth out of the service worker", () => {
    const appJs = readFileSync(join(import.meta.dirname, "../src/admin/app.js"), "utf8");
    const sw = readFileSync(join(import.meta.dirname, "../src/admin/sw.js"), "utf8");
    for (const code of PORTAL_SIGNIN_CODES) expect(appJs).toContain(code);
    expect(appJs).toMatch(/Google sign-in is not set up/);
    expect(sw).toMatch(/\/admin\/oauth\//);
  });

  it("records a reason for every rejected Google and bootstrap sign-in", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-portal-reject-"));
    dirs.push(dir);
    const master = Buffer.alloc(32, 6).toString("base64");
    const dbPath = join(dir, "t.db");
    const cfg = loadConfig({
      dbPath,
      masterKeyRaw: master,
      adminToken: ADMIN,
      publicUrl: "http://127.0.0.1:8787",
    });
    const store = new Store(dbPath, master);
    const { privateKey, jwks } = await keys();
    let tokenStatus = 200;
    let tokenBody: Record<string, unknown> = {};
    const fetchImpl: typeof fetch = async (input) => {
      if (String(input) !== GOOGLE_TOKEN_URL) throw new Error(`unexpected fetch ${String(input)}`);
      return new Response(JSON.stringify(tokenBody), {
        status: tokenStatus,
        headers: { "content-type": "application/json" },
      });
    };
    const app = createApp(store, cfg, new UpstreamPool(store), undefined, { fetch: fetchImpl, jwks });
    const logs: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });

    const call = (path: string, init: RequestInit = {}, cookie = "") => {
      const headers = new Headers(init.headers);
      if (!headers.has("origin")) headers.set("origin", "http://127.0.0.1:8787");
      if (!headers.has("x-mcp-flow-request") && init.method && init.method !== "GET") {
        headers.set("x-mcp-flow-request", "1");
      }
      if (cookie) headers.set("cookie", cookie);
      return app.request(`http://127.0.0.1:8787${path}`, { ...init, headers });
    };

    const sign = (claims: Record<string, unknown>, opts: { audience?: string; issuer?: string; exp?: number } = {}) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "RS256", kid: "test" })
        .setIssuer(opts.issuer ?? "https://accounts.google.com")
        .setAudience(opts.audience ?? "google-client")
        .setIssuedAt()
        .setExpirationTime(opts.exp ?? "5m")
        .sign(privateKey);

    const ws = store.ensureWorkspace("default");
    const rejected = () =>
      store.listAudit(ws.id, { limit: 500 }).filter((row) => row.action === "portal.login_rejected");

    const boot = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: ADMIN }),
    });
    const bootCookie = cookiePair(boot, "mf_portal");
    await call(
      "/v1/portal/google",
      {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ clientId: "google-client", clientSecret: SECRET, hostedDomain: "example.com" }),
      },
      bootCookie,
    );
    await call(
      "/v1/portal/users",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "ada@example.com", platformAdmin: true, workspaceIds: [ws.id] }),
      },
      bootCookie,
    );

    async function callback(cookie: string, query: string, claims?: Record<string, unknown>, tokenOpts?: Parameters<typeof sign>[1]) {
      tokenStatus = 200;
      if (claims) tokenBody = { id_token: await sign(claims, tokenOpts) };
      return call(`/admin/oauth/callback?${query}`, {}, cookie);
    }

    async function start() {
      const res = await call("/admin/oauth/start");
      const loc = new URL(res.headers.get("location") ?? "http://127.0.0.1/missing");
      return { res, loc, state: loc.searchParams.get("state") ?? "", nonce: loc.searchParams.get("nonce") ?? "", cookie: cookiePair(res, "mf_oauth_state") };
    }

    const started = await start();
    expect(started.loc.searchParams.get("hd")).toBe("example.com");
    expect(setCookieLine(started.res, "mf_oauth_state")).not.toMatch(/Secure/i);

    const missingState = await call("/admin/oauth/callback?code=x");
    expect(missingState.headers.get("location")).toContain("portal_error=state_missing");

    const missingCode = await call(`/admin/oauth/callback?state=${encodeURIComponent(started.state)}`, {}, started.cookie);
    expect(missingCode.headers.get("location")).toContain("portal_error=code_missing");

    const provider = await call("/admin/oauth/callback?error=access_denied");
    expect(provider.headers.get("location")).toContain("portal_error=provider_denied");

    const noCookie = await call(`/admin/oauth/callback?code=${AUTH_CODE}&state=${encodeURIComponent(started.state)}`);
    expect(noCookie.headers.get("location")).toContain("portal_error=state_cookie");

    const mismatch = await call(
      `/admin/oauth/callback?code=${AUTH_CODE}&state=${encodeURIComponent(started.state)}`,
      {},
      "mf_oauth_state=not-the-state",
    );
    expect(mismatch.headers.get("location")).toContain("portal_error=state_mismatch");

    tokenStatus = 400;
    tokenBody = { error: "redirect_uri_mismatch", error_description: "https://mcp.example/admin/oauth/callback" };
    const exchanged = await call(
      `/admin/oauth/callback?code=${AUTH_CODE}&state=${encodeURIComponent(started.state)}`,
      {},
      started.cookie,
    );
    expect(exchanged.headers.get("location")).toContain("portal_error=token_exchange");

    const again = await start();
    const badNonce = await callback(
      again.cookie,
      `code=${AUTH_CODE}&state=${encodeURIComponent(again.state)}`,
      { sub: "sub-ada", email: "ada@example.com", email_verified: true, hd: "example.com", nonce: "different-nonce" },
    );
    expect(badNonce.headers.get("location")).toContain("portal_error=nonce");

    const noHd = await start();
    const missingHd = await callback(
      noHd.cookie,
      `code=${AUTH_CODE}&state=${encodeURIComponent(noHd.state)}`,
      { sub: "sub-ada", email: "ada@example.com", email_verified: true, nonce: noHd.nonce },
    );
    expect(missingHd.headers.get("location")).toContain("portal_error=hosted_domain");

    const skew = await start();
    const skewed = await callback(
      skew.cookie,
      `code=${AUTH_CODE}&state=${encodeURIComponent(skew.state)}`,
      { sub: "sub-ada", email: "ada@example.com", email_verified: true, hd: "example.com", nonce: skew.nonce },
      { exp: Math.floor(Date.now() / 1000) - 30 },
    );
    expect(skewed.headers.get("location")).toContain("mfa=1");

    const adaUser = new PortalDirectory(store).listUsers().find((u) => u.email === "ada@example.com");
    expect(adaUser?.googleLinked).toBe(true);
    await call(
      `/v1/portal/users/${adaUser!.id}`,
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "moved@example.com" }),
      },
      bootCookie,
    );
    await call(
      "/v1/portal/users",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "ada@example.com", platformAdmin: false, workspaceIds: [ws.id] }),
      },
      bootCookie,
    );
    const clash = await start();
    const conflict = await callback(
      clash.cookie,
      `code=${AUTH_CODE}&state=${encodeURIComponent(clash.state)}`,
      { sub: "sub-ada", email: "ada@example.com", email_verified: true, hd: "example.com", nonce: clash.nonce },
    );
    expect(conflict.headers.get("location")).toContain("portal_error=identity_conflict");

    const mismatchSub = await start();
    const relink = await callback(
      mismatchSub.cookie,
      `code=${AUTH_CODE}&state=${encodeURIComponent(mismatchSub.state)}`,
      { sub: "sub-other", email: "moved@example.com", email_verified: true, hd: "example.com", nonce: mismatchSub.nonce },
    );
    expect(relink.headers.get("location")).toContain("portal_error=account_mismatch");

    await call(
      `/v1/portal/users/${adaUser!.id}`,
      {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ status: "suspended" }),
      },
      bootCookie,
    );
    const suspendedStart = await start();
    const suspended = await callback(
      suspendedStart.cookie,
      `code=${AUTH_CODE}&state=${encodeURIComponent(suspendedStart.state)}`,
      { sub: "sub-ada", email: "moved@example.com", email_verified: true, hd: "example.com", nonce: suspendedStart.nonce },
    );
    expect(suspended.headers.get("location")).toContain("portal_error=account_inactive");

    const badBoot = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "not-the-admin-token" }),
    });
    expect(badBoot.status).toBe(401);
    expect(((await badBoot.json()) as { reason: string }).reason).toBe("bootstrap_rejected");

    const emptyBoot = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "   " }),
    });
    expect(((await emptyBoot.json()) as { reason: string }).reason).toBe("bootstrap_missing");

    const csrf = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json", "x-mcp-flow-request": "" },
      body: JSON.stringify({ token: ADMIN }),
    });
    expect(csrf.status).toBe(403);
    expect(((await csrf.json()) as { reason: string }).reason).toBe("csrf");

    const foreign = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil.example" },
      body: JSON.stringify({ token: ADMIN }),
    });
    expect(((await foreign.json()) as { reason: string }).reason).toBe("origin");

    const reasons = store.listAudit(ws.id, { limit: 500 }).filter((row) => row.action === "portal.login_rejected").map((row) => String(row.detail?.reason));
    for (const code of [
      "state_missing",
      "code_missing",
      "provider_denied",
      "state_cookie",
      "state_mismatch",
      "token_exchange",
      "nonce",
      "hosted_domain",
      "identity_conflict",
      "account_mismatch",
      "account_inactive",
      "bootstrap_rejected",
      "bootstrap_missing",
      "csrf",
      "origin",
    ]) {
      expect(reasons).toContain(code);
    }
    const exchange = rejected().find((row) => row.detail?.reason === "token_exchange");
    expect(exchange?.detail).toMatchObject({ kind: "google", reason: "token_exchange", provider: "redirect_uri_mismatch" });
    const dumped = JSON.stringify(rejected()) + logs.join("\n");
    expect(dumped).not.toContain("ada@example.com");
    expect(dumped).not.toContain("moved@example.com");
    expect(dumped).not.toContain(SECRET);
    expect(dumped).not.toContain(ADMIN);
    expect(dumped).not.toContain(AUTH_CODE);
    expect(dumped).not.toContain("not-the-admin-token");
    expect(logs.some((line) => line.includes("kind=google code=hosted_domain"))).toBe(true);
    expect(logs.some((line) => line.includes("kind=bootstrap code=bootstrap_rejected"))).toBe(true);
    expect(logs.some((line) => line.includes("provider=redirect_uri_mismatch"))).toBe(true);
    expect(logs.some((line) => line.includes("provider=access_denied"))).toBe(true);

    spy.mockRestore();
    store.close();
  }, 30_000);

  it("refuses an inactive admin agent with a reason code", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-portal-agent-"));
    dirs.push(dir);
    const master = Buffer.alloc(32, 7).toString("base64");
    const dbPath = join(dir, "t.db");
    const store = new Store(dbPath, master);
    const portal = new PortalDirectory(store);
    const ws = store.ensureWorkspace("default");
    const id = portal.ensureAgent("ada@example.com", ws.id);
    store.db.prepare(`UPDATE mcpflow_agent SET status = 'suspended' WHERE id = ?`).run(id);
    try {
      portal.ensureAgent("ada@example.com", ws.id);
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(PortalError);
      expect((err as PortalError).code).toBe("agent_inactive");
    }
    store.close();
  });

  it("hides Google until it is configured, and marks the state cookie Secure behind a proxy", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-portal-secure-"));
    dirs.push(dir);
    const master = Buffer.alloc(32, 8).toString("base64");
    const dbPath = join(dir, "t.db");
    const cfg = loadConfig({
      dbPath,
      masterKeyRaw: master,
      adminToken: ADMIN,
      publicUrl: "https://portal.example",
    });
    const store = new Store(dbPath, master);
    const app = createApp(store, cfg, new UpstreamPool(store));
    const anon = (await (await app.request("http://127.0.0.1:9/admin/session")).json()) as {
      googleConfigured: boolean;
      redirectUri: string | null;
      platformLoginsEnabled: boolean;
    };
    expect(anon).toMatchObject({ googleConfigured: false, platformLoginsEnabled: false, redirectUri: "https://portal.example/admin/oauth/callback" });
    const unconfigured = await app.request("http://127.0.0.1:9/admin/oauth/start", {
      headers: { host: "portal.example" },
    });
    expect(unconfigured.headers.get("location")).toContain("portal_error=google_unconfigured");

    const boot = await app.request("http://127.0.0.1:9/admin/bootstrap-login", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-mcp-flow-request": "1",
        origin: "https://portal.example",
        host: "portal.example",
      },
      body: JSON.stringify({ token: ADMIN }),
    });
    expect(boot.status).toBe(200);
    const bootCookie = cookiePair(boot, "mf_portal");
    expect(setCookieLine(boot, "mf_portal")).toMatch(/Secure/i);
    const saved = await app.request("http://127.0.0.1:9/v1/portal/google", {
      method: "PUT",
      headers: {
        "content-type": "application/json",
        "x-mcp-flow-request": "1",
        origin: "https://portal.example",
        host: "portal.example",
        cookie: bootCookie,
      },
      body: JSON.stringify({ clientId: "google-client", clientSecret: SECRET }),
    });
    expect(saved.status).toBe(200);
    const start = await app.request("http://127.0.0.1:9/admin/oauth/start", {
      headers: { host: "portal.example" },
    });
    expect(start.status).toBe(302);
    expect(setCookieLine(start, "mf_oauth_state")).toMatch(/Secure/i);
    expect(start.headers.get("location")).toContain("accounts.google.com");
    const loc = new URL(start.headers.get("location") ?? "");
    expect(loc.searchParams.get("hd")).toBeNull();
    expect(loc.searchParams.get("redirect_uri")).toBe("https://portal.example/admin/oauth/callback");

    const noPublic = loadConfig({
      dbPath,
      masterKeyRaw: master,
      adminToken: ADMIN,
      publicUrl: "",
      googleClientId: "google-client",
      googleClientSecret: SECRET,
    });
    expect(googleSignInWarnings({
      publicUrl: noPublic.publicUrl,
      clientId: noPublic.googleClientId,
      clientSecretConfigured: Boolean(noPublic.googleClientSecret),
    }).join("\n")).toMatch(/MCP_FLOW_PUBLIC_URL/);

    store.close();
  });
});
