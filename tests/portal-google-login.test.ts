import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type JWTVerifyGetKey } from "jose";
import { createApp } from "../src/api/app.js";
import { loadConfig } from "../src/config.js";
import { fromBase32, totpCode } from "../src/authz/totp.js";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { GOOGLE_TOKEN_URL } from "../src/portal/google.js";
import { PortalDirectory } from "../src/portal/directory.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const ORIGIN = "http://127.0.0.1:8787";
const ADMIN = "bootstrap-admin-token-0123456789";

async function keys(): Promise<{ privateKey: CryptoKey; jwks: JWTVerifyGetKey }> {
  const pair = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(pair.publicKey);
  jwk.kid = "test";
  jwk.alg = "RS256";
  jwk.use = "sig";
  return { privateKey: pair.privateKey, jwks: createLocalJWKSet({ keys: [jwk] }) };
}

function cookieValue(res: Response, name: string): string {
  const all = res.headers.getSetCookie?.() ?? [res.headers.get("set-cookie") ?? ""];
  const line = all.find((item) => item.startsWith(`${name}=`)) ?? "";
  return line.split(";")[0] ?? "";
}

describe("portal google login", () => {
  it("covers bootstrap, Google, TOTP, cutover, and workspaces", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-portal-login-"));
    dirs.push(dir);
    const master = Buffer.alloc(32, 4).toString("base64");
    const dbPath = join(dir, "t.db");
    const cfg = loadConfig({
      dbPath,
      masterKeyRaw: master,
      adminToken: ADMIN,
      publicUrl: ORIGIN,
    });
    const store = new Store(dbPath, master);
    const pool = new UpstreamPool(store);
    const { privateKey, jwks } = await keys();
    let idToken = "";
    const fetchImpl: typeof fetch = async (input) => {
      if (String(input) !== GOOGLE_TOKEN_URL) throw new Error(`unexpected fetch ${String(input)}`);
      return new Response(JSON.stringify({ id_token: idToken }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    };
    const app = createApp(store, cfg, pool, undefined, { fetch: fetchImpl, jwks });

    const call = (path: string, init: RequestInit = {}, cookie = "") => {
      const headers = new Headers(init.headers);
      if (!headers.has("origin")) headers.set("origin", ORIGIN);
      if (!headers.has("x-mcp-flow-request") && init.method && init.method !== "GET") {
        headers.set("x-mcp-flow-request", "1");
      }
      if (cookie) headers.set("cookie", cookie);
      return app.request(`${ORIGIN}${path}`, { ...init, headers });
    };

    const sign = (claims: Record<string, unknown>, audience = "google-client") =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "RS256", kid: "test" })
        .setIssuer("https://accounts.google.com")
        .setAudience(audience)
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(privateKey);

    const noHeader = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json", "x-mcp-flow-request": "" },
      body: JSON.stringify({ token: ADMIN }),
    });
    expect(noHeader.status).toBe(403);

    const foreign = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json", origin: "https://evil.example" },
      body: JSON.stringify({ token: ADMIN }),
    });
    expect(foreign.status).toBe(403);

    const bad = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "nope" }),
    });
    expect(bad.status).toBe(401);

    const boot = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: ADMIN }),
    });
    expect(boot.status).toBe(200);
    const bootCookie = cookieValue(boot, "mf_portal");
    expect(bootCookie.startsWith("mf_portal=")).toBe(true);
    const bootBody = (await boot.json()) as { state: string };
    expect(bootBody.state).toBe("bootstrap");

    const bearer = await call("/v1/workspace", { headers: { authorization: `Bearer ${ADMIN}` } });
    expect(bearer.status).toBe(200);

    const saved = await call(
      "/v1/portal/google",
      {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ clientId: "google-client", clientSecret: "super-secret", hostedDomain: "example.com" }),
      },
      bootCookie,
    );
    expect(saved.status).toBe(200);
    const google = (await call("/v1/portal/google", {}, bootCookie).then((r) => r.json())) as {
      clientId: string;
      secretSet: boolean;
    };
    expect(google).toMatchObject({ clientId: "google-client", secretSet: true });
    expect(JSON.stringify(google)).not.toContain("super-secret");

    const ws = store.ensureWorkspace("default");
    const other = await call(
      "/v1/portal/workspaces",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: "other" }) },
      bootCookie,
    );
    expect(other.status).toBe(201);
    const otherBody = (await other.json()) as { workspace: { id: string } };

    const member = await call(
      "/v1/portal/users",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "ada@example.com",
          platformAdmin: true,
          workspaceIds: [otherBody.workspace.id],
        }),
      },
      bootCookie,
    );
    expect(member.status).toBe(201);
    const plain = await call(
      "/v1/portal/users",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          email: "bea@example.com",
          platformAdmin: false,
          workspaceIds: [ws.id],
        }),
      },
      bootCookie,
    );
    expect(plain.status).toBe(201);
    const plainBody = (await plain.json()) as { user: { id: string } };

    async function googleSession(email: string, extra: Record<string, unknown> = {}, audience = "google-client") {
      const start = await call("/admin/oauth/start");
      expect(start.status).toBe(302);
      const loc = new URL(start.headers.get("location") ?? "");
      const state = loc.searchParams.get("state") ?? "";
      const nonce = loc.searchParams.get("nonce") ?? "";
      const stateCookie = cookieValue(start, "mf_oauth_state");
      idToken = await sign(
        {
          sub: `sub-${email}`,
          email,
          email_verified: extra.email_verified ?? true,
          hd: extra.hd ?? "example.com",
          nonce,
        },
        audience,
      );
      return call(`/admin/oauth/callback?code=abc&state=${encodeURIComponent(state)}`, {}, stateCookie);
    }

    const wrongAud = await googleSession("ada@example.com", {}, "other-client");
    expect(wrongAud.headers.get("location")).toContain("portal_error=denied");

    const unverified = await googleSession("ada@example.com", { email_verified: false });
    expect(unverified.headers.get("location")).toContain("portal_error=denied");

    const wrongHd = await googleSession("ada@example.com", { hd: "other.test" });
    expect(wrongHd.headers.get("location")).toContain("portal_error=denied");

    const unknown = await googleSession("cara@example.com");
    expect(unknown.headers.get("location")).toContain("portal_error=denied");

    const emptyWs = await call(
      "/v1/portal/users",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "nope@example.com", platformAdmin: false, workspaceIds: [] }),
      },
      bootCookie,
    );
    expect(emptyWs.status).toBe(201);
    const noWorkspace = await googleSession("nope@example.com");
    expect(noWorkspace.headers.get("location")).toContain("portal_error=denied");

    const expired = await (async () => {
      const start = await call("/admin/oauth/start");
      const loc = new URL(start.headers.get("location") ?? "");
      idToken = await new SignJWT({
        sub: "sub-ada@example.com",
        email: "ada@example.com",
        email_verified: true,
        hd: "example.com",
        nonce: loc.searchParams.get("nonce"),
      })
        .setProtectedHeader({ alg: "RS256", kid: "test" })
        .setIssuer("https://accounts.google.com")
        .setAudience("google-client")
        .setIssuedAt(Math.floor(Date.now() / 1000) - 3600)
        .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
        .sign(privateKey);
      return call(
        `/admin/oauth/callback?code=abc&state=${encodeURIComponent(loc.searchParams.get("state") ?? "")}`,
        {},
        cookieValue(start, "mf_oauth_state"),
      );
    })();
    expect(expired.headers.get("location")).toContain("portal_error=denied");

    const badIss = await (async () => {
      const start = await call("/admin/oauth/start");
      const loc = new URL(start.headers.get("location") ?? "");
      idToken = await new SignJWT({
        sub: "sub-ada@example.com",
        email: "ada@example.com",
        email_verified: true,
        hd: "example.com",
        nonce: loc.searchParams.get("nonce"),
      })
        .setProtectedHeader({ alg: "RS256", kid: "test" })
        .setIssuer("https://evil.example")
        .setAudience("google-client")
        .setExpirationTime("5m")
        .sign(privateKey);
      return call(
        `/admin/oauth/callback?code=abc&state=${encodeURIComponent(loc.searchParams.get("state") ?? "")}`,
        {},
        cookieValue(start, "mf_oauth_state"),
      );
    })();
    expect(badIss.headers.get("location")).toContain("portal_error=denied");

    const first = await googleSession("ada@example.com");
    expect(first.status).toBe(302);
    expect(first.headers.get("location")).toContain("mfa=1");
    const pre = cookieValue(first, "mf_portal");
    const keysBefore = await call("/v1/keys", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" }, pre);
    expect(keysBefore.status).toBe(401);

    const reused = await call(first.headers.get("location") ? "/admin/oauth/callback?code=abc&state=again" : "/", {}, cookieValue(first, "mf_oauth_state"));
    expect(reused.status === 302 || reused.status === 404).toBe(true);

    const startAgain = await call("/admin/oauth/start");
    const state = cookieValue(startAgain, "mf_oauth_state");
    const loc = new URL(startAgain.headers.get("location") ?? "");
    const once = await call(
      `/admin/oauth/callback?code=abc&state=${encodeURIComponent(loc.searchParams.get("state") ?? "")}`,
      {},
      state,
    );
    idToken = await sign({
      sub: "sub-ada@example.com",
      email: "ada@example.com",
      email_verified: true,
      hd: "example.com",
      nonce: loc.searchParams.get("nonce"),
    });
    const twice = await call(
      `/admin/oauth/callback?code=abc&state=${encodeURIComponent(loc.searchParams.get("state") ?? "")}`,
      {},
      state,
    );
    expect(twice.headers.get("location")).toContain("portal_error=state");
    expect(once.status).toBe(302);

    const beforeMfa = await call("/v1/portal/enable", { method: "POST", body: "{}" }, bootCookie);
    expect(beforeMfa.status).toBe(400);

    const enroll = await call("/admin/session/mfa/enroll", { method: "POST", body: "{}" }, pre);
    expect(enroll.status).toBe(200);
    const enrollBody = (await enroll.json()) as { secret: string };
    const code = totpCode(fromBase32(enrollBody.secret));
    const confirmed = await call(
      "/admin/session/mfa/confirm",
      { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ totp: code }) },
      pre,
    );
    expect(confirmed.status).toBe(200);
    const userCookie = cookieValue(confirmed, "mf_portal");
    const session = (await confirmed.json()) as { state: string; workspace: { id: string } };
    expect(session.state).toBe("user");
    expect(session.workspace.id).toBe(otherBody.workspace.id);

    store.createBackend(otherBody.workspace.id, {
      slug: "onlyother",
      transport: "stdio",
      command: ["true"],
      enabled: false,
    });
    const listed = await call("/v1/backends", {}, userCookie);
    expect(listed.status).toBe(200);
    const listedBody = (await listed.json()) as { backends: Array<{ slug: string }> };
    expect(listedBody.backends.map((b) => b.slug)).toContain("onlyother");

    const setupDenied = await (async () => {
      const login = await googleSession("bea@example.com");
      const beaPre = cookieValue(login, "mf_portal");
      const beaEnroll = await call("/admin/session/mfa/enroll", { method: "POST", body: "{}" }, beaPre);
      const beaSecret = ((await beaEnroll.json()) as { secret: string }).secret;
      const beaOk = await call(
        "/admin/session/mfa/confirm",
        { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ totp: totpCode(fromBase32(beaSecret)) }) },
        beaPre,
      );
      const beaCookie = cookieValue(beaOk, "mf_portal");
      return call(
        "/v1/portal/google",
        { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ clientId: "x", clientSecret: "y" }) },
        beaCookie,
      );
    })();
    expect(setupDenied.status).toBe(403);

    const payloadDenied = await call("/v1/audit/call-payload?call_id=x&phase=request", {}, bootCookie);
    expect(payloadDenied.status).toBe(403);
    const payloadUser = await call("/v1/audit/call-payload?call_id=x&phase=request", {}, userCookie);
    expect(payloadUser.status).not.toBe(403);

    await call(
      "/v1/portal/users",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: "lock@example.com", platformAdmin: false, workspaceIds: [ws.id] }),
      },
      bootCookie,
    );
    const lockLogin = await googleSession("lock@example.com");
    const lockPre = cookieValue(lockLogin, "mf_portal");
    expect((await call("/admin/session/mfa/enroll", { method: "POST", body: "{}" }, lockPre)).status).toBe(200);
    let locked = 0;
    for (let i = 0; i < 8; i++) {
      const attempt = await call(
        "/admin/session/mfa/confirm",
        { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ totp: "000000" }) },
        lockPre,
      );
      locked = attempt.status;
    }
    expect(locked).toBe(429);

    expect(
      (
        await call(
          `/v1/portal/workspaces/${ws.id}`,
          { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ disabled: true }) },
          bootCookie,
        )
      ).status,
    ).toBe(200);
    const blockedBea = await googleSession("bea@example.com");
    expect(blockedBea.headers.get("location") ?? "").toContain("portal_error");
    expect(
      (
        await call(
          `/v1/portal/workspaces/${ws.id}`,
          { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ disabled: false }) },
          bootCookie,
        )
      ).status,
    ).toBe(200);

    const enableEarly = await call("/v1/portal/enable", { method: "POST", body: "{}" }, bootCookie);
    expect(enableEarly.status).toBe(200);
    const retired = await call("/admin/bootstrap-login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: ADMIN }),
    });
    expect(retired.status).toBe(401);
    const bearerRetired = await call("/v1/workspace", { headers: { authorization: `Bearer ${ADMIN}` } });
    expect(bearerRetired.status).toBe(401);
    const oldBoot = await call("/v1/workspace", {}, bootCookie);
    expect(oldBoot.status).toBe(401);

    const still = await call(
      "/v1/portal/google",
      { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ clientId: "google-client", clientSecret: "" }) },
      userCookie,
    );
    expect(still.status).toBe(200);

    const portal = new PortalDirectory(store);
    expect(portal.platformEnabled()).toBe(true);
    portal.resetPlatform();
    expect(portal.platformEnabled()).toBe(false);
    const restored = await call("/v1/workspace", { headers: { authorization: `Bearer ${ADMIN}` } });
    expect(restored.status).toBe(200);
    const noResetRoute = await call("/v1/portal/reset-bootstrap", { method: "POST", body: "{}" }, userCookie);
    expect(noResetRoute.status).toBe(404);

    const suspend = await call(
      `/v1/portal/users/${plainBody.user.id}`,
      { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ status: "suspended" }) },
      userCookie,
    );
    expect(suspend.status).toBe(200);

    store.close();
  }, 30_000);
});
