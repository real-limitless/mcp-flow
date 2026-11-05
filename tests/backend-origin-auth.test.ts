import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { backendUpdateAuditDetail } from "../src/audit/backend-update.js";
import { loadConfig } from "../src/config.js";
import {
  getOauthRow,
  mergeOauthSecrets,
  readOauthSecrets,
  saveOauthTokens,
} from "../src/db/oauth-store.js";
import { Store } from "../src/db/store.js";
import { handleAdminTool } from "../src/mcp/admin-tools.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { startServer, type RunningServer } from "../src/server.js";

const master = Buffer.alloc(32, 12).toString("base64");
const admin = "test-admin-token-please-change";
const API_KEY = "sealed-api-key-alpha";
const HEADER = "sealed-header-beta";
const TRACE = "trace-label";
const ENV_SECRET = "sealed-env-gamma";
const FRESH_HEADER = "fresh-header-delta";
const FRESH_KEY = "fresh-api-key-epsilon";
const ACCESS = "oauth-access-zeta";
const REFRESH = "oauth-refresh-eta";
const CLIENT_SECRET = "oauth-client-theta";
const NEW_CLIENT_SECRET = "oauth-client-iota";
const VERIFIER = "oauth-verifier-kappa";
const DEVICE = "oauth-device-lambda";
const USERINFO = "userinfo-token-mu";
const QUERY_OLD = "query-token-nu";
const QUERY_NEW = "query-token-xi";

const dirs: string[] = [];
const cleanups: Array<() => Promise<void>> = [];

function openStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-origin-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), master);
}

afterEach(async () => {
  while (cleanups.length) {
    await cleanups.pop()!();
  }
  while (dirs.length) {
    rmSync(dirs.pop()!, { recursive: true, force: true });
  }
});

function oauthConn(store: Store) {
  return { db: store.db, masterKey: store.masterKey };
}

function seedOauth(store: Store, backendId: string): void {
  const expiresAt = new Date(Date.now() + 3_600_000).toISOString();
  saveOauthTokens(
    oauthConn(store),
    backendId,
    {
      access_token: ACCESS,
      refresh_token: REFRESH,
      token_type: "Bearer",
    },
    expiresAt,
  );
  mergeOauthSecrets(oauthConn(store), backendId, (secrets) => {
    secrets.codeVerifier = VERIFIER;
    secrets.device = {
      deviceCode: DEVICE,
      intervalSeconds: 5,
      userCode: "ABCD-EFGH",
      verificationUri: "https://auth.example/device",
      expiresAt,
    };
  });
}

function expectOauthKept(store: Store, backendId: string): void {
  const secrets = readOauthSecrets(store.db, store.masterKey, backendId);
  expect(secrets?.tokens?.access_token).toBe(ACCESS);
  expect(secrets?.tokens?.refresh_token).toBe(REFRESH);
  expect(secrets?.codeVerifier).toBe(VERIFIER);
  expect(secrets?.device?.deviceCode).toBe(DEVICE);
  expect(secrets?.clientSecret).toBe(CLIENT_SECRET);
  expect(getOauthRow(store.db, backendId)?.status).toBe("connected");
}

function expectOauthCleared(store: Store, backendId: string, clientSecret = CLIENT_SECRET): void {
  const secrets = readOauthSecrets(store.db, store.masterKey, backendId);
  const row = getOauthRow(store.db, backendId);
  expect(secrets?.tokens).toBeUndefined();
  expect(secrets?.codeVerifier).toBeUndefined();
  expect(secrets?.device).toBeUndefined();
  expect(secrets?.clientSecret).toBe(clientSecret);
  expect(row?.status).toBe("needs_reauth");
  expect(row?.tokenExpiresAt).toBeNull();
  expect(row?.lastError).toBe("upstream origin changed");
  const pub = store.getBackendPublic(
    store.getBackendById(backendId)!.workspaceId,
    backendId,
  );
  const text = JSON.stringify(pub);
  expect(text).not.toContain(ACCESS);
  expect(text).not.toContain(REFRESH);
  expect(text).not.toContain(DEVICE);
  expect(text).not.toContain(VERIFIER);
  expect(text).not.toContain(clientSecret);
}

describe("updateBackend origin change", () => {
  it("keeps sealed headers and oauth tokens when the origin stays the same", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const created = store.createBackend(ws.id, {
      slug: "remote",
      url: "https://API.Example/mcp",
      apiKey: API_KEY,
      headers: { "X-Api-Key": HEADER, "X-Trace": TRACE },
      env: { API_KEY: ENV_SECRET, REGION: "east" },
      enabled: true,
    });
    const oauth = store.createBackend(ws.id, {
      slug: "vendor",
      url: "https://API.Example/mcp",
      headers: { "X-Api-Key": HEADER },
      auth: { type: "oauth", clientId: "client-1", clientSecret: CLIENT_SECRET },
      placement: { mode: "remote" },
      enabled: true,
    });
    seedOauth(store, oauth.id);

    for (const url of [
      "https://api.example/v2/mcp",
      "https://api.example/v2/mcp?x=1",
      "https://api.example:443/v2/mcp",
      "https://API.Example/v2/mcp",
    ]) {
      const patched = store.updateBackend(ws.id, "remote", { url });
      expect(patched?.url).toBe(url);
      expect(store.decryptHeaders(store.getBackend(ws.id, "remote")!)).toEqual({
        Authorization: `Bearer ${API_KEY}`,
        "X-Api-Key": HEADER,
        "X-Trace": TRACE,
      });
      expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
        API_KEY: ENV_SECRET,
        REGION: "east",
      });
    }

    store.updateBackend(ws.id, "vendor", { url: "https://api.example/oauth/callback-path" });
    expect(store.decryptHeaders(store.getBackend(ws.id, "vendor")!)).toEqual({
      "X-Api-Key": HEADER,
    });
    expectOauthKept(store, oauth.id);
    expect(JSON.stringify(created)).not.toContain(API_KEY);
    store.close();
  });

  it("clears headers, apiKey, and oauth tokens when scheme, host, or port changes", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const cases = [
      {
        slug: "scheme",
        from: "https://api.example/mcp",
        to: "http://api.example/mcp",
      },
      {
        slug: "host",
        from: "https://old.example/mcp",
        to: "https://new.example/mcp",
      },
      {
        slug: "port",
        from: "https://api.example:8443/mcp",
        to: "https://api.example:9443/mcp",
      },
    ];

    for (const item of cases) {
      store.createBackend(ws.id, {
        slug: item.slug,
        url: item.from,
        apiKey: API_KEY,
        headers: { "X-Api-Key": HEADER, "X-Trace": TRACE },
        env: { API_KEY: ENV_SECRET, REGION: "east" },
        enabled: true,
      });
      const oauth = store.createBackend(ws.id, {
        slug: `${item.slug}-oauth`,
        url: item.from,
        headers: { "X-Api-Key": HEADER },
        auth: { type: "oauth", clientId: "client-1", clientSecret: CLIENT_SECRET },
        placement: { mode: "remote" },
        enabled: true,
      });
      seedOauth(store, oauth.id);

      const patched = store.updateBackend(ws.id, item.slug, { url: item.to });
      expect(patched?.headerNames).toEqual([]);
      expect(patched?.hasHeaders).toBe(false);
      expect(store.decryptHeaders(store.getBackend(ws.id, item.slug)!)).toEqual({});
      expect(store.decryptEnv(store.getBackend(ws.id, item.slug)!)).toEqual({
        API_KEY: ENV_SECRET,
        REGION: "east",
      });
      expect(JSON.stringify(patched)).not.toContain(API_KEY);
      expect(JSON.stringify(patched)).not.toContain(HEADER);

      store.updateBackend(ws.id, oauth.id, { url: item.to });
      expect(store.decryptHeaders(store.getBackend(ws.id, oauth.id)!)).toEqual({});
      expectOauthCleared(store, oauth.id);
    }

    const resent = store.createBackend(ws.id, {
      slug: "resent",
      url: "https://old.example/mcp",
      auth: { type: "oauth", clientId: "client-1", clientSecret: CLIENT_SECRET },
      placement: { mode: "remote" },
      enabled: true,
    });
    seedOauth(store, resent.id);
    store.updateBackend(ws.id, resent.id, {
      url: "https://new.example/mcp",
      auth: { type: "oauth", clientSecret: NEW_CLIENT_SECRET },
    });
    expectOauthCleared(store, resent.id, NEW_CLIENT_SECRET);
    store.close();
  });

  it("stores only headers re-supplied with a host change", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://old.example/mcp",
      apiKey: API_KEY,
      headers: { "X-Api-Key": HEADER, "X-Trace": TRACE },
      enabled: true,
    });

    store.createBackend(ws.id, {
      slug: "blankkeep",
      url: "https://old.example/mcp",
      apiKey: API_KEY,
      headers: { "X-Api-Key": HEADER },
      enabled: true,
    });
    store.updateBackend(ws.id, "blankkeep", {
      url: "https://new.example/mcp",
      headers: { Authorization: "", "X-Api-Key": "   " },
      apiKey: "  ",
    });
    expect(store.decryptHeaders(store.getBackend(ws.id, "blankkeep")!)).toEqual({});

    const replaced = store.updateBackend(ws.id, "remote", {
      url: "https://new.example/mcp",
      headers: { "X-New-Key": FRESH_HEADER },
    });
    expect(replaced?.headerNames).toEqual(["X-New-Key"]);
    expect(store.decryptHeaders(store.getBackend(ws.id, "remote")!)).toEqual({
      "X-New-Key": FRESH_HEADER,
    });
    expect(JSON.stringify(replaced)).not.toContain(FRESH_HEADER);
    expect(JSON.stringify(replaced)).not.toContain(API_KEY);
    store.close();
  });

  it("stores a re-supplied apiKey and drops the previous headers", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://old.example/mcp",
      apiKey: API_KEY,
      headers: { "X-Api-Key": HEADER, "X-Trace": TRACE },
      enabled: true,
    });
    const updated = store.updateBackend(ws.id, "remote", {
      url: "https://new.example/mcp",
      apiKey: FRESH_KEY,
      headers: { "X-New-Key": FRESH_HEADER },
    });
    expect(updated?.headerNames).toEqual(["Authorization", "X-New-Key"]);
    expect(store.decryptHeaders(store.getBackend(ws.id, "remote")!)).toEqual({
      Authorization: `Bearer ${FRESH_KEY}`,
      "X-New-Key": FRESH_HEADER,
    });
    expect(JSON.stringify(updated)).not.toContain(API_KEY);
    expect(JSON.stringify(updated)).not.toContain(HEADER);
    expect(JSON.stringify(updated)).not.toContain(FRESH_KEY);
    store.close();
  });
});

describe("origin audit", () => {
  it("records origins and omits userinfo, query, and secret values", () => {
    const previousUrl = `https://operator:${USERINFO}@old.example/mcp?access_token=${QUERY_OLD}`;
    const nextUrl = `https://new.example/mcp?access_token=${QUERY_NEW}`;
    const detail = backendUpdateAuditDetail(
      {
        url: nextUrl,
        headers: { "X-New-Key": FRESH_HEADER },
        apiKey: FRESH_KEY,
      },
      { previousUrl },
    );
    expect(detail.previousOrigin).toBe("https://old.example");
    expect(detail.origin).toBe("https://new.example");
    const text = JSON.stringify(detail);
    expect(text).toContain("X-New-Key");
    expect(text).not.toContain(USERINFO);
    expect(text).not.toContain(QUERY_OLD);
    expect(text).not.toContain(QUERY_NEW);
    expect(text).not.toContain(FRESH_HEADER);
    expect(text).not.toContain(FRESH_KEY);
    expect(text).not.toContain("/mcp");
    expect(text).not.toContain("access_token");

    const same = backendUpdateAuditDetail(
      { url: "https://example.com/v2" },
      { previousUrl: "https://example.com/mcp" },
    );
    expect(same.previousOrigin).toBeUndefined();
    expect(same.origin).toBeUndefined();
    expect(JSON.stringify(same)).not.toContain("https://example.com/v2");
  });
});

async function bootGateway(): Promise<RunningServer> {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-origin-gw-"));
  dirs.push(dir);
  const cfg = loadConfig({
    dbPath: join(dir, "t.db"),
    masterKeyRaw: master,
    adminToken: admin,
    host: "127.0.0.1",
    port: 0 as unknown as number,
    allowPrivateUrls: true,
    workspaceName: "default",
  });
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) =>
    probe.close((err) => (err ? reject(err) : resolve())),
  );
  cfg.port = port;
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

describe("PATCH and mf_admin_update_backend", () => {
  it("PATCH clears auth on a host change and audits origins only", async () => {
    const gw = await bootGateway();
    const ws = gw.store.ensureWorkspace("default");
    const created = gw.store.createBackend(ws.id, {
      slug: "vendor",
      url: `https://operator:${USERINFO}@old.example/mcp?access_token=${QUERY_OLD}`,
      headers: { "X-Api-Key": HEADER },
      env: { REGION: "east", API_KEY: ENV_SECRET },
      auth: { type: "oauth", clientId: "client-1", clientSecret: CLIENT_SECRET },
      placement: { mode: "remote" },
      enabled: true,
    });
    seedOauth(gw.store, created.id);

    const nextUrl = `https://new.example/mcp?access_token=${QUERY_NEW}`;
    const patched = await fetch(`${gw.url}/v1/backends/${created.id}`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ url: nextUrl }),
    });
    expect(patched.status).toBe(200);
    const body = (await patched.json()) as {
      backend: { headerNames: string[]; auth: { status: string } };
    };
    expect(body.backend.headerNames).toEqual([]);
    expect(body.backend.auth.status).toBe("needs_reauth");
    expect(gw.store.decryptHeaders(gw.store.getBackend(ws.id, "vendor")!)).toEqual({});
    expect(gw.store.decryptEnv(gw.store.getBackend(ws.id, "vendor")!)).toEqual({
      REGION: "east",
      API_KEY: ENV_SECRET,
    });
    expectOauthCleared(gw.store, created.id);

    const audit = gw.store
      .listAudit(ws.id)
      .find((event) => event.action === "backend.update");
    expect(audit?.detail).toMatchObject({
      previousOrigin: "https://old.example",
      origin: "https://new.example",
    });
    const text = JSON.stringify(audit);
    for (const secret of [
      USERINFO,
      QUERY_OLD,
      QUERY_NEW,
      HEADER,
      ACCESS,
      REFRESH,
      DEVICE,
      VERIFIER,
      CLIENT_SECRET,
      ENV_SECRET,
    ]) {
      expect(text).not.toContain(secret);
    }
    expect(text).not.toContain("access_token");
    expect(text).not.toContain("/mcp");
  });

  it("mf_admin_update_backend uses re-supplied headers and audits origins only", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-origin-admin-"));
    dirs.push(dir);
    const dbPath = join(dir, "t.db");
    const store = new Store(dbPath, master);
    const ws = store.ensureWorkspace("default");
    const created = store.createBackend(ws.id, {
      slug: "remote",
      url: `https://operator:${USERINFO}@old.example/mcp?access_token=${QUERY_OLD}`,
      apiKey: API_KEY,
      headers: { "X-Api-Key": HEADER, "X-Trace": TRACE },
      env: { REGION: "east" },
      enabled: true,
    });
    const pool = new UpstreamPool(store);
    const cfg = loadConfig({
      dbPath,
      masterKeyRaw: master,
      adminToken: admin,
      allowPrivateUrls: true,
    });
    const nextUrl = `https://new.example/mcp?access_token=${QUERY_NEW}`;
    const args = {
      idOrSlug: "remote",
      url: nextUrl,
      headers: { "X-New-Key": FRESH_HEADER },
    };
    const result = await handleAdminTool("mf_admin_update_backend", args, {
      store,
      pool,
      cfg,
      auth: { kind: "admin", workspaceId: ws.id },
      edgeEnabled: false,
    });
    expect(result.isError).toBeFalsy();
    const response = result.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    expect(response).not.toContain(API_KEY);
    expect(response).not.toContain(HEADER);
    expect(response).not.toContain(FRESH_HEADER);
    expect(response).not.toContain(USERINFO);
    expect(store.decryptHeaders(store.getBackend(ws.id, "remote")!)).toEqual({
      "X-New-Key": FRESH_HEADER,
    });
    expect(store.getBackend(ws.id, created.id)?.url).toBe(nextUrl);

    const audit = store.listAudit(ws.id).find((event) => event.action === "backend.update");
    expect(audit?.detail).toMatchObject({
      via: "mf_admin",
      previousOrigin: "https://old.example",
      origin: "https://new.example",
    });
    const text = JSON.stringify(audit);
    for (const secret of [USERINFO, QUERY_OLD, QUERY_NEW, API_KEY, HEADER, FRESH_HEADER, TRACE]) {
      expect(text).not.toContain(secret);
    }
    expect(text).toContain("X-New-Key");
    expect(text).not.toContain("access_token");
    expect(text).not.toContain("/mcp");
    store.close();
  });
});
