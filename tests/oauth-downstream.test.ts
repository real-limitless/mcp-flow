import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";

const master = Buffer.alloc(32, 4).toString("base64");
const admin = "downstream-admin-token";
const dirs: string[] = [];
const cleanups: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

async function boot(): Promise<RunningServer & { dbPath: string }> {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-down-"));
  dirs.push(dir);
  const dbPath = join(dir, "t.db");
  const cfg = loadConfig({
    dbPath,
    masterKeyRaw: master,
    adminToken: admin,
    host: "127.0.0.1",
    port: 0,
    allowPrivateUrls: true,
    publicUrl: "",
    workspaceName: "default",
  });
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "127.0.0.1", resolve));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve, reject) =>
    probe.close((err) => (err ? reject(err) : resolve())),
  );
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return Object.assign(running, { dbPath });
}

function pkce() {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

describe("downstream OAuth login", () => {
  it("publishes connector values, completes PKCE login, and revokes the grant", async () => {
    const gw = await boot();
    const headers = { Authorization: `Bearer ${admin}` };
    const meta = await fetch(
      `${gw.url}/.well-known/oauth-protected-resource/mcp`,
    );
    const metadata = (await meta.json()) as {
      resource: string;
      authorization_servers: string[];
    };
    expect(metadata.resource).toBe(`${gw.url}/mcp`);
    expect(metadata.authorization_servers).toEqual([gw.url]);

    const connectorRes = await fetch(`${gw.url}/v1/oauth/connector`, { headers });
    const connector = (await connectorRes.json()) as {
      clientId: string;
      clientSecret: null;
      authorizationEndpoint: string;
      tokenEndpoint: string;
      tokenEndpointAuthMethod: string;
      scopes: string[];
    };
    expect(connector.clientSecret).toBeNull();
    expect(connector.tokenEndpointAuthMethod).toBe("none");
    expect(connector.authorizationEndpoint).toBe(`${gw.url}/oauth/authorize`);
    expect(connector.tokenEndpoint).toBe(`${gw.url}/oauth/token`);
    expect(connector.scopes).toContain("mcp");

    const redirectUri = "http://127.0.0.1:9/cb";
    const { verifier, challenge } = pkce();
    const allowed = await fetch(`${gw.url}/oauth/authorize`, {
      method: "POST",
      body: new URLSearchParams({
        client_id: connector.clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge,
        scope: "mcp",
        state: "st",
        decision: "allow",
        admin_token: admin,
      }),
      redirect: "manual",
    });
    expect(allowed.status).toBe(303);
    const code = new URL(allowed.headers.get("location")!).searchParams.get("code");
    expect(code).toBeTruthy();

    const bad = await fetch(`${gw.url}/oauth/token`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: redirectUri,
        client_id: connector.clientId,
        code_verifier: "a".repeat(43),
      }),
    });
    expect(bad.status).toBe(400);
    const replay = await fetch(`${gw.url}/oauth/token`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: redirectUri,
        client_id: connector.clientId,
        code_verifier: verifier,
      }),
    });
    expect(replay.status).toBe(400);

    const { verifier: verifier2, challenge: challenge2 } = pkce();
    const allowed2 = await fetch(`${gw.url}/oauth/authorize`, {
      method: "POST",
      body: new URLSearchParams({
        client_id: connector.clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge2,
        scope: "mcp",
        state: "st2",
        decision: "allow",
        admin_token: admin,
      }),
      redirect: "manual",
    });
    const code2 = new URL(allowed2.headers.get("location")!).searchParams.get("code")!;
    const tokenRes = await fetch(`${gw.url}/oauth/token`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code2,
        redirect_uri: redirectUri,
        client_id: connector.clientId,
        code_verifier: verifier2,
      }),
    });
    expect(tokenRes.status).toBe(200);
    const token = (await tokenRes.json()) as {
      access_token: string;
      refresh_token: string;
      token_type: string;
      scope: string;
    };
    expect(token.token_type).toBe("Bearer");
    expect(token.scope).toBe("mcp");
    expect(token.access_token.startsWith("mfo_")).toBe(true);

    const mcp = await fetch(`${gw.url}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "t", version: "0" },
        },
      }),
    });
    expect(mcp.status).toBe(200);

    const listed = await (
      await fetch(`${gw.url}/v1/oauth/grants`, { headers })
    ).text();
    expect(listed).not.toContain(token.access_token);
    expect(listed).not.toContain(token.refresh_token);
    gw.store.db.exec("PRAGMA wal_checkpoint(FULL)");
    const raw = readFileSync(gw.dbPath).toString("utf8");
    expect(raw).not.toContain(token.access_token);
    expect(raw).not.toContain(token.refresh_token);

    const grants = (await (
      await fetch(`${gw.url}/v1/oauth/grants`, { headers })
    ).json()) as { grants: Array<{ id: string }> };
    const revoked = await fetch(
      `${gw.url}/v1/oauth/grants/${grants.grants[0]!.id}`,
      { method: "DELETE", headers },
    );
    expect(revoked.status).toBe(200);
    const after = await fetch(`${gw.url}/mcp`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(after.status).toBe(401);
  });

  it("accepts an agent key and copies that key's scopes onto the grant", async () => {
    const gw = await boot();
    const headers = {
      Authorization: `Bearer ${admin}`,
      "Content-Type": "application/json",
    };
    const created = await fetch(`${gw.url}/v1/keys`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        name: "cursor",
        toolPrefixAllowlist: ["github__"],
      }),
    });
    expect(created.status).toBe(201);
    const agentKey = ((await created.json()) as { key: { token: string } }).key.token;
    expect(agentKey.startsWith("mf_")).toBe(true);

    const connector = (await (
      await fetch(`${gw.url}/v1/oauth/connector`, {
        headers: { Authorization: `Bearer ${admin}` },
      })
    ).json()) as { clientId: string };
    const { verifier, challenge } = pkce();
    const redirectUri = "http://127.0.0.1:9/cb";
    const allowed = await fetch(`${gw.url}/oauth/authorize`, {
      method: "POST",
      body: new URLSearchParams({
        client_id: connector.clientId,
        redirect_uri: redirectUri,
        code_challenge: challenge,
        scope: "mcp:admin",
        state: "agent",
        decision: "allow",
        admin_token: `Bearer ${agentKey}`,
      }),
      redirect: "manual",
    });
    expect(allowed.status).toBe(303);
    const code = new URL(allowed.headers.get("location")!).searchParams.get("code");
    expect(code).toBeTruthy();
    const tokenRes = await fetch(`${gw.url}/oauth/token`, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: redirectUri,
        client_id: connector.clientId,
        code_verifier: verifier,
      }),
    });
    const token = (await tokenRes.json()) as { scope: string };
    expect(token.scope).toBe("mcp");
    const grants = (await (
      await fetch(`${gw.url}/v1/oauth/grants`, {
        headers: { Authorization: `Bearer ${admin}` },
      })
    ).json()) as {
      grants: Array<{ scopes: { admin?: boolean; toolPrefixAllowlist?: string[] } | null }>;
    };
    expect(grants.grants[0]?.scopes?.admin).toBeUndefined();
    expect(grants.grants[0]?.scopes?.toolPrefixAllowlist).toEqual(["github__"]);
  });
});
