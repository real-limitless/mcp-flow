import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../src/api/app.js";
import { loadConfig } from "../src/config.js";
import { Store } from "../src/db/store.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { originHostMatches, portalCookieIsSecure } from "../src/portal/cookies.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("portal origin check", () => {
  it("matches the public host even when the request URL is the container address", () => {
    expect(originHostMatches("https://portal.example", "portal.example")).toBe(true);
    expect(originHostMatches("https://portal.example", "evil.example")).toBe(false);
  });

  it("marks the sign-in cookie Secure from the public host, not from a cross-site Origin", () => {
    expect(
      portalCookieIsSecure({
        requestOrigin: "http://127.0.0.1:9",
        publicUrl: "https://portal.example",
        host: "portal.example",
      }),
    ).toBe(true);
    expect(
      portalCookieIsSecure({
        origin: "https://accounts.google.com",
        requestOrigin: "http://127.0.0.1:8787",
        publicUrl: "http://127.0.0.1:8787",
        host: "127.0.0.1:8787",
      }),
    ).toBe(false);
    expect(
      portalCookieIsSecure({
        requestOrigin: "http://127.0.0.1:9",
        publicUrl: "https://portal.example",
        host: "127.0.0.1:9",
        forwardedProto: "https",
        forwardedHost: "portal.example",
      }),
    ).toBe(true);
    expect(
      portalCookieIsSecure({
        requestOrigin: "http://127.0.0.1:9",
        publicUrl: "https://portal.example",
        host: "127.0.0.1:9",
        forwardedProto: "https",
      }),
    ).toBe(false);
  });

  it("accepts a sign-in from the public site while Node sees an internal URL", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-origin-"));
    dirs.push(dir);
    const master = Buffer.alloc(32, 5).toString("base64");
    const admin = "bootstrap-admin-token-0123456789";
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: admin,
      publicUrl: "https://portal.example",
    });
    const store = new Store(cfg.dbPath, master);
    const app = createApp(store, cfg, new UpstreamPool(store));
    const headers = {
      "content-type": "application/json",
      "x-mcp-flow-request": "1",
      origin: "https://portal.example",
      host: "portal.example",
    };
    const ok = await app.request("http://10.0.0.8:8787/admin/bootstrap-login", {
      method: "POST",
      headers,
      body: JSON.stringify({ token: admin }),
    });
    expect(ok.status).toBe(200);

    const evil = await app.request("http://10.0.0.8:8787/admin/bootstrap-login", {
      method: "POST",
      headers: { ...headers, origin: "https://evil.example" },
      body: JSON.stringify({ token: admin }),
    });
    expect(evil.status).toBe(403);
    store.close();
  });
});
