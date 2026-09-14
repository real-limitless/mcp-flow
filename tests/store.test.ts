import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";

const master = Buffer.alloc(32, 9).toString("base64");
const dirs: string[] = [];

function openStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), master);
}

afterEach(() => {
  while (dirs.length) {
    const d = dirs.pop()!;
    rmSync(d, { recursive: true, force: true });
  }
});

describe("store", () => {
  it("bootstraps workspace and mints keys", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const created = store.createApiKey(ws.id, "agent-1");
    expect(created.token.startsWith("mf_")).toBe(true);
    expect(store.listApiKeys(ws.id)[0]!.prefix).toBe(created.prefix);
    // list never includes token
    expect(JSON.stringify(store.listApiKeys(ws.id))).not.toContain(
      created.token,
    );

    const auth = store.authenticateApiKey(created.token);
    expect(auth?.keyId).toBe(created.id);

    store.revokeApiKey(ws.id, created.id);
    expect(store.authenticateApiKey(created.token)).toBeNull();
    store.close();
  });

  it("seals backend headers and redacts on public view", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const be = store.createBackend(ws.id, {
      slug: "github",
      url: "https://example.com/mcp",
      headers: { Authorization: "Bearer super-secret" },
      enabled: true,
    });
    expect(be.hasHeaders).toBe(true);
    expect(JSON.stringify(be)).not.toContain("super-secret");

    const raw = store.getBackend(ws.id, "github")!;
    expect(raw.headersEnc).toBeTruthy();
    expect(raw.headersEnc).not.toContain("super-secret");
    expect(store.decryptHeaders(raw)).toEqual({
      Authorization: "Bearer super-secret",
    });
    store.close();
  });

  it("prefixes Bearer when sealing a raw Authorization token or apiKey", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const raw = store.createBackend(ws.id, {
      slug: "rawauth",
      url: "https://example.com/mcp",
      headers: { Authorization: "of_raw_token" },
      enabled: true,
    });
    expect(raw.hasHeaders).toBe(true);
    expect(store.decryptHeaders(store.getBackend(ws.id, "rawauth")!)).toEqual({
      Authorization: "Bearer of_raw_token",
    });

    const viaKey = store.createBackend(ws.id, {
      slug: "apikey",
      url: "https://example.com/mcp",
      apiKey: "of_via_field",
      enabled: true,
    });
    expect(viaKey.hasHeaders).toBe(true);
    expect(JSON.stringify(viaKey)).not.toContain("of_via_field");
    expect(store.decryptHeaders(store.getBackend(ws.id, "apikey")!)).toEqual({
      Authorization: "Bearer of_via_field",
    });
    store.close();
  });

  it("does not seal empty header or env values", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const be = store.createBackend(ws.id, {
      slug: "emptyhdr",
      url: "https://example.com/mcp",
      headers: { Authorization: "", "X-Empty": "   " },
      env: { FOO: "" },
      enabled: true,
    });
    expect(be.hasHeaders).toBe(false);
    expect(be.hasEnv).toBe(false);
    const raw = store.getBackend(ws.id, "emptyhdr")!;
    expect(raw.headersEnc).toBeNull();
    expect(raw.envEnc).toBeNull();

    const patched = store.updateBackend(ws.id, "emptyhdr", {
      headers: { Authorization: "Bearer kept", Unused: "" },
    });
    expect(patched?.hasHeaders).toBe(true);
    expect(store.decryptHeaders(store.getBackend(ws.id, "emptyhdr")!)).toEqual({
      Authorization: "Bearer kept",
    });
    store.close();
  });

  it("rejects bad slugs", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    expect(() =>
      store.createBackend(ws.id, { slug: "Bad Slug" }),
    ).toThrow(/slug/);
    store.close();
  });
});
