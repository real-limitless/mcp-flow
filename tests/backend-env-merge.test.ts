import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { backendUpdateAuditDetail } from "../src/audit/backend-update.js";
import { redactAdminToolAuditArgs } from "../src/audit/redact-admin-args.js";
import { sanitizeForAudit } from "../src/audit/sanitize.js";
import { loadConfig } from "../src/config.js";
import { applyEnvPatch } from "../src/db/env-patch.js";
import { BackendInputError } from "../src/db/secret-input.js";
import { Store } from "../src/db/store.js";
import { handleAdminTool } from "../src/mcp/admin-tools.js";
import { UpstreamPool } from "../src/mcp/upstream.js";
import { planEdgeCliArgs } from "../docker/edge-launch.mjs";
import { startServer, type RunningServer } from "../src/server.js";

const master = Buffer.alloc(32, 11).toString("base64");
const admin = "test-admin-token-please-change";
const SECRET_A = "sealed-value-alpha";
const SECRET_B = "sealed-value-beta";
const SECRET_C = "sealed-value-gamma";
const dirs: string[] = [];
const cleanups: Array<() => Promise<void>> = [];

function openStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-env-"));
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

async function bootGateway(): Promise<RunningServer> {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-env-gw-"));
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
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  const p = (probe.address() as { port: number }).port;
  await new Promise<void>((r, j) => probe.close((e) => (e ? j(e) : r())));
  cfg.port = p;
  const running = await startServer(cfg);
  cleanups.push(() => running.close());
  return running;
}

describe("env merge", () => {
  it("merges one key, deletes one key, and keeps the rest", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://example.com/mcp",
      env: { API_KEY: SECRET_A, REGION: "east", OTHER: SECRET_B },
      enabled: true,
    });

    const merged = store.updateBackend(ws.id, "remote", {
      env: { API_KEY: SECRET_C, REGION: "" },
      unsetEnv: ["OTHER"],
    });
    expect(merged?.envKeys).toEqual(["API_KEY", "REGION"]);
    expect(JSON.stringify(merged)).not.toContain(SECRET_A);
    expect(JSON.stringify(merged)).not.toContain(SECRET_B);
    expect(JSON.stringify(merged)).not.toContain(SECRET_C);
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      API_KEY: SECRET_C,
      REGION: "east",
    });

    const cleared = store.updateBackend(ws.id, "remote", {
      env: { REGION: null },
    });
    expect(cleared?.envKeys).toEqual(["API_KEY"]);
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      API_KEY: SECRET_C,
    });

    const replaced = store.updateBackend(ws.id, "remote", {
      envMode: "replace",
      env: { REGION: "west" },
    });
    expect(replaced?.envKeys).toEqual(["REGION"]);
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      REGION: "west",
    });
    expect(JSON.stringify(replaced)).not.toContain(SECRET_C);

    const wiped = store.updateBackend(ws.id, "remote", { env: null });
    expect(wiped?.hasEnv).toBe(false);
    expect(wiped?.envKeys).toEqual([]);
    store.close();
  });

  it("records changed key names and never their values", () => {
    const current = { API_KEY: SECRET_A, OTHER: SECRET_B };
    const input = {
      url: "https://example.com/v2",
      env: { API_KEY: SECRET_C, OTHER: "" },
      envMode: "merge" as const,
    };
    const detail = backendUpdateAuditDetail(input);
    expect(JSON.stringify(detail)).not.toContain(SECRET_A);
    expect(JSON.stringify(detail)).not.toContain(SECRET_C);
    expect(JSON.stringify(detail)).not.toContain("https://example.com/v2");

    const safe = sanitizeForAudit(detail) as {
      changed: Array<{ field: string }>;
      envSet: Array<{ name: string }>;
      envMode: string;
    };
    expect(safe.changed).toEqual([{ field: "url" }, { field: "env" }]);
    expect(safe.envSet).toEqual([{ name: "API_KEY" }]);
    expect(safe.envMode).toBe("merge");
    expect(JSON.stringify(safe)).not.toContain(SECRET_C);
    expect(applyEnvPatch(current, input).set).toEqual(["API_KEY"]);
  });
});

describe("PATCH /v1/backends and mf_admin_update_backend", () => {
  it("masks secrets and writes a sanitized audit entry", async () => {
    const gw = await bootGateway();
    const base = gw.url;
    const headers = {
      Authorization: `Bearer ${admin}`,
      "Content-Type": "application/json",
    };
    const created = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        slug: "remote",
        url: "https://example.com/mcp",
        apiKey: SECRET_A,
        env: { API_KEY: SECRET_B, REGION: "east" },
        enabled: true,
        placement: { mode: "remote" },
      }),
    });
    expect(created.status).toBe(201);
    const createdText = await created.text();
    expect(createdText).not.toContain(SECRET_A);
    expect(createdText).not.toContain(SECRET_B);
    expect(createdText).not.toContain("east");
    const createdBody = JSON.parse(createdText) as {
      backend: { id: string; envKeys: string[]; headerNames: string[] };
    };
    expect(createdBody.backend.envKeys).toEqual(["API_KEY", "REGION"]);
    expect(createdBody.backend.headerNames).toEqual(["Authorization"]);

    const patchBody = {
      url: "https://example.com/v2",
      env: { API_KEY: SECRET_C },
      envMode: "merge",
    };
    const patched = await fetch(`${base}/v1/backends/${createdBody.backend.id}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify(patchBody),
    });
    expect(patched.status).toBe(200);
    const patchedText = await patched.text();
    expect(patchedText).not.toContain(SECRET_A);
    expect(patchedText).not.toContain(SECRET_B);
    expect(patchedText).not.toContain(SECRET_C);
    expect(patchedText).not.toContain("east");
    const patchedBody = JSON.parse(patchedText) as {
      backend: { url: string; envKeys: string[]; headerNames: string[] };
    };
    expect(patchedBody.backend.url).toBe("https://example.com/v2");
    expect(patchedBody.backend.envKeys).toEqual(["API_KEY", "REGION"]);
    expect(patchedBody.backend.headerNames).toEqual(["Authorization"]);

    const ws = gw.store.ensureWorkspace("default");
    expect(gw.store.decryptEnv(gw.store.getBackend(ws.id, "remote")!)).toEqual({
      API_KEY: SECRET_C,
      REGION: "east",
    });

    const audit = gw.store
      .listAudit(ws.id)
      .find((event) => event.action === "backend.update");
    expect(audit?.detail).toEqual(
      sanitizeForAudit(backendUpdateAuditDetail(patchBody)),
    );
    const auditJson = JSON.stringify(audit);
    expect(auditJson).toContain("API_KEY");
    expect(auditJson).toContain("url");
    expect(auditJson).not.toContain(SECRET_A);
    expect(auditJson).not.toContain(SECRET_B);
    expect(auditJson).not.toContain(SECRET_C);
    expect(auditJson).not.toContain("https://example.com/v2");

    const listed = await fetch(`${base}/v1/backends`, { headers });
    const listedText = await listed.text();
    expect(listedText).not.toContain(SECRET_C);
    expect(listedText).toContain("API_KEY");
  });

  it("mf_admin_update_backend merges env and audits key names only", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-env-admin-"));
    dirs.push(dir);
    const dbPath = join(dir, "t.db");
    const store = new Store(dbPath, master);
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://example.com/mcp",
      env: { API_KEY: SECRET_A, REGION: "east" },
      apiKey: SECRET_B,
      enabled: true,
    });
    const pool = new UpstreamPool(store);
    const cfg = loadConfig({
      dbPath,
      masterKeyRaw: master,
      adminToken: admin,
      allowPrivateUrls: true,
    });
    const args = {
      idOrSlug: "remote",
      url: "https://example.com/v2",
      env: { API_KEY: SECRET_C },
      unsetEnv: ["REGION"],
    };
    const result = await handleAdminTool("mf_admin_update_backend", args, {
      store,
      pool,
      cfg,
      auth: { kind: "admin", workspaceId: ws.id },
      edgeEnabled: false,
    });
    expect(result.isError).toBeFalsy();
    const text = result.content.map((block) => ("text" in block ? block.text : "")).join("\n");
    expect(text).not.toContain(SECRET_A);
    expect(text).not.toContain(SECRET_B);
    expect(text).not.toContain(SECRET_C);
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      API_KEY: SECRET_C,
    });
    const pub = store.getBackendPublic(ws.id, "remote");
    expect(pub?.envKeys).toEqual(["API_KEY"]);
    expect(pub?.headerNames).toEqual(["Authorization"]);
    expect(pub?.url).toBe("https://example.com/v2");

    const audit = store.listAudit(ws.id).find((event) => event.action === "backend.update");
    const { idOrSlug: _id, ...patch } = args;
    expect(audit?.detail).toEqual(
      sanitizeForAudit({
        via: "mf_admin",
        ...backendUpdateAuditDetail(patch),
      }),
    );
    const auditJson = JSON.stringify(audit);
    expect(auditJson).toContain("API_KEY");
    expect(auditJson).toContain("REGION");
    expect(auditJson).not.toContain(SECRET_A);
    expect(auditJson).not.toContain(SECRET_C);
    store.close();
  });
});

describe("edge-only compose", () => {
  it("uses the server URL and device token without waiting for bootstrap", () => {
    const plan = planEdgeCliArgs({
      args: ["edge", "--name", "edge"],
      env: {
        MCP_FLOW_URL: "https://mcp-flow.example",
        MCP_FLOW_DEVICE_TOKEN: "replace-with-device-token",
      },
      tokenFromFile: "",
    });
    expect(plan.waitForTokenFile).toBe(false);
    expect(plan.cliArgs).toEqual([
      "edge",
      "--name",
      "edge",
      "--url",
      "https://mcp-flow.example",
    ]);
    expect(plan.cliArgs?.join(" ")).not.toContain("replace-with-device-token");
  });

  it("still waits for the bootstrap token file when no token is supplied", () => {
    const waiting = planEdgeCliArgs({
      args: ["edge", "--url", "http://mcp-flow:8787", "--name", "compose-edge"],
      env: {},
      tokenFromFile: "",
    });
    expect(waiting.waitForTokenFile).toBe(true);

    const ready = planEdgeCliArgs({
      args: ["edge", "--url", "http://mcp-flow:8787", "--name", "compose-edge"],
      env: {},
      tokenFromFile: "file-token",
    });
    expect(ready.waitForTokenFile).toBe(false);
    expect(ready.cliArgs).toEqual([
      "edge",
      "--url",
      "http://mcp-flow:8787",
      "--name",
      "compose-edge",
      "--token",
      "file-token",
    ]);
  });

  it("describes only the edge service and placeholder settings", () => {
    const text = readFileSync(join(process.cwd(), "docker-compose.edge.yaml"), "utf8");
    expect(text).toContain("MCP_FLOW_URL");
    expect(text).toContain("MCP_FLOW_DEVICE_TOKEN");
    expect(text).not.toContain("bootstrap:");
    expect(text).not.toContain("tailscale:");
    expect(text).not.toContain("http://mcp-flow:8787");
    expect(text).not.toMatch(/\b\d{1,3}(?:\.\d{1,3}){3}\b/);
    expect(text).not.toMatch(/^ {2}mcp-flow:/m);
    expect(text).toMatch(/healthcheck:\n\s+disable:\s+true/);
    const command = text.slice(text.indexOf("command:"));
    expect(command).not.toContain("--token");
    expect(command).not.toContain("MCP_FLOW_DEVICE_TOKEN");
  });

  it("keeps the full-stack client JSON reference ahead of the edge-only section", () => {
    const readme = readFileSync(join(process.cwd(), "README.md"), "utf8");
    const jsonAt = readme.indexOf("that JSON");
    const edgeAt = readme.indexOf("### Edge only");
    expect(jsonAt).toBeGreaterThan(0);
    expect(edgeAt).toBeGreaterThan(jsonAt);
    expect(readme.slice(edgeAt, edgeAt + 1200)).not.toMatch(/healthy/i);
  });

  it("sends padded env and api key values and treats a blank value as keep", () => {
    const app = readFileSync(join(process.cwd(), "src/admin/app.js"), "utf8");
    const save = app.slice(
      app.indexOf("async function saveBackendEdit"),
      app.indexOf("function wireBackendTable"),
    );
    expect(save).toContain('if (apiKey.trim()) body.apiKey = apiKey');
    expect(save).toContain("if (name && value.trim()) env[name] = value");
    expect(save).not.toContain("beEditApiKey\")?.value?.trim()");
    expect(save).not.toContain('value ?? "").trim()');
    const collect = app.slice(
      app.indexOf("function collectKvPairs"),
      app.indexOf("function collectHeaderPairs"),
    );
    expect(collect).toContain("if (name && value.trim()) out[name] = value");
    expect(collect).not.toContain('value ?? "").trim()');
  });
});

const PADDED = "  pad-secret  ";
const STRIPE = "stripe-placeholder-value";
const REDIS = "redis://placeholder.example/0";
const SENTRY = "https://placeholder.example/dsn";
const SIG = "sig-placeholder-value";
const KEY = "key-placeholder-value";

describe("secret input validation", () => {
  it("keeps padded env values and treats only blank values as keep", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://example.com/mcp",
      env: { STRIPE_SK: PADDED, REGION: "east" },
    });
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      STRIPE_SK: PADDED,
      REGION: "east",
    });

    const kept = store.updateBackend(ws.id, "remote", {
      env: { STRIPE_SK: "   ", REGION: "" },
    });
    expect(kept?.envKeys).toEqual(["REGION", "STRIPE_SK"]);
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      STRIPE_SK: PADDED,
      REGION: "east",
    });

    const next = applyEnvPatch(
      { STRIPE_SK: PADDED },
      { env: { STRIPE_SK: PADDED } },
    );
    expect(next.next).toEqual({ STRIPE_SK: PADDED });
    store.close();
  });

  it("merges headers per key and keeps Authorization", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://example.com/mcp",
      apiKey: SECRET_A,
      headers: { "X-Existing": "keep-me" },
    });
    const merged = store.updateBackend(ws.id, "remote", {
      headers: { "X-Upstream-Sig": SIG, "X-Existing": "   " },
    });
    expect(merged?.headerNames).toEqual([
      "Authorization",
      "X-Existing",
      "X-Upstream-Sig",
    ]);
    expect(store.decryptHeaders(store.getBackend(ws.id, "remote")!)).toEqual({
      Authorization: `Bearer ${SECRET_A}`,
      "X-Existing": "keep-me",
      "X-Upstream-Sig": SIG,
    });

    const dropped = store.updateBackend(ws.id, "remote", {
      headers: { "X-Existing": null },
    });
    expect(dropped?.headerNames).toEqual(["Authorization", "X-Upstream-Sig"]);
    expect(
      store.decryptHeaders(store.getBackend(ws.id, "remote")!).Authorization,
    ).toBe(`Bearer ${SECRET_A}`);

    const replaced = store.updateBackend(ws.id, "remote", {
      headerMode: "replace",
      headers: { "X-Upstream-Sig": SIG },
    });
    expect(replaced?.headerNames).toEqual(["X-Upstream-Sig"]);
    store.close();
  });

  it("rejects malformed env, headers, and unsetEnv", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://example.com/mcp",
      env: { REGION: "east" },
      apiKey: SECRET_A,
    });
    const bad: unknown[] = [
      { unsetEnv: "NOPE" },
      { unsetEnv: ["OK", 1] },
      { env: "hello" },
      { env: ["a"] },
      { env: { FOO: 1 } },
      { env: { "A=B": "x" } },
      { env: { "BAD\nNAME": "x" } },
      { env: { ["N".repeat(10000)]: "x" } },
      { headers: "nope" },
      { headers: ["a"] },
      { headers: { "X\nY": "x" } },
      { headers: { "A B": "x" } },
      { headers: { "X:Y": "x" } },
      { headers: { "ÄÖ_X": "x" } },
      { envMode: "MERGE" },
      { headerMode: "bogus" },
    ];
    for (const patch of bad) {
      expect(() =>
        store.updateBackend(ws.id, "remote", patch as never),
      ).toThrow(BackendInputError);
    }
    expect(() =>
      store.createBackend(ws.id, {
        slug: "other",
        env: "hello" as never,
      }),
    ).toThrow(BackendInputError);
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      REGION: "east",
    });
    expect(store.getBackend(ws.id, "other")).toBeNull();
    store.close();
  });

  it("drops __proto__ and still stores ordinary keys", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://example.com/mcp",
      env: { REGION: "east" },
    });
    const updated = store.updateBackend(ws.id, "remote", {
      env: JSON.parse('{"__proto__":"x","REGION":"west"}') as Record<
        string,
        string
      >,
    });
    expect(updated?.envKeys).toEqual(["REGION"]);
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      REGION: "west",
    });
    expect(JSON.stringify(updated)).not.toContain("\"__proto__\"");

    const placed = store.createBackend(ws.id, {
      slug: "placed",
      url: "https://example.com/mcp",
      placement: { mode: "remote", env: { STRIPE_SK: STRIPE } } as never,
      sandbox: { memory: "512m", headers: { "X-Upstream-Sig": SIG } } as never,
    });
    expect(JSON.stringify(placed)).not.toContain(STRIPE);
    expect(JSON.stringify(placed)).not.toContain(SIG);
    expect(placed.placement).toEqual({ mode: "remote" });
    expect(placed.sandbox).toEqual({ memory: "512m" });
    const row = store.getBackend(ws.id, "placed")!;
    expect(row.placementJson).not.toContain(STRIPE);
    expect(row.sandboxJson ?? "").not.toContain(SIG);
    store.close();
  });

  it("logs submitted secret names without comparing stored values", () => {
    const input = {
      env: { STRIPE_SK: STRIPE, OTHER: "   " },
      unsetEnv: ["GONE"],
      headers: { "X-Upstream-Sig": SIG },
      envMode: "merge" as const,
    };
    const once = backendUpdateAuditDetail(input);
    const twice = backendUpdateAuditDetail(input);
    expect(twice).toEqual(once);
    expect(once.envSet).toEqual([{ name: "STRIPE_SK" }]);
    expect(once.envUnset).toEqual([{ name: "GONE" }]);
    expect(once.headerSet).toEqual([{ name: "X-Upstream-Sig" }]);
    expect(once.headerUnset).toBeUndefined();
    const text = JSON.stringify(once);
    expect(text).not.toContain(STRIPE);
    expect(text).not.toContain(SIG);

    const both = backendUpdateAuditDetail({
      env: { STRIPE_SK: STRIPE },
      unsetEnv: ["STRIPE_SK"],
    });
    expect(both.envSet).toBeUndefined();
    expect(both.envUnset).toEqual([{ name: "STRIPE_SK" }]);

    const replaced = backendUpdateAuditDetail({
      envMode: "replace",
      env: { REGION: "west" },
      unsetEnv: ["STRIPE_SK"],
    });
    expect(replaced.envMode).toBe("replace");
    expect(replaced.envSet).toEqual([{ name: "REGION" }]);
    expect(replaced.envUnset).toBeUndefined();
  });
});

describe("admin tool audit redaction", () => {
  it("redacts ordinary env, header, and apiKey values on admin tools", () => {
    const args = {
      slug: "remote",
      env: { STRIPE_SK: STRIPE, REDIS_URL: REDIS, SENTRY_DSN: null },
      headers: { "X-Upstream-Sig": SIG },
      apiKey: KEY,
    };
    const redacted = redactAdminToolAuditArgs("mf_admin_create_backend", args);
    expect(redacted).not.toBe(args);
    expect(redacted.env).toEqual({
      STRIPE_SK: "[redacted]",
      REDIS_URL: "[redacted]",
      SENTRY_DSN: null,
    });
    expect(redacted.headers).toEqual({ "X-Upstream-Sig": "[redacted]" });
    expect(redacted.apiKey).toBe("[redacted]");
    expect(args.env.STRIPE_SK).toBe(STRIPE);
    expect(args.apiKey).toBe(KEY);

    const installed = redactAdminToolAuditArgs("mf_admin_catalog_install", {
      id: "example/server",
      env: { NOTION_INTEGRATION: "notion-placeholder" },
      headers: "not-a-map",
    });
    expect(installed.env).toEqual({ NOTION_INTEGRATION: "[redacted]" });
    expect(installed.headers).toBe("[redacted]");

    const plain = { text: "hi" };
    expect(redactAdminToolAuditArgs("up__echo", plain)).toBe(plain);

    const extra = "extra-note-placeholder";
    const sandboxExtra = "sandbox-extra-placeholder";
    const nested = {
      Env: { STRIPE_SK: STRIPE },
      HEADERS: { "X-Upstream-Sig": SIG },
      placement: {
        mode: "remote",
        env: { STRIPE_SK: STRIPE },
        extra: { note: extra },
        affinity: { env: { STRIPE_SK: STRIPE } },
      },
      sandbox: {
        memory: "512m",
        headers: { "X-Upstream-Sig": SIG },
        extra: { note: sandboxExtra },
        token: "sandbox-token-placeholder",
      },
    };
    const nestedRedacted = redactAdminToolAuditArgs("mf_admin_update_backend", nested);
    expect(nestedRedacted).not.toBe(nested);
    expect(nestedRedacted).not.toHaveProperty("Env");
    expect(nestedRedacted).not.toHaveProperty("HEADERS");
    expect(nestedRedacted.placement).toEqual({
      mode: "remote",
      affinity: "[redacted]",
    });
    expect(nestedRedacted.sandbox).toEqual({ memory: "512m" });
    const nestedText = JSON.stringify(nestedRedacted);
    expect(nestedText).not.toContain(STRIPE);
    expect(nestedText).not.toContain(SIG);
    expect(nestedText).not.toContain(extra);
    expect(nestedText).not.toContain(sandboxExtra);
    expect(nestedText).not.toContain("sandbox-token-placeholder");
    expect((nested.placement as { env: { STRIPE_SK: string } }).env.STRIPE_SK).toBe(STRIPE);

    const top = "top-level-stripe-placeholder";
    const leaked = redactAdminToolAuditArgs("mf_admin_update_backend", {
      idOrSlug: "sb",
      STRIPE_SK: top,
      extra: "top-extra-placeholder",
      note: { deep: top },
    });
    expect(leaked).toEqual({ idOrSlug: "sb" });
    expect(JSON.stringify(leaked)).not.toContain(top);
    const installedLeak = redactAdminToolAuditArgs("mf_admin_catalog_install", {
      id: "example/server",
      STRIPE_SK: top,
      note: top,
    });
    expect(installedLeak).toEqual({ id: "example/server" });
    expect(JSON.stringify(installedLeak)).not.toContain(top);
    expect(redactAdminToolAuditArgs("mf_admin_status", { STRIPE_SK: top })).toEqual({});

    const wrapped = {
      name: "mf_admin_update_backend",
      arguments: {
        idOrSlug: "sb",
        env: { STRIPE_SK: STRIPE },
        headers: { "X-Upstream-Sig": SIG },
        extra: extra,
        apiKey: KEY,
      },
    };
    const wrappedCopy = redactAdminToolAuditArgs("mf_call_tool", wrapped);
    expect(wrappedCopy).not.toBe(wrapped);
    expect(wrappedCopy).toEqual({
      name: "mf_admin_update_backend",
      arguments: "[redacted]",
    });
    expect(JSON.stringify(wrappedCopy)).not.toContain(STRIPE);
    expect(JSON.stringify(wrappedCopy)).not.toContain(extra);
    expect(JSON.stringify(wrappedCopy)).not.toContain("STRIPE_SK");
    expect(wrapped.arguments.env.STRIPE_SK).toBe(STRIPE);
    const plainCall = { name: "remote__echo", arguments: { text: "hi" } };
    expect(redactAdminToolAuditArgs("mf_call_tool", plainCall)).toBe(plainCall);
  });

  it("records only a sanitized inner name when mf_call_tool is not an upstream tool", () => {
    const secret = "wrap-variant-placeholder";
    const header = "wrap-header-placeholder";
    const extra = "wrap-extra-placeholder";
    const note = "wrap-note-placeholder";
    const place = "wrap-placement-placeholder";
    const inner = {
      idOrSlug: "sb",
      env: { STRIPE_SK: secret, SLACK_BOT: secret },
      headers: { "X-Upstream-Sig": header },
      apiKey: KEY,
      extra,
      note: { deep: note },
      placement: { extra: place },
    };
    const expectCollapsed = (
      tool: string,
      args: Record<string, unknown>,
      name: string,
    ) => {
      const copy = redactAdminToolAuditArgs(tool, args);
      expect(copy).toEqual({ name, arguments: "[redacted]" });
      const text = JSON.stringify(copy);
      expect(text).not.toContain(secret);
      expect(text).not.toContain(header);
      expect(text).not.toContain(extra);
      expect(text).not.toContain(note);
      expect(text).not.toContain(place);
      expect(text).not.toContain(KEY);
      expect(text).not.toContain("SLACK_BOT");
      expect(text).not.toContain("STRIPE_SK");
    };

    expectCollapsed(
      "mf_call_tool",
      { name: "mf_admin_update_backend", arguments: inner },
      "mf_admin_update_backend",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: "mf_admin_create_backend", arguments: inner },
      "mf_admin_create_backend",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: "mf_admin_catalog_install", arguments: inner },
      "mf_admin_catalog_install",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: "  mf_admin_update_backend  ", arguments: inner },
      "mf_admin_update_backend",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: "\tmf_admin_update_backend\t", arguments: inner },
      "mf_admin_update_backend",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: "mf_admin_update_backend", arguments: [inner] as unknown as Record<string, unknown> },
      "mf_admin_update_backend",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: "mf_admin_update_backend", arguments: secret },
      "mf_admin_update_backend",
    );
    expectCollapsed(
      "mf_call_tool",
      {
        name: "mf_call_tool",
        arguments: { name: "mf_admin_update_backend", arguments: inner },
      },
      "mf_call_tool",
    );
    expectCollapsed(
      "mf_call_tool",
      {
        name: "mf_call_tool",
        arguments: {
          name: "mf_call_tool",
          arguments: {
            name: "mf_call_tool",
            arguments: { name: "mf_admin_update_backend", arguments: inner },
          },
        },
      },
      "mf_call_tool",
    );
    expectCollapsed(
      "mf_call_tool",
      {
        name: "MF_ADMIN_update_backend",
        arguments: inner,
        extra,
        env: { STRIPE_SK: secret },
      },
      "MF_ADMIN_update_backend",
    );
    expectCollapsed(
      "Mf_Call_Tool",
      { name: "Mf_Admin_update_backend", arguments: inner, extra },
      "Mf_Admin_update_backend",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: "mf_status", arguments: { env: { STRIPE_SK: secret } }, extra },
      "mf_status",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: { env: { STRIPE_SK: secret }, extra }, arguments: inner },
      "[invalid]",
    );
    expectCollapsed(
      "mf_call_tool",
      { name: "mf_admin_\u0001update_backend", arguments: inner },
      "mf_admin_update_backend",
    );
    const long = "mf_admin_" + "n".repeat(80);
    expectCollapsed(
      "mf_call_tool",
      { name: `  ${long}  `, arguments: inner },
      long.slice(0, 64),
    );
    const spacedUpstream = { name: " remote__echo ", arguments: { text: secret } };
    expect(redactAdminToolAuditArgs("mf_call_tool", spacedUpstream)).toBe(spacedUpstream);
  });

  it("stores redacted tools/call arguments for admin backend tools", async () => {
    const gw = await bootGateway();
    const base = gw.url;
    const keyRes = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${admin}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ name: "ops", admin: true }),
    });
    expect(keyRes.status).toBe(201);
    const opToken = ((await keyRes.json()) as { key: { token: string } }).key
      .token;
    const client = new Client({ name: "ops", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${opToken}` } },
      }),
    );
    const created = await client.callTool({
      name: "mf_admin_create_backend",
      arguments: {
        slug: "remote",
        url: "https://example.com/mcp",
        apiKey: KEY,
        env: { STRIPE_SK: STRIPE, REDIS_URL: REDIS, SENTRY_DSN: SENTRY },
        headers: { "X-Upstream-Sig": SIG },
        enabled: false,
        placement: { mode: "remote" },
      },
    });
    expect(created.isError).not.toBe(true);
    const updated = await client.callTool({
      name: "mf_admin_update_backend",
      arguments: {
        idOrSlug: "remote",
        apiKey: KEY,
        env: { STRIPE_SK: STRIPE, REDIS_URL: null },
        headers: { "X-Upstream-Sig": SIG },
      },
    });
    expect(updated.isError).not.toBe(true);
    const nestedValue = "nested-stripe-placeholder";
    const nestedCall = await client.callTool({
      name: "mf_admin_update_backend",
      arguments: {
        idOrSlug: "remote",
        placement: { mode: "remote", env: { STRIPE_SK: nestedValue } },
        sandbox: { memory: "512m", headers: { "X-Upstream-Sig": SIG } },
      },
    });
    expect(nestedCall.isError).not.toBe(true);
    await client.close();

    const ws = gw.store.ensureWorkspace("default");
    const events = gw.store
      .listAudit(ws.id, { limit: 100 })
      .filter((event) => event.action === "tools/call");
    expect(events).toHaveLength(3);
    const blob = JSON.stringify(events);
    expect(blob).toContain("STRIPE_SK");
    expect(blob).toContain("REDIS_URL");
    expect(blob).toContain("SENTRY_DSN");
    expect(blob).toContain("X-Upstream-Sig");
    expect(blob).toContain("[redacted]");
    expect(blob).not.toContain(STRIPE);
    expect(blob).not.toContain(REDIS);
    expect(blob).not.toContain(SENTRY);
    expect(blob).not.toContain(SIG);
    expect(blob).not.toContain(KEY);
    expect(blob).not.toContain("nested-stripe-placeholder");
    const createArgs = (
      events.find((event) => {
        const args = (event.detail as { arguments?: { slug?: string } } | null)
          ?.arguments;
        return args?.slug === "remote";
      })?.detail as {
        arguments: {
          env: Record<string, unknown>;
          headers: Record<string, unknown>;
          apiKey: string;
        };
      }
    ).arguments;
    expect(createArgs.env).toEqual({
      STRIPE_SK: "[redacted]",
      REDIS_URL: "[redacted]",
      SENTRY_DSN: "[redacted]",
    });
    expect(createArgs.headers).toEqual({ "X-Upstream-Sig": "[redacted]" });
    expect(createArgs.apiKey).toBe("[redacted]");
  }, 60_000);
});

describe("backend patch errors", () => {
  it("returns 400 for a malformed unsetEnv and other bad secret input", async () => {
    const gw = await bootGateway();
    const base = gw.url;
    const headers = {
      Authorization: `Bearer ${admin}`,
      "Content-Type": "application/json",
    };
    const created = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        slug: "remote",
        url: "https://example.com/mcp",
        env: { REGION: "east" },
        apiKey: SECRET_A,
        placement: { mode: "remote" },
      }),
    });
    expect(created.status).toBe(201);
    const id = ((await created.json()) as { backend: { id: string } }).backend.id;
    const cases = [
      { unsetEnv: "NOPE" },
      { unsetEnv: ["OK", 1] },
      { env: "hello" },
      { env: ["a"] },
      { env: { FOO: 1 } },
      { env: { "A=B": "x" } },
      { env: { "BAD\nNAME": "x" } },
      { headers: { "X\nY": SIG } },
      { headers: { "A B": SIG } },
      { headers: { "X:Y": SIG } },
      { headers: { "ÄÖ_X": SIG } },
      { envMode: "bogus" },
      { headerMode: "MERGE" },
    ];
    for (const body of cases) {
      const res = await fetch(`${base}/v1/backends/${id}`, {
        method: "PATCH",
        headers,
        body: JSON.stringify(body),
      });
      const text = await res.text();
      expect(res.status, text).toBe(400);
      expect(text).not.toMatch(/TypeError/);
    }
    const posted = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        slug: "broken",
        url: "https://example.com/mcp",
        env: "hello",
        placement: { mode: "remote" },
      }),
    });
    const postedText = await posted.text();
    expect(posted.status).toBe(400);
    expect(postedText).not.toMatch(/TypeError/);

    const ws = gw.store.ensureWorkspace("default");
    expect(gw.store.decryptEnv(gw.store.getBackend(ws.id, "remote")!)).toEqual({
      REGION: "east",
    });
    expect(
      gw.store.decryptHeaders(gw.store.getBackend(ws.id, "remote")!).Authorization,
    ).toBe(`Bearer ${SECRET_A}`);
  });

  it("does not leak a TypeError for a malformed unsetEnv tool call", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-env-admin-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    store.createBackend(ws.id, {
      slug: "remote",
      url: "https://example.com/mcp",
      env: { REGION: "east" },
    });
    const pool = new UpstreamPool(store);
    const cfg = loadConfig({
      dbPath: join(dir, "t.db"),
      masterKeyRaw: master,
      adminToken: admin,
      allowPrivateUrls: true,
    });
    const result = await handleAdminTool(
      "mf_admin_update_backend",
      { idOrSlug: "remote", unsetEnv: "NOPE" },
      {
        store,
        pool,
        cfg,
        auth: { kind: "admin", workspaceId: ws.id },
        edgeEnabled: false,
      },
    );
    const text = result.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    expect(result.isError).toBe(true);
    expect(text).toMatch(/unsetEnv/);
    expect(text).not.toMatch(/TypeError/);
    expect(store.decryptEnv(store.getBackend(ws.id, "remote")!)).toEqual({
      REGION: "east",
    });
    store.close();
  });
});

describe("placement and sandbox shapes", () => {
  it("rejects mistyped placement and sandbox values and omits unknown keys from audit", async () => {
    const gw = await bootGateway();
    const base = gw.url;
    const headers = {
      Authorization: `Bearer ${admin}`,
      "Content-Type": "application/json",
    };
    const created = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        slug: "sb",
        transport: "stdio",
        command: ["echo", "ok"],
        placement: { mode: "central-sandbox" },
      }),
    });
    expect(created.status).toBe(201);
    const ws = gw.store.ensureWorkspace("default");
    const before = gw.store.getBackend(ws.id, "sb")!;
    const affinityBody = {
      placement: {
        mode: "central-sandbox",
        affinity: { env: { STRIPE_SK: STRIPE }, note: "affinity-note-placeholder" },
      },
    };
    const memoryBody = {
      sandbox: { memory: { env: { STRIPE_SK: STRIPE } } },
    };
    const bad = [
      affinityBody,
      memoryBody,
      { sandbox: { cpus: { env: { STRIPE_SK: STRIPE } } } },
      { sandbox: { networkMode: { env: { STRIPE_SK: STRIPE } } } },
      {
        placement: {
          mode: "central-sandbox",
          deviceTags: ["ok", { env: { STRIPE_SK: STRIPE } }],
        },
      },
      {
        placement: {
          mode: { env: { STRIPE_SK: STRIPE } },
        },
      },
      {
        placement: {
          mode: "central-sandbox",
          deviceId: { env: { STRIPE_SK: STRIPE } },
        },
      },
    ];
    for (const body of bad) {
      const res = await fetch(`${base}/v1/backends/sb`, {
        method: "PATCH",
        headers,
        body: JSON.stringify(body),
      });
      const text = await res.text();
      expect(res.status, text).toBe(400);
      expect(text).not.toContain(STRIPE);
      expect(text).not.toContain("affinity-note-placeholder");
      expect(text).not.toMatch(/TypeError/);
    }
    const echoed = await fetch(`${base}/v1/backends/sb`, { headers });
    const echoedText = await echoed.text();
    expect(echoed.status).toBe(200);
    expect(echoedText).not.toContain(STRIPE);
    expect(echoedText).not.toContain("affinity-note-placeholder");
    const row = gw.store.getBackend(ws.id, "sb")!;
    expect(row.placementJson).toBe(before.placementJson);
    expect(row.sandboxJson).toBe(before.sandboxJson);
    expect(row.placementJson).not.toContain(STRIPE);
    expect(row.sandboxJson ?? "").not.toContain(STRIPE);

    const posted = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        slug: "bad-shape",
        transport: "stdio",
        command: ["echo", "ok"],
        placement: affinityBody.placement,
        sandbox: memoryBody.sandbox,
      }),
    });
    const postedText = await posted.text();
    expect(posted.status).toBe(400);
    expect(postedText).not.toContain(STRIPE);
    expect(postedText).not.toMatch(/TypeError/);
    expect(gw.store.getBackend(ws.id, "bad-shape")).toBeNull();

    const pool = new UpstreamPool(gw.store);
    const cfg = loadConfig({
      dbPath: join(tmpdir(), "unused-shape.db"),
      masterKeyRaw: master,
      adminToken: admin,
      allowPrivateUrls: true,
    });
    const deps = {
      store: gw.store,
      pool,
      cfg,
      auth: { kind: "admin" as const, workspaceId: ws.id },
      edgeEnabled: false,
    };
    const mcpUpdate = await handleAdminTool(
      "mf_admin_update_backend",
      { idOrSlug: "sb", ...affinityBody },
      deps,
    );
    const mcpMemory = await handleAdminTool(
      "mf_admin_update_backend",
      { idOrSlug: "sb", ...memoryBody },
      deps,
    );
    const mcpCreate = await handleAdminTool(
      "mf_admin_create_backend",
      {
        slug: "bad-mcp",
        transport: "stdio",
        command: ["echo", "ok"],
        placement: affinityBody.placement,
        sandbox: memoryBody.sandbox,
      },
      deps,
    );
    for (const result of [mcpUpdate, mcpMemory, mcpCreate]) {
      const text = result.content
        .map((block) => ("text" in block ? block.text : ""))
        .join("\n");
      expect(result.isError).toBe(true);
      expect(text).not.toContain(STRIPE);
      expect(text).not.toMatch(/TypeError/);
    }
    expect(
      mcpUpdate.content.map((block) => ("text" in block ? block.text : "")).join("\n"),
    ).toMatch(/affinity/);
    expect(
      mcpMemory.content.map((block) => ("text" in block ? block.text : "")).join("\n"),
    ).toMatch(/memory/);
    expect(gw.store.getBackend(ws.id, "bad-mcp")).toBeNull();
    expect(gw.store.getBackend(ws.id, "sb")!.placementJson).toBe(before.placementJson);

    const keyRes = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "ops-shape", admin: true }),
    });
    expect(keyRes.status).toBe(201);
    const opToken = ((await keyRes.json()) as { key: { token: string } }).key.token;
    const client = new Client({ name: "ops-shape", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${opToken}` } },
      }),
    );
    const extra = "placement-extra-placeholder";
    const sandboxExtra = "sandbox-extra-placeholder";
    const kept = await client.callTool({
      name: "mf_admin_update_backend",
      arguments: {
        idOrSlug: "sb",
        placement: {
          mode: "central-sandbox",
          affinity: "pinned",
          deviceTags: ["lab"],
          extra: { note: extra, env: { STRIPE_SK: STRIPE } },
        },
        sandbox: {
          memory: "512m",
          cpus: "1.0",
          networkMode: "bridge",
          extra: { note: sandboxExtra },
        },
      },
    });
    expect(kept.isError).not.toBe(true);
    const rejected = await client.callTool({
      name: "mf_admin_update_backend",
      arguments: {
        idOrSlug: "sb",
        placement: affinityBody.placement,
        sandbox: memoryBody.sandbox,
      },
    });
    expect(rejected.isError).toBe(true);
    await client.close();

    const stored = gw.store.getBackendPublic(ws.id, "sb");
    expect(stored?.placement).toEqual({
      mode: "central-sandbox",
      affinity: "pinned",
      deviceTags: ["lab"],
    });
    expect(stored?.sandbox).toEqual({
      memory: "512m",
      cpus: "1.0",
      networkMode: "bridge",
    });
    const storedText = JSON.stringify(stored);
    expect(storedText).not.toContain(STRIPE);
    expect(storedText).not.toContain(extra);
    expect(storedText).not.toContain(sandboxExtra);

    const events = gw.store.listAudit(ws.id, { limit: 100 });
    const blob = JSON.stringify(events);
    expect(blob).not.toContain(STRIPE);
    expect(blob).not.toContain(extra);
    expect(blob).not.toContain(sandboxExtra);
    expect(blob).not.toContain("affinity-note-placeholder");
    const calls = events.filter((event) => event.action === "tools/call");
    expect(calls.length).toBeGreaterThanOrEqual(2);

    const listed = await handleAdminTool(
      "mf_admin_list_audit",
      { limit: 100 },
      deps,
    );
    const listedText = listed.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    expect(listed.isError).not.toBe(true);
    expect(listedText).not.toContain(STRIPE);
    expect(listedText).not.toContain(extra);
    expect(listedText).not.toContain(sandboxExtra);
    expect(listedText).not.toContain("affinity-note-placeholder");
  }, 60_000);

  it("rejects unknown admin arguments and unbounded config strings, and keeps null placement", async () => {
    const gw = await bootGateway();
    const base = gw.url;
    const headers = {
      Authorization: `Bearer ${admin}`,
      "Content-Type": "application/json",
    };
    const created = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        slug: "sb",
        transport: "stdio",
        command: ["echo", "ok"],
        placement: { mode: "central-sandbox" },
      }),
    });
    expect(created.status).toBe(201);
    const ws = gw.store.ensureWorkspace("default");
    const before = gw.store.getBackend(ws.id, "sb")!.placementJson;
    const long = "d".repeat(100_000);
    const spaced = "x y;z";
    const badBodies = [
      { placement: { mode: "central-sandbox", deviceId: long } },
      { placement: { mode: "central-sandbox", deviceId: spaced } },
      { placement: { mode: "central-sandbox", deviceId: "bad\nid" } },
      { placement: { mode: "central-sandbox", deviceTags: ["ok", spaced] } },
      { placement: { mode: "central-sandbox", deviceTags: [long] } },
      { sandbox: { memory: long } },
      { sandbox: { memory: "512 m" } },
      { sandbox: { cpus: "1.0\t" } },
      { sandbox: { networkMode: "br idge" } },
    ];
    for (const body of badBodies) {
      const res = await fetch(`${base}/v1/backends/sb`, {
        method: "PATCH",
        headers,
        body: JSON.stringify(body),
      });
      const text = await res.text();
      expect(res.status, text).toBe(400);
      expect(text).not.toContain(long);
      expect(text).not.toContain(spaced);
      expect(text).not.toMatch(/TypeError/);
    }
    expect(gw.store.getBackend(ws.id, "sb")!.placementJson).toBe(before);

    const kept = await fetch(`${base}/v1/backends/sb`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        placement: {
          mode: "central-sandbox",
          deviceId: "device-1",
          deviceTags: ["edge-a"],
          affinity: "harness-local",
        },
        sandbox: { memory: "not-a-size!!", cpus: "1.0", networkMode: "bridge" },
      }),
    });
    expect(kept.status).toBe(200);
    const keptBody = (await kept.json()) as {
      backend: { placement: Record<string, unknown>; sandbox: Record<string, unknown> };
    };
    expect(keptBody.backend.placement).toMatchObject({
      mode: "central-sandbox",
      deviceId: "device-1",
      affinity: "harness-local",
    });
    expect(keptBody.backend.sandbox.memory).toBe("not-a-size!!");

    const cleared = await fetch(`${base}/v1/backends/sb`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ placement: null }),
    });
    expect(cleared.status).toBe(200);
    const clearedBody = (await cleared.json()) as {
      backend: { placement: Record<string, unknown> };
    };
    expect(clearedBody.backend.placement.mode).toBe("central-sandbox");
    expect(clearedBody.backend.placement.deviceId).toBe("device-1");

    const nulled = await fetch(`${base}/v1/backends/sb`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        placement: {
          mode: "central-sandbox",
          deviceId: null,
          affinity: null,
          deviceTags: null,
        },
      }),
    });
    expect(nulled.status).toBe(200);
    const nulledBody = (await nulled.json()) as {
      backend: { placement: Record<string, unknown> };
    };
    expect(nulledBody.backend.placement.mode).toBe("central-sandbox");
    expect(nulledBody.backend.placement.deviceId).toBeNull();
    expect(nulledBody.backend.placement.affinity).toBeNull();

    const noMode = await fetch(`${base}/v1/backends/sb`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ placement: { affinity: "pinned" } }),
    });
    const noModeText = await noMode.text();
    expect(noMode.status, noModeText).toBe(200);
    expect(noModeText).not.toMatch(/placement\.mode is invalid/);
    expect(JSON.parse(noModeText).backend.placement).toMatchObject({
      mode: "central-sandbox",
      affinity: "pinned",
    });

    const pool = new UpstreamPool(gw.store);
    const cfg = loadConfig({
      dbPath: join(tmpdir(), "unused-shape.db"),
      masterKeyRaw: master,
      adminToken: admin,
      allowPrivateUrls: true,
    });
    const deps = {
      store: gw.store,
      pool,
      cfg,
      auth: { kind: "admin" as const, workspaceId: ws.id },
      edgeEnabled: false,
    };
    const mcpLong = await handleAdminTool(
      "mf_admin_update_backend",
      {
        idOrSlug: "sb",
        sandbox: { memory: long },
      },
      deps,
    );
    const mcpLongText = mcpLong.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    expect(mcpLong.isError).toBe(true);
    expect(mcpLongText).toMatch(/memory/);
    expect(mcpLongText).not.toContain(long);
    expect(mcpLongText).not.toMatch(/TypeError/);

    const mcpNull = await handleAdminTool(
      "mf_admin_update_backend",
      {
        idOrSlug: "sb",
        placement: { mode: "central-sandbox", deviceId: null, affinity: null },
      },
      deps,
    );
    expect(mcpNull.isError).not.toBe(true);
    const mcpMissingMode = await handleAdminTool(
      "mf_admin_create_backend",
      {
        slug: "no-mode",
        url: "https://example.com/mcp",
        placement: { affinity: "any-online" },
      },
      deps,
    );
    expect(mcpMissingMode.isError).not.toBe(true);
    const createdNoMode = gw.store.getBackendPublic(ws.id, "no-mode");
    expect(createdNoMode?.placement).toMatchObject({
      mode: "remote",
      affinity: "any-online",
    });

    const keyRes = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "ops-unknown", admin: true }),
    });
    const opToken = ((await keyRes.json()) as { key: { token: string } }).key.token;
    const client = new Client(
      { name: "ops-unknown", version: "1.0.0" },
      { capabilities: {} },
    );
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${opToken}` } },
      }),
    );
    const top = "top-level-stripe-placeholder";
    const extraVal = "top-extra-placeholder";
    const noteVal = "top-note-placeholder";
    const calls = [
      {
        name: "mf_admin_update_backend",
        arguments: {
          idOrSlug: "sb",
          STRIPE_SK: top,
          extra: extraVal,
          note: { deep: noteVal },
        },
        unknown: 3,
      },
      {
        name: "mf_admin_create_backend",
        arguments: {
          slug: "leaky",
          url: "https://example.com/mcp",
          STRIPE_SK: top,
          extra: extraVal,
        },
        unknown: 2,
      },
      {
        name: "mf_admin_catalog_install",
        arguments: { id: "example/server", note: noteVal, extra: extraVal },
        unknown: 2,
      },
      {
        name: "mf_admin_list_backends",
        arguments: { STRIPE_SK: top },
        unknown: 1,
      },
    ];
    for (const call of calls) {
      const result = await client.callTool({
        name: call.name,
        arguments: call.arguments,
      });
      const text = result.content
        .map((block) => ("text" in block ? block.text : ""))
        .join("\n");
      expect(result.isError, text).toBe(true);
      expect(text).toBe(`unknown argument (${call.unknown})`);
      expect(text).not.toContain("STRIPE_SK");
      expect(text).not.toContain("extra");
      expect(text).not.toContain("note");
      expect(text).not.toContain(top);
      expect(text).not.toContain(extraVal);
      expect(text).not.toContain(noteVal);
    }
    await client.close();
    expect(gw.store.getBackend(ws.id, "leaky")).toBeNull();

    const blob = JSON.stringify(gw.store.listAudit(ws.id, { limit: 100 }));
    expect(blob).not.toContain(top);
    expect(blob).not.toContain(extraVal);
    expect(blob).not.toContain(noteVal);
    expect(blob).not.toContain("STRIPE_SK");
    expect(blob).not.toContain("\"extra\"");
    expect(blob).not.toContain("\"note\"");
    expect(blob).not.toContain(long);
    const listed = await handleAdminTool("mf_admin_list_audit", { limit: 100 }, deps);
    const listedText = listed.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    expect(listedText).not.toContain(top);
    expect(listedText).not.toContain(extraVal);
    expect(listedText).not.toContain(noteVal);
    expect(listedText).not.toContain("STRIPE_SK");
    expect(listedText).not.toContain(long);
  }, 60_000);

  it("rejects NEL, format characters, and empty config strings, and redacts wrapped admin calls", async () => {
    const gw = await bootGateway();
    const base = gw.url;
    const headers = {
      Authorization: `Bearer ${admin}`,
      "Content-Type": "application/json",
    };
    const created = await fetch(`${base}/v1/backends`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        slug: "sb",
        transport: "stdio",
        command: ["echo", "ok"],
        placement: { mode: "central-sandbox" },
      }),
    });
    expect(created.status).toBe(201);
    const ws = gw.store.ensureWorkspace("default");
    const before = gw.store.getBackend(ws.id, "sb")!;
    const nel = "64m\u0085x";
    const zwsp = "dev\u200b1";
    const rlo = "1\u202e0";
    const lone = "dev\uD800";
    const loneLow = "dev\uDC00";
    const pua = "dev\uE000";
    const nonchar = "dev\uFFFF";
    const noncharFdd0 = "dev\uFDD0";
    const bad = [
      { sandbox: { memory: nel } },
      { sandbox: { cpus: rlo } },
      { sandbox: { networkMode: "" } },
      { sandbox: { memory: lone } },
      { sandbox: { cpus: pua } },
      { sandbox: { networkMode: nonchar } },
      { placement: { mode: "central-sandbox", deviceId: "id\u0085" } },
      { placement: { mode: "central-sandbox", deviceId: zwsp } },
      { placement: { mode: "central-sandbox", deviceId: "" } },
      { placement: { mode: "central-sandbox", deviceId: lone } },
      { placement: { mode: "central-sandbox", deviceId: pua } },
      { placement: { mode: "central-sandbox", deviceId: nonchar } },
      { placement: { mode: "central-sandbox", deviceTags: ["ok", "\u200b"] } },
      { placement: { mode: "central-sandbox", deviceTags: [""] } },
      { placement: { mode: "central-sandbox", deviceTags: ["ok", loneLow] } },
      { placement: { mode: "central-sandbox", deviceTags: [noncharFdd0] } },
    ];
    for (const body of bad) {
      const res = await fetch(`${base}/v1/backends/sb`, {
        method: "PATCH",
        headers,
        body: JSON.stringify(body),
      });
      const text = await res.text();
      expect(res.status, text).toBe(400);
      expect(text).not.toContain(nel);
      expect(text).not.toContain(zwsp);
      expect(text).not.toContain(rlo);
      expect(text).not.toContain("\u0085");
      expect(text).not.toContain("\u200b");
      expect(text).not.toContain("\u202e");
      expect(text).not.toContain(lone);
      expect(text).not.toContain(loneLow);
      expect(text).not.toContain(pua);
      expect(text).not.toContain(nonchar);
      expect(text).not.toContain(noncharFdd0);
      expect(text.toLowerCase()).not.toContain("\\ud800");
      expect(text.toLowerCase()).not.toContain("\\udc00");
      expect(text).not.toMatch(/TypeError/);
    }
    const row = gw.store.getBackend(ws.id, "sb")!;
    expect(row.placementJson).toBe(before.placementJson);
    expect(row.sandboxJson).toBe(before.sandboxJson);
    expect(row.placementJson).not.toContain("\u0085");
    expect(row.sandboxJson ?? "").not.toContain("\u0085");
    expect(row.placementJson).not.toContain(pua);
    expect(row.placementJson).not.toContain(nonchar);
    expect(row.sandboxJson ?? "").not.toContain(pua);
    expect(row.sandboxJson ?? "").not.toContain(nonchar);
    const emoji = "dev-\uD83D\uDE00";
    const kept = await fetch(`${base}/v1/backends/sb`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        placement: { mode: "central-sandbox", deviceId: emoji },
      }),
    });
    expect(kept.status).toBe(200);
    const keptRow = gw.store.getBackend(ws.id, "sb")!;
    expect(keptRow.placementJson).toContain(emoji);

    const pool = new UpstreamPool(gw.store);
    const cfg = loadConfig({
      dbPath: join(tmpdir(), "unused-shape.db"),
      masterKeyRaw: master,
      adminToken: admin,
      allowPrivateUrls: true,
    });
    const deps = {
      store: gw.store,
      pool,
      cfg,
      auth: { kind: "admin" as const, workspaceId: ws.id },
      edgeEnabled: false,
    };
    const mcpNel = await handleAdminTool(
      "mf_admin_update_backend",
      { idOrSlug: "sb", sandbox: { memory: nel } },
      deps,
    );
    const mcpNelText = mcpNel.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    expect(mcpNel.isError).toBe(true);
    expect(mcpNelText).toMatch(/memory/);
    expect(mcpNelText).not.toContain(nel);
    expect(mcpNelText).not.toContain("\u0085");
    for (const args of [
      { idOrSlug: "sb", placement: { deviceId: lone } },
      { idOrSlug: "sb", sandbox: { cpus: pua } },
      { idOrSlug: "sb", sandbox: { networkMode: nonchar } },
      { idOrSlug: "sb", placement: { deviceTags: [loneLow, noncharFdd0] } },
    ]) {
      const rejected = await handleAdminTool("mf_admin_update_backend", args, deps);
      const rejectedText = rejected.content
        .map((block) => ("text" in block ? block.text : ""))
        .join("\n");
      expect(rejected.isError, rejectedText).toBe(true);
      expect(rejectedText).not.toContain(lone);
      expect(rejectedText).not.toContain(pua);
      expect(rejectedText).not.toContain(nonchar);
      expect(rejectedText).not.toContain(loneLow);
      expect(rejectedText).not.toContain(noncharFdd0);
      expect(rejectedText.toLowerCase()).not.toContain("\\ud800");
    }
    const afterRejects = gw.store.getBackend(ws.id, "sb")!;
    expect(afterRejects.placementJson).toContain(emoji);
    expect(afterRejects.placementJson).not.toContain(pua);
    expect(afterRejects.placementJson).not.toContain(nonchar);
    expect(afterRejects.sandboxJson ?? "").not.toContain(pua);
    expect(afterRejects.sandboxJson ?? "").not.toContain(nonchar);

    const keyRes = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "ops-wrap", admin: true }),
    });
    const opToken = ((await keyRes.json()) as { key: { token: string } }).key.token;
    const client = new Client({ name: "ops-wrap", version: "1.0.0" }, { capabilities: {} });
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${opToken}` } },
      }),
    );
    const extraVal = "wrapped-extra-placeholder";
    const wrapped = await client.callTool({
      name: "mf_call_tool",
      arguments: {
        name: "mf_admin_update_backend",
        arguments: {
          idOrSlug: "sb",
          env: { STRIPE_SK: STRIPE },
          headers: { "X-Upstream-Sig": SIG },
          extra: extraVal,
          apiKey: KEY,
        },
      },
    });
    const wrappedText = wrapped.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    expect(wrapped.isError).toBe(true);
    expect(wrappedText).not.toContain(STRIPE);
    expect(wrappedText).not.toContain(SIG);
    expect(wrappedText).not.toContain(extraVal);
    expect(wrappedText).not.toContain(KEY);
    const wrappedCreate = await client.callTool({
      name: "mf_call_tool",
      arguments: {
        name: "mf_admin_create_backend",
        arguments: {
          slug: "wrapped",
          env: { STRIPE_SK: STRIPE },
          extra: extraVal,
        },
      },
    });
    expect(wrappedCreate.isError).toBe(true);
    await client.close();
    expect(gw.store.getBackend(ws.id, "wrapped")).toBeNull();

    const blob = JSON.stringify(gw.store.listAudit(ws.id, { limit: 100 }));
    expect(blob).not.toContain(STRIPE);
    expect(blob).not.toContain(SIG);
    expect(blob).not.toContain(extraVal);
    expect(blob).not.toContain(KEY);
    expect(blob).not.toContain(nel);
    expect(blob).not.toContain("\u0085");
    expect(blob).not.toContain("\u200b");
    expect(blob).not.toContain("\u202e");
    expect(blob).not.toContain("STRIPE_SK");
    expect(blob).toContain("[redacted]");
    const listed = await handleAdminTool("mf_admin_list_audit", { limit: 100 }, deps);
    const listedText = listed.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    expect(listedText).not.toContain(STRIPE);
    expect(listedText).not.toContain(SIG);
    expect(listedText).not.toContain(extraVal);
    expect(listedText).not.toContain(KEY);
    expect(listedText).not.toContain("\u0085");
  }, 60_000);

  it("audits every rejected mf_call_tool wrapper as a name and a redacted blob", async () => {
    const gw = await bootGateway();
    const base = gw.url;
    const headers = {
      Authorization: `Bearer ${admin}`,
      "Content-Type": "application/json",
    };
    const keyRes = await fetch(`${base}/v1/keys`, {
      method: "POST",
      headers,
      body: JSON.stringify({ name: "ops-wrap-variants", admin: true }),
    });
    const opToken = ((await keyRes.json()) as { key: { token: string } }).key.token;
    const client = new Client(
      { name: "ops-wrap-variants", version: "1.0.0" },
      { capabilities: {} },
    );
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
        requestInit: { headers: { Authorization: `Bearer ${opToken}` } },
      }),
    );
    const secret = "wrap-variant-placeholder";
    const slack = "wrap-slack-placeholder";
    const header = "wrap-header-placeholder";
    const extra = "wrap-extra-placeholder";
    const note = "wrap-note-placeholder";
    const place = "wrap-placement-placeholder";
    const inner = {
      idOrSlug: "sb",
      env: { STRIPE_SK: secret, SLACK_BOT: slack },
      headers: { "X-Upstream-Sig": header },
      apiKey: KEY,
      extra,
      note: { deep: note },
      placement: { extra: place },
    };
    const calls: Array<{ arguments: Record<string, unknown>; name: string }> = [
      { arguments: { name: "mf_admin_update_backend", arguments: inner }, name: "mf_admin_update_backend" },
      { arguments: { name: "mf_admin_create_backend", arguments: inner }, name: "mf_admin_create_backend" },
      { arguments: { name: "mf_admin_catalog_install", arguments: inner }, name: "mf_admin_catalog_install" },
      { arguments: { name: "  mf_admin_update_backend  ", arguments: inner }, name: "mf_admin_update_backend" },
      { arguments: { name: "\tmf_admin_update_backend\t", arguments: inner }, name: "mf_admin_update_backend" },
      { arguments: { name: "mf_admin_update_backend", arguments: [inner] }, name: "mf_admin_update_backend" },
      { arguments: { name: "mf_admin_update_backend", arguments: secret }, name: "mf_admin_update_backend" },
      {
        arguments: {
          name: "mf_call_tool",
          arguments: { name: "mf_admin_update_backend", arguments: inner },
        },
        name: "mf_call_tool",
      },
      {
        arguments: {
          name: "mf_call_tool",
          arguments: {
            name: "mf_call_tool",
            arguments: {
              name: "mf_call_tool",
              arguments: { name: "mf_admin_update_backend", arguments: inner },
            },
          },
        },
        name: "mf_call_tool",
      },
      {
        arguments: { name: "MF_ADMIN_update_backend", arguments: inner, extra, env: { STRIPE_SK: secret } },
        name: "MF_ADMIN_update_backend",
      },
      {
        arguments: { name: "Mf_Admin_update_backend", arguments: inner, extra },
        name: "Mf_Admin_update_backend",
      },
      {
        arguments: { name: "mf_status", arguments: { env: { STRIPE_SK: secret } }, extra },
        name: "mf_status",
      },
      {
        arguments: { name: { env: { STRIPE_SK: secret }, extra }, arguments: inner },
        name: "[invalid]",
      },
      {
        arguments: { name: "mf_admin_\u0001update_backend", arguments: inner },
        name: "mf_admin_update_backend",
      },
    ];
    for (const call of calls) {
      const result = await client.callTool({
        name: "mf_call_tool",
        arguments: call.arguments,
      });
      const text = result.content
        .map((block) => ("text" in block ? block.text : ""))
        .join("\n");
      expect(result.isError, text).toBe(true);
      expect(text).not.toContain(secret);
      expect(text).not.toContain(slack);
      expect(text).not.toContain(header);
      expect(text).not.toContain(extra);
      expect(text).not.toContain(note);
      expect(text).not.toContain(place);
      expect(text).not.toContain(KEY);
    }
    await client.close();

    const ws = gw.store.ensureWorkspace("default");
    const events = gw.store
      .listAudit(ws.id, { limit: 100 })
      .filter((event) => event.action === "tools/call");
    expect(events).toHaveLength(calls.length);
    const storedNames = events.map((event) => {
      const args = (event.detail as { arguments?: Record<string, unknown> } | null)
        ?.arguments;
      expect(args).toEqual({
        name: expect.any(String),
        arguments: "[redacted]",
      });
      expect(Object.keys(args ?? {}).sort()).toEqual(["arguments", "name"]);
      return String(args?.name);
    });
    const expectedStored = calls.map((call) =>
      /\bmf_[A-Za-z0-9_-]{16,}/.test(call.name) ? "[redacted]" : call.name,
    );
    expect(storedNames.slice().sort()).toEqual(expectedStored.slice().sort());

    const blob = JSON.stringify(gw.store.listAudit(ws.id, { limit: 100 }));
    for (const leaked of [secret, slack, header, extra, note, place, KEY, "SLACK_BOT", "STRIPE_SK"]) {
      expect(blob).not.toContain(leaked);
    }
    expect(gw.store.listApprovals(ws.id, { status: "all", limit: 50 })).toHaveLength(0);

    const pool = new UpstreamPool(gw.store);
    const cfg = loadConfig({
      dbPath: join(tmpdir(), "unused-wrap.db"),
      masterKeyRaw: master,
      adminToken: admin,
      allowPrivateUrls: true,
    });
    const listed = await handleAdminTool(
      "mf_admin_list_audit",
      { limit: 100 },
      {
        store: gw.store,
        pool,
        cfg,
        auth: { kind: "admin" as const, workspaceId: ws.id },
        edgeEnabled: false,
      },
    );
    const listedText = listed.content
      .map((block) => ("text" in block ? block.text : ""))
      .join("\n");
    for (const leaked of [secret, slack, header, extra, note, place, KEY]) {
      expect(listedText).not.toContain(leaked);
    }
  }, 60_000);
});
