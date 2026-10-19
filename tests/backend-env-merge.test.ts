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

    const nested = {
      Env: { STRIPE_SK: STRIPE },
      HEADERS: { "X-Upstream-Sig": SIG },
      placement: { mode: "remote", env: { STRIPE_SK: STRIPE } },
      sandbox: { memory: "512m", headers: { "X-Upstream-Sig": SIG } },
    };
    const nestedRedacted = redactAdminToolAuditArgs("mf_admin_update_backend", nested);
    expect(nestedRedacted).not.toBe(nested);
    expect(nestedRedacted.Env).toEqual({ STRIPE_SK: "[redacted]" });
    expect(nestedRedacted.HEADERS).toEqual({ "X-Upstream-Sig": "[redacted]" });
    expect(nestedRedacted.placement).toEqual({
      mode: "remote",
      env: { STRIPE_SK: "[redacted]" },
    });
    expect(nestedRedacted.sandbox).toEqual({
      memory: "512m",
      headers: { "X-Upstream-Sig": "[redacted]" },
    });
    expect((nested.placement as { env: { STRIPE_SK: string } }).env.STRIPE_SK).toBe(STRIPE);
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
    const caseValue = "case-env-placeholder";
    const nestedCall = await client.callTool({
      name: "mf_admin_update_backend",
      arguments: {
        idOrSlug: "remote",
        Env: { STRIPE_SK: caseValue },
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
    expect(blob).not.toContain("case-env-placeholder");
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
