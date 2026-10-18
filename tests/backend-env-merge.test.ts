import { readFileSync } from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { backendUpdateAuditDetail } from "../src/audit/backend-update.js";
import { sanitizeForAudit } from "../src/audit/sanitize.js";
import { loadConfig } from "../src/config.js";
import { applyEnvPatch } from "../src/db/env-patch.js";
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
    const detail = backendUpdateAuditDetail(
      {
        title: "remote",
        transport: "streamable-http",
        url: "https://example.com/mcp",
        image: null,
        enabled: true,
        commandJson: null,
        placementJson: JSON.stringify({ mode: "remote" }),
        sandboxJson: null,
        toolAllowlistJson: null,
        env: current,
        headerNames: ["Authorization"],
      },
      input,
    );
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

    const before = gw.store.getBackend(gw.store.ensureWorkspace("default").id, "remote")!;
    const snap = gw.store.backendUpdateSnapshot(before);
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
      sanitizeForAudit(backendUpdateAuditDetail(snap, patchBody)),
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
    const before = store.getBackend(ws.id, "remote")!;
    const snap = store.backendUpdateSnapshot(before);
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
        ...backendUpdateAuditDetail(snap, patch),
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
      "--token",
      "replace-with-device-token",
      "--url",
      "https://mcp-flow.example",
    ]);
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
  });
});
