/**
 * Issue #74: an agent key with secrets:project:write can generate, upload, and
 * bind secrets for its own project. The value never appears in a tool response,
 * an audit detail, or a log line.
 */
import { chmodSync, closeSync, mkdtempSync, openSync, rmSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { createServer } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  loadConfig,
  parseProjectSecretProductionApproval,
  parseProjectSecretQuota,
  parseSecretUploadTtl,
} from "../src/config.js";
import { parseProtectedTargets } from "../src/secrets/protected.js";
import { estimateImportBits } from "../src/secrets/project-scope.js";
import { toolAllowedByScopes } from "../src/types.js";
import { startServer, type RunningServer } from "../src/server.js";

const dirs: string[] = [];
let gw: RunningServer | null = null;
afterEach(async () => {
  await gw?.close();
  gw = null;
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function write0400(path: string, body: Buffer) {
  const fd = openSync(path, "wx", 0o400);
  try { writeSync(fd, body); } finally { closeSync(fd); }
  chmodSync(path, 0o400);
}

async function mcpText(url: string, token: string, name: string, args: Record<string, unknown>): Promise<{ error: boolean; text: string }> {
  const client = new Client({ name: "project-secrets", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${url}/mcp`), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  try {
    const result = await client.callTool({ name, arguments: args });
    const text = Array.isArray(result.content) ? result.content.map((p) => ("text" in p ? String(p.text) : "")).join("\n") : "";
    return { error: result.isError === true, text };
  } finally {
    await client.close();
  }
}

interface SetupOpts {
  quota?: number;
  productionApproval?: boolean;
  protectedRaw?: string;
}

async function setup(opts: SetupOpts = {}) {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-projsec-"));
  dirs.push(dir);
  const kekFile = join(dir, "kek");
  write0400(kekFile, randomBytes(32));
  const master = Buffer.alloc(32, 7).toString("base64");
  const cfg = loadConfig({
    dbPath: join(dir, "t.db"),
    masterKeyRaw: master,
    adminToken: "break-glass-placeholder",
    host: "localhost",
    allowPrivateUrls: false,
    workspaceName: "default",
    kekFile,
    kekProvider: "file",
    protectedTargets: parseProtectedTargets(opts.protectedRaw ?? "cmp_protected"),
    projectSecretQuota: opts.quota,
    projectSecretProductionApproval: opts.productionApproval,
  });
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, "localhost", resolve));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  const g = await startServer(cfg);
  gw = g;
  const store = g.store;
  const ws = store.ensureWorkspace("default");
  const chen = store.identity.bootstrapWorkspace(ws.id, { name: "chen", owner: "chen" });
  store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'app')`).run(chen);
  store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'other')`).run(chen);
  const humanKey = store.identity.createKey({ agentId: chen, createdBy: chen, projects: ["app", "other"] });
  const bot = store.identity.createAgent({
    workspaceId: ws.id, name: "bot", owner: "chen", kind: "grokbot", projects: ["app"], createdBy: chen,
  });
  const botKey = store.identity.createKey({ agentId: bot, createdBy: chen, projects: ["app"] });
  const otherBot = store.identity.createAgent({
    workspaceId: ws.id, name: "otherbot", owner: "chen", kind: "grokbot", projects: ["app"], createdBy: chen,
  });
  const otherKey = store.identity.createKey({ agentId: otherBot, createdBy: chen, projects: ["app"] });
  const envState = { value: "KEEP_ME=1\n" };
  g.pool.callTool = async (_ws: string, name: string, args: { env?: string }) => {
    if (name === "cmp__compose-one") {
      return { content: [{ type: "text", text: JSON.stringify({ env: envState.value }) }], isError: false, sent: true } as never;
    }
    if (name === "cmp__compose-saveEnvironment") {
      envState.value = String(args.env ?? "");
      return { content: [{ type: "text", text: "ok" }], isError: false, sent: true } as never;
    }
    return { content: [{ type: "text", text: "nope" }], isError: true, sent: false } as never;
  };
  return { g, store, ws, chen, humanToken: humanKey.token, botToken: botKey.token, botKeyId: botKey.keyId, otherToken: otherKey.token, envState };
}

function flag(store: Awaited<ReturnType<typeof setup>>["store"], keyId: string): number {
  const row = store.db.prepare(`SELECT secrets_project_write AS n FROM mcpflow_api_key WHERE id = ?`).get(keyId) as { n: number };
  return row.n;
}

function storedText(store: Awaited<ReturnType<typeof setup>>["store"]): string {
  const audits = store.db.prepare(`SELECT action, ifnull(detail_json, '') AS detail_json FROM audit_events`).all();
  const secrets = store.db.prepare(`SELECT name, ifnull(description, '') AS description, generator_json, type FROM mcpflow_secret`).all();
  const uploads = store.db.prepare(`SELECT name, ifnull(description, '') AS description, token_hash FROM mcpflow_secret_upload`).all();
  const approvals = store.db.prepare(`SELECT action, ref, state FROM mcpflow_project_secret_approval`).all();
  return JSON.stringify({ audits, secrets, uploads, approvals });
}

function actions(store: Awaited<ReturnType<typeof setup>>["store"]): string[] {
  return (store.db.prepare(`SELECT action FROM audit_events`).all() as Array<{ action: string }>).map((row) => row.action);
}

async function withLogs<T>(fn: () => Promise<T>): Promise<{ result: T; logs: string }> {
  const chunks: string[] = [];
  const methods = ["log", "info", "warn", "error", "debug"] as const;
  const prev = Object.fromEntries(methods.map((name) => [name, console[name]])) as Record<(typeof methods)[number], (...args: unknown[]) => void>;
  for (const name of methods) {
    console[name] = (...args: unknown[]) => {
      chunks.push(args.map((part) => (typeof part === "string" ? part : JSON.stringify(part))).join(" "));
      prev[name](...args);
    };
  }
  try {
    const result = await fn();
    return { result, logs: chunks.join("\n") };
  } finally {
    for (const name of methods) console[name] = prev[name] as never;
  }
}

describe("project secret scope", () => {
  it("is off by default and refuses another project, a protected target, and a second key", async () => {
    const s = await setup();
    expect(flag(s.store, s.botKeyId)).toBe(0);
    const denied = await mcpText(s.g.url, s.botToken, "mf_project_secret_create", { name: "mailbox", type: "token" });
    expect(denied.error).toBe(true);
    expect(denied.text).toContain("secrets:project:write");
    expect(actions(s.store)).toContain("project_secret.denied");

    const grant = await mcpText(s.g.url, s.humanToken, "mf_admin_secret_scope_set", { key_id: s.botKeyId, enabled: true });
    expect(grant.error).toBe(false);
    expect(flag(s.store, s.botKeyId)).toBe(1);
    const botAdmin = await mcpText(s.g.url, s.botToken, "mf_admin_secret_scope_set", { key_id: s.botKeyId, enabled: true });
    expect(botAdmin.error).toBe(true);

    const cross = await mcpText(s.g.url, s.botToken, "mf_project_secret_create", { project: "other", name: "mailbox", type: "token" });
    expect(cross.error).toBe(true);
    expect(cross.text).toContain("not permitted");

    const protectedReg = await mcpText(s.g.url, s.humanToken, "mf_admin_env_target_register", {
      project: "app", backend: "cmp", compose_id: "cmp_protected", tier: "DEVELOPMENT",
    });
    expect(protectedReg.error).toBe(true);
    expect(protectedReg.text).toContain("protected target");
    const protectedSet = await mcpText(s.g.url, s.botToken, "mf_env_keys_set", {
      backend: "cmp", compose_id: "cmp_protected", project: "app", values: { X: "secret://app/nope" },
    });
    expect(protectedSet.error).toBe(true);
    expect(protectedSet.text).toContain("protected target");

    const stillOff = await mcpText(s.g.url, s.otherToken, "mf_project_secret_create", { name: "mailbox", type: "token" });
    expect(stillOff.error).toBe(true);
    expect(stillOff.text).toContain("secrets:project:write");
  });

  it("generates, lists, rotates, and binds without returning or logging the value", async () => {
    const s = await setup();
    await mcpText(s.g.url, s.humanToken, "mf_admin_secret_scope_set", { key_id: s.botKeyId, enabled: true });
    await mcpText(s.g.url, s.humanToken, "mf_admin_env_target_register", {
      project: "app", backend: "cmp", compose_id: "cmp_test_1", tier: "DEVELOPMENT",
    });
    const watched = await withLogs(async () => {
      const created = await mcpText(s.g.url, s.botToken, "mf_project_secret_create", {
        name: "mailbox",
        type: "token",
        params: { encoding: "hex", bytes: 16, entries: ["mailbox", "hook"] },
      });
      const listed = await mcpText(s.g.url, s.botToken, "mf_project_secret_list", { project: "app" });
      const rotated = await mcpText(s.g.url, s.botToken, "mf_project_secret_rotate", { ref: "secret://app/mailbox" });
      const plain = await mcpText(s.g.url, s.botToken, "mf_env_keys_set", {
        backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { TOKEN: "not-a-ref" },
      });
      const bound = await mcpText(s.g.url, s.botToken, "mf_env_keys_set", {
        backend: "cmp", compose_id: "cmp_test_1", project: "app", values: { TOKEN: "secret://app/mailbox" },
      });
      const otherTarget = await mcpText(s.g.url, s.botToken, "mf_env_keys_set", {
        backend: "cmp", compose_id: "cmp_test_2", project: "app", values: { TOKEN: "secret://app/mailbox" },
      });
      return { created, listed, rotated, plain, bound, otherTarget };
    });
    const { created, listed, rotated, plain, bound, otherTarget } = watched.result;
    expect(created.error).toBe(false);
    expect(rotated.error).toBe(false);
    expect(JSON.parse(rotated.text).version).toBe(2);
    expect(plain.error).toBe(true);
    expect(plain.text).toContain("secret refs");
    expect(bound.error).toBe(false);
    expect(otherTarget.error).toBe(true);
    const buf = s.store.secrets.openForTest({ workspaceId: s.ws.id, project: "app", name: "mailbox", version: 2 });
    const value = buf.toString("utf8");
    buf.fill(0);
    const parsed = JSON.parse(value) as Record<string, string>;
    expect(parsed.mailbox).toMatch(/^[0-9a-f]{32}$/);
    expect(s.envState.value).toContain(parsed.mailbox);
    const visible = [created.text, listed.text, rotated.text, bound.text, watched.logs, storedText(s.store)].join("\n");
    expect(visible).not.toContain(parsed.mailbox);
    expect(visible).not.toContain(parsed.hook);
    expect(actions(s.store)).toEqual(expect.arrayContaining(["project_secret.create", "project_secret.rotate", "project_secret.bind"]));
    const grants = s.store.db.prepare(`SELECT count(*) AS n FROM mcpflow_secret_grant`).get() as { n: number };
    expect(grants.n).toBe(0);
  });

  it("accepts an upload once, refuses a second use and an expired link, and does not log the value", async () => {
    const s = await setup();
    await mcpText(s.g.url, s.humanToken, "mf_admin_secret_scope_set", { key_id: s.botKeyId, enabled: true });
    const issued = await mcpText(s.g.url, s.botToken, "mf_project_secret_upload_link", { name: "vendor" });
    expect(issued.error).toBe(false);
    const body = JSON.parse(issued.text) as { ticket_id: string; upload_url: string };
    const token = decodeURIComponent(body.upload_url.slice(body.upload_url.indexOf("#") + 1));
    const value = "Uploaded-Value-Not-Real-7kQ2";
    expect(estimateImportBits(value)).toBeGreaterThanOrEqual(64);
    const post = (ticket: string, uploadToken: string, uploadValue: string) => fetch(`${s.g.url}/secret-uploads/${ticket}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: uploadToken, value: uploadValue }),
    });
    const watched = await withLogs(async () => {
      const weak = await post(body.ticket_id, token, "short-key");
      const weakBody = await weak.json() as { error?: string };
      const ok = await post(body.ticket_id, token, value);
      const okBody = await ok.json() as { ref?: string; value?: string };
      const again = await post(body.ticket_id, token, value);
      return { weakStatus: weak.status, weakBody, okStatus: ok.status, okBody, againStatus: again.status };
    });
    expect(watched.result.weakStatus).toBe(400);
    expect(JSON.stringify(watched.result.weakBody)).not.toContain(value);
    expect(watched.result.okStatus).toBe(200);
    expect(watched.result.okBody.ref).toBe("secret://app/vendor");
    expect(watched.result.okBody.value).toBeUndefined();
    expect(JSON.stringify(watched.result.okBody)).not.toContain(value);
    expect(watched.result.againStatus).toBe(409);
    const expired = await mcpText(s.g.url, s.botToken, "mf_project_secret_upload_link", { name: "vendor2" });
    const expiredBody = JSON.parse(expired.text) as { ticket_id: string; upload_url: string };
    const expiredToken = decodeURIComponent(expiredBody.upload_url.slice(expiredBody.upload_url.indexOf("#") + 1));
    s.store.db.prepare(`UPDATE mcpflow_secret_upload SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?`).run(expiredBody.ticket_id);
    const late = await post(expiredBody.ticket_id, expiredToken, value);
    expect(late.status).toBe(400);
    const lateBody = await late.json() as { error?: string };
    expect(lateBody.error).toContain("expired");
    const opened = s.store.secrets.openForTest({ workspaceId: s.ws.id, project: "app", name: "vendor", version: 1 });
    expect(opened.toString("utf8")).toBe(value);
    opened.fill(0);
    const visible = [issued.text, watched.logs, storedText(s.store), JSON.stringify(lateBody)].join("\n");
    expect(visible).not.toContain(value);
    expect(actions(s.store)).toEqual(expect.arrayContaining(["project_secret.upload_issued", "project_secret.upload_consumed"]));
    const page = await fetch(`${s.g.url}/secret-uploads/${expiredBody.ticket_id}`);
    expect(page.status).toBe(404);
    expect(await page.text()).not.toContain(value);
  });

  it("holds a PRODUCTION bind until a human admin approves, and applies immediately when the gate is off", async () => {
    const gated = await setup({ productionApproval: true });
    await mcpText(gated.g.url, gated.humanToken, "mf_admin_secret_scope_set", { key_id: gated.botKeyId, enabled: true });
    await mcpText(gated.g.url, gated.humanToken, "mf_admin_env_target_register", {
      project: "app", backend: "cmp", compose_id: "cmp_prod", tier: "PRODUCTION",
    });
    const created = await mcpText(gated.g.url, gated.botToken, "mf_project_secret_create", { name: "db", type: "token", params: { bytes: 16 } });
    expect(created.error).toBe(false);
    const pending = await mcpText(gated.g.url, gated.botToken, "mf_env_keys_set", {
      backend: "cmp", compose_id: "cmp_prod", project: "app", values: { DB: "secret://app/db" },
    });
    expect(pending.error).toBe(false);
    const pendingBody = JSON.parse(pending.text) as { pending: boolean; approvals: Array<{ approval_id: string }> };
    expect(pendingBody.pending).toBe(true);
    expect(gated.envState.value).toBe("KEEP_ME=1\n");
    const buf = gated.store.secrets.openForTest({ workspaceId: gated.ws.id, project: "app", name: "db", version: 1 });
    const value = buf.toString("utf8");
    buf.fill(0);
    expect(pending.text).not.toContain(value);
    const decided = await mcpText(gated.g.url, gated.humanToken, "mf_admin_project_secret_approval_decide", {
      approval_id: pendingBody.approvals[0]!.approval_id, decision: "approve",
    });
    expect(decided.error).toBe(false);
    expect(decided.text).not.toContain(value);
    expect(gated.envState.value).toContain(value);
    expect(storedText(gated.store)).not.toContain(value);
    expect(actions(gated.store)).toContain("project_secret.approval_decided");

    await gw?.close();
    gw = null;
    const open = await setup({ productionApproval: false });
    await mcpText(open.g.url, open.humanToken, "mf_admin_secret_scope_set", { key_id: open.botKeyId, enabled: true });
    await mcpText(open.g.url, open.humanToken, "mf_admin_env_target_register", {
      project: "app", backend: "cmp", compose_id: "cmp_prod", tier: "PRODUCTION",
    });
    await mcpText(open.g.url, open.botToken, "mf_project_secret_create", { name: "db", type: "token", params: { bytes: 16 } });
    const direct = await mcpText(open.g.url, open.botToken, "mf_env_keys_set", {
      backend: "cmp", compose_id: "cmp_prod", project: "app", values: { DB: "secret://app/db" },
    });
    expect(direct.error).toBe(false);
    expect(direct.text).not.toContain("pending");
    const directBuf = open.store.secrets.openForTest({ workspaceId: open.ws.id, project: "app", name: "db", version: 1 });
    const directValue = directBuf.toString("utf8");
    directBuf.fill(0);
    expect(open.envState.value).toContain(directValue);
    expect(direct.text).not.toContain(directValue);
  });

  it("refuses a prefix-restricted key until mf_project_secret_ is allowed, and rejects bad env values", () => {
    expect(toolAllowedByScopes("mf_project_secret_create", { toolPrefixAllowlist: ["other__"] })).toBe(false);
    expect(toolAllowedByScopes("mf_project_secret_create", { toolPrefixAllowlist: ["mf_project_secret_"] })).toBe(true);
    expect(toolAllowedByScopes("mf_project_secret_create", null)).toBe(true);
    expect(parseProjectSecretQuota(undefined)).toBe(32);
    expect(parseSecretUploadTtl(undefined)).toBe(900);
    expect(parseProjectSecretProductionApproval(undefined)).toBe(true);
    expect(() => parseProjectSecretQuota("nope")).toThrow(/MCP_FLOW_PROJECT_SECRET_QUOTA/);
    expect(() => parseSecretUploadTtl("1")).toThrow(/MCP_FLOW_SECRET_UPLOAD_TTL_SEC/);
    expect(() => parseProjectSecretProductionApproval("maybe")).toThrow(/MCP_FLOW_PROJECT_SECRET_PRODUCTION_APPROVAL/);
  });

  it("stops at the per-project quota", async () => {
    const s = await setup({ quota: 1 });
    await mcpText(s.g.url, s.humanToken, "mf_admin_secret_scope_set", { key_id: s.botKeyId, enabled: true });
    const first = await mcpText(s.g.url, s.botToken, "mf_project_secret_create", { name: "one", type: "uuid" });
    expect(first.error).toBe(false);
    const second = await mcpText(s.g.url, s.botToken, "mf_project_secret_create", { name: "two", type: "uuid" });
    expect(second.error).toBe(true);
    expect(second.text).toContain("quota");
    expect(actions(s.store)).toContain("project_secret.denied");
  });
});
