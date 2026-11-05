/** Secrets A1: call_payload insert, encrypt, purge, and the policy path keeping secret://. */
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  decryptCallPayload,
  insertCallPayload,
  prepareCallPayload,
  purgeCallPayloads,
  readCallPayload,
} from "../src/audit/call-payload.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer } from "../src/policy/enforcer.js";
import type { CallContext } from "../src/policy/engine.js";
import { openAt, seedAgent, seedWorkspace } from "./helpers/migration-seed.js";

const keys = derivePolicyKeys("call-payload-unit");

describe("call payload storage", () => {
  it("encrypts under audit-enc with AAD, refuses update and delete, and purges only the payload", () => {
    const d = openAt();
    const { ws, chen } = seedWorkspace(d);
    const bot = seedAgent(d, ws, "bot", chen);
    const callId = "call_payload_unit";
    d.prepare(
      `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, policy_decision, actor) VALUES ('decision', ?, ?, 'allow', ?)`,
    ).run(callId, ws, chen);
    const body = { api_key: "super-secret-value", note: "secret://proj/db@v1", title: "visible" };
    const prepared = prepareCallPayload(keys, "request", body, "echo");
    insertCallPayload(d, keys, {
      callId,
      phase: "request",
      workspaceId: ws,
      red: prepared.red,
      createdAt: "2020-01-01T00:00:00.000Z",
    });
    const row = d.prepare(`SELECT ciphertext FROM mcpflow_call_payload WHERE call_id = ?`).get(callId) as { ciphertext: Uint8Array };
    expect(Buffer.from(row.ciphertext).toString("utf8")).not.toContain("super-secret-value");
    const plain = decryptCallPayload(keys.auditEnc, callId, "request", row.ciphertext) as { note: string; title: string; api_key: string };
    expect(plain.api_key).toBe("[redacted]");
    expect(plain.note).toBe("secret://proj/db@v1");
    expect(plain.title).toBe("visible");
    expect(() => decryptCallPayload(keys.auditEnc, callId, "result", row.ciphertext)).toThrow();
    expect(() => d.prepare(`UPDATE mcpflow_call_payload SET byte_len = 1 WHERE call_id = ?`).run(callId)).toThrow(/insert-only/);
    expect(() => d.prepare(`DELETE FROM mcpflow_call_payload WHERE call_id = ?`).run(callId)).toThrow(/maintenance-only/);

    const dry = purgeCallPayloads(d, { workspaceId: ws, actor: chen, before: "2024-01-01T00:00:00.000Z" });
    expect(dry).toMatchObject({ dryRun: true, rows: 1 });
    expect(d.prepare(`SELECT count(*) AS n FROM mcpflow_call_payload`).get()).toEqual({ n: 1 });
    expect(() => purgeCallPayloads(d, { workspaceId: ws, actor: bot, before: "2024-01-01T00:00:00.000Z", execute: true })).toThrow(/human admin/);
    const done = purgeCallPayloads(d, { workspaceId: ws, actor: chen, before: "2024-01-01T00:00:00.000Z", execute: true });
    expect(done.rows).toBe(1);
    expect(d.prepare(`SELECT count(*) AS n FROM mcpflow_call_payload`).get()).toEqual({ n: 0 });
    expect(
      d.prepare(`SELECT count(*) AS n FROM mcpflow_call_audit WHERE event_type = 'decision'`).get(),
    ).toEqual({ n: 1 });
    const life = d.prepare(`SELECT lifecycle_action FROM mcpflow_call_audit WHERE event_type = 'lifecycle'`).get() as { lifecycle_action: string };
    expect(life.lifecycle_action).toBe("payload_purge");
  });

  it("readCallPayload decrypts for an active human admin and records payload_read", () => {
    const d = openAt();
    const { ws, chen } = seedWorkspace(d);
    const callId = "call_payload_read";
    d.prepare(
      `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, policy_decision, actor) VALUES ('decision', ?, ?, 'allow', ?)`,
    ).run(callId, ws, chen);
    const prepared = prepareCallPayload(keys, "request", { title: "visible" }, "echo");
    insertCallPayload(d, keys, { callId, phase: "request", workspaceId: ws, red: prepared.red });
    const out = readCallPayload(d, keys, { workspaceId: ws, callId, phase: "request", actor: chen });
    expect(out.body).toEqual({ title: "visible" });
    expect(
      d.prepare(`SELECT lifecycle_action FROM mcpflow_call_audit WHERE event_type = 'lifecycle'`).get(),
    ).toEqual({ lifecycle_action: "payload_read" });
  });
});

describe("policy path keeps secret:// and scrubs the stored result only", () => {
  it("stores the ref in the request payload and returns the live result unchanged", async () => {
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db);
    const ws = "ws_" + "c".repeat(24);
    const dir = new AgentDirectory(db, keys);
    const chen = dir.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
    const bot = dir.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["gb_devops"], createdBy: chen });
    const botKey = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
    const id = `rule_${randomBytes(12).toString("hex")}`;
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, ws, chen);
    db.prepare(
      `INSERT INTO mcpflow_policy_rule_version (rule_id, version, priority, description, match_agents, match_projects,
         match_backends, match_tools, match_args, effect, created_by)
       VALUES (?,1,100,'allow','["*"]','["*"]','["*"]','["*"]','[]','allow',?)`,
    ).run(id, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version = 1 WHERE id = ?`).run(id);
    db.exec("COMMIT;");
    const pe = new PolicyEnforcer({ db, keys });
    const ctx: CallContext = {
      workspaceId: ws,
      agentId: bot,
      agentName: "bot",
      keyId: botKey,
      keyPrefix: null,
      sessionId: null,
      projectId: "gb_devops",
      backendSlug: "gh",
      tool: "echo",
      qualifiedTool: "gh__echo",
      placement: "remote",
      deviceId: null,
    };
    const live: CallToolResult = { content: [{ type: "text", text: "Bearer abcdefghijklmnop" }] };
    const result = await pe.enforce({
      ctx,
      args: { note: "secret://proj/db@v1", token: "super-secret-value" },
      dispatch: async () => live,
    });
    expect(result).toBe(live);
    const blob = db.prepare(`SELECT ciphertext FROM mcpflow_call_payload WHERE phase = 'request'`).get() as { ciphertext: Uint8Array };
    const stored = decryptCallPayload(keys.auditEnc, String((db.prepare(`SELECT call_id FROM mcpflow_call_payload WHERE phase = 'request'`).get() as { call_id: string }).call_id), "request", blob.ciphertext) as { note: string; token: string };
    expect(stored.note).toBe("secret://proj/db@v1");
    expect(stored.token).toBe("[redacted]");
    const resultBlob = db.prepare(`SELECT ciphertext, call_id FROM mcpflow_call_payload WHERE phase = 'result'`).get() as { ciphertext: Uint8Array; call_id: string };
    const storedResult = JSON.stringify(decryptCallPayload(keys.auditEnc, resultBlob.call_id, "result", resultBlob.ciphertext));
    expect(storedResult).not.toContain("abcdefghijklmnop");
    expect(storedResult).toContain("Bearer [redacted]");
    db.close();
  });
});
