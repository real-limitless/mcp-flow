/** Seed helpers for staged-migration tests (fake ids/hashes only; no real secrets). */
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { applyConnectionPragmas, runMigrations } from "../../src/db/migrations/index.js";

export const hex = (n = 12) => randomBytes(n).toString("hex");
export const mkid = (p: string) => `${p}_${hex()}`;
export const iso = (offsetMs = 0) => new Date(Date.now() + offsetMs).toISOString();
export const DAY = 86_400_000;

export function openAt(upTo?: string): DatabaseSync {
  const d = new DatabaseSync(":memory:");
  applyConnectionPragmas(d);
  runMigrations(d, upTo);
  return d;
}

export function seedWorkspace(d: DatabaseSync): { ws: string; chen: string } {
  const ws = mkid("ws");
  const chen = mkid("agt");
  d.exec("BEGIN IMMEDIATE;");
  d.prepare(`INSERT INTO mcpflow_workspace (id, owner_principal_id) VALUES (?, ?)`).run(ws, chen);
  d.prepare(`INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by) VALUES (?, ?, 'chen', 'chen', 'human', 1, NULL)`).run(chen, ws);
  d.exec("COMMIT;");
  return { ws, chen };
}

export function seedAgent(d: DatabaseSync, ws: string, name: string, createdBy: string, kind = "grokbot"): string {
  const a = mkid("agt");
  d.prepare(`INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by) VALUES (?, ?, ?, 'chen', ?, 0, ?)`).run(a, ws, name, kind, createdBy);
  return a;
}

export function seedKey(d: DatabaseSync, agent: string, createdBy: string): string {
  const k = mkid("key");
  d.prepare(
    `INSERT INTO mcpflow_api_key (id, agent_id, prefix, secret_hash, status, expires_at, created_by) VALUES (?, ?, ?, ?, 'active', ?, ?)`,
  ).run(k, agent, randomBytes(9).toString("base64url").slice(0, 12), `sha256-pepper$v1$${hex(32)}`, iso(90 * DAY), createdBy);
  return k;
}

export function seedSession(d: DatabaseSync, agent: string, key: string, prefix = "mf_sess_"): string {
  const s = `${prefix}${hex()}`;
  d.prepare(`INSERT INTO mcpflow_session (id, token_hash, agent_id, key_id, project_id, expires_at) VALUES (?, ?, ?, ?, 'gb_devops', ?)`).run(
    s, `sha256-pepper$v1$${hex(32)}`, agent, key, iso(DAY),
  );
  return s;
}

export function seedPending(
  d: DatabaseSync,
  o: { ws: string; agent: string; key: string; approvers: string[]; session?: string | null; tool?: string },
): string {
  const pc = mkid("pc");
  d.prepare(
    `INSERT INTO mcpflow_pending_call (id, call_id, workspace_id, agent_id, key_id, session_id, project_id,
       backend_slug, tool, args_redacted, args_ciphertext, args_key_ref, args_hash, matched_rules,
       approvers, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, 'gb_devops', 'gh-repos-shell', ?, '{"command":"ls"}', ?, 'dev-v1', ?, '[]', ?, ?, ?)`,
  ).run(pc, `call_${hex()}`, o.ws, o.agent, o.key, o.session ?? null, o.tool ?? "run_command", Buffer.from("ciphertext"), hex(32),
    JSON.stringify(o.approvers), iso(), iso(300_000));
  return pc;
}

export function fkClean(d: DatabaseSync): unknown[] {
  return d.prepare("PRAGMA foreign_key_check").all();
}
export function integrityOk(d: DatabaseSync): boolean {
  const r = d.prepare("PRAGMA integrity_check").all() as Array<Record<string, string>>;
  return r.length === 1 && Object.values(r[0]!)[0] === "ok";
}
