import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { beforeEach, describe, expect, it } from "vitest";
import {
  MIGRATIONS,
  applyConnectionPragmas,
  runMigrations,
} from "../src/db/migrations/index.js";
import { claimPendingDispatch } from "../src/db/pending-dispatch.js";

const hex = () => randomBytes(12).toString("hex");
const id = (p: string) => `${p}_${hex()}`;
const iso = (offsetMs = 0) => new Date(Date.now() + offsetMs).toISOString();
const DAY = 86_400_000;

let db: DatabaseSync;
let ws: string;
let chen: string;
let bot: string;
let bot2: string;

function open(): DatabaseSync {
  const d = new DatabaseSync(":memory:");
  applyConnectionPragmas(d);
  runMigrations(d);
  return d;
}

function insertAgent(
  d: DatabaseSync,
  o: { id?: string; ws: string; name: string; kind?: string; admin?: number; createdBy?: string | null },
): string {
  const aid = o.id ?? id("agt");
  d.prepare(
    `INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by)
     VALUES (?, ?, ?, 'chen', ?, ?, ?)`,
  ).run(aid, o.ws, o.name, o.kind ?? "grokbot", o.admin ?? 0, o.createdBy ?? null);
  return aid;
}

function bootstrap(d: DatabaseSync): { ws: string; chen: string } {
  const w = id("ws");
  const c = id("agt");
  d.exec("BEGIN IMMEDIATE;");
  d.prepare(`INSERT INTO mcpflow_workspace (id, owner_principal_id) VALUES (?, ?)`).run(w, c);
  insertAgent(d, { id: c, ws: w, name: "chen", kind: "human", admin: 1 });
  d.exec("COMMIT;");
  return { ws: w, chen: c };
}

function insertKey(
  d: DatabaseSync,
  agent: string,
  o: { status?: string; expiresAt?: string; pred?: string | null } = {},
): string {
  const kid = id("key");
  d.prepare(
    `INSERT INTO mcpflow_api_key (id, agent_id, prefix, secret_hash, status, predecessor_key_id, expires_at, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    kid,
    agent,
    randomBytes(9).toString("base64url").slice(0, 12),
    `sha256-pepper$v1$${randomBytes(32).toString("hex")}`,
    o.status ?? "active",
    o.pred ?? null,
    o.expiresAt ?? iso(90 * DAY),
    chen,
  );
  return kid;
}

function insertSession(d: DatabaseSync, agent: string, key: string, expiresAt = iso(DAY)): string {
  const sid = `sess_${hex()}`; // 0009: new ids are sess_ only; token_hash is a hash, never a token
  d.prepare(
    `INSERT INTO mcpflow_session (id, token_hash, agent_id, key_id, project_id, expires_at)
     VALUES (?, ?, ?, ?, 'gb_devops', ?)`,
  ).run(sid, `sha256-pepper$v1$${randomBytes(32).toString("hex")}`, agent, key, expiresAt);
  return sid;
}

function insertPending(
  d: DatabaseSync,
  o: { agent: string; key: string; approvers?: string[]; createdAt?: string; expiresAt?: string },
): string {
  const pc = id("pc");
  d.prepare(
    `INSERT INTO mcpflow_pending_call (id, call_id, workspace_id, agent_id, key_id, project_id,
       backend_slug, tool, args_redacted, args_ciphertext, args_key_ref, args_hash, matched_rules,
       approvers, created_at, expires_at)
     VALUES (?, ?, ?, ?, ?, 'gb_devops', 'gh-repos-shell', 'run_command', '{"command":"ls"}', ?, 'dev-v1',
       ?, '[]', ?, ?, ?)`,
  ).run(
    pc,
    `call_${hex()}`,
    ws,
    o.agent,
    o.key,
    Buffer.from("ciphertext"),
    hex(),
    JSON.stringify(o.approvers ?? [chen]),
    o.createdAt ?? iso(),
    o.expiresAt ?? iso(300_000),
  );
  return pc;
}

function decide(d: DatabaseSync, pc: string, status: string, by: string | null) {
  return d
    .prepare(
      `UPDATE mcpflow_pending_call SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending'`,
    )
    .run(status, by, iso(), pc);
}

function audit(d: DatabaseSync, cols: Record<string, unknown>) {
  const keys = Object.keys(cols);
  d.prepare(
    `INSERT INTO mcpflow_call_audit (${keys.join(",")}) VALUES (${keys.map(() => "?").join(",")})`,
  ).run(...(Object.values(cols) as never[]));
}

beforeEach(() => {
  db = open();
  ({ ws, chen } = bootstrap(db));
  bot = insertAgent(db, { ws, name: "grokbot-backend", createdBy: chen });
  bot2 = insertAgent(db, { ws, name: "grokbot-devops", createdBy: chen });
});

describe("connection and runner", () => {
  it("sets the required pragmas", () => {
    const fk = db.prepare("PRAGMA foreign_keys").get() as Record<string, number>;
    const bt = db.prepare("PRAGMA busy_timeout").get() as Record<string, number>;
    expect(Object.values(fk)[0]).toBe(1);
    expect(Object.values(bt)[0]).toBe(5000);
  });

  it("is idempotent and records every migration", () => {
    expect(runMigrations(db)).toEqual([]);
    const rows = db.prepare("SELECT id FROM mcpflow_schema_migrations ORDER BY id").all();
    expect(rows.map((r) => (r as { id: string }).id)).toEqual(MIGRATIONS.map((m) => m.id));
  });

  it("creates STRICT tables", () => {
    const strict = db
      .prepare(`SELECT name FROM pragma_table_list WHERE name LIKE 'mcpflow_%' AND type='table' AND strict = 1`)
      .all()
      .map((r) => (r as { name: string }).name);
    for (const t of [
      "mcpflow_workspace", "mcpflow_agent", "mcpflow_api_key", "mcpflow_session",
      "mcpflow_call_audit", "mcpflow_policy_rule", "mcpflow_policy_rule_version",
      "mcpflow_pending_call", "mcpflow_approval_grant",
    ]) expect(strict).toContain(t);
  });

  it("bootstrap workspace + human agent commit together (deferred FK)", () => {
    const d = open();
    expect(() => bootstrap(d)).not.toThrow();
    // without the agent, the deferred FK fails at COMMIT
    d.exec("BEGIN IMMEDIATE;");
    d.prepare(`INSERT INTO mcpflow_workspace (id, owner_principal_id) VALUES (?, ?)`).run(id("ws"), id("agt"));
    expect(() => d.exec("COMMIT;")).toThrow(/FOREIGN KEY/);
    d.exec("ROLLBACK;");
  });

  it("rejects malformed ids and enum values", () => {
    expect(() => insertAgent(db, { id: "agt_nothex", ws, name: "x", createdBy: chen })).toThrow(/CHECK/);
    expect(() => insertAgent(db, { ws, name: "y", kind: "robot", createdBy: chen })).toThrow(/CHECK/);
  });
});

describe("agents", () => {
  it("only human agents may be admin", () => {
    expect(() => insertAgent(db, { ws, name: "evil", kind: "grokbot", admin: 1, createdBy: chen })).toThrow(/CHECK/);
  });

  it("revoked is terminal", () => {
    db.prepare(`UPDATE mcpflow_agent SET status='revoked', revoked_at=?, revoked_by=?, revoked_reason='x' WHERE id=?`)
      .run(iso(), chen, bot);
    expect(() =>
      db.prepare(`UPDATE mcpflow_agent SET status='active', revoked_at=NULL, revoked_by=NULL, revoked_reason=NULL WHERE id=?`).run(bot),
    ).toThrow(/terminal/);
  });

  it("kind and workspace are immutable; never deleted", () => {
    expect(() => db.prepare(`UPDATE mcpflow_agent SET kind='human' WHERE id=?`).run(bot)).toThrow(/immutable/);
    expect(() => db.prepare(`DELETE FROM mcpflow_agent WHERE id=?`).run(bot)).toThrow(/never deleted/);
  });
});

describe("api keys", () => {
  it("allows at most 2 live keys per agent (insert and reactivation)", () => {
    insertKey(db, bot);
    insertKey(db, bot, { status: "rotating" });
    expect(() => insertKey(db, bot)).toThrow(/2 live keys/);
    const exp = insertKey(db, bot, { status: "expired" });
    expect(() => db.prepare(`UPDATE mcpflow_api_key SET status='active' WHERE id=?`).run(exp)).toThrow(/2 live keys/);
    // other agents unaffected
    expect(() => insertKey(db, bot2)).not.toThrow();
  });

  it("prefix is UNIQUE and exactly 12 chars", () => {
    const k = insertKey(db, bot);
    const prefix = (db.prepare(`SELECT prefix FROM mcpflow_api_key WHERE id=?`).get(k) as { prefix: string }).prefix;
    expect(() =>
      db.prepare(`INSERT INTO mcpflow_api_key (id, agent_id, prefix, secret_hash, expires_at, created_by) VALUES (?,?,?,?,?,?)`)
        .run(id("key"), bot2, prefix, `sha256-pepper$v1$${randomBytes(32).toString("hex")}`, iso(DAY), chen),
    ).toThrow(/UNIQUE/);
    expect(() =>
      db.prepare(`INSERT INTO mcpflow_api_key (id, agent_id, prefix, secret_hash, expires_at, created_by) VALUES (?,?,?,?,?,?)`)
        .run(id("key"), bot2, "short", `sha256-pepper$v1$${randomBytes(32).toString("hex")}`, iso(DAY), chen),
    ).toThrow(/CHECK/);
  });

  it("expiry is shorten-only except on a rotating key; max 365 days", () => {
    const k = insertKey(db, bot);
    expect(() => db.prepare(`UPDATE mcpflow_api_key SET expires_at=? WHERE id=?`).run(iso(100 * DAY), k)).toThrow(/extended/);
    expect(() => db.prepare(`UPDATE mcpflow_api_key SET expires_at=? WHERE id=?`).run(iso(10 * DAY), k)).not.toThrow();
    db.prepare(`UPDATE mcpflow_api_key SET status='rotating', expires_at=? WHERE id=?`).run(iso(7 * DAY), k);
    expect(() => db.prepare(`UPDATE mcpflow_api_key SET expires_at=? WHERE id=?`).run(iso(14 * DAY), k)).not.toThrow();
    expect(() => insertKey(db, bot2, { expiresAt: iso(400 * DAY) })).toThrow(/CHECK/);
  });

  it("revoked is terminal and identity columns are immutable", () => {
    const k = insertKey(db, bot);
    expect(() => db.prepare(`UPDATE mcpflow_api_key SET secret_hash='x' WHERE id=?`).run(k)).toThrow(/immutable/);
    db.prepare(`UPDATE mcpflow_api_key SET status='revoked', revoked_at=?, revoked_by=?, revoked_reason='r' WHERE id=?`).run(iso(), chen, k);
    expect(() =>
      db.prepare(`UPDATE mcpflow_api_key SET status='active', revoked_at=NULL, revoked_by=NULL, revoked_reason=NULL WHERE id=?`).run(k),
    ).toThrow(/terminal/);
    expect(() => db.prepare(`DELETE FROM mcpflow_api_key WHERE id=?`).run(k)).toThrow(/never deleted/);
  });

  it("predecessor must belong to the same agent", () => {
    const k = insertKey(db, bot);
    expect(() => insertKey(db, bot2, { pred: k })).toThrow(/same agent/);
  });
});

describe("sessions", () => {
  it("session agent must own the key; expiry clamped to key expiry", () => {
    const k = insertKey(db, bot, { expiresAt: iso(DAY) });
    expect(() => insertSession(db, bot2, k)).toThrow(/own key/);
    const s = insertSession(db, bot, k, iso(30 * DAY));
    const row = db.prepare(`SELECT s.expires_at AS se, k.expires_at AS ke FROM mcpflow_session s JOIN mcpflow_api_key k ON k.id=s.key_id WHERE s.id=?`).get(s) as { se: string; ke: string };
    expect(row.se).toBe(row.ke);
  });

  it("revoking a key or suspending an agent revokes sessions; others unaffected", () => {
    const k1 = insertKey(db, bot);
    const k2 = insertKey(db, bot2);
    const s1 = insertSession(db, bot, k1);
    const s2 = insertSession(db, bot2, k2);
    db.prepare(`UPDATE mcpflow_api_key SET status='revoked', revoked_at=?, revoked_by=?, revoked_reason='r' WHERE id=?`).run(iso(), chen, k1);
    const live = () => db.prepare(`SELECT session_id FROM mcpflow_resolvable_session`).all().map((r) => (r as { session_id: string }).session_id);
    expect(live()).toEqual([s2]);
    db.prepare(`UPDATE mcpflow_agent SET status='suspended' WHERE id=?`).run(bot2);
    expect(live()).toEqual([]);
    const revoked = db.prepare(`SELECT count(*) AS n FROM mcpflow_session WHERE revoked_at IS NOT NULL`).get() as { n: number };
    expect(revoked.n).toBe(2);
    expect(s1).toBeTruthy();
  });

  it("session revoke is terminal and expiry shorten-only", () => {
    const k = insertKey(db, bot);
    const s = insertSession(db, bot, k);
    expect(() => db.prepare(`UPDATE mcpflow_session SET expires_at=? WHERE id=?`).run(iso(2 * DAY), s)).toThrow(/shorten-only/);
    db.prepare(`UPDATE mcpflow_session SET revoked_at=? WHERE id=?`).run(iso(), s);
    expect(() => db.prepare(`UPDATE mcpflow_session SET revoked_at=NULL WHERE id=?`).run(s)).toThrow(/terminal/);
  });

  it("resolvable_key hides revoked/suspended/expired", async () => {
    insertKey(db, bot, { expiresAt: iso(40) });
    insertKey(db, bot2);
    const n = () => (db.prepare(`SELECT count(*) AS n FROM mcpflow_resolvable_key`).get() as { n: number }).n;
    expect(n()).toBe(2);
    await new Promise((r) => setTimeout(r, 60));
    expect(n()).toBe(1);
    db.prepare(`UPDATE mcpflow_agent SET status='suspended' WHERE id=?`).run(bot2);
    expect(n()).toBe(0);
  });
});

describe("call_audit (append-only, Q6)", () => {
  const base = () => ({ call_id: `call_${hex()}`, workspace_id: ws, agent_id: bot });

  it("rejects UPDATE and DELETE", () => {
    audit(db, { ...base(), event_type: "decision", policy_decision: "allow" });
    expect(() => db.prepare(`UPDATE mcpflow_call_audit SET tool='x'`).run()).toThrow(/append-only/);
    expect(() => db.prepare(`DELETE FROM mcpflow_call_audit`).run()).toThrow(/append-only/);
  });

  it("approver must be human and not the caller", () => {
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "approval_denied", result_status: "not_dispatched", approver: bot2 })).toThrow(/human/);
    expect(() => audit(db, { ...base(), agent_id: chen, event_type: "completion", final_outcome: "approval_denied", result_status: "not_dispatched", approver: chen })).toThrow(/own call/);
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "approval_denied", result_status: "not_dispatched", approver: chen })).not.toThrow();
  });

  it("Q6: completion rows always carry a result_status", () => {
    // backend reached and failed / timed out
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "executed", result_status: "error" })).not.toThrow();
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "executed", result_status: "timeout" })).not.toThrow();
    // gateway failure before dispatch
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "error", result_status: "not_dispatched", error_code: "audit_unavailable" })).not.toThrow();
    // gateway failure after dispatch (no 'unknown' in enum -> 'error')
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "error", result_status: "error", error_code: "gateway_stream_lost" })).not.toThrow();
    // NULL result_status is rejected; non-executed outcomes must be not_dispatched
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "error" })).toThrow(/CHECK/);
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "denied", result_status: "ok" })).toThrow(/CHECK/);
    expect(() => audit(db, { ...base(), event_type: "completion", final_outcome: "unknown", result_status: "error" })).toThrow(/CHECK/);
  });

  it("decision and lifecycle row shape checks", () => {
    expect(() => audit(db, { ...base(), event_type: "decision" })).toThrow(/CHECK/);
    expect(() => audit(db, { ...base(), agent_id: null, event_type: "decision", error_code: "unauthenticated" })).not.toThrow();
    expect(() => audit(db, { ...base(), event_type: "lifecycle", lifecycle_action: "key_revoke" })).toThrow(/CHECK/);
    expect(() => audit(db, { ...base(), event_type: "lifecycle", lifecycle_action: "key_revoke", actor: chen })).not.toThrow();
  });
});

describe("policy rules", () => {
  function rule(): string {
    const r = id("rule");
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(r, ws, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, effect, created_by) VALUES (?,1,'d','deny',?)`).run(r, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(r);
    db.exec("COMMIT;");
    return r;
  }

  it("versions are immutable and consecutive", () => {
    const r = rule();
    expect(() => db.prepare(`UPDATE mcpflow_policy_rule_version SET description='x'`).run()).toThrow(/immutable/);
    expect(() => db.prepare(`DELETE FROM mcpflow_policy_rule_version`).run()).toThrow(/immutable/);
    expect(() =>
      db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, effect, created_by) VALUES (?,3,'d','allow',?)`).run(r, chen),
    ).toThrow(/consecutive/);
    expect(() => db.prepare(`DELETE FROM mcpflow_policy_rule WHERE id=?`).run(r)).toThrow(/never deleted/);
  });

  it("require_approval needs human approvers", () => {
    const r = rule();
    expect(() =>
      db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, effect, approvers, approval_timeout_s, created_by) VALUES (?,2,'d','require_approval',?,300,?)`)
        .run(r, JSON.stringify([bot]), chen),
    ).toThrow(/human/);
    expect(() =>
      db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, effect, created_by) VALUES (?,2,'d','require_approval',?)`).run(r, chen),
    ).toThrow(/CHECK/);
  });

  it("current_version FK is enforced at commit", () => {
    const r = rule();
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=9 WHERE id=?`).run(r);
    expect(() => db.exec("COMMIT;")).toThrow(/FOREIGN KEY/);
    db.exec("ROLLBACK;");
  });
});

describe("pending calls", () => {
  let key: string;
  beforeEach(() => {
    key = insertKey(db, bot);
  });

  it("approvers must be human", () => {
    expect(() => insertPending(db, { agent: bot, key, approvers: [bot2] })).toThrow(/human/);
  });

  it("moves only from pending to a terminal state", () => {
    const pc = insertPending(db, { agent: bot, key });
    decide(db, pc, "denied", chen);
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET status='approved' WHERE id=?`).run(pc)).toThrow(/terminal/);
    expect(() => db.prepare(`DELETE FROM mcpflow_pending_call WHERE id=?`).run(pc)).toThrow(/never deleted/);
  });

  it("snapshot is immutable", () => {
    const pc = insertPending(db, { agent: bot, key });
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET tool='other' WHERE id=?`).run(pc)).toThrow(/snapshot/);
  });

  it("no self-approval; decider must be a listed active human", () => {
    const chen2 = insertAgent(db, { ws, name: "other-human", kind: "human", createdBy: chen });
    const pcSelf = insertPending(db, { agent: chen2, key: insertKey(db, chen2), approvers: [chen2, chen] });
    expect(() => decide(db, pcSelf, "approved", chen2)).toThrow(/self-approval/);
    const pc = insertPending(db, { agent: bot, key });
    expect(() => decide(db, pc, "approved", bot2)).toThrow(/not an approver/);
    const pc2 = insertPending(db, { agent: bot, key, approvers: [chen, chen2] });
    db.prepare(`UPDATE mcpflow_agent SET status='suspended' WHERE id=?`).run(chen2);
    expect(() => decide(db, pc2, "approved", chen2)).toThrow(/active human/);
    expect(Number(decide(db, pc, "approved", chen).changes)).toBe(1);
  });

  it("timeout = deny: no decision after expires_at; no early expiry", () => {
    const live = insertPending(db, { agent: bot, key });
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET status='expired', decided_at=? WHERE id=?`).run(iso(), live)).toThrow(/before expires_at/);
    const old = insertPending(db, { agent: bot, key, createdAt: iso(-120_000), expiresAt: iso(-60_000) });
    expect(() => decide(db, old, "approved", chen)).toThrow(/timeout = deny/);
    db.prepare(`UPDATE mcpflow_pending_call SET status='expired', decided_at=? WHERE id=?`).run(iso(), old);
    expect(() => decide(db, old, "approved", chen)).not.toThrow(); // WHERE status='pending' matches nothing
    const row = db.prepare(`SELECT status FROM mcpflow_pending_call WHERE id=?`).get(old) as { status: string };
    expect(row.status).toBe("expired");
  });

  it("revoking the key or suspending the agent cancels pending calls", () => {
    const pc1 = insertPending(db, { agent: bot, key });
    db.prepare(`UPDATE mcpflow_api_key SET status='revoked', revoked_at=?, revoked_by=?, revoked_reason='r' WHERE id=?`).run(iso(), chen, key);
    const k2 = insertKey(db, bot2);
    const pc2 = insertPending(db, { agent: bot2, key: k2 });
    db.prepare(`UPDATE mcpflow_agent SET status='suspended' WHERE id=?`).run(bot2);
    const st = (pc: string) => (db.prepare(`SELECT status FROM mcpflow_pending_call WHERE id=?`).get(pc) as { status: string }).status;
    expect(st(pc1)).toBe("cancelled");
    expect(st(pc2)).toBe("cancelled");
  });

  it("ciphertext can only be purged after dispatch", () => {
    const pc = insertPending(db, { agent: bot, key });
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET args_ciphertext=NULL WHERE id=?`).run(pc)).toThrow(/purged/);
    decide(db, pc, "approved", chen);
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET args_ciphertext=NULL WHERE id=?`).run(pc)).toThrow(/purged/);
    expect(claimPendingDispatch(db, pc)).toBe(true);
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET args_ciphertext=NULL WHERE id=?`).run(pc)).not.toThrow();
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET args_ciphertext=? WHERE id=?`).run(Buffer.from("x"), pc)).toThrow(/purged/);
  });
});

describe("dispatch claim", () => {
  it("exactly one claim succeeds (changes()==1)", () => {
    const key = insertKey(db, bot);
    const pc = insertPending(db, { agent: bot, key });
    expect(claimPendingDispatch(db, pc)).toBe(false); // not approved yet
    decide(db, pc, "approved", chen);
    const results = [claimPendingDispatch(db, pc), claimPendingDispatch(db, pc), claimPendingDispatch(db, pc)];
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET dispatched_at=? WHERE id=?`).run(iso(), pc)).toThrow(/already dispatched/);
  });

  it("two connections racing on one file claim once", async () => {
    const { mkdtempSync, rmSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { tmpdir } = await import("node:os");
    const dir = mkdtempSync(join(tmpdir(), "mcpflow-claim-"));
    try {
      const a = new DatabaseSync(join(dir, "t.db"));
      applyConnectionPragmas(a);
      runMigrations(a);
      const b = new DatabaseSync(join(dir, "t.db"));
      applyConnectionPragmas(b);
      const prev = db;
      db = a;
      ({ ws, chen } = bootstrap(a));
      bot = insertAgent(a, { ws, name: "bot", createdBy: chen });
      const pc = insertPending(a, { agent: bot, key: insertKey(a, bot) });
      decide(a, pc, "approved", chen);
      db = prev;
      expect([claimPendingDispatch(a, pc), claimPendingDispatch(b, pc)].filter(Boolean)).toHaveLength(1);
      a.close();
      b.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("cannot dispatch a denied/expired/cancelled call", () => {
    const key = insertKey(db, bot);
    const pc = insertPending(db, { agent: bot, key });
    decide(db, pc, "denied", chen);
    expect(claimPendingDispatch(db, pc)).toBe(false);
    expect(() => db.prepare(`UPDATE mcpflow_pending_call SET dispatched_at=? WHERE id=?`).run(iso(), pc)).toThrow(/CHECK/);
  });
});

describe("approval grants", () => {
  let pc: string;
  beforeEach(() => {
    const key = insertKey(db, bot);
    pc = insertPending(db, { agent: bot, key });
    decide(db, pc, "approved", chen);
  });

  function grant(o: { by?: string; agent?: string; tool?: string; maxUses?: number | null; minutes?: number } = {}) {
    const g = id("grt");
    const now = new Date();
    db.prepare(
      `INSERT INTO mcpflow_approval_grant (id, source_pending_call_id, workspace_id, agent_id, project_id,
         backend_slug, tool, overrides_rule_ids, granted_by, granted_at, expires_at, max_uses)
       VALUES (?, ?, ?, ?, 'gb_devops', 'gh-repos-shell', ?, ?, ?, ?, ?, ?)`,
    ).run(
      g, pc, ws, o.agent ?? bot, o.tool ?? "run_command", JSON.stringify([id("rule")]),
      o.by ?? chen, now.toISOString(), new Date(now.getTime() + (o.minutes ?? 30) * 60_000).toISOString(),
      o.maxUses === undefined ? 2 : o.maxUses,
    );
    return g;
  }

  it("granter must be a human other than the grantee, from the same approved scope", () => {
    expect(() => grant({ by: bot2 })).toThrow(/human/);
    expect(() => grant({ tool: "other" })).toThrow(/same scope/);
    expect(() => grant({ minutes: 90 })).toThrow(/CHECK/);
    expect(() => grant()).not.toThrow();
  });

  it("scope immutable, use_count +1 only, max_uses enforced, revoke terminal", () => {
    const g = grant();
    expect(() => db.prepare(`UPDATE mcpflow_approval_grant SET tool='x' WHERE id=?`).run(g)).toThrow(/immutable/);
    expect(() => db.prepare(`UPDATE mcpflow_approval_grant SET use_count=2 WHERE id=?`).run(g)).toThrow(/increments/);
    db.prepare(`UPDATE mcpflow_approval_grant SET use_count=use_count+1 WHERE id=?`).run(g);
    db.prepare(`UPDATE mcpflow_approval_grant SET use_count=use_count+1 WHERE id=?`).run(g);
    expect(() => db.prepare(`UPDATE mcpflow_approval_grant SET use_count=use_count+1 WHERE id=?`).run(g)).toThrow(/CHECK/);
    db.prepare(`UPDATE mcpflow_approval_grant SET revoked_at=?, revoked_by=?, revoked_reason='r' WHERE id=?`).run(iso(), chen, g);
    expect(() => db.prepare(`UPDATE mcpflow_approval_grant SET revoked_at=NULL, revoked_by=NULL WHERE id=?`).run(g)).toThrow(/terminal/);
    expect(() => db.prepare(`DELETE FROM mcpflow_approval_grant WHERE id=?`).run(g)).toThrow(/never deleted/);
  });

  it("a revoked grant cannot be used", () => {
    const g = grant({ maxUses: null });
    db.prepare(`UPDATE mcpflow_approval_grant SET revoked_at=?, revoked_by=?, revoked_reason='r' WHERE id=?`).run(iso(), chen, g);
    expect(() => db.prepare(`UPDATE mcpflow_approval_grant SET use_count=use_count+1 WHERE id=?`).run(g)).toThrow(/not live/);
  });
});
