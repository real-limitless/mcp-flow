/**
 * REST surface for policy approvals (T2.3 API, for the Frontend/PWA).
 *
 * Auth: Bearer agent key (mf_…) or agent session (mf_sess_…) of a HUMAN agent.
 * Env admin token, legacy keys and non-human agents are refused (401/403).
 * Visibility: a caller only sees/decides pending calls that list them in `approvers`;
 * anything else is a 404 (no existence oracle). The DB triggers remain the final
 * authority (listed approver, human, no self-approval, not expired, terminal state).
 * Every decision is also written to audit_events ("policy.approval.*").
 */
import { Hono, type Context } from "hono";
import type { Store } from "../db/store.js";
import type { ResolvedAgent } from "../identity/agents.js";
import { clientIp } from "../http/client-ip.js";
import { canonicalJson } from "../policy/crypto.js";
import { validateArgMatchers, type ArgMatcher } from "../policy/matchers.js";

type Env = { Variables: { approver: ResolvedAgent } };

const PUBLIC_COLS = `id, call_id, workspace_id, agent_id, project_id, backend_slug, tool, qualified_tool,
  placement, args_redacted, matched_rules, reason_to_agent, created_at, expires_at, status,
  decided_by, decided_at, note, dispatched_at, grant_id`;

function view(r: Record<string, unknown>, agentNames: Map<string, string>) {
  return {
    id: r.id,
    call_id: r.call_id,
    agent: { id: r.agent_id, name: agentNames.get(String(r.agent_id)) ?? null },
    project_id: r.project_id,
    backend_slug: r.backend_slug,
    tool: r.tool,
    qualified_tool: r.qualified_tool,
    placement: r.placement,
    args_redacted: JSON.parse(String(r.args_redacted)),
    matched_rules: JSON.parse(String(r.matched_rules)),
    reason: r.reason_to_agent,
    created_at: r.created_at,
    expires_at: r.expires_at,
    status: r.status,
    decided_by: r.decided_by,
    decided_at: r.decided_at,
    note: r.note,
    dispatched_at: r.dispatched_at,
    grant_id: r.grant_id,
  };
}

const ERR_STATUS: Array<[RegExp, number, string]> = [
  [/not pending|already resolved/, 409, "not_pending"],
  [/expired/, 409, "expired"],
  [/self-approval/, 403, "self_approval"],
  [/not an approver|not a human/, 403, "not_approver"],
];

export function policyApprovalsRouter(store: Store) {
  const r = new Hono<Env>();
  const db = store.db;

  r.use("*", async (c, next) => {
    const h = c.req.header("authorization") ?? "";
    const token = h.toLowerCase().startsWith("bearer ") ? h.slice(7).trim() : "";
    if (!token) return c.json({ error: "unauthorized" }, 401);
    const res = token.startsWith("mf_sess_")
      ? store.identity.resolveSession(token)
      : store.identity.resolveKey(token, clientIp(c));
    if (res.status !== "ok" && res.status !== "forbidden") return c.json({ error: "unauthorized" }, 401);
    if (res.agent.kind !== "human") return c.json({ error: "approvers must be human agents" }, 403);
    c.set("approver", res.agent);
    await next();
    // Security T2.5 R-6: approver responses can carry unredacted args (args_full); never cache them
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
  });

  const names = (rows: Array<Record<string, unknown>>) => {
    const ids = [...new Set(rows.map((x) => String(x.agent_id)))];
    const m = new Map<string, string>();
    for (const id of ids) {
      const a = db.prepare(`SELECT name FROM mcpflow_agent WHERE id = ?`).get(id) as { name: string } | undefined;
      if (a) m.set(id, a.name);
    }
    return m;
  };

  /** Row visible to this approver, or undefined. */
  const visible = (c: Context<Env>, id: string) => {
    const me = c.get("approver");
    return db
      .prepare(
        `SELECT ${PUBLIC_COLS} FROM mcpflow_pending_call p
          WHERE p.id = ? AND p.workspace_id = ?
            AND EXISTS (SELECT 1 FROM json_each(p.approvers) j WHERE j.value = ?)`,
      )
      .get(id, me.workspaceId, me.agentId) as Record<string, unknown> | undefined;
  };

  const audit = (c: Context<Env>, action: string, detail: Record<string, unknown>) => {
    const me = c.get("approver");
    store.writeAudit({ workspaceId: me.workspaceId, keyId: me.keyId, action, detail: { approver: me.agentId, ...detail }, ip: clientIp(c) });
  };

  const fail = (c: Context<Env>, msg: string) => {
    for (const [re, status, code] of ERR_STATUS) if (re.test(msg)) return c.json({ error: code }, status as 403 | 409);
    return c.json({ error: "decision_failed" }, 409);
  };

  // GET /pending?limit=&before=  (open calls awaiting me, oldest-expiring first)
  r.get("/pending", (c) => {
    const me = c.get("approver");
    const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 50) || 50, 1), 200);
    const rows = db
      .prepare(
        `SELECT ${PUBLIC_COLS} FROM mcpflow_pending_call p
          WHERE p.workspace_id = ? AND p.status = 'pending' AND p.expires_at > ?
            AND p.agent_id <> ?
            AND EXISTS (SELECT 1 FROM json_each(p.approvers) j WHERE j.value = ?)
          ORDER BY p.expires_at ASC LIMIT ?`,
      )
      .all(me.workspaceId, new Date().toISOString(), me.agentId, me.agentId, limit) as Array<Record<string, unknown>>;
    const n = names(rows);
    return c.json({ pending: rows.map((x) => view(x, n)) });
  });

  // GET /history?limit=  (calls I was an approver for, newest first, any status)
  r.get("/history", (c) => {
    const me = c.get("approver");
    const limit = Math.min(Math.max(Number(c.req.query("limit") ?? 50) || 50, 1), 200);
    const rows = db
      .prepare(
        `SELECT ${PUBLIC_COLS} FROM mcpflow_pending_call p
          WHERE p.workspace_id = ? AND EXISTS (SELECT 1 FROM json_each(p.approvers) j WHERE j.value = ?)
          ORDER BY p.created_at DESC LIMIT ?`,
      )
      .all(me.workspaceId, me.agentId, limit) as Array<Record<string, unknown>>;
    const n = names(rows);
    return c.json({ calls: rows.map((x) => view(x, n)) });
  });

  /**
   * Security T2.5 H-1: the approver sees the exact payload that will run (decrypted from the
   * ciphertext, unredacted) and its sha256; approve/approve-similar may echo args_sha256 back and
   * are refused if it no longer matches. Dispatch re-verifies the keyed hash before sending.
   */
  const fullArgs = (id: string) => {
    try {
      return store.policy.approverArgs(id);
    } catch {
      return "corrupt" as const;
    }
  };

  r.get("/:id", (c) => {
    const id = c.req.param("id");
    const row = visible(c, id);
    if (!row) return c.json({ error: "not_found" }, 404);
    const full = fullArgs(id);
    if (full === "corrupt") return c.json({ error: "args_integrity" }, 409);
    const v = view(row, names([row]));
    return c.json({
      ...v,
      args_full: full?.args ?? null,
      args_sha256: full?.sha256 ?? null,
      args_hidden_in_summary: full ? canonicalJson(full.args) !== canonicalJson(v.args_redacted) : false,
    });
  });

  /**
   * REQUIRED echo of the hash the approver saw (Security T2.5 H-1 re-review): missing = 400,
   * mismatch = 409. Approving is impossible without having fetched the exact payload.
   */
  const checkEcho = (id: string, body: Record<string, unknown>): string | null => {
    if (typeof body.args_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(body.args_sha256)) return "args_sha256_required";
    const full = fullArgs(id);
    if (full === "corrupt") return "args_integrity";
    if (!full || full.sha256 !== String(body.args_sha256)) return "args_mismatch";
    return null;
  };

  /** Already decided or past expiry: 409 before any body validation (the decision would fail anyway). */
  const closed = (row: Record<string, unknown>): string | null =>
    row.status !== "pending" ? "not_pending" : String(row.expires_at) <= new Date().toISOString() ? "expired" : null;

  const decideRoute = (decision: "approved" | "denied") => async (c: Context<Env>) => {
    const id = c.req.param("id")!;
    const row = visible(c, id);
    if (!row) return c.json({ error: "not_found" }, 404);
    const shut = closed(row);
    if (shut) {
      audit(c, decision === "approved" ? "policy.approval.approve" : "policy.approval.deny", { pending_call_id: id, ok: false, error: shut });
      return c.json({ error: shut }, 409);
    }
    const body = (await c.req.json().catch(() => ({}))) as { note?: unknown; args_sha256?: unknown };
    if (decision === "approved") {
      const bad = checkEcho(id, body);
      if (bad) return c.json({ error: bad }, bad === "args_sha256_required" ? 400 : 409);
    }
    const note = typeof body.note === "string" ? body.note.slice(0, 500) : undefined;
    const res = store.policy.decide(id, c.get("approver").agentId, decision, note);
    audit(c, decision === "approved" ? "policy.approval.approve" : "policy.approval.deny", {
      pending_call_id: id, ok: res.ok, ...(res.ok ? {} : { error: res.error }),
    });
    if (!res.ok) return fail(c, res.error);
    return c.json({ ok: true, id, status: decision });
  };
  r.post("/:id/approve", decideRoute("approved"));
  r.post("/:id/deny", decideRoute("denied"));

  // POST /:id/approve-similar {minutes 1-60, max_uses?, same_args_only?, note?}
  r.post("/:id/approve-similar", async (c) => {
    const id = c.req.param("id");
    const row = visible(c, id);
    if (!row) return c.json({ error: "not_found" }, 404);
    const shut = closed(row);
    if (shut) {
      audit(c, "policy.approval.approve_similar", { pending_call_id: id, ok: false, error: shut });
      return c.json({ error: shut }, 409);
    }
    const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    const minutes = Number(body.minutes);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 60) {
      return c.json({ error: "minutes must be an integer 1-60" }, 400);
    }
    let maxUses: number | undefined;
    if (body.max_uses != null) {
      maxUses = Number(body.max_uses);
      if (!Number.isInteger(maxUses) || maxUses < 1) return c.json({ error: "max_uses must be a positive integer" }, 400);
    }
    const bad = checkEcho(id, body);
    if (bad) return c.json({ error: bad }, bad === "args_sha256_required" ? 400 : 409);
    // Security T2.5 M-3: exact-args by default; broader grants need explicit match_args
    const sameArgsOnly = body.same_args_only !== false;
    let matchArgs: ArgMatcher[] | undefined;
    if (!sameArgsOnly) {
      try {
        matchArgs = validateArgMatchers(body.match_args);
      } catch (err) {
        return c.json({ error: `match_args: ${(err as Error).message}` }, 400);
      }
      if (!matchArgs.length) return c.json({ error: "match_args is required when same_args_only is false" }, 400);
    }
    const res = store.policy.approveSimilar(id, c.get("approver").agentId, minutes, {
      maxUses,
      matchArgs,
      sameArgsOnly,
      note: typeof body.note === "string" ? body.note.slice(0, 500) : undefined,
    });
    audit(c, "policy.approval.approve_similar", {
      pending_call_id: id, minutes, max_uses: maxUses ?? null, same_args_only: sameArgsOnly, match_args: matchArgs ?? null,
      ok: res.ok, ...(res.ok ? { grant_id: res.grantId } : { error: res.error }),
    });
    if (!res.ok) return res.error.startsWith("invalid match_args") ? c.json({ error: res.error }, 400) : fail(c, res.error);
    const g = db.prepare(`SELECT id, expires_at, max_uses, match_args, args_hash IS NOT NULL AS same_args_only FROM mcpflow_approval_grant WHERE id = ?`).get(res.grantId) as Record<string, unknown>;
    return c.json({
      ok: true, id, status: "approved",
      grant: { ...g, match_args: JSON.parse(String(g.match_args)), same_args_only: Boolean(g.same_args_only) },
    });
  });

  return r;
}
