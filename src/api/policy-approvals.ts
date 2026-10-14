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

  r.get("/:id", (c) => {
    const row = visible(c, c.req.param("id"));
    if (!row) return c.json({ error: "not_found" }, 404);
    return c.json(view(row, names([row])));
  });

  const decideRoute = (decision: "approved" | "denied") => async (c: Context<Env>) => {
    const id = c.req.param("id")!;
    if (!visible(c, id)) return c.json({ error: "not_found" }, 404);
    const body = (await c.req.json().catch(() => ({}))) as { note?: unknown };
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
    if (!visible(c, id)) return c.json({ error: "not_found" }, 404);
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
    const res = store.policy.approveSimilar(id, c.get("approver").agentId, minutes, {
      maxUses,
      sameArgsOnly: body.same_args_only === true,
      note: typeof body.note === "string" ? body.note.slice(0, 500) : undefined,
    });
    audit(c, "policy.approval.approve_similar", {
      pending_call_id: id, minutes, max_uses: maxUses ?? null, same_args_only: body.same_args_only === true,
      ok: res.ok, ...(res.ok ? { grant_id: res.grantId } : { error: res.error }),
    });
    if (!res.ok) return fail(c, res.error);
    const g = db.prepare(`SELECT id, expires_at, max_uses FROM mcpflow_approval_grant WHERE id = ?`).get(res.grantId) as Record<string, unknown>;
    return c.json({ ok: true, id, status: "approved", grant: g });
  });

  return r;
}
