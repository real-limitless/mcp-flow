/**
 * T2.2 — per-call policy enforcement before backend dispatch (T2.1 §4/§5, db-t2.1 "Gateway flows").
 *
 * Every call: evaluate -> BEGIN IMMEDIATE { decision audit row [+ grant claim] [+ pending_call] } COMMIT
 * -> only then dispatch / hold. Any DB error before commit = policy_denied (audit_unavailable), no dispatch.
 *
 * Completion rows (Q6, Database 2026-10-14; 0002 CHECKs kept as written):
 *  - backend reached, returned error / timed out : final_outcome='executed', result_status='error'|'timeout'
 *  - gateway failed before dispatch              : final_outcome='error', result_status='not_dispatched'
 *  - gateway failed after dispatch               : final_outcome='error', result_status='error'
 *    (a gateway failure after dispatch is recorded as result_status='error', the same value a backend
 *     error gets; final_outcome='error' vs 'executed' is what tells a gateway failure from a backend one)
 *  - deny / approval_denied / approval_expired / cancelled : result_status='not_dispatched'
 */
import { randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { sanitizeForAudit } from "../audit/sanitize.js";
import type { PolicyKeys } from "../identity/dev-keys.js";
import { argsHash, decryptArgs, encryptArgs } from "./crypto.js";
import { evaluate, loadActiveRules, type CallContext, type Decision, type PolicyRule } from "./engine.js";
import { allArgsMatch, type ArgMatcher } from "./matchers.js";

export type DenyReason =
  | "rule_deny"
  | "no_matching_rule"
  | "policy_unavailable"
  | "audit_unavailable"
  | "approval_denied"
  | "approval_timeout"
  | "cancelled"
  | "approval_busy"
  | "dispatch_conflict";

export interface PendingNotice {
  pendingCallId: string;
  workspaceId: string;
  agentId: string;
  agentName: string;
  projectId: string;
  backendSlug: string;
  tool: string;
  argsRedacted: unknown;
  approvers: string[];
  expiresAt: string;
  reasonToAgent: string | null;
}

export type ApprovalNotifier = (n: PendingNotice) => Promise<void>;

export interface EnforcerDeps {
  db: DatabaseSync;
  keys: PolicyKeys;
  notify?: ApprovalNotifier;
  clock?: () => number;
  /** Max concurrent holds per workspace */
  maxHolds?: number;
  /** Test hook: fail audit writes */
  auditFault?: () => boolean;
}

type Resolution = "approved" | "denied" | "expired" | "cancelled";

const newId = (p: string) => `${p}_${randomBytes(12).toString("hex")}`;
export const HOLD_POLL_MS = 250;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function policyDeniedResult(p: {
  reason: DenyReason;
  tool: string;
  ruleId?: string | null;
  ruleVersion?: number | null;
  pendingCallId?: string | null;
  message?: string | null;
  note?: string | null;
}): CallToolResult {
  const payload: Record<string, unknown> = {
    code: "policy_denied",
    reason: p.reason,
    tool: p.tool,
    rule_id: p.ruleId ?? null,
  };
  if (p.ruleVersion != null) payload.rule_version = p.ruleVersion;
  if (p.pendingCallId) payload.pending_call_id = p.pendingCallId;
  if (p.note) payload.note = p.note;
  payload.message = p.message ?? DEFAULT_MESSAGES[p.reason];
  return { isError: true, content: [{ type: "text", text: JSON.stringify(payload) }] };
}

const DEFAULT_MESSAGES: Record<DenyReason, string> = {
  rule_deny: "This call is denied by policy.",
  no_matching_rule: "No policy rule allows this call (project default is deny).",
  policy_unavailable: "Policy could not be evaluated; the gateway fails closed.",
  audit_unavailable: "The audit log is unavailable; the gateway fails closed.",
  approval_denied: "A human denied this call.",
  approval_timeout: "This call needed human approval and was not approved in time (timeout = deny).",
  cancelled: "The pending call was cancelled.",
  approval_busy: "Too many calls are waiting for approval. Retry shortly.",
  dispatch_conflict: "This approved call was already dispatched.",
};

export class PolicyEnforcer {
  private readonly waiters = new Map<string, (r: Resolution) => void>();
  private readonly clock: () => number;

  constructor(private readonly deps: EnforcerDeps) {
    this.clock = deps.clock ?? Date.now;
  }

  private iso(ms = this.clock()): string {
    return new Date(ms).toISOString();
  }

  /** Number of in-process holds for a workspace. */
  holds(workspaceId: string): number {
    return (
      this.deps.db
        .prepare(`SELECT count(*) AS n FROM mcpflow_pending_call WHERE workspace_id = ? AND status = 'pending'`)
        .get(workspaceId) as { n: number }
    ).n;
  }

  async enforce(input: {
    ctx: CallContext;
    args: Record<string, unknown>;
    dispatch: (args: Record<string, unknown>) => Promise<CallToolResult>;
    signal?: AbortSignal;
  }): Promise<CallToolResult> {
    const { ctx, args } = input;
    const db = this.deps.db;
    const callId = newId("call");
    const started = this.clock();
    const redacted = sanitizeForAudit(args ?? {});
    const hash = argsHash(this.deps.keys.argsHmac, args);

    // 1) evaluate; any error -> deny (fail closed)
    let decision: Decision;
    try {
      decision = evaluate(loadActiveRules(db, ctx.workspaceId), ctx, args);
    } catch {
      decision = { decision: "deny", rule: null, matched: [], reason: "policy_unavailable" };
    }

    // 2) one IMMEDIATE txn: decision row [+ grant claim] [+ pending_call]
    let grantId: string | null = null;
    let pendingId: string | null = null;
    let expiresAt: string | null = null;
    let busy = false;
    try {
      this.tx(() => {
        if (decision.decision === "require_approval") {
          grantId = this.claimGrant(ctx, args, hash, decision);
          if (!grantId && this.holds(ctx.workspaceId) >= (this.deps.maxHolds ?? 32)) busy = true;
        }
        this.writeAudit({
          event_type: "decision",
          call_id: callId,
          ...this.ctxCols(ctx),
          args_redacted: JSON.stringify(redacted),
          args_hash: hash,
          policy_decision: decision.decision,
          rule_id: decision.rule?.ruleId ?? null,
          rule_version: decision.rule?.version ?? null,
          matched_rule_ids: JSON.stringify(decision.matched.map((r) => r.ruleId)),
          grant_id: grantId,
          error_code: decision.decision === "deny" ? decision.reason : busy ? "approval_busy" : null,
        });
        if (decision.decision === "require_approval" && !grantId && !busy) {
          pendingId = newId("pc");
          const created = this.clock();
          expiresAt = this.iso(created + (decision.timeoutS ?? 300) * 1000);
          db.prepare(
            `INSERT INTO mcpflow_pending_call (id, call_id, workspace_id, agent_id, key_id, session_id,
               project_id, backend_slug, tool, qualified_tool, placement, device_id, args_redacted,
               args_ciphertext, args_key_ref, args_hash, matched_rules, approvers, reason_to_agent,
               created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          ).run(
            pendingId, callId, ctx.workspaceId, ctx.agentId, ctx.keyId, ctx.sessionId,
            ctx.projectId, ctx.backendSlug, ctx.tool, ctx.qualifiedTool, ctx.placement, ctx.deviceId,
            JSON.stringify(redacted), encryptArgs(this.deps.keys.argsEnc, args), this.deps.keys.keyRef, hash,
            JSON.stringify(decision.matched.map((r) => ({ rule_id: r.ruleId, version: r.version, effect: r.effect }))),
            JSON.stringify(decision.approvers ?? []), decision.rule?.reasonToAgent ?? null,
            this.iso(created), expiresAt,
          );
        }
      });
    } catch {
      // nothing committed: no audit row, no hold, no dispatch
      return policyDeniedResult({ reason: "audit_unavailable", tool: ctx.qualifiedTool });
    }

    const notDispatched = (finalOutcome: string, extra: Record<string, unknown> = {}) =>
      this.completion(callId, ctx, {
        final_outcome: finalOutcome,
        result_status: "not_dispatched",
        latency_ms: this.clock() - started,
        rule_id: decision.rule?.ruleId ?? null,
        rule_version: decision.rule?.version ?? null,
        pending_call_id: pendingId,
        grant_id: grantId,
        ...extra,
      });

    // 3) deny
    if (decision.decision === "deny" || busy) {
      const reason: DenyReason = busy ? "approval_busy" : (decision.reason as DenyReason);
      notDispatched("denied", { error_code: reason });
      return policyDeniedResult({
        reason,
        tool: ctx.qualifiedTool,
        ruleId: decision.rule?.ruleId,
        ruleVersion: decision.rule?.version,
        message: decision.rule?.reasonToAgent,
      });
    }

    // 4) allow (or require_approval satisfied by a live grant)
    if (decision.decision === "allow" || grantId) {
      return this.dispatchAndComplete(callId, ctx, decision, input.dispatch, args, started, { grantId });
    }

    // 5) hold
    const pc = pendingId!;
    if (this.deps.notify) {
      void this.deps
        .notify({
          pendingCallId: pc, workspaceId: ctx.workspaceId, agentId: ctx.agentId, agentName: ctx.agentName,
          projectId: ctx.projectId, backendSlug: ctx.backendSlug, tool: ctx.tool, argsRedacted: redacted,
          approvers: decision.approvers ?? [], expiresAt: expiresAt!, reasonToAgent: decision.rule?.reasonToAgent ?? null,
        })
        .catch(() => undefined);
    }
    const resolution = await this.waitFor(pc, expiresAt!, input.signal);
    const row = db
      .prepare(`SELECT status, decided_by, note FROM mcpflow_pending_call WHERE id = ?`)
      .get(pc) as { status: string; decided_by: string | null; note: string | null };
    const status = row?.status ?? resolution;

    if (status === "approved") {
      if (!this.claimDispatch(pc)) {
        notDispatched("error", { error_code: "dispatch_conflict", approver: row.decided_by });
        return policyDeniedResult({ reason: "dispatch_conflict", tool: ctx.qualifiedTool, pendingCallId: pc });
      }
      const stored = db.prepare(`SELECT args_ciphertext FROM mcpflow_pending_call WHERE id = ?`).get(pc) as {
        args_ciphertext: Uint8Array | null;
      };
      let frozen: Record<string, unknown>;
      try {
        frozen = decryptArgs(this.deps.keys.argsEnc, stored.args_ciphertext!);
      } catch {
        // claimed but not sent: gateway failure before dispatch
        notDispatched("error", { error_code: "args_decrypt_failed", approver: row.decided_by });
        this.purge(pc);
        return policyDeniedResult({ reason: "policy_unavailable", tool: ctx.qualifiedTool, pendingCallId: pc });
      }
      const res = await this.dispatchAndComplete(callId, ctx, decision, input.dispatch, frozen, started, {
        pendingCallId: pc,
        approver: row.decided_by,
        approverNote: row.note,
      });
      this.purge(pc);
      return res;
    }

    const map: Record<string, [string, DenyReason]> = {
      denied: ["approval_denied", "approval_denied"],
      expired: ["approval_expired", "approval_timeout"],
      cancelled: ["cancelled", "cancelled"],
    };
    const [outcome, reason] = map[status] ?? ["cancelled", "cancelled"];
    notDispatched(outcome, {
      error_code: reason,
      approver: status === "denied" ? row.decided_by : null,
      approver_note: status === "denied" ? row.note : null,
    });
    this.purge(pc);
    return policyDeniedResult({
      reason,
      tool: ctx.qualifiedTool,
      ruleId: decision.rule?.ruleId,
      ruleVersion: decision.rule?.version,
      pendingCallId: pc,
      note: status === "denied" ? row.note : null,
    });
  }

  // ---------- approver actions (API for T2.3) ----------

  /** Approve or deny one pending call. Triggers enforce human approver, listed, no self-approval, not expired. */
  decide(pendingCallId: string, deciderAgentId: string, decision: "approved" | "denied", note?: string): { ok: true } | { ok: false; error: string } {
    try {
      const res = this.deps.db
        .prepare(
          `UPDATE mcpflow_pending_call SET status = ?, decided_by = ?, decided_at = ?, note = ?
            WHERE id = ? AND status = 'pending'`,
        )
        .run(decision, deciderAgentId, this.iso(), note ?? null, pendingCallId);
      if (Number(res.changes) !== 1) return { ok: false, error: "not pending" };
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
    this.waiters.get(pendingCallId)?.(decision);
    return { ok: true };
  }

  /** Approve this call and create an expiring grant for similar calls (≤ 60 min, never overrides deny). */
  approveSimilar(pendingCallId: string, deciderAgentId: string, minutes: number, opts: { maxUses?: number; note?: string; matchArgs?: ArgMatcher[]; sameArgsOnly?: boolean } = {}):
    { ok: true; grantId: string } | { ok: false; error: string } {
    const db = this.deps.db;
    const pc = db.prepare(`SELECT * FROM mcpflow_pending_call WHERE id = ?`).get(pendingCallId) as Record<string, unknown> | undefined;
    if (!pc) return { ok: false, error: "not found" };
    const overrides = (JSON.parse(String(pc.matched_rules)) as Array<{ rule_id: string; effect: string }>)
      .filter((r) => r.effect === "require_approval")
      .map((r) => r.rule_id);
    const grantId = newId("grt");
    try {
      this.tx(() => {
        const res = db
          .prepare(
            `UPDATE mcpflow_pending_call SET status = 'approved', decided_by = ?, decided_at = ?, note = ?
              WHERE id = ? AND status = 'pending'`,
          )
          .run(deciderAgentId, this.iso(), opts.note ?? null, pendingCallId);
        if (Number(res.changes) !== 1) throw new Error("not pending");
        const now = this.clock();
        db.prepare(
          `INSERT INTO mcpflow_approval_grant (id, source_pending_call_id, workspace_id, agent_id, project_id,
             backend_slug, tool, match_args, args_hash, overrides_rule_ids, granted_by, granted_at, expires_at, max_uses)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          grantId, pendingCallId, String(pc.workspace_id), String(pc.agent_id), String(pc.project_id),
          String(pc.backend_slug), String(pc.tool), JSON.stringify(opts.matchArgs ?? []),
          opts.sameArgsOnly ? String(pc.args_hash) : null, JSON.stringify(overrides), deciderAgentId,
          this.iso(now), this.iso(now + Math.min(Math.max(minutes, 1), 60) * 60_000), opts.maxUses ?? null,
        );
        db.prepare(`UPDATE mcpflow_pending_call SET grant_id = ? WHERE id = ?`).run(grantId, pendingCallId);
      });
    } catch (err) {
      return { ok: false, error: (err as Error).message };
    }
    this.waiters.get(pendingCallId)?.("approved");
    return { ok: true, grantId };
  }

  /** Expire every overdue pending call (timeout = deny). Returns ids expired. */
  sweepExpired(): string[] {
    const now = this.iso();
    const rows = this.deps.db
      .prepare(`SELECT id FROM mcpflow_pending_call WHERE status = 'pending' AND expires_at <= ?`)
      .all(now) as Array<{ id: string }>;
    const out: string[] = [];
    for (const { id } of rows) {
      if (this.tryExpire(id)) {
        out.push(id);
        this.waiters.get(id)?.("expired");
      }
    }
    return out;
  }

  /** mf_pending_status: status only (0003 Q7 default; no stored result). */
  pendingStatus(pendingCallId: string, agentId: string): { status: string; expiresAt: string } | null {
    const r = this.deps.db
      .prepare(`SELECT status, expires_at FROM mcpflow_pending_call WHERE id = ? AND agent_id = ?`)
      .get(pendingCallId, agentId) as { status: string; expires_at: string } | undefined;
    return r ? { status: r.status, expiresAt: r.expires_at } : null;
  }

  // ---------- internals ----------

  private async waitFor(pc: string, expiresAt: string, signal?: AbortSignal): Promise<Resolution> {
    return new Promise<Resolution>((resolve) => {
      let done = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      // DB-side changes (revoke cascade -> cancelled, another process deciding) are picked up by polling
      const poll = setInterval(() => {
        const st = this.deps.db.prepare(`SELECT status FROM mcpflow_pending_call WHERE id = ?`).get(pc) as
          | { status: string }
          | undefined;
        if (st && st.status !== "pending") finish(st.status as Resolution);
      }, HOLD_POLL_MS);
      const finish = (r: Resolution) => {
        if (done) return;
        done = true;
        clearInterval(poll);
        if (timer) clearTimeout(timer);
        this.waiters.delete(pc);
        signal?.removeEventListener("abort", onAbort);
        resolve(r);
      };
      const onAbort = () => {
        this.deps.db
          .prepare(`UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = ?, note = 'client disconnected' WHERE id = ? AND status = 'pending'`)
          .run(this.iso(), pc);
        finish("cancelled");
      };
      const onTimeout = async () => {
        // the trigger refuses to expire before expires_at; retry briefly on clock skew
        for (let i = 0; i < 50 && !done; i++) {
          if (this.tryExpire(pc)) return finish("expired");
          const st = this.deps.db.prepare(`SELECT status FROM mcpflow_pending_call WHERE id = ?`).get(pc) as { status: string };
          if (st.status !== "pending") return finish(st.status as Resolution);
          await sleep(10);
        }
        finish("expired");
      };
      this.waiters.set(pc, finish);
      if (signal?.aborted) return onAbort();
      signal?.addEventListener("abort", onAbort, { once: true });
      timer = setTimeout(() => void onTimeout(), Math.max(0, Date.parse(expiresAt) - this.clock()) + 5);
    });
  }

  private tryExpire(pc: string): boolean {
    try {
      const r = this.deps.db
        .prepare(`UPDATE mcpflow_pending_call SET status = 'expired', decided_at = ? WHERE id = ? AND status = 'pending'`)
        .run(this.iso(), pc);
      return Number(r.changes) === 1;
    } catch {
      return false; // not yet at expires_at
    }
  }

  /** Exactly-once claim: changes() must be 1. */
  private claimDispatch(pc: string): boolean {
    try {
      const r = this.deps.db
        .prepare(`UPDATE mcpflow_pending_call SET dispatched_at = ? WHERE id = ? AND status = 'approved' AND dispatched_at IS NULL`)
        .run(this.iso(), pc);
      return Number(r.changes) === 1;
    } catch {
      return false;
    }
  }

  private purge(pc: string): void {
    try {
      this.deps.db
        .prepare(`UPDATE mcpflow_pending_call SET args_ciphertext = NULL WHERE id = ? AND status <> 'pending' AND args_ciphertext IS NOT NULL
                   AND NOT (status = 'approved' AND dispatched_at IS NULL)`)
        .run(pc);
    } catch {
      /* best effort; trigger guards correctness */
    }
  }

  private claimGrant(ctx: CallContext, args: unknown, hash: string, d: Decision): string | null {
    const reqRules = d.matched.filter((r) => r.effect === "require_approval").map((r) => r.ruleId);
    if (d.matched.some((r: PolicyRule) => r.effect === "deny")) return null;
    const now = this.iso();
    const grants = this.deps.db
      .prepare(
        `SELECT id, match_args, args_hash, overrides_rule_ids FROM mcpflow_approval_grant
          WHERE agent_id = ? AND project_id = ? AND backend_slug = ? AND tool = ? AND workspace_id = ?
            AND revoked_at IS NULL AND expires_at > ? AND (max_uses IS NULL OR use_count < max_uses)
          ORDER BY expires_at`,
      )
      .all(ctx.agentId, ctx.projectId, ctx.backendSlug, ctx.tool, ctx.workspaceId, now) as Record<string, unknown>[];
    for (const g of grants) {
      const overrides = new Set(JSON.parse(String(g.overrides_rule_ids)) as string[]);
      if (!reqRules.every((r) => overrides.has(r))) continue;
      if (g.args_hash != null && g.args_hash !== hash) continue;
      if (!allArgsMatch(JSON.parse(String(g.match_args)) as ArgMatcher[], args)) continue;
      const r = this.deps.db
        .prepare(
          `UPDATE mcpflow_approval_grant SET use_count = use_count + 1
            WHERE id = ? AND revoked_at IS NULL AND expires_at > ? AND (max_uses IS NULL OR use_count < max_uses)`,
        )
        .run(String(g.id), now);
      if (Number(r.changes) === 1) return String(g.id);
    }
    return null;
  }

  private async dispatchAndComplete(
    callId: string,
    ctx: CallContext,
    decision: Decision,
    dispatch: (a: Record<string, unknown>) => Promise<CallToolResult>,
    args: Record<string, unknown>,
    started: number,
    extra: { grantId?: string | null; pendingCallId?: string; approver?: string | null; approverNote?: string | null },
  ): Promise<CallToolResult> {
    const t0 = this.clock();
    let result: CallToolResult;
    let finalOutcome = "executed";
    let resultStatus = "ok";
    let errorCode: string | null = null;
    try {
      result = await dispatch(args);
      if (result.isError) {
        resultStatus = /timed? ?out|timeout/i.test(JSON.stringify(result.content ?? "")) ? "timeout" : "error";
      }
    } catch (err) {
      // gateway failed after dispatch started: final 'error', result_status 'error' (see header)
      finalOutcome = "error";
      resultStatus = "error";
      errorCode = "gateway_dispatch_failed";
      result = { isError: true, content: [{ type: "text", text: `gateway error: ${(err as Error).message}` }] };
    }
    this.completion(callId, ctx, {
      final_outcome: finalOutcome,
      result_status: resultStatus,
      error_code: errorCode,
      latency_ms: this.clock() - started,
      backend_latency_ms: this.clock() - t0,
      rule_id: decision.rule?.ruleId ?? null,
      rule_version: decision.rule?.version ?? null,
      grant_id: extra.grantId ?? null,
      pending_call_id: extra.pendingCallId ?? null,
      approver: extra.approver ?? null,
      approver_note: extra.approverNote ?? null,
    });
    return result;
  }

  private ctxCols(ctx: CallContext): Record<string, unknown> {
    return {
      workspace_id: ctx.workspaceId,
      agent_id: ctx.agentId,
      agent_name: ctx.agentName,
      key_id: ctx.keyId,
      key_prefix: ctx.keyPrefix,
      project_id: ctx.projectId,
      backend_slug: ctx.backendSlug,
      tool: ctx.tool,
      qualified_tool: ctx.qualifiedTool,
      placement: ctx.placement,
      device_id: ctx.deviceId,
    };
  }

  /** Completion rows are best effort after the fact: the decision row already committed. */
  private completion(callId: string, ctx: CallContext, cols: Record<string, unknown>): void {
    try {
      this.writeAudit({ event_type: "completion", call_id: callId, ...this.ctxCols(ctx), ...cols });
    } catch (err) {
      console.error(`[mcp-flow] completion audit write failed for ${callId}: ${(err as Error).message}`);
    }
  }

  private writeAudit(cols: Record<string, unknown>): void {
    if (this.deps.auditFault?.()) throw new Error("audit write failed (fault injected)");
    const keys = Object.keys(cols);
    this.deps.db
      .prepare(`INSERT INTO mcpflow_call_audit (${keys.join(", ")}) VALUES (${keys.map(() => "?").join(", ")})`)
      .run(...(Object.values(cols) as never[]));
  }

  private tx(fn: () => void): void {
    const db = this.deps.db;
    db.exec("BEGIN IMMEDIATE;");
    try {
      fn();
      db.exec("COMMIT;");
    } catch (err) {
      try {
        db.exec("ROLLBACK;");
      } catch {
        /* ignore */
      }
      throw err;
    }
  }
}
