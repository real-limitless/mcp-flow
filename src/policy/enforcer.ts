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
import { createHash, randomBytes } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { redactSecrets, sanitizeForAudit } from "../audit/sanitize.js";
import type { PolicyKeys } from "../identity/dev-keys.js";
import { argsHash, canonicalJson, decryptArgs, encryptArgs } from "./crypto.js";
import { alwaysDenied, evaluate, loadActiveRules, type CallContext, type Decision, type PolicyRule } from "./engine.js";
import { allArgsMatch, validateArgMatchers, type ArgMatcher } from "./matchers.js";

export type DenyReason =
  | "rule_deny"
  | "no_matching_rule"
  | "policy_unavailable"
  | "audit_unavailable"
  | "approval_denied"
  | "approval_timeout"
  | "cancelled"
  | "approval_busy"
  | "dispatch_conflict"
  | "unknown_tool"
  | "unknown_backend"
  | "no_active_project"
  | "invalid_idempotency_key"
  | "idempotency_conflict"
  | "gateway_shutting_down"
  | "no_active_approver";

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
  /** True when redaction/truncation changed what argsRedacted shows: approvers must open the full view */
  argsHidden?: boolean;
  /** Ignored for links (Security T2.5 H-2): links come only from configured MCP_FLOW_PUBLIC_URL */
  approveBaseUrl?: string | null;
}

export type ApprovalNotifier = (n: PendingNotice) => Promise<void>;

export interface EnforcerDeps {
  db: DatabaseSync;
  keys: PolicyKeys;
  notify?: ApprovalNotifier;
  clock?: () => number;
  /** Max concurrent holds per workspace */
  maxHolds?: number;
  /** R-2 caps for stored results */
  maxResultBytes?: number;
  maxResultTotalBytes?: number;
  /** Security R2-3: per-agent cap on stored result bytes (one agent cannot evict others' results) */
  maxResultAgentBytes?: number;
  resultTtlMs?: number;
  /** Progress notification interval while holding (default 15 s) */
  progressIntervalMs?: number;
  /** Max concurrent holds per agent (Security T2.5 L-1), default 8 */
  maxHoldsPerAgent?: number;
  /** Test hook: fail audit writes */
  auditFault?: () => boolean;
}

type Resolution = "approved" | "denied" | "expired" | "cancelled";

const newId = (p: string) => `${p}_${randomBytes(12).toString("hex")}`;
export const HOLD_POLL_MS = 250;
export const PROGRESS_INTERVAL_MS = 15_000;
export const RESULT_TTL_MS = 24 * 3600_000;
export const MAX_RESULT_BYTES = 256 * 1024;
export const MAX_RESULT_TOTAL_BYTES = 64 * 1024 * 1024;
export interface RecoveryCounts { cancelled: number; abandoned: number; unknown: number }
export const MAX_RESULT_AGENT_BYTES = 8 * 1024 * 1024;

/** Durable call state from the completion pair (Q6 mapping). */
export function outcomeState(finalOutcome: string, resultStatus: string): "executed" | "not_executed" | "unknown" {
  if (resultStatus === "not_dispatched") return "not_executed";
  if (finalOutcome === "executed") return "executed";
  return "unknown"; // gateway failure after dispatch: the backend may or may not have acted
}

const OUTCOME_MESSAGES: Record<string, string> = {
  executed: "The call ran. Its result was already read, purged, or lost in a restart. Do not re-send it.",
  not_executed: "The call never reached the backend. It is safe to send again (as a new call).",
  unknown: "The call was dispatched but its outcome is unknown. Do NOT retry blindly; check the backend first.",
};

export function outcomeSummary(row: Record<string, unknown>, replayed: boolean): CallToolResult {
  return {
    isError: row.state !== "executed",
    content: [{ type: "text", text: JSON.stringify({
      code: "call_outcome",
      state: row.state,
      final_outcome: row.final_outcome ?? null,
      result_status: row.result_status ?? null,
      pending_call_id: row.pending_call_id ?? null,
      call_id: row.call_id,
      result_available: false,
      ...(replayed ? { replayed: true } : {}),
      message: OUTCOME_MESSAGES[String(row.state)] ?? "",
    }) }],
  };
}

type EnforceInput = {
  ctx: CallContext;
  args: Record<string, unknown>;
  dispatch: (args: Record<string, unknown>) => Promise<CallToolResult>;
  signal?: AbortSignal;
  approveBaseUrl?: string | null;
  /** Opt-in: return approval_pending immediately instead of holding the request open */
  asyncApproval?: boolean;
  /** Called every progressIntervalMs while the request is held */
  onProgress?: (p: { pendingCallId: string; elapsedMs: number; expiresAt: string }) => void;
  /** Client-chosen key: a re-send with the same key never runs again (R-1) */
  idempotencyKey?: string | null;
};
type CoreOut = { callId: string; tracked: boolean; earlyReturn: boolean; duplicateKey?: boolean };
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export function policyDeniedResult(p: {
  reason: DenyReason;
  tool: string;
  ruleId?: string | null;
  ruleVersion?: number | null;
  pendingCallId?: string | null;
  message?: string | null;
  note?: string | null;
  /** 0011 pending_call.cancel_reason, when a hold was cancelled */
  cancelReason?: string | null;
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
  if (p.cancelReason) payload.cancel_reason = p.cancelReason;
  payload.message = p.message ?? (p.cancelReason && CANCEL_MESSAGES[p.cancelReason]) ?? DEFAULT_MESSAGES[p.reason];
  return { isError: true, content: [{ type: "text", text: JSON.stringify(payload) }] };
}

const CANCEL_MESSAGES: Record<string, string> = {
  agent_suspended: "The pending call was cancelled because the calling agent was suspended.",
  agent_revoked: "The pending call was cancelled because the calling agent was revoked.",
  key_revoked: "The pending call was cancelled because the API key was revoked.",
  no_active_approver: "The pending call was cancelled because no listed approver is an active human any more.",
  client_disconnected: "The pending call was cancelled because the client disconnected.",
  shutdown: "The pending call was cancelled because the gateway shut down; nothing was dispatched.",
};

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
  unknown_tool: "This tool is not in the backend's tool list (names must match exactly); nothing was dispatched.",
  unknown_backend: "Unknown backend; nothing was dispatched.",
  no_active_project: "No active project for this agent; nothing was dispatched.",
  invalid_idempotency_key: "Idempotency keys are 1-128 printable ASCII characters; nothing was dispatched.",
  idempotency_conflict: "This idempotency key was already used with different arguments; nothing was dispatched.",
  gateway_shutting_down: "The gateway is shutting down; nothing was dispatched. Retry after it restarts.",
  no_active_approver: "No listed approver is an active human, so this call cannot be approved; nothing was dispatched.",
};

export class PolicyEnforcer {
  private readonly waiters = new Map<string, (r: Resolution) => void>();
  /** Dispatched calls not yet completed (QA V51-F1 shutdown drain). */
  private readonly inflight = new Map<string, { ctx: CallContext; started: number; pendingCallId: string | null; decision: Decision; promise: Promise<CallToolResult> }>();
  private draining = false;
  /** Timer teardown per open hold, so close() can stop polling a DB that is about to close. */
  private readonly waitTimers = new Map<string, () => void>();
  private closed = false;
  private readonly clock: () => number;

  constructor(private readonly deps: EnforcerDeps) {
    this.clock = deps.clock ?? Date.now;
  }

  /** T2.4: install the approver notifier (Web Push). */
  /**
   * Stop all hold timers (QA v2 Low). Called by Store.close() before the DB closes. Open holds are
   * left unresolved in this process; the next start's recoverOrphans() cancels them durably.
   */
  close(): void {
    this.closed = true;
    for (const stop of this.waitTimers.values()) stop();
    this.waitTimers.clear();
  }

  /**
   * QA V51-F1 step 1: stop taking new calls, and close this process's holds that have not been
   * dispatched (pending -> cancelled, approved-undispatched -> abandoned). Dispatched calls keep running.
   */
  beginShutdown(): RecoveryCounts & { byWorkspace: Record<string, RecoveryCounts> } {
    this.draining = true;
    return this.recoverOrphans({ holdsOnly: true, note: "gateway shutdown" });
  }

  waiterCount(): number {
    return this.waiters.size;
  }

  /** Forced stop (second signal): record every still-running dispatched call as outcome unknown, now. */
  markInflightUnknown(): Record<string, number> {
    const n: Record<string, number> = {};
    for (const [callId, e] of [...this.inflight.entries()]) {
      this.completion(callId, e.ctx, {
        final_outcome: "error", result_status: "error", error_code: "shutdown_unknown",
        latency_ms: this.clock() - e.started, rule_id: e.decision.rule?.ruleId ?? null,
        rule_version: e.decision.rule?.version ?? null, pending_call_id: e.pendingCallId,
      });
      this.inflight.delete(callId);
      n[e.ctx.workspaceId] = (n[e.ctx.workspaceId] ?? 0) + 1;
    }
    return n;
  }

  inflightCount(): number {
    return this.inflight.size;
  }

  /**
   * QA V51-F1 step 2: wait up to graceMs for dispatched calls to finish (their normal completion is
   * written). Calls still running after the grace period get a completion row now (error/error,
   * error_code shutdown_unknown -> outcome unknown): they may or may not have run.
   */
  async drain(graceMs: number): Promise<{ drained: number; unknown: number; byWorkspace: Record<string, { drained: number; unknown: number }> }> {
    const snapshot = [...this.inflight.entries()];
    const byWorkspace: Record<string, { drained: number; unknown: number }> = {};
    const slot = (ws: string) => (byWorkspace[ws] ??= { drained: 0, unknown: 0 });
    if (snapshot.length) {
      let timer: ReturnType<typeof setTimeout> | undefined;
      await Promise.race([
        Promise.allSettled(snapshot.map(([, e]) => e.promise)),
        new Promise<void>((r) => { timer = setTimeout(r, Math.max(0, graceMs)); }),
      ]);
      if (timer) clearTimeout(timer);
    }
    let drained = 0;
    let unknown = 0;
    for (const [callId, e] of snapshot) {
      if (!this.inflight.has(callId)) {
        drained++;
        slot(e.ctx.workspaceId).drained++;
        continue;
      }
      this.completion(callId, e.ctx, {
        final_outcome: "error",
        result_status: "error",
        error_code: "shutdown_unknown",
        latency_ms: this.clock() - e.started,
        rule_id: e.decision.rule?.ruleId ?? null,
        rule_version: e.decision.rule?.version ?? null,
        pending_call_id: e.pendingCallId,
      });
      this.inflight.delete(callId);
      unknown++;
      slot(e.ctx.workspaceId).unknown++;
    }
    return { drained, unknown, byWorkspace };
  }

  /** Number of holds with live timers (tests). */
  activeHoldTimers(): number {
    return this.waitTimers.size;
  }

  setNotifier(notify: ApprovalNotifier | undefined): void {
    this.deps.notify = notify;
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

  /**
   * QA T2.5 F1/F2: a call refused by the gateway before policy runs (unknown backend, no active
   * project, tool name not exactly in the backend catalog). Writes the decision + completion pair
   * (Q6: gateway failure before dispatch = error/not_dispatched). Fails closed if audit is down.
   */
  refuseBeforePolicy(
    ctx: Partial<CallContext> & { workspaceId: string; agentId: string; keyId: string },
    reason: "unknown_tool" | "unknown_backend" | "no_active_project" | "gateway_shutting_down",
    requested: string,
    args: Record<string, unknown>,
  ): CallToolResult {
    const callId = newId("call");
    const cols = {
      call_id: callId,
      workspace_id: ctx.workspaceId,
      agent_id: ctx.agentId,
      agent_name: ctx.agentName ?? null,
      key_id: ctx.keyId,
      key_prefix: ctx.keyPrefix ?? null,
      project_id: ctx.projectId ?? null,
      backend_slug: ctx.backendSlug ?? null,
      // the caller's spelling, stored as data only (never used for matching)
      tool: requested.slice(0, 512),
      qualified_tool: null,
      args_redacted: JSON.stringify(sanitizeForAudit(args ?? {})),
      args_hash: argsHash(this.deps.keys.argsHmac, args ?? {}),
    };
    try {
      this.tx(() => {
        this.writeAudit({ event_type: "decision", ...cols, policy_decision: "deny", error_code: reason });
        this.writeAudit({
          event_type: "completion", ...cols, final_outcome: "error", result_status: "not_dispatched",
          error_code: reason, latency_ms: 0,
        });
      });
    } catch {
      return policyDeniedResult({ reason: "audit_unavailable", tool: requested });
    }
    return policyDeniedResult({ reason, tool: requested });
  }

  /** Drop tools that policy denies for every args (listing only; errors keep the tool listed). */
  hideAlwaysDenied<T extends { backendSlug: string; upstreamName: string }>(
    tools: T[],
    who: { workspaceId: string; agentId: string; projectId: string },
  ): T[] {
    let rules: PolicyRule[];
    try {
      rules = loadActiveRules(this.deps.db, who.workspaceId);
    } catch {
      return tools;
    }
    return tools.filter((t) => {
      try {
        return !alwaysDenied(rules, { agentId: who.agentId, projectId: who.projectId, backendSlug: t.backendSlug, tool: t.upstreamName });
      } catch {
        return true;
      }
    });
  }

  agentHolds(agentId: string): number {
    return (
      this.deps.db
        .prepare(`SELECT count(*) AS n FROM mcpflow_pending_call WHERE agent_id = ? AND status = 'pending'`)
        .get(agentId) as { n: number }
    ).n;
  }

  /**
   * Approver view of a pending call (Security T2.5 H-1): the exact args that will run, decrypted
   * from the ciphertext, plus a sha256 over their canonical JSON that approve/deny can echo back.
   * Null once resolved (ciphertext purged).
   */
  approverArgs(pendingCallId: string): { args: Record<string, unknown>; sha256: string } | null {
    const row = this.deps.db
      .prepare(`SELECT args_ciphertext, args_hash FROM mcpflow_pending_call WHERE id = ?`)
      .get(pendingCallId) as { args_ciphertext: Uint8Array | null; args_hash: string } | undefined;
    if (!row?.args_ciphertext) return null;
    const args = decryptArgs(this.deps.keys.argsEnc, row.args_ciphertext);
    if (argsHash(this.deps.keys.argsHmac, args) !== row.args_hash) throw new Error("args hash mismatch");
    return { args, sha256: createHash("sha256").update(canonicalJson(args), "utf8").digest("hex") };
  }

  /**
   * Public entry. Idempotency (Security T2.5 R-1): a call carrying an idempotency key is recorded
   * durably; a re-send with the same key never runs again — it replays the stored outcome
   * (or approval_pending), and a re-send with different args is refused.
   */
  async enforce(input: EnforceInput): Promise<CallToolResult> {
    // QA V51-F1: once shutdown starts, new calls are refused cleanly (audited, nothing dispatched)
    if (this.draining) {
      return this.refuseBeforePolicy(input.ctx, "gateway_shutting_down", input.ctx.qualifiedTool, input.args ?? {});
    }
    const key = input.idempotencyKey;
    if (key !== undefined && key !== null) {
      if (typeof key !== "string" || !/^[\x21-\x7e]{1,128}$/.test(key)) {
        return policyDeniedResult({ reason: "invalid_idempotency_key", tool: input.ctx.qualifiedTool });
      }
      const prior = this.outcomeByKey(input.ctx.agentId, key);
      if (prior) return this.replay(prior, argsHash(this.deps.keys.argsHmac, input.args), input.ctx.qualifiedTool);
    }
    const out: CoreOut = { callId: newId("call"), tracked: false, earlyReturn: false };
    let res: CallToolResult;
    try {
      res = await this.enforceCore(input, out);
    } catch (err) {
      if (out.duplicateKey && key) {
        const prior = this.outcomeByKey(input.ctx.agentId, key);
        if (prior) return this.replay(prior, argsHash(this.deps.keys.argsHmac, input.args), input.ctx.qualifiedTool);
      }
      throw err;
    }
    if (out.tracked && !out.earlyReturn) this.storeResult(out.callId, res);
    return res;
  }

  private async enforceCore(input: EnforceInput, out: CoreOut): Promise<CallToolResult> {
    const { ctx, args } = input;
    const db = this.deps.db;
    const callId = out.callId;
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
    let noApprover = false;
    try {
      this.tx(() => {
        if (decision.decision === "require_approval") {
          grantId = this.matchLiveGrant(ctx, args, hash, decision);
          if (
            !grantId &&
            (this.holds(ctx.workspaceId) >= (this.deps.maxHolds ?? 32) ||
              this.agentHolds(ctx.agentId) >= (this.deps.maxHoldsPerAgent ?? 8))
          ) {
            busy = true;
          }
          // 0011 / T2.1 §10.5: fail closed when no listed approver is an active human (same check as the
          // mcpflow_pending_call_ins_active_approver trigger, done first so the decision row is still written)
          if (!grantId && !busy && !this.hasActiveApprover(decision.approvers ?? [])) noApprover = true;
        }
        this.writeAudit({
          event_type: "decision",
          call_id: callId,
          ...this.ctxCols(ctx),
          args_redacted: JSON.stringify(redacted),
          args_hash: hash,
          // T2.1 §10: a require_approval covered by a live grant is an allow; rule_id stays the overridden rule
          policy_decision: grantId ? "allow" : decision.decision,
          rule_id: decision.rule?.ruleId ?? null,
          rule_version: decision.rule?.version ?? null,
          matched_rule_ids: JSON.stringify(decision.matched.map((r) => r.ruleId)),
          grant_id: grantId,
          error_code: decision.decision === "deny" ? decision.reason : busy ? "approval_busy" : noApprover ? "no_active_approver" : null,
        });
        if (decision.decision === "require_approval" && !grantId && !busy && !noApprover) {
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
        // R-1: durable outcome row for idempotent calls and for async holds
        if (input.idempotencyKey || (input.asyncApproval && pendingId)) {
          out.tracked = true;
          try {
            db.prepare(
              `INSERT INTO mcpflow_call_outcome (call_id, pending_call_id, workspace_id, agent_id, key_id, idempotency_key,
                 qualified_tool, args_hash, async, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            ).run(callId, pendingId, ctx.workspaceId, ctx.agentId, ctx.keyId, input.idempotencyKey ?? null,
              ctx.qualifiedTool, hash, input.asyncApproval && pendingId ? 1 : 0, this.iso());
          } catch (err) {
            if (/UNIQUE/.test((err as Error).message)) out.duplicateKey = true;
            throw err;
          }
        }
      });
    } catch (err) {
      if (out.duplicateKey) throw new Error("duplicate idempotency key");
      // the DB trigger is the backstop for the pre-check above
      if (/no_active_approver/.test((err as Error).message)) {
        return policyDeniedResult({ reason: "no_active_approver", tool: ctx.qualifiedTool, ruleId: decision.rule?.ruleId, ruleVersion: decision.rule?.version });
      }
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
    if (decision.decision === "deny" || busy || noApprover) {
      const reason: DenyReason = busy ? "approval_busy" : noApprover ? "no_active_approver" : (decision.reason as DenyReason);
      // db-t2.1 §10: no_active_approver at hold time is recorded as cancelled/not_dispatched
      notDispatched(noApprover ? "cancelled" : "denied", { error_code: reason });
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
          argsHidden: canonicalJson(redacted) !== canonicalJson(args ?? {}),
          approveBaseUrl: input.approveBaseUrl ?? null,
        })
        .catch(() => undefined);
    }
    const rest = async (signal?: AbortSignal): Promise<CallToolResult> => {
      const resolution = await this.waitFor(pc, expiresAt!, signal);
      const row = db
        .prepare(`SELECT status, decided_by, note, cancel_reason FROM mcpflow_pending_call WHERE id = ?`)
        .get(pc) as { status: string; decided_by: string | null; note: string | null; cancel_reason: string | null };
      const status = row?.status ?? resolution;

      if (status === "approved") {
        if (!this.claimDispatch(pc)) {
          notDispatched("error", { error_code: "dispatch_conflict", approver: row.decided_by });
          return policyDeniedResult({ reason: "dispatch_conflict", tool: ctx.qualifiedTool, pendingCallId: pc });
        }
        const stored = db.prepare(`SELECT args_ciphertext, args_hash FROM mcpflow_pending_call WHERE id = ?`).get(pc) as {
          args_ciphertext: Uint8Array | null;
          args_hash: string;
        };
        let frozen: Record<string, unknown>;
        try {
          frozen = decryptArgs(this.deps.keys.argsEnc, stored.args_ciphertext!);
          // Security T2.5 H-1: dispatch only the exact payload the approver was shown and approved
          if (argsHash(this.deps.keys.argsHmac, frozen) !== stored.args_hash) throw new Error("args hash mismatch");
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
      let [outcome, reason] = map[status] ?? ["cancelled", "cancelled"];
      // 0011: DB-side cancels (revoke/suspend cascades, last approver gone) carry cancel_reason
      const cancelReason = status === "cancelled" ? (row?.cancel_reason ?? null) : null;
      if (cancelReason === "no_active_approver") reason = "no_active_approver";
      notDispatched(outcome, {
        error_code: cancelReason === "no_active_approver" || !cancelReason ? reason : cancelReason,
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
        cancelReason,
      });
    };

    // approval_pending early return (opt-in): the hold continues in the background; the agent
    // polls mf_pending_status and collects the outcome once with mf_pending_result.
    if (input.asyncApproval) {
      out.earlyReturn = true;
      this.inflightAsync.add(pc);
      void rest(undefined)
        .then((res) => this.storeResult(callId, res))
        .catch(() => this.storeResult(callId, policyDeniedResult({ reason: "policy_unavailable", tool: ctx.qualifiedTool, pendingCallId: pc })))
        .finally(() => this.inflightAsync.delete(pc));
      return {
        isError: true,
        content: [{
          type: "text",
          text: JSON.stringify({
            code: "approval_pending",
            pending_call_id: pc,
            tool: ctx.qualifiedTool,
            expires_at: expiresAt,
            message: "This call needs human approval. Poll mf_pending_status; when it is resolved, call mf_pending_result once to get the outcome. Do not re-send the call (a re-send with the same idempotency key replays this outcome).",
          }),
        }],
      };
    }

    // MCP progress notifications while the caller waits (every 15 s by default)
    const progress = input.onProgress
      ? setInterval(() => {
          try {
            input.onProgress!({ pendingCallId: pc, elapsedMs: this.clock() - started, expiresAt: expiresAt! });
          } catch {
            /* progress is best effort */
          }
        }, this.deps.progressIntervalMs ?? PROGRESS_INTERVAL_MS)
      : undefined;
    try {
      return await rest(input.signal);
    } finally {
      if (progress) clearInterval(progress);
    }
  }

  // ---------- durable outcomes (Security T2.5 R-1/R-2; migration 0006) ----------

  private readonly inflightAsync = new Set<string>();

  /** Security R2-1: scoped to the AGENT (survives key rotation); agent ids are server-derived. */
  private outcomeByKey(agentId: string, key: string): Record<string, unknown> | undefined {
    return this.deps.db
      .prepare(`SELECT * FROM mcpflow_call_outcome WHERE agent_id = ? AND idempotency_key = ? ORDER BY created_at LIMIT 1`)
      .get(agentId, key) as Record<string, unknown> | undefined;
  }

  /** A re-send with a known idempotency key: never runs again. R2-2: tool (incl. backend) must match too. */
  private replay(prior: Record<string, unknown>, hash: string, qualifiedTool: string): CallToolResult {
    if (String(prior.args_hash) !== hash || String(prior.qualified_tool ?? "") !== qualifiedTool) {
      return policyDeniedResult({
        reason: "idempotency_conflict",
        tool: qualifiedTool,
        message: "This idempotency key was already used for a different tool or different arguments; nothing was dispatched.",
      });
    }
    if (prior.state === "pending") {
      return {
        isError: true,
        content: [{ type: "text", text: JSON.stringify({
          code: prior.pending_call_id ? "approval_pending" : "in_progress",
          pending_call_id: prior.pending_call_id ?? null,
          call_id: prior.call_id,
          replayed: true,
          message: "This call is already in progress; it was not sent again.",
        }) }],
      };
    }
    const stored = this.readResult(String(prior.call_id), false);
    if (stored) return stored;
    return outcomeSummary(prior, true);
  }

  /** Persist a (capped, encrypted) result for a tracked call; enforce global caps. */
  private storeResult(callId: string, result: CallToolResult): void {
    try {
      let json = JSON.stringify(result);
      let truncated = 0;
      const max = this.deps.maxResultBytes ?? MAX_RESULT_BYTES;
      if (Buffer.byteLength(json, "utf8") > max) {
        truncated = 1;
        const text = (result.content ?? [])
          .map((c) => (c && typeof c === "object" && (c as { type?: string }).type === "text" ? String((c as { text?: unknown }).text ?? "") : `[${(c as { type?: string })?.type ?? "content"} omitted]`))
          .join("\n");
        json = JSON.stringify({
          isError: Boolean(result.isError),
          content: [{ type: "text", text: `${text.slice(0, Math.floor(max / 2))}\n…[result truncated by mcp-flow]` }],
        });
      }
      const bytes = Buffer.byteLength(json, "utf8");
      this.deps.db
        .prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = ?, result_bytes = ?, result_truncated = ? WHERE call_id = ? AND result_purged_at IS NULL AND result_read_at IS NULL`)
        .run(encryptArgs(this.deps.keys.resultEnc, JSON.parse(json)), bytes, truncated, callId);
      this.purgeResults();
    } catch (err) {
      console.error(`[mcp-flow] storing result for ${callId} failed: ${redactSecrets((err as Error).message)}`);
    }
  }

  /** R-2: drop stored results past their TTL, then oldest-first until under the total byte cap. */
  purgeResults(): number {
    const db = this.deps.db;
    const now = this.iso();
    const cutoff = this.iso(this.clock() - (this.deps.resultTtlMs ?? RESULT_TTL_MS));
    let n = Number(db.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = NULL, result_purged_at = ?
                                  WHERE result_ciphertext IS NOT NULL AND completed_at < ?`).run(now, cutoff).changes);
    // R2-3: per-agent quota first, so an agent over its share only evicts its own results
    const agentCap = this.deps.maxResultAgentBytes ?? MAX_RESULT_AGENT_BYTES;
    const over = db.prepare(`SELECT agent_id, sum(result_bytes) AS t FROM mcpflow_call_outcome WHERE result_ciphertext IS NOT NULL
                              GROUP BY agent_id HAVING sum(result_bytes) > ?`).all(agentCap) as Array<{ agent_id: string; t: number }>;
    for (const o of over) {
      let t = Number(o.t);
      const rows = db.prepare(`SELECT call_id, result_bytes FROM mcpflow_call_outcome WHERE result_ciphertext IS NOT NULL AND agent_id = ?
                                ORDER BY completed_at, call_id`).all(o.agent_id) as Array<{ call_id: string; result_bytes: number }>;
      for (const r of rows) {
        if (t <= agentCap) break;
        db.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = NULL, result_purged_at = ? WHERE call_id = ?`).run(now, r.call_id);
        t -= Number(r.result_bytes ?? 0);
        n++;
      }
    }
    const cap = this.deps.maxResultTotalBytes ?? MAX_RESULT_TOTAL_BYTES;
    let total = Number((db.prepare(`SELECT coalesce(sum(result_bytes),0) AS t FROM mcpflow_call_outcome WHERE result_ciphertext IS NOT NULL`).get() as { t: number }).t);
    while (total > cap) {
      const oldest = db.prepare(`SELECT call_id, result_bytes FROM mcpflow_call_outcome WHERE result_ciphertext IS NOT NULL ORDER BY completed_at, call_id LIMIT 1`).get() as { call_id: string; result_bytes: number } | undefined;
      if (!oldest) break;
      db.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = NULL, result_purged_at = ? WHERE call_id = ?`).run(now, oldest.call_id);
      total -= Number(oldest.result_bytes ?? 0);
      n++;
    }
    return n;
  }

  private readResult(callId: string, consume: boolean): CallToolResult | null {
    const row = this.deps.db.prepare(`SELECT result_ciphertext FROM mcpflow_call_outcome WHERE call_id = ?`).get(callId) as { result_ciphertext: Uint8Array | null } | undefined;
    if (!row?.result_ciphertext) return null;
    let res: CallToolResult;
    try {
      res = decryptArgs(this.deps.keys.resultEnc, row.result_ciphertext) as unknown as CallToolResult;
    } catch {
      return null; // undecryptable (e.g. written under the pre-R2-7 key): fall back to the outcome summary
    }
    if (consume) {
      this.deps.db.prepare(`UPDATE mcpflow_call_outcome SET result_ciphertext = NULL, result_read_at = ? WHERE call_id = ?`).run(this.iso(), callId);
    }
    return res;
  }

  /**
   * mf_pending_result: one-time read of an approval_pending call's result, same agent + key only.
   * After the read (or purge/restart) the durable outcome still says executed / not_executed / unknown.
   */
  takeAsyncResult(pc: string, agentId: string, keyId: string): CallToolResult | "not_ready" | "gone" {
    const row = this.deps.db
      .prepare(`SELECT * FROM mcpflow_call_outcome WHERE pending_call_id = ? AND agent_id = ? AND key_id = ?`)
      .get(pc, agentId, keyId) as Record<string, unknown> | undefined;
    if (!row) return "gone";
    if (row.state === "pending" || this.inflightAsync.has(pc)) return "not_ready";
    return this.readResult(String(row.call_id), true) ?? outcomeSummary(row, false);
  }

  /**
   * Startup recovery (single gateway process per DB): every hold whose waiter died with the previous
   * process is closed out so "ran" and "never ran" stay distinguishable, and encrypted args are purged.
   *  - pending                      -> cancelled ('gateway restarted', cancel_reason 'shutdown'), not_executed
   *  - approved, never dispatched   -> abandoned (can never dispatch), not_executed
   *  - dispatched, no completion    -> unknown (do not retry blindly)
   *  - tracked sync calls left open -> executed/not_executed from the audit trail, else unknown
   */
  recoverOrphans(opts: { holdsOnly?: boolean; note?: string } = {}): RecoveryCounts & { byWorkspace: Record<string, RecoveryCounts> } {
    const db = this.deps.db;
    const now = this.iso();
    const out = { cancelled: 0, abandoned: 0, unknown: 0, byWorkspace: {} as Record<string, RecoveryCounts> };
    // R2-7: per-workspace totals, so each workspace's policy.recover audit row carries only its own counts
    const bump = (ws: string, k: keyof RecoveryCounts) => {
      out[k]++;
      (out.byWorkspace[ws] ??= { cancelled: 0, abandoned: 0, unknown: 0 })[k]++;
    };
    const hasCompletion = (callId: string) =>
      Boolean(db.prepare(`SELECT 1 FROM mcpflow_call_audit WHERE call_id = ? AND event_type = 'completion'`).get(callId));
    const complete = (callId: string, finalOutcome: string, resultStatus: string, errorCode: string, pc: string | null) => {
      if (hasCompletion(callId)) return;
      db.prepare(
        `INSERT INTO mcpflow_call_audit (event_type, call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id,
           backend_slug, tool, qualified_tool, placement, device_id, args_hash, pending_call_id, final_outcome, result_status, error_code)
         SELECT 'completion', call_id, workspace_id, agent_id, agent_name, key_id, key_prefix, project_id,
           backend_slug, tool, qualified_tool, placement, device_id, args_hash, ?, ?, ?, ?
           FROM mcpflow_call_audit WHERE call_id = ? AND event_type = 'decision'`,
      ).run(pc, finalOutcome, resultStatus, errorCode, callId);
    };
    const setOutcome = (callId: string, state: string, finalOutcome: string, resultStatus: string) =>
      db.prepare(`UPDATE mcpflow_call_outcome SET state = ?, final_outcome = ?, result_status = ?, completed_at = ? WHERE call_id = ? AND state = 'pending'`)
        .run(state, finalOutcome, resultStatus, now, callId);
    const restartCode = opts.holdsOnly ? "gateway_shutdown" : "gateway_restart";
    this.tx(() => {
      for (const r of db.prepare(`SELECT id, call_id, workspace_id FROM mcpflow_pending_call WHERE status = 'pending'`).all() as Array<{ id: string; call_id: string; workspace_id: string }>) {
        // 0011: a hold cut off by shutdown or by a restart after one is cancel_reason 'shutdown'
        db.prepare(`UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = ?, note = ?, cancel_reason = 'shutdown' WHERE id = ? AND status = 'pending'`).run(now, opts.note ?? 'gateway restarted', r.id);
        complete(r.call_id, "cancelled", "not_dispatched", restartCode, r.id);
        setOutcome(r.call_id, "not_executed", "cancelled", "not_dispatched");
        bump(r.workspace_id, "cancelled");
      }
      for (const r of db.prepare(`SELECT id, call_id, workspace_id FROM mcpflow_pending_call WHERE status = 'approved' AND dispatched_at IS NULL AND abandoned_at IS NULL`).all() as Array<{ id: string; call_id: string; workspace_id: string }>) {
        db.prepare(`UPDATE mcpflow_pending_call SET abandoned_at = ? WHERE id = ?`).run(now, r.id);
        complete(r.call_id, "error", "not_dispatched", restartCode, r.id);
        setOutcome(r.call_id, "not_executed", "error", "not_dispatched");
        bump(r.workspace_id, "abandoned");
      }
      if (!opts.holdsOnly) {
      for (const r of db.prepare(`SELECT id, call_id, workspace_id FROM mcpflow_pending_call WHERE status = 'approved' AND dispatched_at IS NOT NULL`).all() as Array<{ id: string; call_id: string; workspace_id: string }>) {
        if (hasCompletion(r.call_id)) continue;
        complete(r.call_id, "error", "error", "outcome_unknown", r.id);
        setOutcome(r.call_id, "unknown", "error", "error");
        bump(r.workspace_id, "unknown");
      }
      for (const r of db.prepare(`SELECT call_id, workspace_id FROM mcpflow_call_outcome WHERE state = 'pending'`).all() as Array<{ call_id: string; workspace_id: string }>) {
        const c = db.prepare(`SELECT final_outcome, result_status FROM mcpflow_call_audit WHERE call_id = ? AND event_type = 'completion'`).get(r.call_id) as { final_outcome: string; result_status: string } | undefined;
        if (c) setOutcome(r.call_id, outcomeState(c.final_outcome, c.result_status), c.final_outcome, c.result_status);
        else {
          complete(r.call_id, "error", "error", "outcome_unknown", null);
          setOutcome(r.call_id, "unknown", "error", "error");
          bump(r.workspace_id, "unknown");
        }
      }
      }
      // purge every resolved hold's encrypted args (now allowed for abandoned holds too)
      db.prepare(`UPDATE mcpflow_pending_call SET args_ciphertext = NULL WHERE args_ciphertext IS NOT NULL AND status <> 'pending'
                   AND NOT (status = 'approved' AND dispatched_at IS NULL AND abandoned_at IS NULL)`).run();
    });
    return out;
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
  approveSimilar(pendingCallId: string, deciderAgentId: string, minutes: number, opts: { note?: string; matchArgs?: ArgMatcher[]; sameArgsOnly?: boolean } = {}):
    { ok: true; grantId: string } | { ok: false; error: string } {
    const db = this.deps.db;
    const pc = db.prepare(`SELECT * FROM mcpflow_pending_call WHERE id = ?`).get(pendingCallId) as Record<string, unknown> | undefined;
    if (!pc) return { ok: false, error: "not found" };
    // Security T2.5 M-3: grants are bound to the exact args by default; a broader grant needs
    // explicit, validated arg matchers chosen by the approver.
    const sameArgsOnly = opts.sameArgsOnly !== false;
    if (!sameArgsOnly) {
      try {
        opts.matchArgs = validateArgMatchers(opts.matchArgs ?? []);
      } catch (err) {
        return { ok: false, error: `invalid match_args: ${(err as Error).message}` };
      }
      if (!opts.matchArgs.length) return { ok: false, error: "invalid match_args: required when same_args_only is false" };
      try {
        if (!allArgsMatch(opts.matchArgs, decryptArgs(this.deps.keys.argsEnc, pc.args_ciphertext as Uint8Array))) {
          return { ok: false, error: "invalid match_args: does not match the call being approved" };
        }
      } catch {
        return { ok: false, error: "invalid match_args: could not be checked" };
      }
    }
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
          `INSERT INTO mcpflow_policy_grant (id, source_pending_call_id, workspace_id, agent_id, project_id,
             backend_slug, tool, match_args, args_hash, overrides_rule_ids, granted_by, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          grantId, pendingCallId, String(pc.workspace_id), String(pc.agent_id), String(pc.project_id),
          String(pc.backend_slug), String(pc.tool), JSON.stringify(opts.matchArgs ?? []),
          sameArgsOnly ? String(pc.args_hash) : null, JSON.stringify(overrides), deciderAgentId,
          this.iso(now), this.iso(now + Math.min(Math.max(minutes, 1), 60) * 60_000),
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

  /**
   * mf_pending_status: approval status plus the durable outcome (Security T2.5 R-1 supersedes the
   * 0003 "status only" default): outcome = pending | executed | not_executed | unknown. No result body.
   */
  pendingStatus(pendingCallId: string, agentId: string): {
    status: string; expiresAt: string; outcome: string; finalOutcome: string | null; resultStatus: string | null; dispatched: boolean;
    cancelReason: string | null;
  } | null {
    const db = this.deps.db;
    const r = db
      .prepare(`SELECT call_id, status, expires_at, dispatched_at, abandoned_at, cancel_reason FROM mcpflow_pending_call WHERE id = ? AND agent_id = ?`)
      .get(pendingCallId, agentId) as { call_id: string; status: string; expires_at: string; dispatched_at: string | null; abandoned_at: string | null; cancel_reason: string | null } | undefined;
    if (!r) return null;
    const o = db.prepare(`SELECT state, final_outcome, result_status FROM mcpflow_call_outcome WHERE call_id = ?`).get(r.call_id) as
      | { state: string; final_outcome: string | null; result_status: string | null } | undefined;
    const c = o ?? (() => {
      const a = db.prepare(`SELECT final_outcome, result_status FROM mcpflow_call_audit WHERE call_id = ? AND event_type = 'completion'`).get(r.call_id) as
        | { final_outcome: string; result_status: string } | undefined;
      return a ? { state: outcomeState(a.final_outcome, a.result_status), final_outcome: a.final_outcome, result_status: a.result_status } : null;
    })();
    return {
      status: r.status, expiresAt: r.expires_at, outcome: c?.state ?? "pending",
      finalOutcome: c?.final_outcome ?? null, resultStatus: c?.result_status ?? null, dispatched: r.dispatched_at != null,
      cancelReason: r.cancel_reason ?? null,
    };
  }

  // ---------- internals ----------

  private async waitFor(pc: string, expiresAt: string, signal?: AbortSignal): Promise<Resolution> {
    return new Promise<Resolution>((resolve) => {
      let done = false;
      let timer: ReturnType<typeof setTimeout> | undefined;
      // DB-side changes (revoke cascade -> cancelled, another process deciding) are picked up by polling
      const stopTimers = () => {
        clearInterval(poll);
        if (timer) clearTimeout(timer);
        this.waitTimers.delete(pc);
      };
      const poll = setInterval(() => {
        if (this.closed) return stopTimers();
        let st: { status: string } | undefined;
        try {
          st = this.deps.db.prepare(`SELECT status FROM mcpflow_pending_call WHERE id = ?`).get(pc) as { status: string } | undefined;
        } catch {
          return stopTimers(); // DB gone: stop polling; restart recovery closes the hold
        }
        if (st && st.status !== "pending") finish(st.status as Resolution);
      }, HOLD_POLL_MS);
      this.waitTimers.set(pc, stopTimers);
      const finish = (r: Resolution) => {
        if (done) return;
        done = true;
        stopTimers();
        this.waiters.delete(pc);
        signal?.removeEventListener("abort", onAbort);
        resolve(r);
      };
      const onAbort = () => {
        this.deps.db
          .prepare(`UPDATE mcpflow_pending_call SET status = 'cancelled', decided_at = ?, note = 'client disconnected',
                      cancel_reason = 'client_disconnected' WHERE id = ? AND status = 'pending'`)
          .run(this.iso(), pc);
        finish("cancelled");
      };
      const onTimeout = async () => {
        if (this.closed) return stopTimers();
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
      if (this.closed) return stopTimers();
      timer = setTimeout(() => void onTimeout().catch(() => stopTimers()), Math.max(0, Date.parse(expiresAt) - this.clock()) + 5);
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
        .prepare(`UPDATE mcpflow_pending_call SET dispatched_at = ? WHERE id = ? AND status = 'approved' AND dispatched_at IS NULL AND abandoned_at IS NULL`)
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

  private hasActiveApprover(approvers: string[]): boolean {
    if (!approvers.length) return false;
    const r = this.deps.db
      .prepare(
        `SELECT 1 AS ok FROM json_each(?) j JOIN mcpflow_agent a ON a.id = j.value
          WHERE a.kind = 'human' AND a.status = 'active' LIMIT 1`,
      )
      .get(JSON.stringify(approvers));
    return r != null;
  }

  private matchLiveGrant(ctx: CallContext, args: unknown, hash: string, d: Decision): string | null {
    const reqRules = d.matched.filter((r) => r.effect === "require_approval").map((r) => r.ruleId);
    if (d.matched.some((r: PolicyRule) => r.effect === "deny")) return null;
    const now = this.iso();
    // 0010: live grants come from mcpflow_live_policy_grant; there is no use limit, so nothing is bumped.
    // `expires_at > ?` also applies the gateway clock (the view uses SQLite's wall clock).
    const grants = this.deps.db
      .prepare(
        `SELECT id, match_args, args_hash, overrides_rule_ids FROM mcpflow_live_policy_grant
          WHERE agent_id = ? AND project_id = ? AND backend_slug = ? AND tool = ? AND workspace_id = ?
            AND expires_at > ?
          ORDER BY expires_at`,
      )
      .all(ctx.agentId, ctx.projectId, ctx.backendSlug, ctx.tool, ctx.workspaceId, now) as Record<string, unknown>[];
    for (const g of grants) {
      const overrides = new Set(JSON.parse(String(g.overrides_rule_ids)) as string[]);
      if (!reqRules.every((r) => overrides.has(r))) continue;
      if (g.args_hash != null && g.args_hash !== hash) continue;
      let ok = false;
      try {
        ok = allArgsMatch(JSON.parse(String(g.match_args)) as ArgMatcher[], args);
      } catch {
        ok = false; // matcher error = grant does not apply (fail closed to approval)
      }
      if (ok) return String(g.id);
    }
    return null;
  }

  private dispatchAndComplete(
    callId: string,
    ctx: CallContext,
    decision: Decision,
    dispatch: (a: Record<string, unknown>) => Promise<CallToolResult>,
    args: Record<string, unknown>,
    started: number,
    extra: { grantId?: string | null; pendingCallId?: string; approver?: string | null; approverNote?: string | null },
  ): Promise<CallToolResult> {
    // QA V51-F1: track dispatched calls so shutdown can drain them (or record them as unknown)
    const p = this.dispatchAndCompleteInner(callId, ctx, decision, dispatch, args, started, extra);
    this.inflight.set(callId, { ctx, started, pendingCallId: extra.pendingCallId ?? null, decision, promise: p });
    void p.finally(() => this.inflight.delete(callId)).catch(() => {});
    return p;
  }

  private async dispatchAndCompleteInner(
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
      // Security T2.5 L-9: generic message to the agent; details (redacted) stay server-side
      console.error(`[mcp-flow] gateway error on ${callId}: ${redactSecrets(String((err as Error)?.message ?? err))}`);
      result = { isError: true, content: [{ type: "text", text: JSON.stringify({ code: "gateway_error", call_id: callId, message: "The gateway failed to reach the backend." }) }] };
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
    // exactly one completion per call: recovery may already have closed this call out
    if (this.deps.db.prepare(`SELECT 1 FROM mcpflow_call_audit WHERE call_id = ? AND event_type = 'completion'`).get(callId)) return;
    try {
      this.writeAudit({ event_type: "completion", call_id: callId, ...this.ctxCols(ctx), ...cols });
    } catch (err) {
      console.error(`[mcp-flow] completion audit write failed for ${callId}: ${(err as Error).message}`);
    }
    try {
      const fo = String(cols.final_outcome);
      const rs = String(cols.result_status);
      this.deps.db
        .prepare(`UPDATE mcpflow_call_outcome SET state = ?, final_outcome = ?, result_status = ?, completed_at = ? WHERE call_id = ? AND state = 'pending'`)
        .run(outcomeState(fo, rs), fo, rs, this.iso(), callId);
    } catch (err) {
      console.error(`[mcp-flow] outcome write failed for ${callId}: ${(err as Error).message}`);
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
