import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { sanitizeForAudit } from "../audit/sanitize.js";
import type { Store } from "../db/store.js";
import type { PlacementMode } from "../types.js";
import {
  evaluateAuthzRulesForContexts,
  type AuthzEvalContext,
} from "./match.js";
import type { Approval, AuthzRule } from "./types.js";
import { isAuthzExemptTool } from "./types.js";
import {
  globalApprovalWaiters,
  type ApprovalWaiterMap,
} from "./waiters.js";

export type AuthzDenyReason = "authz_denied" | "authz_timeout" | "authz_busy";

export function asPlacementMode(raw: string | null | undefined): PlacementMode | null {
  if (
    raw === "remote" ||
    raw === "central-sandbox" ||
    raw === "edge-sandbox" ||
    raw === "edge-bare"
  ) {
    return raw;
  }
  return null;
}

export function authzErrorResult(opts: {
  reason: AuthzDenyReason;
  tool: string;
  approvalId?: string;
  waitedSeconds?: number;
  approveUrl?: string | null;
}): CallToolResult {
  const payload: Record<string, unknown> = {
    denied: true,
    reason: opts.reason,
    tool: opts.tool,
  };
  if (opts.approvalId) payload.approvalId = opts.approvalId;
  if (opts.waitedSeconds != null) payload.waitedSeconds = opts.waitedSeconds;
  if (opts.approveUrl) payload.approveUrl = opts.approveUrl;
  if (opts.reason === "authz_timeout") {
    payload.message =
      "This tool required human approval and was not approved in time. Tell the user to open the approve URL (or Admin → Approvals) when a gated tool is running, then retry this tool call.";
  } else if (opts.reason === "authz_denied") {
    payload.message =
      "A human denied this tool call. Tell the user it was blocked.";
  } else {
    payload.message =
      "Too many gated tool calls are waiting for human approval. Retry shortly.";
  }
  return {
    isError: true,
    content: [{ type: "text", text: JSON.stringify(payload, null, 2) }],
  };
}

export function approveUrlFor(
  approveBaseUrl: string | null | undefined,
  approvalId: string,
): string | null {
  if (!approveBaseUrl) return `/admin/#approvals/${approvalId}`;
  const base = approveBaseUrl.replace(/\/$/, "");
  return `${base}/admin/#approvals/${approvalId}`;
}

export function pickAuthzRule(
  store: Store,
  workspaceId: string,
  ctxs: AuthzEvalContext[],
): AuthzRule | null {
  const rules = store.listAuthzRules(workspaceId);
  return evaluateAuthzRulesForContexts(rules, ctxs);
}

export async function runAuthzGate(opts: {
  store: Store;
  workspaceId: string;
  keyId: string | null | undefined;
  tool: string;
  contexts: AuthzEvalContext[];
  args: Record<string, unknown>;
  abortSignal?: AbortSignal;
  approveBaseUrl?: string | null;
  ip?: string | null;
  waiters?: ApprovalWaiterMap;
}): Promise<
  | { proceed: true; frozenArgs: Record<string, unknown> }
  | { proceed: false; result: CallToolResult }
> {
  const tool = opts.tool;
  if (isAuthzExemptTool(tool) && opts.contexts.every((c) => isAuthzExemptTool(c.tool))) {
    return { proceed: true, frozenArgs: opts.args };
  }

  const rule = pickAuthzRule(opts.store, opts.workspaceId, opts.contexts);
  if (!rule) return { proceed: true, frozenArgs: opts.args };

  const waiters = opts.waiters ?? globalApprovalWaiters;
  if (waiters.atCap(opts.workspaceId)) {
    return {
      proceed: false,
      result: authzErrorResult({ reason: "authz_busy", tool }),
    };
  }

  const approval = opts.store.createApproval({
    workspaceId: opts.workspaceId,
    ruleId: rule.id,
    keyId: opts.keyId ?? "",
    tool,
    arguments: opts.args,
    backendSlug: opts.contexts.find((c) => c.backendSlug)?.backendSlug ?? null,
    requirement: rule.requirement,
    ttlSeconds: rule.ttlSeconds,
  });

  const approveUrl = approveUrlFor(opts.approveBaseUrl, approval.id);
  opts.store.writeAudit({
    workspaceId: opts.workspaceId,
    keyId: opts.keyId,
    action: "authz.pending",
    tool,
    backendSlug: approval.backendSlug,
    detail: {
      pending: true,
      approvalId: approval.id,
      ruleId: rule.id,
      requirement: rule.requirement,
      ttlSeconds: rule.ttlSeconds,
      arguments: sanitizeForAudit(opts.args),
      approveUrl,
    },
    ip: opts.ip,
  });

  const started = Date.now();
  const decision = await waiters.wait(approval.id, {
    workspaceId: opts.workspaceId,
    timeoutMs: rule.ttlSeconds * 1000,
    signal: opts.abortSignal,
    onTimeout: () => {
      const expired = opts.store.expireApproval(opts.workspaceId, approval.id);
      if (expired) {
        opts.store.writeAudit({
          workspaceId: opts.workspaceId,
          keyId: opts.keyId,
          action: "authz.timeout",
          tool,
          backendSlug: approval.backendSlug,
          detail: {
            approvalId: approval.id,
            waitedSeconds: rule.ttlSeconds,
            approveUrl,
          },
          ip: opts.ip,
        });
      }
    },
    onAbort: () => {
      opts.store.expireApproval(opts.workspaceId, approval.id);
    },
  });

  const waitedSeconds = Math.max(1, Math.round((Date.now() - started) / 1000));

  if (decision.status === "approved") {
    const row = opts.store.getApproval(opts.workspaceId, approval.id, {
      redact: false,
    });
    const frozen =
      row?.arguments && typeof row.arguments === "object" ? row.arguments : opts.args;
    return { proceed: true, frozenArgs: frozen };
  }

  if (decision.status === "denied") {
    return {
      proceed: false,
      result: authzErrorResult({
        reason: "authz_denied",
        tool,
        approvalId: approval.id,
      }),
    };
  }

  return {
    proceed: false,
    result: authzErrorResult({
      reason: "authz_timeout",
      tool,
      approvalId: approval.id,
      waitedSeconds,
      approveUrl,
    }),
  };
}

export type { Approval };
