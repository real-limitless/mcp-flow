/**
 * T2.4 — approver notification, Web Push only (mcp-flow PM decision 2026-10-14).
 *
 * - Targets subscriptions owned by the call's human approver agents.
 *   If no approver has a linked device yet, falls back to the workspace's unlinked operator
 *   devices (audience "workspace") so a hold is never silent; linked devices of non-approvers
 *   are never targeted.
 * - Payload: agent, project, backend/tool, short redacted args summary, expiry, pending id, URL.
 *   It carries NO decide token: approvers decide in the authenticated admin UI (T2.3), where the
 *   pending_call triggers enforce approver identity. Nothing in a push can approve a call.
 * - Send failures are audited; 404/410 subscriptions are pruned. A failed push never approves.
 */
import webpush from "web-push";
import type { Store } from "../db/store.js";
import type { ApprovalNotifier, PendingNotice } from "./enforcer.js";

export interface PendingPushPayload {
  title: string;
  body: string;
  kind: "pending_call";
  pendingCallId: string;
  agent: string;
  project: string;
  backend: string;
  tool: string;
  argsSummary: string;
  expiresAt: string;
  reason: string | null;
  /** Absolute link from configured MCP_FLOW_PUBLIC_URL; null when unset (fail closed: no link) */
  url: string | null;
  /** Redaction/truncation hid part of the args: open the full view before deciding */
  argsHidden: boolean;
  audience: "approver" | "workspace";
}

export const ARGS_SUMMARY_MAX = 200;

type Sender = typeof webpush.sendNotification;

export function buildPendingPayload(
  n: PendingNotice,
  audience: "approver" | "workspace",
  approveBaseUrl?: string | null,
): PendingPushPayload {
  const raw = JSON.stringify(n.argsRedacted ?? {});
  const argsSummary0 = raw.length > ARGS_SUMMARY_MAX ? `${raw.slice(0, ARGS_SUMMARY_MAX)}…` : raw;
  // Security T2.5 H-2: only the configured origin; n.approveBaseUrl (request-derived) is ignored
  const base = approveBaseUrl ? approveBaseUrl.replace(/\/$/, "") : null;
  return {
    title: "Approve tool call",
    body: `${n.agentName} · ${n.backendSlug}__${n.tool} · ${n.projectId}`,
    kind: "pending_call",
    pendingCallId: n.pendingCallId,
    agent: n.agentName,
    project: n.projectId,
    backend: n.backendSlug,
    tool: n.tool,
    argsSummary: argsSummary0,
    expiresAt: n.expiresAt,
    reason: n.reasonToAgent,
    url: base ? `${base}/admin/#pending/${n.pendingCallId}` : null,
    argsHidden: Boolean(n.argsHidden),
    audience,
  };
}

export function createPendingCallNotifier(
  store: Store,
  opts: { approveBaseUrl?: string | null; sender?: Sender; clock?: () => number } = {},
): ApprovalNotifier {
  const send: Sender = opts.sender ?? webpush.sendNotification.bind(webpush);
  const clock = opts.clock ?? Date.now;
  const fn = async (n: PendingNotice) => {
    let subs: Array<{ id: string; endpoint: string; p256dh: string; auth: string }> =
      store.listApproverPushSubscriptions(n.workspaceId, n.approvers);
    let audience: "approver" | "workspace" = "approver";
    if (!subs.length) {
      audience = "workspace";
      const linked = new Set(
        (store.db
          .prepare(`SELECT id FROM push_subscriptions WHERE workspace_id = ? AND agent_id IS NOT NULL`)
          .all(n.workspaceId) as Array<{ id: string }>).map((r) => r.id),
      );
      subs = store.listPushSubscriptions(n.workspaceId).filter((s) => !linked.has(s.id));
    }
    let sent = 0;
    let failed = 0;
    const errors: string[] = [];
    if (subs.length) {
      const vapid = store.getPushVapid(n.workspaceId);
      const body = JSON.stringify(buildPendingPayload(n, audience, opts.approveBaseUrl));
      const ttl = Math.max(1, Math.floor((Date.parse(n.expiresAt) - clock()) / 1000));
      for (const sub of subs) {
        try {
          await send(
            { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
            body,
            {
              vapidDetails: { subject: vapid.subject, publicKey: vapid.publicKey, privateKey: vapid.privateKey },
              TTL: ttl,
              urgency: "high",
              topic: n.pendingCallId.replace(/[^A-Za-z0-9\-_]/g, "").slice(0, 32),
            },
          );
          sent += 1;
        } catch (err) {
          failed += 1;
          const status = (err as { statusCode?: number }).statusCode;
          errors.push(String(status ?? (err as Error).message ?? "error").slice(0, 120));
          if (status === 404 || status === 410) {
            store.deletePushSubscriptionByEndpoint(n.workspaceId, sub.endpoint);
          }
        }
      }
    }
    store.writeAudit({
      workspaceId: n.workspaceId,
      action: "policy.notify",
      tool: `${n.backendSlug}__${n.tool}`,
      backendSlug: n.backendSlug,
      detail: {
        pendingCallId: n.pendingCallId,
        channel: "webpush",
        audience,
        targets: subs.length,
        sent,
        failed,
        ...(errors.length ? { errors } : {}),
        ...(subs.length ? {} : { warning: "no push subscriptions; approver not notified" }),
      },
    });
  };
  return fn;
}
