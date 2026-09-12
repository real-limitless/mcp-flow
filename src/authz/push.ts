import webpush from "web-push";
import type { Store } from "../db/store.js";
import { requirementNeedsMfa, type Approval } from "./types.js";

export interface ApprovalPushPayload {
  title: string;
  body: string;
  approvalId: string;
  tool: string;
  requirement: string;
  url: string;
  token?: string;
}

export async function notifyApprovalPush(opts: {
  store: Store;
  approval: Approval;
  decideToken: string | null;
  approveBaseUrl?: string | null;
  ttlSeconds: number;
}): Promise<{ sent: number; failed: number }> {
  const subs = opts.store.listPushSubscriptions(opts.approval.workspaceId);
  if (!subs.length) return { sent: 0, failed: 0 };

  const vapid = opts.store.getPushVapid(opts.approval.workspaceId);
  const url = opts.approveBaseUrl
    ? `${opts.approveBaseUrl.replace(/\/$/, "")}/admin/#approvals/${opts.approval.id}`
    : `/admin/#approvals/${opts.approval.id}`;
  const includeToken =
    Boolean(opts.decideToken) && !requirementNeedsMfa(opts.approval.requirement);
  const payload: ApprovalPushPayload = {
    title: "Approve tool call",
    body: `${opts.approval.tool}${opts.approval.keyPrefix ? ` · ${opts.approval.keyPrefix}` : ""}`,
    approvalId: opts.approval.id,
    tool: opts.approval.tool,
    requirement: opts.approval.requirement,
    url,
  };
  if (includeToken && opts.decideToken) payload.token = opts.decideToken;

  const body = JSON.stringify(payload);
  let sent = 0;
  let failed = 0;
  for (const sub of subs) {
    try {
      await webpush.sendNotification(
        {
          endpoint: sub.endpoint,
          keys: { p256dh: sub.p256dh, auth: sub.auth },
        },
        body,
        {
          vapidDetails: {
            subject: vapid.subject,
            publicKey: vapid.publicKey,
            privateKey: vapid.privateKey,
          },
          TTL: Math.max(1, opts.ttlSeconds),
          urgency: "high",
          topic: opts.approval.id.replace(/[^A-Za-z0-9\-_]/g, "").slice(0, 32),
        },
      );
      sent += 1;
    } catch (err) {
      failed += 1;
      const status = (err as { statusCode?: number }).statusCode;
      if (status === 404 || status === 410) {
        opts.store.deletePushSubscriptionByEndpoint(
          opts.approval.workspaceId,
          sub.endpoint,
        );
      }
    }
  }
  return { sent, failed };
}
