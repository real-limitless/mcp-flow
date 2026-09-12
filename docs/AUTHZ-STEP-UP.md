# Plan: step-up MFA and notify-then-approve for tool calls

Status: **P7a + TOTP decide (P7b) implemented.** Webhook notify (P7c) and WebAuthn (P7d) are not. Gateway-first. Does not change catalog schema.

Operators should be able to pick **which tools** and **which rules** require a human in the loop before mcp-flow proxies the call:

1. **MFA** — the human proves presence (TOTP / WebAuthn) before the call proceeds.
2. **Notify-then-approve** — mcp-flow posts a notification; a human must **manually approve** (or deny) in Admin (or via a signed webhook callback). The upstream tool does **not** run until that happens.

These are extra gates **after** today’s allow/deny (key scopes, projects, dynamic working set). A tool that is out of scope is still denied; it never reaches MFA or an approval inbox.

## Why hold the HTTP `tools/call`

Harnesses issue `tools/call` and **block that turn** until a result comes back. That is the right place to wait.

If mcp-flow returned immediately with “pending, call `mf_resume_call` later,” many agents would not retry, or they would continue the chat as if the tool never ran. Holding the request keeps the harness in “tool running” until the human decides or the wait expires — one round-trip, no extra meta-tool.

```text
Harness ──tools/call github__delete_repo──► mcp-flow
                                              │
                         match authz rule? ──┤
                            no ──► proxy upstream (today)
                            yes ──► create Approval (pending)
                                  post notification (Admin + optional webhook)
                                  HOLD this HTTP request (default 180s)
                                              │
                    ┌──────── approve ─────────┼──────── deny ────────── timeout ──┐
                    ▼                         ▼                                 ▼
              proxy upstream            return denied                     return denied
              return real result        (human said no)                 (no decision in time)
              on the SAME tools/call   tell agent to tell the user       tell agent to tell the
                                        this was blocked                 user to approve, then retry
```

**Default wait: 180 seconds (3 minutes)** per gated call, configurable per rule (`ttlSeconds`). Clock starts when the approval row is created.

| Decision | Same `tools/call` returns | Agent should |
| --- | --- | --- |
| Approve (and MFA if required) | Real upstream result | Continue |
| Deny | `isError`, `reason: "authz_denied"` | Tell the user the call was blocked |
| Timeout (no tap in 3 min) | `isError`, `reason: "authz_timeout"` | Tell the user to approve in Admin when prompted, then **retry the same tool call** |

Approving is **never** an agent-facing MCP tool (the model must not self-approve). The original request stays open; Admin/webhook only flips the waiter.

**Pre-exec only.** Notify → (wait) → approve → then run. Do not run the tool first and hold the result.

**If the harness disconnects** (client abort, proxy drop): cancel the waiter, mark the approval `expired`, do **not** run upstream. A later retry is a new 3-minute window.

`mf_resume_call` is **not** v1. Timeout means “try again,” not a second protocol.

## Wait vs proxies (ops, not a reason to skip wait)

A 3-minute hold is idle from the proxy’s point of view until the JSON response is written. Reverse proxies often kill idle HTTP around 60s.

mcp-flow must:

- Hold the original HTTP `tools/call` (default 180s) until approve, deny, or timeout.
- Document Traefik/nginx/`respondingTimeouts` / Cloudflare so **idle timeout ≥ `ttlSeconds` + upstream runtime** (suggest ≥ 4 minutes). JSON streamable HTTP (`enableJsonResponse: true`) cannot SSE-ping during the wait, so proxy idle time is the real limit.
- Cap concurrent waiting approvals per workspace (32) so a stuck agent cannot pin the process.
- Not hold a SQLite transaction for the 3 minutes — insert pending, commit, wait in memory, then decide + proxy.

If a deployment cannot raise proxy idle time, lower `ttlSeconds` (e.g. 45s). The protocol stays “wait on this call,” not resume-later.

## What operators select

Two complementary matchers, same requirement enum.

### Tools (explicit)

From the live in-scope catalog (`mf_list_tools` / Admin tool picker):

- Exact namespaced names: `github__delete_repo`, `fs__write_file`
- Optional: whole backend (`github__*`) via the prefix field rather than exploding 200 checkboxes

### Rules (patterns / conditions)

A rule is a named row, enabled/disabled, with a **match** and a **requirement**.

| Match field | Example | Notes |
| --- | --- | --- |
| `prefixes` | `shell__`, `mf_admin_` | Same prefix style as key scopes |
| `backends` | `github`, `fs` | Backend slug |
| `tools` | exact names | Union with prefixes |
| `placements` | `edge-bare` | Placement of the target backend |
| `keys` | specific key ids | Optional; empty = all agent keys |
| `meta` | `mf_admin_*` | Operator tools |

v1 does **not** match on argument values (paths, URLs). That is v2: easy to get wrong, and args are already redacted in audit.

**Evaluation:** among **enabled** rules that match, take the **strictest** requirement:

`none < notify_approve < mfa < mfa_and_approve`

Overlapping “github prefix = notify” and “delete_repo = MFA” → MFA and approve.

Read-only discovery metas stay ungated: `mf_status`, `mf_list_tools`, `mf_list_projects`, `mf_list_backends`, `mf_get_tool_schema`. Gating those would deadlock the agent (and you cannot approve if `mf_status` is stuck). `mf_enable_tools` is **not** gated by default (listing/enabling is not executing). `mf_call_tool` and native `tools/call` share the same wait gate.

## Requirements

| `requirement` | Human action during the wait | Upstream runs when |
| --- | --- | --- |
| `notify_approve` | Inbox + notification; tap Approve/Deny | Approved before timeout |
| `mfa` | TOTP or WebAuthn on the approve page | MFA ok before timeout |
| `mfa_and_approve` | Notification, then MFA **and** explicit Approve | Both before timeout |

**Who is the human?** Workspace **operators** (env admin token or `scopes.admin` keys), not the agent key. Enroll MFA on the operator identity. Agent keys never store TOTP secrets.

**Reuse window (optional per rule):** after successful MFA, skip MFA for the same key + same rule for N seconds (e.g. 5–15 min). Notify-approve does **not** auto-reuse unless the rule sets `autoApproveWindowSeconds` (default 0). Destructive tools should stay 0.

## Timeout / deny payload (agent)

The **same** `tools/call` returns `isError: true` with structured text JSON. No second call.

Timeout (default 3 minutes, no decision):

```json
{
  "denied": true,
  "reason": "authz_timeout",
  "tool": "github__delete_repo",
  "waitedSeconds": 180,
  "approvalId": "appr_…",
  "approveUrl": "https://gateway.example/admin/#approvals/appr_…",
  "message": "This tool required human approval and was not approved in time. Tell the user to open the approve URL (or Admin → Approvals) when a gated tool is running, then retry this tool call."
}
```

Human deny:

```json
{
  "denied": true,
  "reason": "authz_denied",
  "tool": "github__delete_repo",
  "approvalId": "appr_…",
  "message": "A human denied this tool call. Tell the user it was blocked."
}
```

`approveUrl` is useful on timeout if the row is still visible as expired (read-only). A retry creates a **new** approval and a new 3-minute wait. Do not run a timed-out call just because someone taps Approve late.

Audit: `detail.pending` while waiting; then `authz.approve` / `authz.deny` / `authz.timeout` plus the usual `tools/call` result.

## Notifications

Posted **immediately** when the wait starts (second 0), not after timeout.

| Channel | Behavior |
| --- | --- |
| **Admin inbox** | Source of truth. New **Approvals** tab. Live pending + remaining seconds. |
| **Webhook** | Optional `POST` JSON to an operator URL (Slack/n8n/ntfy). HMAC with a sealed workspace secret. Body: approval id, tool, key name/prefix, redacted args, remaining seconds, approve/deny URLs. **No upstream secrets.** |

Email/SMS later. Do not add a mailer in v1.

Webhook **approve/deny** (optional): signed POST back to `/v1/approvals/:id/decision`. Prefer Admin UI for MFA; webhook can do `notify_approve` without MFA. `mfa_*` requirements **must** complete in Admin (or `/approve`) so TOTP never goes through Slack.

## Data model

New tables (SQLite, workspace-scoped). No catalog JSON. Seal MFA secrets with `MCP_FLOW_MASTER_KEY`.

```ts
type AuthzRequirement = "notify_approve" | "mfa" | "mfa_and_approve";

interface AuthzRule {
  id: string;
  workspaceId: string;
  name: string;
  enabled: boolean;
  priority: number; // tie-break only; strictness still wins
  match: {
    tools?: string[];
    prefixes?: string[];
    backends?: string[];
    placements?: PlacementMode[];
    keyIds?: string[];
  };
  requirement: AuthzRequirement;
  ttlSeconds: number; // default 180 (3 minutes)
  mfaReuseSeconds?: number; // default 0
  createdAt: string;
  updatedAt: string;
}

interface Approval {
  id: string;
  workspaceId: string;
  ruleId: string;
  keyId: string;
  tool: string;
  argumentsJson: string; // already sanitizeForAudit
  backendSlug: string | null;
  status: "pending" | "approved" | "denied" | "expired";
  requirement: AuthzRequirement;
  mfaSatisfiedAt: string | null;
  decidedByKeyId: string | null; // operator
  expiresAt: string;
  createdAt: string;
  decidedAt: string | null;
}

interface OperatorMfa {
  workspaceId: string;
  operatorKeyId: string | null; // null = env-admin enrollment
  kind: "totp";
  secretEnc: string; // sealed
  enrolledAt: string;
}
```

In-memory (not SQLite): `Map<approvalId, { resolve, abort }>` so `/v1/approvals/:id/decision` unblocks the waiting `tools/call`. Process restart while waiting → treat as expired (harness will error; user retries).

`WorkspacePolicy` gains optional notify webhook URL + sealed HMAC secret (names only in GET; secret set via PATCH). Optional `authzWaitSeconds` workspace default (180).

Audit actions: `authz.pending`, `authz.approve`, `authz.deny`, `authz.timeout`.

## Gateway hook

After scope / project / dynamic working-set, **before** `upstream.callTool` and before `mf_call_tool`’s inner invoke:

```ts
const gate = evaluateAuthz(store, { workspaceId, keyId, tool, backend, placement });
if (gate) {
  const approval = createApproval({ ttlSeconds: gate.ttlSeconds ?? 180 });
  notifyOperators(approval);
  const decision = await waitForDecision(approval.id, {
    timeoutMs: approval.ttlSeconds * 1000,
    signal: requestAbortSignal, // client disconnect
  });
  if (decision.status !== "approved") {
    return deniedResult(decision); // timeout or deny — do not proxy
  }
  // fall through to upstream.callTool on the same request
}
```

Do not gate env-admin REST `/v1/*` (operators must reach Approvals while a call is waiting). Operator MCP `mf_admin_*` **can** be gated by a rule (recommended starter). Beware: gating every admin tool can lock you out of Approvals over MCP — keep decide on REST/UI.

## Admin UI

New tab **Approvals** (and a **Policy** subsection or Status card):

**Policy / rules**

- List rules: name, match summary, requirement, wait seconds (default 180), on/off
- Create/edit: pick tools from catalog search, prefixes, backends, placements
- Suggested starters (opt-in, not default-on): `mf_admin_*`, `edge-bare`, prefixes the operator types (`shell__`, `fs__`)

**Inbox**

- Pending cards: countdown, key name + prefix, tool, redacted args, rule name
- Approve / Deny (unblocks the waiting HTTP call immediately)
- If requirement includes MFA: TOTP field **before** Approve enables
- Deep link `#approvals/<id>` for notify URL

**Status**

- Count of in-flight waits
- MFA enrolled? yes/no

No agent token in screenshots; prefixes only.

## REST / CLI (operators)

```text
GET    /v1/authz/rules
POST   /v1/authz/rules
PATCH  /v1/authz/rules/:id
DELETE /v1/authz/rules/:id

GET    /v1/approvals?status=pending
POST   /v1/approvals/:id/decision   { "decision": "approve"|"deny", "totp"?: "123456" }

GET    /v1/operators/mfa
POST   /v1/operators/mfa/begin      // secret once; { replace, totp } to rotate
POST   /v1/operators/mfa/confirm    { "totp": "123456" }
POST   /v1/operators/mfa/disable   { "totp": "123456" }
```

CLI: `mcp-flow authz rule add|list`, `mcp-flow approvals list|decide`.

## Suggested starter rules (templates, off until saved)

| Name | Match | Requirement |
| --- | --- | --- |
| Operator tools | prefix `mf_admin_` | `mfa_and_approve` |
| Edge bare | placement `edge-bare` | `mfa_and_approve` |
| Custom destructive | operator-picked prefixes | `notify_approve` or `mfa_and_approve` |

Default workspace: **no rules**. Existing keys keep today’s behavior.

## Security

- Approve/deny only with operator auth (admin token or admin key), never agent key
- Args frozen at pending time; after approve, proxy those args (model cannot swap mid-wait)
- TOTP secret sealed; never in audit, catalog, tool results, or webhooks
- Approval webhook payloads redacted with `sanitizeForAudit`
- Enterprise: deny edge-bare stays independent; this is an extra gate
- Rate-limit TOTP verify; lockout after N failures
- Client abort / process restart: do not execute
- Late approve after timeout: no-op (status already `expired`)

## Phases (implementation order)

| Phase | Deliverable | Unlocks |
| --- | --- | --- |
| **P7a** | Rules + approvals; match engine; **hold `tools/call` up to 180s**; Admin inbox + REST decide; timeout/deny payloads; audit | Notify-then-approve without a resume protocol |
| **P7b** | TOTP enroll + MFA on decide during the wait; `mfa` / `mfa_and_approve`; reuse window | Step-up during the same call |
| **P7c** | Webhook notify + HMAC; one-time decide token for `notify_approve` only | Phone/Slack within the 3-minute window |
| **P7d** | WebAuthn; argument matchers; per-key extras | Harder policies |

Do not block gateway fixes for this. Catalog schema unchanged.

## Tests (when building)

- Rule match: prefix, backend, placement, exact tool; strictest-wins
- Gated call does not hit upstream until approve (mock pool)
- Approve within 3 min: same `tools/call` returns upstream result
- Deny: same call returns `authz_denied`, no upstream
- Fake clock / short ttl: timeout returns `authz_timeout`, message tells agent to instruct the user
- Late approve after timeout does not invoke upstream
- Client abort: no upstream
- Agent key cannot hit `/v1/approvals/:id/decision`
- MFA required: approve without TOTP fails; waiter still running
- Discovery metas still return immediately
- Concurrent wait cap
- Audit has actor key on pending/approve/timeout; no TOTP secret

## Non-goals

- Per-harness native MFA UI (no spec support we can rely on)
- Running the tool before approval
- Letting the model approve via `mf_approve_*`
- `mf_resume_call` in v1 (timeout → retry a new wait)
- Multi-tenant SaaS IdP (self-hosted workspace operators)
- Push/email providers in v1
- Catalog/McpGalleryEntry fields for authz
