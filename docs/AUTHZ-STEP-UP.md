# Plan: step-up MFA and notify-then-approve for tool calls

Status: **design only** (not implemented). Gateway-first. Does not change catalog schema.

Operators should be able to pick **which tools** and **which rules** require a human in the loop before mcp-flow proxies the call:

1. **MFA** — the human proves presence (TOTP / WebAuthn) before the call proceeds.
2. **Notify-then-approve** — mcp-flow posts a notification; a human must **manually approve** (or deny) in Admin (or via a signed webhook callback). The upstream tool does **not** run until that happens.

These are extra gates **after** today’s allow/deny (key scopes, projects, dynamic working set). A tool that is out of scope is still denied; it never reaches MFA or an approval inbox.

## Why this shape

Harnesses (IDEs, chatbots) issue `tools/call` and expect a JSON result. They do **not** reliably host a TOTP prompt or an “Approve” button inside the model loop. Holding the HTTP request until a human taps a phone will time out.

So the gateway **fails closed and returns a pending payload**. The agent tells the user to approve. After approval, the **same API key** resumes with `mf_resume_call`. Approving is **never** an agent-facing MCP tool (the model must not be able to self-approve).

```text
Harness ──tools/call github__delete_repo──► mcp-flow
                                              │
                         match authz rule? ──┤
                            no ──► proxy upstream (today)
                            yes ──► create Approval (pending)
                                  post notification
                                  return { pending, approvalId, approveUrl }
                                              │
Human ──Admin / webhook── approve or deny
                                              │
Harness ──mf_resume_call({ approvalId })──► proxy only if approved + unexpired
```

**Pre-exec only (v1).** Notify → approve → then run. Do not run the tool first and hold the result: side effects (delete, send, pay) would already have happened.

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

Read-only discovery metas stay ungated: `mf_status`, `mf_list_tools`, `mf_list_projects`, `mf_list_backends`, `mf_get_tool_schema`. Gating those would deadlock the agent. `mf_enable_tools` is **not** gated by default (listing/enabling is not executing). `mf_call_tool` and native `tools/call` share the same gate.

## Requirements

| `requirement` | Human action | Upstream runs when |
| --- | --- | --- |
| `notify_approve` | Inbox + notification; tap Approve/Deny | Approved |
| `mfa` | TOTP or WebAuthn on the approve page (or a dedicated step-up page) | MFA ok; auto-consumes if no extra approve step |
| `mfa_and_approve` | Notification, then MFA **and** explicit Approve | Both |

**Who is the human?** Workspace **operators** (env admin token or `scopes.admin` keys), not the agent key. Enroll MFA on the operator identity (or a small `operators` table). Agent keys never store TOTP secrets.

**Reuse window (optional per rule):** after successful MFA, skip MFA for the same key + same rule for N seconds (e.g. 5–15 min). Notify-approve does **not** auto-reuse unless the rule sets `autoApproveWindowSeconds` (default 0). Destructive tools should stay 0.

## Pending call contract (agent)

On a gated `tools/call` / `mf_call_tool`, do **not** proxy. Return `isError: true` (so harnesses surface it) with structured text JSON:

```json
{
  "pending": true,
  "reason": "notify_approve",
  "approvalId": "appr_…",
  "tool": "github__delete_repo",
  "expiresAt": "2026-09-12T00:00:00.000Z",
  "approveUrl": "https://gateway.example/admin/#approvals/appr_…",
  "resume": { "tool": "mf_resume_call", "arguments": { "approvalId": "appr_…" } }
}
```

`approveUrl` is the Admin UI deep link. No secrets in the payload. Audit the pending event (`denied` is wrong here — use `detail.pending: true`, `reason: "authz"`).

### `mf_resume_call`

- Always-allowed meta (like `mf_status`) so scoped keys can finish a gated call.
- Args: `{ approvalId }`
- Same `keyId` that created the approval; else deny.
- Status `approved` → proxy the **stored** tool + args (do not let the model swap args on resume).
- Then mark `consumed`. One-shot.
- `denied` / `expired` / `consumed` → error, no proxy.

## Notifications

v1 channels (workspace config, not per-rule except enable/disable):

| Channel | Behavior |
| --- | --- |
| **Admin inbox** | Source of truth. New **Approvals** tab. Poll on Refresh. |
| **Webhook** | Optional `POST` JSON to an operator URL (Slack/n8n/ntfy). HMAC with a sealed workspace secret. Body: approval id, tool, key name/prefix, redacted args, approve/deny URLs. **No upstream secrets.** |

Email/SMS later. Do not add a mailer in v1.

Webhook **approve/deny** (optional): signed POST back to `/v1/approvals/:id/decision` with the operator’s admin bearer **or** a one-time token minted on the approval row (hash at rest, shown in the notify payload). Prefer Admin UI for MFA; webhook can do `notify_approve` without MFA. `mfa_*` requirements **must** complete in Admin (or a small standalone `/approve` page) so TOTP never goes through Slack.

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
  ttlSeconds: number; // default 900
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
  status: "pending" | "approved" | "denied" | "expired" | "consumed";
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

`WorkspacePolicy` gains optional notify webhook URL + sealed HMAC secret (names only in GET; secret set via PATCH).

Audit actions: `authz.pending`, `authz.approve`, `authz.deny`, `authz.expire`, `authz.resume`.

## Gateway hook

Single function, after scope / project / dynamic working-set, **before** `upstream.callTool` and before `mf_call_tool`’s inner invoke:

```ts
const gate = evaluateAuthz(store, { workspaceId, keyId, tool, backend, placement });
if (gate) {
  if (resumeApproval?.status === "approved" && resumeApproval.tool === name) {
    // consume + fall through
  } else {
    return pendingResult(createApproval(...));
  }
}
```

Do not gate env-admin REST `/v1/*` with this (operators need to reach Approvals). Operator MCP `mf_admin_*` **can** be gated by a rule (recommended starter rule).

## Admin UI

New tab **Approvals** (and a **Policy** subsection or Status card):

**Policy / rules**

- List rules: name, match summary, requirement, on/off
- Create/edit: pick tools from catalog search (same as Keys discovery picker), prefixes, backends, placements
- Suggested starters (opt-in, not default-on): `mf_admin_*`, `edge-bare`, prefixes the operator types (`shell__`, `fs__`)

**Inbox**

- Pending cards: time, key name + prefix, tool, redacted args, rule name
- Approve / Deny
- If requirement includes MFA: TOTP field (or WebAuthn later) **before** Approve enables
- Deep link `#approvals/<id>` for `approveUrl`

**Status**

- Count of pending approvals
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
POST   /v1/operators/mfa/enroll    { "totpSecret" shown once / or enroll URL }
POST   /v1/operators/mfa/verify
```

CLI: `mcp-flow authz rule add|list`, `mcp-flow approvals list|decide`.

`mf_admin_list_approvals` / `mf_admin_decide_approval` for operator keys — still MFA-gated in-process when the **rule** requires MFA (Admin TOTP on that tool call is awkward; prefer REST/UI for decide).

## Suggested starter rules (templates, off until saved)

| Name | Match | Requirement |
| --- | --- | --- |
| Operator tools | prefix `mf_admin_` | `mfa_and_approve` |
| Edge bare | placement `edge-bare` | `mfa_and_approve` |
| Custom destructive | operator-picked prefixes | `notify_approve` or `mfa_and_approve` |

Default workspace: **no rules**. Existing keys keep today’s behavior.

## Security

- Approve/deny only with operator auth (admin token or admin key), never agent key
- Resume only same agent `keyId`; args frozen at pending time
- TOTP secret sealed; never in audit, catalog, tool results, or webhooks
- Approval webhook payloads redacted with `sanitizeForAudit`
- Enterprise: deny edge-bare stays independent; this is an extra gate
- Rate-limit TOTP verify; lockout after N failures
- Expired pending rows: sweeper on serve / on list

## Phases (implementation order)

| Phase | Deliverable | Unlocks |
| --- | --- | --- |
| **P7a** | `authz_rules` + `approvals`; match engine; pending return; Admin inbox + REST decide; `mf_resume_call`; audit | Notify-then-approve for selected tools/rules |
| **P7b** | TOTP enroll + MFA on decide; `mfa` / `mfa_and_approve`; reuse window | Step-up |
| **P7c** | Webhook notify + HMAC; one-time decide token for `notify_approve` only | Phone/Slack without sitting on Admin |
| **P7d** | WebAuthn; argument matchers; per-key extras | Harder policies |

Do not block gateway fixes for this. Catalog schema unchanged.

## Tests (when building)

- Rule match: prefix, backend, placement, exact tool; strictest-wins
- Gated call does not hit upstream (mock pool)
- Resume after approve proxies once; second resume fails
- Wrong key cannot resume
- Agent key cannot hit `/v1/approvals/:id/decision`
- MFA required: approve without TOTP fails
- Discovery metas still call without approval
- Audit has actor key on pending/approve/resume; no TOTP secret

## Non-goals

- Per-harness native MFA UI (no spec support we can rely on)
- Running the tool before approval
- Letting the model approve via `mf_approve_*`
- Multi-tenant SaaS IdP (self-hosted workspace operators)
- Push/email providers in v1
- Catalog/McpGalleryEntry fields for authz
