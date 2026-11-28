/** Stable rejection codes. Safe to log, audit, and show. Never an email, token, or secret. */
export const PORTAL_SIGNIN_CODES = [
  "state_missing",
  "code_missing",
  "state_cookie",
  "state_mismatch",
  "state_expired",
  "state_unreadable",
  "provider_denied",
  "google_unconfigured",
  "public_url",
  "token_exchange",
  "token_audience",
  "token_issuer",
  "token_expired",
  "token_rejected",
  "email_unverified",
  "nonce",
  "identity_conflict",
  "unknown_account",
  "account_mismatch",
  "hosted_domain",
  "account_inactive",
  "no_workspace",
  "workspace_disabled",
  "agent_inactive",
  "session_rejected",
  "bootstrap_missing",
  "bootstrap_rejected",
  "bootstrap_retired",
  "origin",
  "csrf",
] as const;

export type PortalSignInCode = (typeof PORTAL_SIGNIN_CODES)[number];

const CODE_SET = new Set<string>(PORTAL_SIGNIN_CODES);

export function isPortalSignInCode(value: string): value is PortalSignInCode {
  return CODE_SET.has(value);
}

/** Google's error token, or empty when the value is not a short machine code. */
export function safeProviderCode(raw: string | undefined): string | undefined {
  const value = (raw ?? "").trim();
  return /^[a-z0-9_]{1,40}$/.test(value) ? value : undefined;
}
