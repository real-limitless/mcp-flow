import { unseal } from "../crypto.js";
import type { Store } from "../db/store.js";
import type { AuthContext } from "../types.js";
import { fromBase32, verifyTotp } from "./totp.js";
import {
  mfaIsLocked,
  mfaRecordFailure,
  mfaRecordSuccess,
  mfaSubjectKey,
} from "./mfa-lockout.js";

export function operatorSubject(auth: AuthContext): string {
  return auth.kind === "admin" ? "" : (auth.keyId ?? "");
}

export type TotpVerifyResult =
  | { ok: true }
  | { ok: false; error: "locked" | "invalid" | "not_enrolled" };

export function verifyOperatorTotp(
  store: Store,
  workspaceId: string,
  operatorKeyId: string,
  code: string,
  opts: { requireEnrolled?: boolean } = {},
): TotpVerifyResult {
  const subject = mfaSubjectKey(workspaceId, operatorKeyId);
  if (mfaIsLocked(subject)) return { ok: false, error: "locked" };
  const row = store.getOperatorMfaSecretEnc(workspaceId, operatorKeyId);
  if (!row) return { ok: false, error: "not_enrolled" };
  if (opts.requireEnrolled !== false && !row.enrolled) {
    return { ok: false, error: "not_enrolled" };
  }
  let base32 = "";
  try {
    const payload = unseal<{ base32?: string }>(store.masterKey, row.secretEnc);
    base32 = String(payload.base32 ?? "");
  } catch {
    return { ok: false, error: "invalid" };
  }
  const secret = fromBase32(base32);
  if (!verifyTotp(secret, code)) {
    mfaRecordFailure(subject);
    return { ok: false, error: "invalid" };
  }
  mfaRecordSuccess(subject);
  return { ok: true };
}
