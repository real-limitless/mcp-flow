/** In-memory TOTP verify lockout (per operator subject). */

const FAIL_LIMIT = 8;
const LOCK_MS = 60_000;

const fails = new Map<string, { n: number; lockedUntil: number }>();

export function mfaSubjectKey(workspaceId: string, operatorKeyId: string): string {
  return `${workspaceId}:${operatorKeyId}`;
}

export function mfaIsLocked(subject: string, now = Date.now()): boolean {
  const row = fails.get(subject);
  if (!row) return false;
  if (row.lockedUntil && now < row.lockedUntil) return true;
  if (row.lockedUntil && now >= row.lockedUntil) {
    fails.delete(subject);
    return false;
  }
  return false;
}

export function mfaRecordFailure(subject: string, now = Date.now()): void {
  const row = fails.get(subject) ?? { n: 0, lockedUntil: 0 };
  const n = row.n + 1;
  fails.set(subject, {
    n,
    lockedUntil: n >= FAIL_LIMIT ? now + LOCK_MS : 0,
  });
}

export function mfaRecordSuccess(subject: string): void {
  fails.delete(subject);
}
