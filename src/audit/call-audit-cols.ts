/**
 * SecOPS item 7 (governance side): mcpflow_call_audit text columns are sanitized on WRITE
 * (the table is append-only; existing rows are never rewritten). Same style as audit_events'
 * auditIdent (A0 6aa270c8): embedded secrets redacted, control characters replaced, capped at 256.
 * - free text (qualified_tool, tool, agent_name, error_code): auditText
 * - actor: shape-checked id (agt_<24 hex> or a system actor); anything else is refused without
 *   echoing the value (the 0013 CHECK would refuse it too, but with the value in no message).
 */
import { redactSecrets } from "./sanitize.js";

export const CALL_AUDIT_TEXT_MAX = 256;

/** Redact secrets, replace control characters with "?", cap at max (+ "…"). Idempotent. */
export function auditText(v: unknown, max = CALL_AUDIT_TEXT_MAX): string | null {
  if (v == null) return null;
  const s = redactSecrets(String(v).slice(0, max * 4)).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

const ACTOR_RE = /^(?:agt_[0-9a-f]{24}|system:(?:sweeper|quota))$/;

export function isAuditActor(v: unknown): boolean {
  return typeof v === "string" && ACTOR_RE.test(v);
}

/** actor column: null or a well-formed actor id; throws (value not echoed) otherwise. */
export function auditActor(v: unknown): string | null {
  if (v == null) return null;
  if (!isAuditActor(v)) throw new Error("call_audit actor fails the id shape check (agt_<24 hex> or system:sweeper|quota)");
  return v as string;
}

const TEXT_COLS = ["qualified_tool", "tool", "agent_name", "error_code"] as const;

/** Sanitize a call_audit column map before INSERT (only the columns present are touched). */
export function sanitizeCallAuditCols<T extends Record<string, unknown>>(cols: T): T {
  const out: Record<string, unknown> = { ...cols };
  for (const k of TEXT_COLS) if (k in out) out[k] = auditText(out[k]);
  if ("actor" in out) out.actor = auditActor(out.actor);
  return out as T;
}
