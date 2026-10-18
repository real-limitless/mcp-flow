/**
 * SecOPS item 7 (governance side): mcpflow_call_audit text columns are sanitized on WRITE
 * (the table is append-only; existing rows are never rewritten). Same style as audit_events'
 * auditIdent (A0 6aa270c8): embedded secrets redacted, control characters replaced, capped at 256.
 * - free text (qualified_tool, tool, agent_name, error_code; approver_note capped at 2048): auditText
 * - identifiers (key_prefix, placement, device_id, backend_slug, project_id): shape-checked, else "[invalid]"
 * - actor: shape-checked id (agt_<24 hex> or a system actor); anything else is refused without
 *   echoing the value (the 0013 CHECK would refuse it too, but with the value in no message).
 */
import { redactSecrets } from "./sanitize.js";

export const CALL_AUDIT_TEXT_MAX = 256;

/**
 * Redact secrets, replace control characters with "?", cap at max (+ "…"). Idempotent for
 * single-line text. For multi-line text a second pass can redact more, never less: once a line
 * break became "?", a redacted value runs to the end of the text (e.g. a pending-call note, already
 * sanitized, copied into call_audit.approver_note keeps only the text up to the redacted value).
 */
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

/** Free-text columns and their caps (approver_note is a human's deny note: longer cap). */
export const CALL_AUDIT_NOTE_MAX = 2048;
const TEXT_COLS: Readonly<Record<string, number>> = {
  qualified_tool: CALL_AUDIT_TEXT_MAX,
  tool: CALL_AUDIT_TEXT_MAX,
  agent_name: CALL_AUDIT_TEXT_MAX,
  error_code: CALL_AUDIT_TEXT_MAX,
  approver_note: CALL_AUDIT_NOTE_MAX,
};

/**
 * Identifier columns: kept only when they have the shape the code mints, else "[invalid]" (never free
 * text, so a token passed by mistake is not stored). Same rule as audit_events' auditKeyId/auditSlug.
 * - key_prefix: the 12 base64url characters after "mf_" (LOOKUP_PREFIX_LEN; 8-16 accepted)
 * - placement: one of the PlacementMode values
 * - device_id: an identifier (dev_<24 hex> when minted; letters, digits, _ . : -, max 64)
 * - backend_slug / project_id: a slug, as createBackend / createProject validate it
 */
const ID_COLS: Readonly<Record<string, RegExp>> = {
  key_prefix: /^[A-Za-z0-9_-]{8,16}$/,
  placement: /^(?:remote|central-sandbox|edge-sandbox|edge-bare)$/,
  device_id: /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/,
  backend_slug: /^[a-z][a-z0-9_-]{0,63}$/,
  project_id: /^[a-z][a-z0-9_-]{0,63}$/,
};

export const CALL_AUDIT_INVALID = "[invalid]";

/** Identifier column: null / "" -> null, a well-shaped id as is, anything else "[invalid]". */
export function auditIdCol(col: keyof typeof ID_COLS | string, v: unknown): string | null {
  if (v == null || v === "") return null;
  const re = ID_COLS[col];
  if (!re) throw new Error("unknown call_audit id column");
  return typeof v === "string" && re.test(v) ? v : CALL_AUDIT_INVALID;
}

/** Sanitize a call_audit column map before INSERT (only the columns present are touched). */
export function sanitizeCallAuditCols<T extends Record<string, unknown>>(cols: T): T {
  const out: Record<string, unknown> = { ...cols };
  for (const [k, max] of Object.entries(TEXT_COLS)) if (k in out) out[k] = auditText(out[k], max);
  for (const k of Object.keys(ID_COLS)) if (k in out) out[k] = auditIdCol(k, out[k]);
  if ("actor" in out) out.actor = auditActor(out.actor);
  return out as T;
}
