import { redactSecrets } from "../audit/sanitize.js";

/** Redact a message before it is written to the gateway's own stderr. */
export function redactLog(v: unknown): string {
  return redactSecrets(v instanceof Error ? v.message : String(v));
}

/**
 * Line-buffered redaction for a passthrough stream (a backend's stderr): complete lines are
 * redacted and written; a partial line waits for its newline (or is flushed once it passes
 * maxPending, or on flush()) so a secret split across chunks is still seen whole.
 */
export function lineRedactor(
  write: (s: string) => void,
  maxPending = 64 * 1024,
): { push: (chunk: string) => void; flush: () => void } {
  let pending = "";
  return {
    push(chunk: string) {
      pending += chunk;
      const nl = pending.lastIndexOf("\n");
      if (nl >= 0) {
        write(redactSecrets(pending.slice(0, nl + 1)));
        pending = pending.slice(nl + 1);
      }
      if (pending.length > maxPending) {
        write(redactSecrets(pending));
        pending = "";
      }
    },
    flush() {
      if (pending) write(redactSecrets(pending));
      pending = "";
    },
  };
}
