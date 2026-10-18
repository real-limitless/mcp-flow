import { isSecretName, redactSecrets } from "../audit/sanitize.js";

/** Redact a message before it is written to the gateway's own stderr. */
export function redactLog(v: unknown): string {
  return redactSecrets(v instanceof Error ? v.message : String(v));
}

const PEM_BEGIN_RE = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----/g;
const PEM_END_RE = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----/;
/** Max lines redacted after a PEM BEGIN line without an END marker before the state resets. */
export const PEM_MAX_LINES = 200;
/** Max partial-line tail kept back after a forced flush (the cut is at the last whitespace). */
export const PENDING_TAIL_MAX = 4 * 1024;

/** A segment that ends in a secret NAME= / NAME: (or Bearer / --password) with no value yet. */
const DANGLING_NAME_RE = /(?:^|[^A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]{0,255})["']?[ \t]*[=:][ \t]*["']?$/;
const DANGLING_SCHEME_RE = /(?:\b(?:Bearer|Basic|Token|Digest)|--(?:password|token|secret|api-key)|\s-p)[ \t=]*$/i;

function dangling(seg: string): boolean {
  const tail = seg.slice(-512);
  if (DANGLING_SCHEME_RE.test(tail)) return true;
  const m = DANGLING_NAME_RE.exec(tail);
  return !!m && isSecretName(m[1]!);
}

/** Line opens a private key block that it does not close. */
function opensPem(line: string): boolean {
  PEM_BEGIN_RE.lastIndex = 0;
  let last = -1;
  for (let m; (m = PEM_BEGIN_RE.exec(line)); ) last = m.index;
  return last >= 0 && !PEM_END_RE.test(line.slice(last));
}

/**
 * Line-buffered redaction for a passthrough stream (a backend's stderr): complete lines are
 * redacted and written; a partial line waits for its newline so a secret split across chunks
 * is still seen whole.
 *
 * - After a `-----BEGIN … PRIVATE KEY-----` line every following line is written as
 *   [redacted] up to and including the END marker (at most PEM_MAX_LINES, then it resets).
 * - A partial line longer than maxPending is cut at its last whitespace, keeping a tail of at
 *   most PENDING_TAIL_MAX. If what was written ends in a secret NAME= / NAME: (or Bearer …)
 *   with no value, or in a value that may continue, the rest of that line is suppressed as
 *   [redacted] until the next newline.
 */
export function lineRedactor(
  write: (s: string) => void,
  maxPending = 64 * 1024,
): { push: (chunk: string) => void; flush: () => void } {
  let pending = "";
  let pemLines = 0; // > 0 while inside a private key block
  let skipLine = false; // suppress until the next newline

  const line = (l: string) => {
    if (pemLines > 0) {
      write(l.endsWith("\n") ? "[redacted]\n" : "[redacted]");
      if (PEM_END_RE.test(l) || ++pemLines > PEM_MAX_LINES) pemLines = 0;
      return;
    }
    write(redactSecrets(l));
    if (opensPem(l)) pemLines = 1;
  };

  const skip = (data: string): string | null => {
    const i = data.indexOf("\n");
    if (i < 0) return null;
    skipLine = false;
    write("\n");
    if (pemLines > 0 && ++pemLines > PEM_MAX_LINES) pemLines = 0;
    return data.slice(i + 1);
  };

  const forced = () => {
    if (pemLines > 0) {
      write("[redacted]");
      pending = "";
      skipLine = true;
      return;
    }
    let cut = -1;
    for (let j = pending.length - 1; j >= 0 && j >= pending.length - 1 - PENDING_TAIL_MAX; j--) {
      const c = pending[j]!;
      if (c === " " || c === "\t" || c === "\r") {
        cut = j;
        break;
      }
    }
    const seg = cut >= 0 ? pending.slice(0, cut + 1) : pending;
    const rest = cut >= 0 ? pending.slice(cut + 1) : "";
    const out = redactSecrets(seg);
    write(out);
    pending = rest;
    if (dangling(seg) || /\[redacted\]["']?[ \t\r]*$/.test(out)) {
      write("[redacted]");
      pending = "";
      skipLine = true;
    }
  };

  return {
    push(chunk: string) {
      let data: string | null = chunk;
      if (skipLine) {
        data = skip(data);
        if (data === null) return;
      }
      pending += data;
      let start = 0;
      for (let i; (i = pending.indexOf("\n", start)) >= 0; start = i + 1) {
        line(pending.slice(start, i + 1));
      }
      pending = pending.slice(start);
      if (pending.length > maxPending) forced();
    },
    flush() {
      if (pending) {
        if (pemLines > 0) write("[redacted]");
        else write(redactSecrets(pending));
      }
      pending = "";
      pemLines = 0;
      skipLine = false;
    },
  };
}
