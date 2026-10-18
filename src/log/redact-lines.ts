import {
  isArmorBodyLine,
  isSecretName,
  PPK_MAX_PRIVATE_LINES,
  redactSecrets,
  secretArmorMarkers,
} from "../audit/sanitize.js";

/** Redact a message before it is written to the gateway's own stderr. */
export function redactLog(v: unknown): string {
  return redactSecrets(v instanceof Error ? v.message : String(v));
}

/**
 * Max lines redacted wholesale after a private key BEGIN line without an END marker (live
 * passthrough only, so a stray BEGIN cannot mute a backend's stderr for good). Large enough
 * for PGP secret key blocks with subkeys. After it the redactor does not go back to raw output:
 * it enters a "body" state that keeps redacting key-body-shaped lines (base64 of 16+, armor
 * headers, =XXXX checksums) and resumes on the first line that is not. Infinity = never stop.
 */
export const PEM_MAX_LINES = 1024;
/** Max partial-line tail kept back after a forced flush (the cut is at the last whitespace). */
export const PENDING_TAIL_MAX = 4 * 1024;
/** Longest armor marker line ("---- BEGIN <label up to 80> ----"). */
const ARMOR_MARKER_MAX = 128;

/** A segment that ends in a secret NAME= / NAME: (or Bearer / --password) with no value yet. */
const DANGLING_NAME_RE = /(?:^|[^A-Za-z0-9_.-])([A-Za-z_][A-Za-z0-9_.-]{0,255})["']?[ \t]*[=:][ \t]*["']?$/;
const DANGLING_SCHEME_RE = /(?:\b(?:Bearer|Basic|Token|Digest)|--(?:password|token|secret|api-key)|\s-p)[ \t=]*$/i;

function dangling(seg: string): boolean {
  const tail = seg.slice(-512);
  if (DANGLING_SCHEME_RE.test(tail)) return true;
  const m = DANGLING_NAME_RE.exec(tail);
  return !!m && isSecretName(m[1]!);
}

const BEGIN_WORD_RE = /begin/gi;
const PARTIAL_BEGIN_TAIL_RE = /-{1,5}[ \t]{0,8}(?:B(?:E(?:G(?:I(?:N(?:[ \t][A-Za-z0-9 \t._]{0,80})?)?)?)?)?)?$/i;

/**
 * Where a forced flush must stop so it does not split an armor BEGIN marker: the start of a
 * BEGIN marker (or a partial one: dashes, "BEG…") within the last ARMOR_MARKER_MAX chars of s,
 * else s.length.
 */
function armorHoldFrom(s: string): number {
  const from = Math.max(0, s.length - ARMOR_MARKER_MAX);
  let k = -1;
  BEGIN_WORD_RE.lastIndex = from;
  for (let m; (m = BEGIN_WORD_RE.exec(s)); ) k = m.index;
  if (k >= 0) {
    let d = k;
    while (d > 0 && k - d < 14 && (s[d - 1] === "-" || s[d - 1] === " " || s[d - 1] === "\t")) d--;
    return d; // complete or not, the marker goes to the next segment whole
  }
  const m = PARTIAL_BEGIN_TAIL_RE.exec(s.slice(from));
  return m ? from + m.index : s.length;
}

/** Line opens a private key armor block (PEM, PGP, SSH2, OpenVPN) that it does not close. */
function opensPem(line: string): boolean {
  let open = false;
  for (const mk of secretArmorMarkers(line)) open = mk.begin;
  return open;
}

/** "Private-Lines: N" in a PuTTY .ppk: the N lines after it are the private key. */
const PPK_PRIVATE_LINES_LINE_RE = /^\s*Private-Lines:[ \t]*(\d{1,6})[ \t]*\r?\n?$/;
/** A forced (over-long) partial line that is all base64: still key body. */
const LONG_BODY_RE = /^\s*[A-Za-z0-9+/=]+\s*$/;

/** Line holds a private key armor END marker. */
function closesPem(line: string): boolean {
  return secretArmorMarkers(line).some((mk) => !mk.begin);
}

/**
 * Line-buffered redaction for a passthrough stream (a backend's stderr): complete lines are
 * redacted and written; a partial line waits for its newline so a secret split across chunks
 * is still seen whole.
 *
 * - After a private key armor BEGIN line (`-----BEGIN … PRIVATE KEY-----`,
 *   `-----BEGIN PGP PRIVATE KEY BLOCK-----`, any case, …) every following line is written as
 *   [redacted] up to and including the END marker. After maxPemLines lines without an END it
 *   switches to the body state (see PEM_MAX_LINES): key-body-shaped lines stay redacted, blank
 *   lines pass without ending it, and the first other line is written normally.
 * - PuTTY .ppk: the N lines after "Private-Lines: N" are written as [redacted] (a count over
 *   PPK_MAX_PRIVATE_LINES redacts that many, then the body state); Private-MAC is redacted.
 * - A partial line longer than maxPending is cut at its last whitespace, keeping a tail of at
 *   most PENDING_TAIL_MAX. If what was written ends in a secret NAME= / NAME: (or Bearer …)
 *   with no value, or in a value that may continue, the rest of that line is suppressed as
 *   [redacted] until the next newline.
 */
export function lineRedactor(
  write: (s: string) => void,
  maxPending = 64 * 1024,
  maxPemLines = PEM_MAX_LINES,
): { push: (chunk: string) => void; flush: () => void } {
  let pending = "";
  let pemLines = 0; // > 0 while inside a private key block
  let body = false; // past the line cap of an unclosed block: redact key-body-shaped lines
  let ppkLeft = 0; // PuTTY private lines still to redact
  let ppkOverflow = false; // Private-Lines count was over the cap
  let skipLine = false; // suppress until the next newline

  const redactedLine = (l: string) => write(l.endsWith("\n") ? "[redacted]\n" : "[redacted]");

  /** One more line of a block (or of PuTTY private lines) consumed. */
  const countLine = () => {
    if (pemLines > 0 && ++pemLines > maxPemLines) {
      pemLines = 0;
      body = true;
    }
    if (ppkLeft > 0 && --ppkLeft === 0 && ppkOverflow) {
      ppkOverflow = false;
      body = true;
    }
  };

  const line = (l: string) => {
    if (pemLines > 0) {
      redactedLine(l);
      if (opensPem(l)) pemLines = 1; // END then a new BEGIN on one line
      else if (closesPem(l)) pemLines = 0;
      else countLine();
      return;
    }
    if (ppkLeft > 0) {
      redactedLine(l);
      countLine();
      return;
    }
    if (body) {
      if (!l.trim()) {
        write(l); // a blank line neither leaks nor ends the body state
        return;
      }
      if (closesPem(l) && !opensPem(l)) {
        redactedLine(l);
        body = false;
        return;
      }
      if (isArmorBodyLine(l)) {
        redactedLine(l);
        return;
      }
      body = false; // first other line (or a new BEGIN): normal handling below
    }
    write(redactSecrets(l));
    if (opensPem(l)) {
      pemLines = 1;
      return;
    }
    const pm = PPK_PRIVATE_LINES_LINE_RE.exec(l);
    if (pm) {
      const n = Number(pm[1]);
      ppkOverflow = n > PPK_MAX_PRIVATE_LINES;
      ppkLeft = Math.min(n, PPK_MAX_PRIVATE_LINES);
    }
  };

  const skip = (data: string): string | null => {
    const i = data.indexOf("\n");
    if (i < 0) return null;
    skipLine = false;
    write("\n");
    countLine();
    return data.slice(i + 1);
  };

  const forced = () => {
    if (pemLines > 0 || ppkLeft > 0 || (body && LONG_BODY_RE.test(pending))) {
      write("[redacted]");
      pending = "";
      skipLine = true;
      return;
    }
    body = false;
    let cut = -1;
    for (let j = pending.length - 1; j >= 0 && j >= pending.length - 1 - PENDING_TAIL_MAX; j--) {
      const c = pending[j]!;
      if (c === " " || c === "\t" || c === "\r") {
        cut = j;
        break;
      }
    }
    let seg = cut >= 0 ? pending.slice(0, cut + 1) : pending;
    let rest = cut >= 0 ? pending.slice(cut + 1) : "";
    // never cut inside an armor BEGIN marker ("-----BEGIN RSA " | "PRIVATE KEY-----",
    // "---- " | "BEGIN SSH2 …"): hold the marker back with the tail so it is seen whole
    const hold = armorHoldFrom(pending);
    if (hold < seg.length) {
      seg = pending.slice(0, hold);
      rest = pending.slice(hold);
    }
    const out = redactSecrets(seg);
    write(out);
    pending = rest;
    if (opensPem(seg)) pemLines = 1; // BEGIN marker in a forced segment: the key lines follow
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
        if (pemLines > 0 || ppkLeft > 0 || (body && isArmorBodyLine(pending))) write("[redacted]");
        else write(redactSecrets(pending));
      }
      pending = "";
      pemLines = 0;
      body = false;
      ppkLeft = 0;
      ppkOverflow = false;
      skipLine = false;
    },
  };
}
