// SecOPS conditions on 6aa270c8..dd009011 and QA r3 partial: body state after the line cap,
// PuTTY .ppk, a stray END limited to the key-body run before it, case-insensitive armor markers.
// Fake values only.
import { describe, expect, it } from "vitest";
import { isArmorBodyLine, redactSecrets } from "../src/audit/sanitize.js";
import { lineRedactor, PEM_MAX_LINES } from "../src/log/redact-lines.js";

const M = "FAKEBODYQX";
/** A 64-char base64-shaped body line carrying the marker. */
const b64 = (i: number) => `${M}${String(i).padStart(6, "0")}${"Ab9+/".repeat(10)}`.slice(0, 64);

const run = (chunks: string[], maxPending?: number) => {
  let s = "";
  const r = lineRedactor((x) => (s += x), maxPending);
  for (const c of chunks) r.push(c);
  r.flush();
  return s;
};

describe("body state after the PEM_MAX_LINES cap (SecOPS MUST 1, QA r3 2000-line key)", () => {
  it("an unclosed block over the cap: body lines stay redacted, the next log line is visible", () => {
    const lines = ["-----BEGIN PGP PRIVATE KEY BLOCK-----", "Version: FakePG 1", "Comment: fake", ""];
    for (let i = 0; i < 2000; i++) lines.push(b64(i));
    lines.push("=Ab12", "server listening on :8080", "next line ok");
    const text = lines.join("\n") + "\n";
    const out = run([text]);
    expect(out).not.toContain(M);
    expect(out).not.toContain("=Ab12");
    expect(out).toContain("server listening on :8080\nnext line ok\n");
    // also with odd chunking
    const chunks: string[] = [];
    for (let i = 0; i < text.length; i += 997) chunks.push(text.slice(i, i + 997));
    expect(run(chunks)).toBe(out);
  });

  it("armor headers, a padded short last line and blank lines after the cap stay in the body state", () => {
    const lines = ["-----BEGIN RSA PRIVATE KEY-----"];
    for (let i = 0; i < PEM_MAX_LINES + 5; i++) lines.push(b64(i));
    lines.push("", "Comment: x", "Version: 2", "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,ABCD", b64(9999), "QUJD==", "  " + b64(7777), "log resumes");
    const out = run([lines.join("\n") + "\n"]);
    expect(out).not.toContain(M);
    expect(out).not.toContain("QUJD==");
    expect(out).not.toMatch(/Proc-Type|DEK-Info|Comment: x|Version: 2/);
    expect(out.endsWith("log resumes\n")).toBe(true);
  });

  it("an END in the body state is redacted and ends it", () => {
    const lines = ["-----BEGIN RSA PRIVATE KEY-----"];
    for (let i = 0; i < PEM_MAX_LINES + 3; i++) lines.push(b64(i));
    lines.push("-----END RSA PRIVATE KEY-----", "aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=", "done");
    const out = run([lines.join("\n") + "\n"]);
    expect(out).not.toContain(M);
    // after the END a base64-looking line is ordinary output again
    expect(out).toContain("aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQ=\ndone\n");
  });

  it("skip path: a forced (over-long) line that crosses the cap enters the body state", () => {
    let s = "";
    const r = lineRedactor((x) => (s += x), 1024);
    r.push("-----BEGIN RSA PRIVATE KEY-----\n");
    for (let i = 0; i < PEM_MAX_LINES - 1; i++) r.push(b64(i) + "\n");
    r.push("Q".repeat(5000)); // forced flush inside the block: skipped to the newline
    r.push(`${M}LONG\n`); // the skipped line is the cap-th line
    r.push(b64(1) + "\n");
    r.push("W".repeat(3000) + M + "Z".repeat(3000)); // over-long all-base64 line in the body state
    r.push("\nback to logs\n");
    r.flush();
    expect(s).not.toContain(M);
    expect(s.endsWith("back to logs\n")).toBe(true);
  });

  it("isArmorBodyLine shapes", () => {
    for (const ok of [b64(1), "  " + b64(2) + "\r", "Comment: x", "version: 1", "=Ab12", "QUJD==", "Zg=="]) expect(isArmorBodyLine(ok), ok).toBe(true);
    for (const no of ["", "   ", "server listening on :8080", "short", "abc def ghi jkl mno pqr", "=Ab1"]) expect(isArmorBodyLine(no), no).toBe(false);
  });
});

const PPK = [
  "PuTTY-User-Key-File-3: ssh-ed25519",
  "Encryption: none",
  "Comment: fake-key",
  "Public-Lines: 2",
  "AAAAC3NzaC1lZDI1NTE5AAAAIPUBLICPUBLICPUBLICPUBLICPUBLIC0001",
  "AAAAC3NzaC1lZDI1NTE5AAAAIPUBLICPUBLICPUBLICPUBLICPUBLIC0002",
  "Private-Lines: 3",
  `AAAAI${M}PRIV1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
  `AAAAI${M}PRIV2bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`,
  `${M}P3`,
  `Private-MAC: ${M}0123456789abcdef0123456789abcdef`,
];

describe("PuTTY .ppk (SecOPS SHOULD 3)", () => {
  it("redactSecrets redacts the Private-Lines and the Private-MAC, keeps the public part", () => {
    const out = redactSecrets(PPK.join("\n") + "\nafter");
    expect(out).not.toContain(M);
    expect(out).toContain("PUBLIC0001");
    expect(out).toContain("Private-Lines: 3\n[redacted]\nPrivate-MAC: [redacted]\nafter");
  });

  it("CRLF and JSON-escaped newlines", () => {
    expect(redactSecrets(PPK.join("\r\n"))).not.toContain(M);
    expect(redactSecrets(JSON.stringify({ k: PPK.join("\n") }))).not.toContain(M);
    expect(redactSecrets(JSON.stringify({ k: PPK.join("\r\n") }))).not.toContain(M);
  });

  it("fewer lines than Private-Lines (cut off) or an over-cap count fail closed", () => {
    expect(redactSecrets(`Private-Lines: 9\n${M}a\n${M}b`)).toBe("Private-Lines: 9\n[redacted]");
    expect(redactSecrets(`Private-Lines: 99999\n${M}a\nmore\nlines`)).toBe("Private-Lines: 99999\n[redacted]");
  });

  it("QA probe-r2 'PuTTY key' case", () => {
    expect(redactSecrets(`PuTTY-User-Key-File-3: ssh-rsa\nPrivate-Lines: 1\n${M}AAAAB3NzaC1yc2E`)).not.toContain(M);
  });

  it("lineRedactor: every 2-way split, public lines and the following log line kept", () => {
    const text = `boot\n${PPK.join("\n")}\nafter-ppk\n`;
    for (let i = 1; i < text.length; i++) {
      const o = run([text.slice(0, i), text.slice(i)]);
      expect(o, `split ${i}`).not.toContain(M);
      expect(o, `split ${i}`).toContain("PUBLIC0002\n");
      expect(o, `split ${i}`).toContain("after-ppk\n");
    }
    expect(run([text.replace(/\n/g, "\r\n")])).not.toContain(M);
  });

  it("lineRedactor: an over-cap Private-Lines count redacts the cap, then the body state", () => {
    const lines = ["Private-Lines: 5000"];
    for (let i = 0; i < 1100; i++) lines.push(b64(i));
    lines.push("log line");
    const out = run([lines.join("\n") + "\n"]);
    expect(out).not.toContain(M);
    expect(out.endsWith("log line\n")).toBe(true);
  });
});

describe("stray END limited to the key-body run before it (SecOPS SHOULD 4)", () => {
  it("text above the run stays readable", () => {
    const s = `request id 42 failed\nsee logs\n${b64(1)}\n${b64(2)}\nQUJD\n-----END RSA PRIVATE KEY-----\nafter`;
    expect(redactSecrets(s)).toBe("request id 42 failed\nsee logs\n[redacted]\nafter");
  });

  it("PGP tail: checksum and short last line right before END, blank line inside the run", () => {
    const s = `ctx line\nComment: x\n\n${b64(1)}\nQUJ\n=Ab12\n-----END PGP PRIVATE KEY BLOCK-----`;
    expect(redactSecrets(s)).toBe("ctx line\n[redacted]");
  });

  it("short unpadded lines further up do not extend the run", () => {
    const s = `ready\n${b64(1)}\n-----END RSA PRIVATE KEY-----`;
    expect(redactSecrets(s)).toBe("ready\n[redacted]");
  });

  it("JSON-escaped newlines", () => {
    const s = JSON.stringify({ e: `boom happened\n${b64(1)}\n${b64(2)}\n-----END PRIVATE KEY-----\nok` });
    const out = redactSecrets(s);
    expect(out).not.toContain(M);
    expect(out).toContain("boom happened\\n[redacted]\\nok");
  });

  it("no body run: only the marker", () => {
    expect(redactSecrets("plain words here\n-----END RSA PRIVATE KEY-----\nz")).toBe("plain words here\n[redacted]\nz");
  });

  it("a run to the start of the string is all redacted", () => {
    expect(redactSecrets(`${b64(1)}\n${b64(2)}\n-----END RSA PRIVATE KEY-----`)).toBe("[redacted]");
  });

  it("a complete block before the stray END is not re-scanned", () => {
    const s = `-----BEGIN RSA PRIVATE KEY-----\n${b64(1)}\n-----END RSA PRIVATE KEY-----\nmiddle text\n${b64(2)}\n-----END RSA PRIVATE KEY-----`;
    expect(redactSecrets(s)).toBe("[redacted]\nmiddle text\n[redacted]");
  });
});

describe("armor marker variants: any case, 4 dashes, extra spaces / tabs (QA r3)", () => {
  const variants = [
    ["-----begin pgp private key block-----", "-----end pgp private key block-----"],
    ["-----Begin Rsa Private Key-----", "-----End Rsa Private Key-----"],
    ["---- begin ssh2 encrypted private key ----", "---- end ssh2 encrypted private key ----"],
    // QA r3 probe-r3-ext variants: double spaces, tabs, 4 dashes
    ["-----BEGIN  PGP PRIVATE KEY BLOCK-----", "-----END  PGP PRIVATE KEY BLOCK-----"],
    ["-----BEGIN PGP PRIVATE  KEY BLOCK-----", "-----END PGP PRIVATE  KEY BLOCK-----"],
    ["-----BEGIN\tPGP PRIVATE KEY BLOCK-----", "-----END\tPGP PRIVATE KEY BLOCK-----"],
    ["----BEGIN PGP PRIVATE KEY BLOCK----", "----END PGP PRIVATE KEY BLOCK----"],
  ];
  it("redactSecrets", () => {
    for (const [b, e] of variants) expect(redactSecrets(`x ${b}\n${M}1\n${e} y`), b).toBe("x [redacted] y");
  });

  it("lineRedactor: every 2-way split", () => {
    for (const [b, e] of variants) {
      const text = `before\n${b}\n${M}aaaa\n${M}bbbb\n${e}\nafter-line\n`;
      for (let i = 1; i < text.length; i++) {
        const o = run([text.slice(0, i), text.slice(i)]);
        expect(o, `${b} split ${i}`).not.toContain(M);
        expect(o, `${b} split ${i}`).toContain("after-line\n");
      }
    }
  });

  it("forced flush holds back a lowercase or tab/4-dash BEGIN marker", () => {
    const head = "x".repeat(64 * 1024 - 10) + " ";
    for (const marker of ["-----begin pgp private key block-----", "----BEGIN\t PGP PRIVATE KEY BLOCK----"]) {
      const text = head + marker;
      for (let i = head.length - 1; i <= text.length; i++) {
        const o = run([text.slice(0, i), text.slice(i), `\n${M}1\n${M}2\n-----end pgp private key block-----\nok\n`]);
        expect(o, `${marker} at ${i}`).not.toContain(M);
        expect(o.endsWith("ok\n"), `${marker} at ${i}`).toBe(true);
      }
    }
  });

  it("PGP MESSAGE and SIGNATURE stay readable by design", () => {
    const t = "-----BEGIN PGP MESSAGE-----\nhQEMcipher\n-----END PGP MESSAGE-----\n-----begin pgp signature-----\niQsig\n-----end pgp signature-----";
    expect(redactSecrets(t)).toBe(t);
    expect(run([t + "\n"])).toBe(t + "\n");
  });
});
