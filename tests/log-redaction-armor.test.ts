// QA PR #36 r2 Leak A: PGP and other private key armor beyond '… PRIVATE KEY-----'. Fake values only.
import { describe, expect, it } from "vitest";
import { redactSecrets, sanitizeForAudit } from "../src/audit/sanitize.js";
import { lineRedactor } from "../src/log/redact-lines.js";

const M = "FAKEARMORQX";
const run = (chunks: string[], maxPending?: number) => {
  let s = "";
  const r = lineRedactor((x) => (s += x), maxPending);
  for (const c of chunks) r.push(c);
  r.flush();
  return s;
};

const SECRET_LABELS: [string, string][] = [
  ["-----BEGIN PGP PRIVATE KEY BLOCK-----", "-----END PGP PRIVATE KEY BLOCK-----"],
  ["-----BEGIN PGP SECRET KEY BLOCK-----", "-----END PGP SECRET KEY BLOCK-----"],
  ["---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----", "---- END SSH2 ENCRYPTED PRIVATE KEY ----"],
  ["-----BEGIN OpenVPN Static key V1-----", "-----END OpenVPN Static key V1-----"],
  ["-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"],
  ["-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----"],
];

describe("Leak A: private key armor beyond '… PRIVATE KEY-----'", () => {
  it("redactSecrets redacts PGP and other secret armor blocks", () => {
    for (const [b, e] of SECRET_LABELS) {
      const out = redactSecrets(`pre ${b}\nVersion: x\n\nlQ${M}xyz\n=AbCd\n${e} post`);
      expect(out, b).not.toContain(M);
      expect(out, b).toBe("pre [redacted] post");
    }
  });

  it("an unterminated PGP block redacts to the end (fail closed)", () => {
    expect(redactSecrets(`ok -----BEGIN PGP PRIVATE KEY BLOCK-----\nlQ${M}`)).toBe("ok [redacted]");
  });

  it("an END whose BEGIN was cut off redacts everything before it", () => {
    const out = redactSecrets(`${M}1\n${M}2\n-----END PGP PRIVATE KEY BLOCK-----\nafter`);
    expect(out).toBe("[redacted]\nafter");
    expect(out).not.toContain(M);
    // after a complete block, a second orphan END redacts back to the first block's end
    const two = redactSecrets(`a -----BEGIN RSA PRIVATE KEY-----\nk\n-----END RSA PRIVATE KEY----- mid ${M} -----END RSA PRIVATE KEY----- z`);
    expect(two).toBe("a [redacted][redacted] z");
  });

  it("public key blocks, signatures and certificates are kept", () => {
    for (const t of [
      "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBPUB\n-----END PGP PUBLIC KEY BLOCK-----",
      "-----BEGIN PGP SIGNATURE-----\niQSIG\n-----END PGP SIGNATURE-----",
      "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----",
      "-----BEGIN PUBLIC KEY-----\nMFkwPUB\n-----END PUBLIC KEY-----",
    ]) expect(redactSecrets(t)).toBe(t);
  });

  it("sanitizeForAudit redacts the QA r2 PGP case (probe-r2 'PGP private key block')", () => {
    const stored = JSON.stringify(sanitizeForAudit({ cmd: `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlQ${M}xyz\n-----END PGP PRIVATE KEY BLOCK-----` }));
    expect(stored).not.toContain(M);
  });

  it("lineRedactor: every 2-way split of each secret armor block, keeping the lines after it", () => {
    for (const [b, e] of SECRET_LABELS) {
      const text = `before\n${b}\n\nlQ${M}aaaa\n${M}bbbb\n=CRC1\n${e}\nafter-line\n`;
      for (let i = 1; i < text.length; i++) {
        const o = run([text.slice(0, i), text.slice(i)]);
        expect(o, `${b} split ${i}`).not.toContain(M);
        expect(o, `${b} split ${i}`).toContain("after-line\n");
      }
      expect(run([text.replace(/\n/g, "\r\n")])).not.toContain(M);
      expect(run([text.replace(/\n/g, "\n    ")])).not.toContain(M);
    }
  });

  it("lineRedactor: PGP public key block is passed through", () => {
    const t = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBPUB\n-----END PGP PUBLIC KEY BLOCK-----\n";
    expect(run([t])).toBe(t);
  });

  it("lineRedactor: END and a new BEGIN on one line keeps the second block redacted", () => {
    const o = run([`-----BEGIN RSA PRIVATE KEY-----\n${M}1\n-----END RSA PRIVATE KEY----------BEGIN PGP PRIVATE KEY BLOCK-----\n${M}2\n-----END PGP PRIVATE KEY BLOCK-----\nok\n`]);
    expect(o).not.toContain(M);
    expect(o.endsWith("ok\n")).toBe(true);
  });

  it("lineRedactor: a forced flush never cuts inside a BEGIN marker", () => {
    const max = 64 * 1024;
    const head = "x".repeat(max - 10) + " ";
    for (const marker of ["-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----", "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----"]) {
      const text = `${head}${marker}`;
      for (let i = head.length - 1; i <= text.length; i++) {
        const o = run([text.slice(0, i), text.slice(i), `\n${M}1\n${M}2\n-----END RSA PRIVATE KEY-----\nok\n`]);
        expect(o, `${marker} at ${i}`).not.toContain(M);
        expect(o.endsWith("ok\n"), `${marker} at ${i}`).toBe(true);
      }
    }
  });

  it("lineRedactor: a BEGIN marker inside a forced segment redacts the key lines that follow", () => {
    const o = run([`-----BEGIN RSA PRIVATE KEY-----${"Z".repeat(70_000)}`, `\n${M}1\n${M}2\n-----END RSA PRIVATE KEY-----\nok\n`]);
    expect(o).not.toContain(M);
    expect(o.endsWith("ok\n")).toBe(true);
  });

  it("lineRedactor with maxPemLines=Infinity never reopens an unterminated block", () => {
    let s = "";
    const r = lineRedactor((x) => (s += x), undefined, Infinity);
    r.push("-----BEGIN PGP PRIVATE KEY BLOCK-----\n");
    for (let i = 0; i < 5000; i++) r.push(`${M}${i}\n`);
    r.flush();
    expect(s).not.toContain(M);
  });
});
