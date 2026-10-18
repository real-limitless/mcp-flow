// Gateway stderr: backend errors and passthrough stderr are redacted before logging. Fake values.
import { afterEach, describe, expect, it, vi } from "vitest";
import { lineRedactor, PEM_MAX_LINES, redactLog } from "../src/log/redact-lines.js";
import { connectStdioCommand } from "../src/mcp/runners/stdio.js";

afterEach(() => vi.restoreAllMocks());

describe("log redaction", () => {
  it("redactLog handles errors and strings", () => {
    expect(redactLog(new Error("connect postgres://u:FAKE1@h failed"))).toBe("connect postgres://[redacted]@h failed");
    expect(redactLog("Authorization: Bearer FAKE2")).toBe("Authorization: [redacted]");
  });

  it("lineRedactor sees secrets split across chunks", () => {
    const out: string[] = [];
    const r = lineRedactor((s) => out.push(s));
    r.push("starting\nDB_PA");
    r.push("SS=FAKE3 rest");
    r.push("\nnext GH_TOKEN=FAKE4");
    r.flush();
    const all = out.join("");
    expect(all).toBe("starting\nDB_PASS=[redacted]\nnext GH_TOKEN=[redacted]");
  });

  it("lineRedactor flushes an over-long partial line", () => {
    const out: string[] = [];
    const r = lineRedactor((s) => out.push(s), 16);
    r.push("x".repeat(20));
    expect(out.join("")).toBe("x".repeat(20));
  });

  it("lineRedactor redacts a PEM private key block split across chunks", () => {
    const out: string[] = [];
    const r = lineRedactor((s) => out.push(s));
    const body = ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", "FAKEKEYLINE2abcdefghijklmnopqrs", "FAKEKEYLINE3tuvwxyz0123456789+/="];
    const text = `loading key\n-----BEGIN PRIVATE KEY-----\n${body.join("\n")}\n-----END PRIVATE KEY-----\nready\n`;
    for (let i = 0; i < text.length; i += 7) r.push(text.slice(i, i + 7)); // split mid-line and mid-marker
    r.flush();
    const all = out.join("");
    for (const b of body) expect(all).not.toContain(b.slice(4, 20));
    expect(all).not.toContain("FAKEKEY");
    expect(all).toContain("loading key\n");
    expect(all.endsWith("[redacted]\n[redacted]\n[redacted]\n[redacted]\nready\n")).toBe(true);
  });

  it("lineRedactor handles RSA/OPENSSH variants and resets after PEM_MAX_LINES lines without END", () => {
    const out: string[] = [];
    const r = lineRedactor((s) => out.push(s));
    r.push("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEOSSH1\n-----END OPENSSH PRIVATE KEY-----\nafter1\n");
    r.push("-----BEGIN RSA PRIVATE KEY-----\n");
    for (let i = 0; i < PEM_MAX_LINES + 50; i++) r.push(`FAKERSA${i}\n`);
    r.flush();
    const all = out.join("");
    expect(all).not.toContain("FAKEOSSH1");
    expect(all).toContain("after1\n");
    for (let i = 0; i < PEM_MAX_LINES; i++) expect(all).not.toContain(`FAKERSA${i}\n`);
    expect(all).toContain(`FAKERSA${PEM_MAX_LINES}\n`); // cap reached, state reset
    expect(all.split("[redacted]\n").length - 1).toBe(2 + PEM_MAX_LINES);
  });

  it("lineRedactor: a public key or certificate is not a private key block", () => {
    const out: string[] = [];
    const r = lineRedactor((s) => out.push(s));
    r.push("-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n");
    r.flush();
    expect(out.join("")).toContain("MIIBcert");
  });

  it("forced flush never splits a secret NAME= from its value", () => {
    const max = 64 * 1024;
    const cases = [
      // exactly what SecOPS reproduced: chunk boundary right after DB_PASS=
      ["x".repeat(max - 4) + " DB_PASS=", "FAKEVAL1 tail\nok\n"],
      ["x".repeat(max - 10) + " DB_PASS: ", "FAKEVAL2\nok\n"],
      ["x".repeat(max - 3) + " Authorization: Bearer ", "FAKEVAL3\nok\n"],
      // value already started when the flush hits
      ["y ".repeat(max / 2) + "API_KEY=FAKEV", "AL4rest more\nok\n"],
      // long value without whitespace
      ["DB_PASSWORD=" + "F".repeat(max + 10), "FAKEVAL5\nok\n"],
    ];
    for (const [a, b] of cases) {
      const out: string[] = [];
      const r = lineRedactor((s) => out.push(s));
      r.push(a!);
      r.push(b!);
      r.flush();
      const all = out.join("");
      expect(all).not.toMatch(/FAKEVAL|FAKEV|AL4rest|FFFF/);
      expect(all.endsWith("ok\n")).toBe(true);
    }
  });

  it("forced flush cuts at the last whitespace and keeps a short tail", () => {
    const out: string[] = [];
    const r = lineRedactor((s) => out.push(s), 64);
    r.push("a".repeat(60) + " DB_PA");
    r.push("SS=FAKEVAL6\n");
    r.flush();
    expect(out.join("")).toBe("a".repeat(60) + " DB_PASS=[redacted]\n");
  });

  it("stdio backend stderr and its startup error are redacted", async () => {
    const written: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    vi.spyOn(process.stderr, "write").mockImplementation(((s: string | Uint8Array, ...rest: unknown[]) => {
      written.push(typeof s === "string" ? s : Buffer.from(s).toString("utf8"));
      return (orig as (...a: unknown[]) => boolean)(typeof s === "string" ? "" : new Uint8Array(), ...rest);
    }) as typeof process.stderr.write);
    let thrown = "";
    try {
      await connectStdioCommand({
        command: [process.execPath, "-e", "console.error('boot DB_PASS=FAKE5 here'); console.error('url redis://:FAKE6@cache'); console.error('-----BEGIN PRIVATE KEY-----\\nFAKEPEM7a\\nFAKEPEM7b\\n-----END PRIVATE KEY-----'); process.exit(3)"],
        env: { PATH: process.env.PATH ?? "" },
      });
    } catch (err) {
      thrown = err instanceof Error ? err.message : String(err);
    }
    await new Promise((r) => setTimeout(r, 100));
    expect(thrown).not.toBe("");
    for (const s of [thrown, written.join("")]) {
      expect(s).not.toContain("FAKE5");
      expect(s).not.toContain("FAKE6");
      expect(s).not.toContain("FAKEPEM7");
    }
    expect(written.join("")).toContain("DB_PASS=[redacted]");
  }, 20_000);
});
