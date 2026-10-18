// SecOPS on 04f6c11e: (1) empty-value names repeated on one line were quadratic (a line scan per
// match); (2) names longer than 1024 characters never matched, so their values were kept.
// Fake values only.
import { describe, expect, it } from "vitest";
import { redactSecrets, sanitizeForAudit } from "../src/audit/sanitize.js";

const F = "FAKELONGNAMEV" + "7q";
const time = (fn: () => void) => {
  fn(); // warm up
  const t = performance.now();
  fn();
  return performance.now() - t;
};

describe("empty values repeated on one 64 KiB line run in linear time", () => {
  const lines: Array<[string, string]> = [
    ["&token=", "&token=".repeat(Math.ceil(65536 / 7))],
    ['"password":,', '"password":,'.repeat(Math.ceil(65536 / 12))],
    ["?api_key=#", "?api_key=#".repeat(Math.ceil(65536 / 10))],
  ];
  for (const [name, line] of lines) {
    it(`${name} x ${line.length} chars: under 50 ms, text unchanged`, () => {
      expect(time(() => redactSecrets(line))).toBeLessThan(50);
      expect(time(() => sanitizeForAudit({ m: line }))).toBeLessThan(50);
      expect(redactSecrets(line)).toBe(line); // empty values: nothing to redact
    });
  }
  it("a value after the empty ones on the same line is still redacted", () => {
    const line = `${"&token=".repeat(5000)}&token=${F}&x=1`;
    const out = redactSecrets(line);
    expect(out).not.toContain(F);
    expect(out.endsWith("&token=[redacted]&x=1")).toBe(true);
  });
});

describe("names longer than 1024 characters are secret names (fail closed)", () => {
  const long = (n: number, c = "A") => c.repeat(n);
  for (const s of [
    `${long(1100)}_PASSWORD=${F}`,
    `X_${long(1030, "B")}_TOKEN=${F} tail`,
    `${long(1100)}_NAME: ${F}`,
    `{"${long(1100)}": "${F}", "b": 1}`,
    `{\\"${long(1100)}\\":\\"${F}\\"}`,
    `cmd ${long(2000, "z")}=${F}`,
    `?${long(1200, "q")}=${F}&b=2`,
  ]) {
    it(`redacts: ${s.slice(0, 12)}…${s.slice(-28)}`, () => {
      expect(redactSecrets(s)).not.toContain(F);
      expect(JSON.stringify(sanitizeForAudit({ m: s }))).not.toContain(F);
    });
  }
  it("keeps the shapes around the value", () => {
    expect(redactSecrets(`?${long(1200, "q")}=${F}&b=2`).endsWith("=[redacted]&b=2")).toBe(true);
    expect(redactSecrets(`{"${long(1100)}": "${F}", "b": 1}`).endsWith(`": "[redacted]", "b": 1}`)).toBe(true);
  });
  it("both sides of the 1024 cap: 1024 (existing rule, name > 256) and 1025 (new pass) are redacted; short non-secret names keep values", () => {
    expect(redactSecrets(`${long(1024, "n")}=${F}`)).toBe(`${long(1024, "n")}=[redacted]`);
    expect(redactSecrets(`${long(1025, "n")}=${F}`)).toBe(`${long(1025, "n")}=[redacted]`);
    expect(redactSecrets(`${long(200, "n")}=visible`)).toBe(`${long(200, "n")}=visible`);
  });
  it("a long run without = or : is left alone, and the scan stays linear", () => {
    const blob = long(65536, "Q");
    expect(redactSecrets(`x ${blob} y`)).toBe(`x ${blob} y`);
    const many = `${long(1100)}= `.repeat(60) + `${long(1100)}=&`.repeat(60);
    expect(time(() => redactSecrets(many))).toBeLessThan(50);
  });
});
