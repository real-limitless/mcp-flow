import { describe, expect, it } from "vitest";
import { fromBase32, generateTotpSecret, totpCode, verifyTotp } from "../src/authz/totp.js";

describe("totp", () => {
  it("generates 6-digit codes and verifies with ±1 window", () => {
    const { raw, base32 } = generateTotpSecret();
    expect(base32.length).toBeGreaterThan(10);
    const at = Date.UTC(2026, 0, 1, 0, 0, 0);
    const code = totpCode(raw, at);
    expect(code).toMatch(/^\d{6}$/);
    expect(verifyTotp(raw, code, { atMs: at })).toBe(true);
    expect(verifyTotp(raw, code, { atMs: at + 30_000 })).toBe(true);
    expect(verifyTotp(raw, code, { atMs: at + 90_000 })).toBe(false);
    expect(verifyTotp(fromBase32(base32), code, { atMs: at })).toBe(true);
    expect(verifyTotp(raw, "000000", { atMs: at })).toBe(false);
    expect(verifyTotp(raw, "12", { atMs: at })).toBe(false);
  });
});
