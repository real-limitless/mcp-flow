import { describe, expect, it } from "vitest";
import {
  deriveMasterKey,
  hashPassword,
  hashToken,
  mintApiToken,
  seal,
  unseal,
  safeEqualStr,
  verifyPassword,
} from "../src/crypto.js";

describe("crypto", () => {
  it("derives 32-byte key from base64", () => {
    const raw = Buffer.alloc(32, 7).toString("base64");
    const key = deriveMasterKey(raw);
    expect(key).toHaveLength(32);
  });

  it("derives from hex", () => {
    const raw = "ab".repeat(32);
    expect(deriveMasterKey(raw)).toHaveLength(32);
  });

  it("seals and unseals objects", () => {
    const key = deriveMasterKey("test-passphrase-not-for-prod");
    const blob = seal(key, { Authorization: "Bearer secret" });
    expect(blob).not.toContain("secret");
    expect(unseal(key, blob)).toEqual({ Authorization: "Bearer secret" });
  });

  it("mints hashed api tokens", () => {
    const { token, prefix, hash } = mintApiToken();
    expect(token.startsWith("mf_")).toBe(true);
    expect(prefix).toBe(token.slice(0, 10));
    expect(hash).toBe(hashToken(token));
    expect(hash).not.toBe(token);
  });

  it("hashes and verifies passwords", () => {
    const stored = hashPassword("correct-horse");
    expect(stored.startsWith("scrypt$")).toBe(true);
    expect(verifyPassword("correct-horse", stored)).toBe(true);
    expect(verifyPassword("wrong", stored)).toBe(false);
  });

  it("safeEqualStr", () => {
    expect(safeEqualStr("abc", "abc")).toBe(true);
    expect(safeEqualStr("abc", "abd")).toBe(false);
    expect(safeEqualStr("a", "ab")).toBe(false);
  });
});
