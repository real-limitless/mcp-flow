import { describe, expect, it } from "vitest";
import { placeholderWriteBlock } from "../src/audit/placeholder-guard.js";

describe("placeholder guard save", () => {
  it("treats compose-saveEnvironment as a write even without env field", () => {
    const ph = "[" + "REDACTED" + "]";
    expect(placeholderWriteBlock("cmp__compose-saveEnvironment", { composeId: "c1", foo: ph })).toBe("placeholder_write");
  });
  it("still ignores reads", () => {
    const ph = "[" + "REDACTED" + "]";
    expect(placeholderWriteBlock("cmp__compose-one", { composeId: ph })).toBeNull();
  });
  it("refuses a full-replace save whose env carries the placeholder", () => {
    const ph = "[" + "REDACTED" + "]";
    expect(placeholderWriteBlock("cmp__compose-saveEnvironment", { composeId: "cmp_test_1", env: `KEEP=1\nDB_URL=${ph}` })).toBe("placeholder_write");
    expect(placeholderWriteBlock("cmp__compose-saveEnvironment", { composeId: "cmp_test_1", env: "KEEP=1" })).toBeNull();
  });
  it("does not treat words that only start with a verb as writes", () => {
    const ph = "[" + "REDACTED" + "]";
    expect(placeholderWriteBlock("cmp__settings-get", { q: ph })).toBeNull();
    expect(placeholderWriteBlock("cmp__savedSearch-get", { q: ph })).toBeNull();
  });
});
