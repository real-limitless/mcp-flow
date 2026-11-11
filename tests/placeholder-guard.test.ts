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
});