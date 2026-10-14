import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalJson } from "../src/policy/crypto.js";

/** Pins the example published in mcp-flow-approvals-api.md "Frontend Q&A" (1). */
describe("args_sha256 canonical JSON", () => {
  it("matches the documented worked example", () => {
    const raw = '{"title":"Café \\u00e9 \\"q\\"\\n","b":[3,1.50,1e21,-0],"a":{"z":true,"B":null,"é":"x"},"n":12345678901234567890}';
    const c = canonicalJson(JSON.parse(raw));
    expect(c).toBe('{"a":{"B":null,"z":true,"é":"x"},"b":[3,1.5,1e+21,0],"n":12345678901234567000,"title":"Café é \\"q\\"\\n"}');
    expect(createHash("sha256").update(c, "utf8").digest("hex")).toBe("9ee2c5fdba41543ead962fc6ecf7b9d22888258b646be2c3bacbdde9e6450be7");
  });
  it("no Unicode normalization: NFC and NFD differ", () => {
    expect(canonicalJson({ s: "\u00e9" })).not.toBe(canonicalJson({ s: "e\u0301" }));
  });
});
