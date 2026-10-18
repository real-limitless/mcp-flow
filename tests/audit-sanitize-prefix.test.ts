// KEY=value after a "word:" prefix (governance worker finding): a non-secret NAME: used to
// consume the boundary the next secret name needs. Fake values only.
import { describe, expect, it } from "vitest";
import { redactSecrets, sanitizeForAudit } from "../src/audit/sanitize.js";

const V = "FAKEPFXQ1";

describe("secret assignment after a word: prefix", () => {
  const leaked = [
    [`a: password=${V}`, "a: password=[redacted]"],
    [`note: token=${V}`, "note: token=[redacted]"],
    [`reason: password: ${V}`, "reason: password: [redacted]"],
    [`a:password=${V}`, "a:password=[redacted]"],
    [`denied: API_KEY=${V}`, "denied: API_KEY=[redacted]"],
    [`no: DB_PASS=${V}`, "no: DB_PASS=[redacted]"],
  ];
  it.each(leaked)("redactSecrets(%j)", (input, want) => {
    expect(redactSecrets(input)).toBe(want);
  });

  it.each(leaked)("sanitizeForAudit stores %j redacted", (input) => {
    expect(JSON.stringify(sanitizeForAudit({ msg: input, nested: [{ text: `x ${input} y` }] }))).not.toContain(V);
  });

  it("forms that were already caught stay caught", () => {
    expect(redactSecrets(`a - password=${V}`)).toBe("a - password=[redacted]");
    expect(redactSecrets(`a; password=${V}`)).toBe("a; password=[redacted]");
    expect(redactSecrets(`a: x password=${V}`)).toBe("a: x password=[redacted]");
  });

  it("chains, tabs, quotes and multiple lines", () => {
    expect(redactSecrets(`a: b: c: password=${V}`)).toBe("a: b: c: password=[redacted]");
    expect(redactSecrets(`level:\tGH_TOKEN=${V}`)).toBe("level:\tGH_TOKEN=[redacted]");
    expect(redactSecrets(`warn: "password": "${V}"`)).toBe('warn: "password": "[redacted]"');
    expect(redactSecrets(`ok: fine\nerr: secret=${V}\nnext: line`)).toBe("ok: fine\nerr: secret=[redacted]\nnext: line");
  });

  it("non-secret NAME: text is kept", () => {
    for (const t of [
      "Content-Type: text",
      "Content-Type: application/json; charset=utf-8",
      "time: 12:30",
      "at: 2026-10-18T12:30:00Z",
      "url: https://x/y",
      "url: https://h:8080/a@b",
      "status: ok, count: 3",
      "a: b: c: d",
      "max_tokens: 1000",
      "key_id: key_abc123",
    ]) expect(redactSecrets(t), t).toBe(t);
  });
});
