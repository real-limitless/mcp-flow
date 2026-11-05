/** Secrets A1: redact-before-persist keeps secret:// refs and fails closed. */
import { describe, expect, it } from "vitest";
import { redactBeforePersist } from "../src/audit/redact-persist.js";
import { placeholderWriteBlock } from "../src/audit/placeholder-guard.js";

describe("redactBeforePersist", () => {
  it("redacts env lines, structuredContent, and bearer tokens, and keeps a pure secret:// ref", () => {
    const env = ["API_KEY=super-secret-value", "PUBLIC=visible", "DB_PASSWORD=secret://proj/db@v1"].join("\n");
    const red = redactBeforePersist({
      note: "Authorization: Bearer abcdefghijklmnop",
      env,
      structuredContent: { api_token: "tok-value", title: "ok" },
      password: "secret://proj/db@v1",
    });
    const json = JSON.stringify(red.value);
    expect(json).not.toContain("super-secret-value");
    expect(json).not.toContain("tok-value");
    expect(json).not.toContain("abcdefghijklmnop");
    expect(json).toContain("PUBLIC=visible");
    expect(json).toContain("secret://proj/db@v1");
    expect(red.secretRefs.map((r) => r.ref)).toContain("secret://proj/db@v1");
    expect(red.flags).toContain("structuredContent");
    expect(red.flags).toContain("env");
    expect(red.plaintextSuspected).toBe(true);
    expect(red.withheld).toBe(false);
  });

  it("withholds the body when the walk throws", () => {
    const boom: Record<string, unknown> = {};
    Object.defineProperty(boom, "a", {
      enumerable: true,
      get() {
        throw new Error("scan failed");
      },
    });
    const red = redactBeforePersist(boom);
    expect(red.withheld).toBe(true);
    expect(red.value).toEqual({ withheld: "scrub_failed" });
    expect(JSON.stringify(red.value)).not.toContain("scan failed");
    expect(red.plaintextSuspected).toBe(true);
  });
});

describe("placeholder write guard", () => {
  it("refuses a write that carries a redaction placeholder and ignores a read", () => {
    expect(placeholderWriteBlock("gh__update_file", { env: "TOKEN=[redacted]" })).toBe("placeholder_write");
    expect(placeholderWriteBlock("gh__get_file", { path: "[redacted]" })).toBeNull();
    expect(placeholderWriteBlock("mf_call_tool", { arguments: { note: "[redacted]" } })).toBeNull();
  });
});
