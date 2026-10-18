// Gateway stderr: backend errors and passthrough stderr are redacted before logging. Fake values.
import { afterEach, describe, expect, it, vi } from "vitest";
import { lineRedactor, redactLog } from "../src/log/redact-lines.js";
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
        command: [process.execPath, "-e", "console.error('boot DB_PASS=FAKE5 here'); console.error('url redis://:FAKE6@cache'); process.exit(3)"],
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
    }
    expect(written.join("")).toContain("DB_PASS=[redacted]");
  }, 20_000);
});
