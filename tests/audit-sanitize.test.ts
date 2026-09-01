import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  sanitizeForAudit,
  summarizeCallToolResult,
  toolCallAuditDetail,
} from "../src/audit/sanitize.js";
import { Store } from "../src/db/store.js";

const master = Buffer.alloc(32, 13).toString("base64");
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("sanitizeForAudit", () => {
  it("redacts nested secret keys and bearer values", () => {
    const out = sanitizeForAudit({
      query: "hello",
      headers: { Authorization: "Bearer super-secret-token" },
      nested: { api_key: "abc", ok: true },
      token: "should-go",
    }) as Record<string, unknown>;
    expect(out.query).toBe("hello");
    expect(out.token).toBe("[redacted]");
    expect((out.nested as Record<string, unknown>).api_key).toBe("[redacted]");
    expect((out.nested as Record<string, unknown>).ok).toBe(true);
    expect(
      (out.headers as Record<string, unknown>).Authorization,
    ).toBe("[redacted]");
    expect(JSON.stringify(out)).not.toContain("super-secret");
  });

  it("truncates oversized payloads", () => {
    const big = "x".repeat(200_000);
    const out = sanitizeForAudit(
      { blob: big },
      { maxBytes: 4096, maxString: 1000 },
    ) as Record<string, unknown>;
    // either truncated string inside or top-level _truncated
    const json = JSON.stringify(out);
    expect(json.length).toBeLessThan(20_000);
    expect(
      out._truncated === true ||
        String((out as { blob?: string }).blob ?? "").includes("truncated"),
    ).toBe(true);
  });
});

describe("summarizeCallToolResult", () => {
  it("keeps text and omits binary", () => {
    const s = summarizeCallToolResult({
      isError: false,
      content: [
        { type: "text", text: "hello" },
        {
          type: "image",
          data: "a".repeat(100),
          mimeType: "image/png",
        },
      ],
    }) as {
      content: Array<Record<string, unknown>>;
      isError: boolean;
    };
    expect(s.isError).toBe(false);
    expect(s.content[0]).toEqual({ type: "text", text: "hello" });
    expect(s.content[1]?._omitted).toBe("binary");
  });
});

describe("writeAudit rich detail", () => {
  it("persists arguments and result with redaction", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-aud-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    store.writeAudit({
      workspaceId: ws.id,
      action: "tools/call",
      tool: "demo__echo",
      detail: toolCallAuditDetail({
        arguments: {
          text: "hi",
          authorization: "Bearer leak-me",
        },
        result: {
          isError: false,
          content: [{ type: "text", text: "echo:hi" }],
        },
        durationMs: 12,
      }),
    });
    const ev = store.listAudit(ws.id)[0]!;
    expect(ev.detail?.durationMs).toBe(12);
    expect((ev.detail?.arguments as { text: string }).text).toBe("hi");
    expect((ev.detail?.arguments as { authorization: string }).authorization).toBe(
      "[redacted]",
    );
    const result = ev.detail?.result as {
      content: Array<{ text?: string }>;
    };
    expect(result.content[0]?.text).toBe("echo:hi");
    expect(JSON.stringify(ev)).not.toContain("leak-me");
    store.close();
  });
});
