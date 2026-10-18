// QA PR #36 r2 Leak B: the init-error stderr tail was cut before it was redacted, so a key whose
// BEGIN line fell outside the window reached the error, the tool result and audit_events. Fake values only.
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { toolCallAuditDetail } from "../src/audit/sanitize.js";
import { Store } from "../src/db/store.js";
import { PEM_MAX_LINES } from "../src/log/redact-lines.js";
import { boundedTail, connectStdioCommand, stderrTailForError } from "../src/mcp/runners/stdio.js";
import { UpstreamPool } from "../src/mcp/upstream.js";

const M = "FAKETAILQX";
const dirs: string[] = [];
afterEach(() => {
  vi.restoreAllMocks();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function silenceStderr(): string[] {
  const written: string[] = [];
  vi.spyOn(process.stderr, "write").mockImplementation(((s: string | Uint8Array) => {
    written.push(typeof s === "string" ? s : Buffer.from(s).toString("utf8"));
    return true;
  }) as typeof process.stderr.write);
  return written;
}

/** QA r2 pem-backend.mjs "bigpem": BEGIN, 100 body lines, END, 5000 filler chars, exit 1. */
function bigPemScript(label = "RSA PRIVATE KEY", end = true, lines = 100): string {
  const dir = mkdtempSync(join(tmpdir(), "mf-armor-"));
  dirs.push(dir);
  const p = join(dir, "bigpem.mjs");
  writeFileSync(
    p,
    `const w = (s) => new Promise((r) => process.stderr.write(s, r));
await w("-----BEGIN ${label}-----\\n");
for (let i = 0; i < ${lines}; i++) await w("${M}BIG" + String(i).padStart(4, "0") + "B".repeat(56) + "\\n");
${end ? `await w("-----END ${label}-----\\n");` : ""}
await w("x".repeat(5000) + "\\n");
process.exit(1);
`,
  );
  return p;
}

describe("Leak B: init-error stderr tail is redacted before it is cut", () => {
  it("boundedTail keeps only the last characters, memory bounded", () => {
    const t = boundedTail(10);
    for (let i = 0; i < 100; i++) t.write("abcdefghij");
    expect(t.text()).toBe("abcdefghij");
  });

  it("stderrTailForError fails closed on an END whose BEGIN is outside the window", () => {
    const tail = stderrTailForError(`${M}1${"A".repeat(48)}\n${M}2${"B".repeat(48)}\n-----END RSA PRIVATE KEY-----\n${"x".repeat(50)}`);
    expect(tail).not.toContain(M);
    expect(tail.length).toBeLessThanOrEqual(8000);
  });

  for (const [name, label, end, lines] of [
    ["RSA, BEGIN beyond the 12000-char window (QA bigpem)", "RSA PRIVATE KEY", true, 100],
    ["PGP, BEGIN beyond the window", "PGP PRIVATE KEY BLOCK", true, 100],
    ["unterminated PGP block larger than the cap", "PGP PRIVATE KEY BLOCK", false, 2000],
  ] as const) {
    it(`connectStdioCommand error: ${name}`, async () => {
      const written = silenceStderr();
      let thrown = "";
      try {
        await connectStdioCommand({ command: [process.execPath, bigPemScript(label, end, lines)], env: { PATH: process.env.PATH ?? "" } });
      } catch (err) {
        thrown = err instanceof Error ? err.message : String(err);
      }
      await new Promise((r) => setTimeout(r, 50));
      expect(thrown).toContain("--- stderr ---");
      expect(thrown).not.toContain(M);
      // live passthrough redacts up to PEM_MAX_LINES lines of an unterminated block, then resets
      const live = written.join("");
      for (let i = 0; i < Math.min(lines, PEM_MAX_LINES); i++) expect(live).not.toContain(`${M}BIG${String(i).padStart(4, "0")}`);
      if (end) expect(thrown).toContain("xxxxx"); // lines after the block are kept
    }, 20_000);
  }

  it("UpstreamPool tool result and audit_events.detail_json carry no key lines (QA probe-bigpem-audit)", async () => {
    silenceStderr();
    const dir = mkdtempSync(join(tmpdir(), "mf-armor-db-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), Buffer.alloc(32, 6).toString("base64"));
    const ws = store.ensureWorkspace("default").id;
    store.createBackend(ws, {
      slug: "pem",
      transport: "stdio",
      command: [process.execPath, bigPemScript()],
      enabled: true,
      placement: { mode: "central-sandbox" },
    });
    const pool = new UpstreamPool(store);
    try {
      const r = (await pool.callTool(ws, "pem__x", {})) as { isError?: boolean; content?: { text?: string }[] };
      const text = String(r?.content?.[0]?.text ?? "");
      expect(r.isError).toBe(true);
      expect(text).not.toContain(M);
      store.writeAudit({
        workspaceId: ws,
        action: "tools/call",
        tool: "pem__x",
        detail: toolCallAuditDetail({ arguments: {}, result: r, durationMs: 1 }) as Record<string, unknown>,
      });
      const row = store.db.prepare("SELECT detail_json FROM audit_events ORDER BY rowid DESC LIMIT 1").get() as { detail_json: string };
      expect(row.detail_json).not.toContain(M);
    } finally {
      await pool.closeAll();
      store.close();
    }
  }, 30_000);
});
