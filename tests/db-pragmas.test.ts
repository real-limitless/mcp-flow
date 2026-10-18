/** PM: PRAGMA journal_size_limit set at DB open (default 64 MiB), configurable via MCP_FLOW_JOURNAL_SIZE_LIMIT_MB. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig, parseJournalSizeLimitBytes } from "../src/config.js";
import { applyConnectionPragmas, DEFAULT_JOURNAL_SIZE_LIMIT_BYTES } from "../src/db/migrations/index.js";
import { Store } from "../src/db/store.js";

const MiB = 1024 * 1024;
const dirs: string[] = [];
const tmp = () => { const d = mkdtempSync(join(tmpdir(), "mcp-flow-pragma-")); dirs.push(d); return d; };
afterEach(() => { while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true }); });
const pragma = (db: DatabaseSync, p: string) => Object.values(db.prepare(`PRAGMA ${p}`).get() as Record<string, unknown>)[0];
const master = Buffer.alloc(32, 7).toString("base64");

describe("journal_size_limit", () => {
  it("defaults to 64 MiB on every connection opened through applyConnectionPragmas / Store", () => {
    expect(DEFAULT_JOURNAL_SIZE_LIMIT_BYTES).toBe(64 * MiB);
    const db = new DatabaseSync(join(tmp(), "a.db"));
    applyConnectionPragmas(db);
    expect(pragma(db, "journal_size_limit")).toBe(64 * MiB);
    expect(pragma(db, "journal_mode")).toBe("wal");
    db.close();
    const s = new Store(join(tmp(), "s.db"), master);
    expect(pragma(s.db, "journal_size_limit")).toBe(64 * MiB);
    s.db.close();
  });

  it("is configurable (Store option, applyConnectionPragmas option, loadConfig env)", () => {
    const s = new Store(join(tmp(), "s.db"), master, { journalSizeLimitBytes: 8 * MiB });
    expect(pragma(s.db, "journal_size_limit")).toBe(8 * MiB);
    s.db.close();
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db, { journalSizeLimitBytes: 3 * MiB });
    expect(pragma(db, "journal_size_limit")).toBe(3 * MiB);
    expect(() => applyConnectionPragmas(db, { journalSizeLimitBytes: -1 })).toThrow();
    const prev = process.env.MCP_FLOW_JOURNAL_SIZE_LIMIT_MB;
    try {
      process.env.MCP_FLOW_JOURNAL_SIZE_LIMIT_MB = "16";
      expect(loadConfig({ dbPath: join(tmp(), "c.db") }).journalSizeLimitBytes).toBe(16 * MiB);
      delete process.env.MCP_FLOW_JOURNAL_SIZE_LIMIT_MB;
      expect(loadConfig({ dbPath: join(tmp(), "c.db") }).journalSizeLimitBytes).toBe(64 * MiB);
    } finally {
      if (prev === undefined) delete process.env.MCP_FLOW_JOURNAL_SIZE_LIMIT_MB; else process.env.MCP_FLOW_JOURNAL_SIZE_LIMIT_MB = prev;
    }
  });

  it("parse: whole MiB, clamped 1..4096, unset/invalid -> 64", () => {
    for (const [raw, mb] of [[undefined, 64], ["", 64], ["abc", 64], ["1.5", 64], ["-3", 64], ["0", 1], ["1", 1], ["128", 128], ["99999", 4096], [" 32 ", 32]] as const)
      expect(parseJournalSizeLimitBytes(raw as string | undefined)).toBe(mb * MiB);
  });

  it("after a checkpoint the WAL kept on disk shrinks to the limit (control: no limit keeps it large)", () => {
    const { statSync } = require("node:fs") as typeof import("node:fs");
    const walAfter = (limit: number | null) => {
      const path = join(tmp(), "w.db");
      const db = new DatabaseSync(path);
      applyConnectionPragmas(db, { journalSizeLimitBytes: 64 * 1024 });
      if (limit === null) db.exec("PRAGMA journal_size_limit = -1;");
      db.exec("PRAGMA wal_autocheckpoint = 0; CREATE TABLE t (b BLOB);");
      const ins = db.prepare("INSERT INTO t VALUES (randomblob(4096))");
      for (let i = 0; i < 500; i++) ins.run();
      expect(statSync(`${path}-wal`).size).toBeGreaterThan(1024 * 1024);
      db.exec("PRAGMA wal_checkpoint(PASSIVE);"); // checkpoint only, no forced truncate
      db.exec("INSERT INTO t VALUES (1)"); // the next write restarts the WAL and applies journal_size_limit
      const size = statSync(`${path}-wal`).size;
      db.close();
      return size;
    };
    expect(walAfter(null)).toBeGreaterThan(1024 * 1024);
    expect(walAfter(64 * 1024)).toBeLessThanOrEqual(64 * 1024);
  });
});
