// SecOPS (afcbc646 block, MUST 2): lifecycle audit detail is sanitizeForAudit'd, and free-text revoke
// reasons are stored redacted; a fake secret in a revoke reason is absent from the .db and -wal bytes.
// Fake values only; temp dirs.
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory, REVOKE_REASON_MAX } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";

const WS = "ws_" + "c".repeat(24);
const PW = "FAKEREVOKEPW" + "4k2z9";
const TOK = "ghp_" + "Q7".repeat(18); // built at runtime: no raw token literal in the repo
const NAME_PW = "FAKENAMEPW" + "8r3t";
const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function filesWith(dir: string, needle: string): string[] {
  return readdirSync(dir).filter((f) => readFileSync(join(dir, f)).includes(Buffer.from(needle)));
}

describe("lifecycle audit: revoke reasons and agent names are sanitized on write", () => {
  it("fake secrets in revoke reasons never reach the DB bytes; detail is sanitized", () => {
    const dir = mkdtempSync(join(tmpdir(), "mf-lc-bytes-"));
    dirs.push(dir);
    const db = new DatabaseSync(join(dir, "t.db"));
    applyConnectionPragmas(db);
    runMigrations(db);
    const ids = new AgentDirectory(db, derivePolicyKeys("unit-test-dev-key"), () => Date.now());
    const chen = ids.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const a = ids.createAgent({
      workspaceId: WS, name: `bot password=${NAME_PW}`, owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen,
    });
    const k = ids.createKey({ agentId: a, createdBy: chen });
    expect(ids.revokeKey(k.keyId, chen, `rotated, password=${PW} was pasted in CI`)).toBe(true);
    expect(ids.revokeAgent(a, chen, `compromised, token ${TOK} found\nin a log`)).toBe(true);

    const rows = db
      .prepare(`SELECT lifecycle_action AS a, args_redacted AS d FROM mcpflow_call_audit WHERE event_type='lifecycle'`)
      .all() as { a: string; d: string }[];
    const all = JSON.stringify(rows);
    for (const s of [PW, TOK, NAME_PW]) expect(all).not.toContain(s);
    const det = (a: string) => JSON.parse(rows.find((r) => r.a === a)!.d) as Record<string, string>;
    expect(det("key_revoke").reason).toContain("[redacted]");
    expect(det("agent_revoke").reason).toContain("[redacted]");
    expect(det("agent_create").name).toContain("[redacted]");

    const kr = db.prepare(`SELECT revoked_reason r FROM mcpflow_api_key WHERE id=?`).get(k.keyId) as { r: string };
    const ar = db.prepare(`SELECT revoked_reason r FROM mcpflow_agent WHERE id=?`).get(a) as { r: string };
    expect(kr.r.startsWith("rotated, password=[redacted]")).toBe(true);
    expect(ar.r).not.toContain(TOK);
    expect(ar.r).not.toContain("\n"); // control characters replaced

    // revoke-reason secrets: absent from every file (WAL not yet checkpointed, then after checkpoint/close)
    for (const s of [PW, TOK]) expect(filesWith(dir, s)).toEqual([]);
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    for (const s of [PW, TOK]) expect(filesWith(dir, s)).toEqual([]);
    db.close();
    for (const s of [PW, TOK]) expect(filesWith(dir, s)).toEqual([]);
  });

  it("caps a long revoke reason", () => {
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db);
    const ids = new AgentDirectory(db, derivePolicyKeys("unit-test-dev-key"), () => Date.now());
    const chen = ids.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const a = ids.createAgent({ workspaceId: WS, name: "b", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    ids.revokeAgent(a, chen, "x".repeat(10_000));
    const ar = db.prepare(`SELECT revoked_reason r FROM mcpflow_agent WHERE id=?`).get(a) as { r: string };
    expect(ar.r.length).toBe(REVOKE_REASON_MAX + 1);
  });
});
