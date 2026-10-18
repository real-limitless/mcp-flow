// SecOPS (5d004abc, pre-prod follow-up 1): mcpflow_pending_call.note is approver free text; stored
// redacted and capped (auditText, CALL_AUDIT_NOTE_MAX) by decide() and approveSimilar(). Fake
// values only; temp dirs.
import { randomBytes } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { CALL_AUDIT_NOTE_MAX } from "../src/audit/call-audit-cols.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer } from "../src/policy/enforcer.js";

const WS = "ws_" + "9".repeat(24);
const PW1 = "FAKENOTEPW" + "1x7";
const PW2 = "FAKENOTEPW" + "2y8";
const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});
const filesWith = (dir: string, needle: string) => readdirSync(dir).filter((f) => readFileSync(join(dir, f)).includes(Buffer.from(needle)));

describe("pending_call.note is sanitized on write", () => {
  it("deny and approve-similar notes: fake secrets absent from the row, the .db and the -wal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mf-pcnote-"));
    dirs.push(dir);
    const db = new DatabaseSync(join(dir, "t.db"));
    applyConnectionPragmas(db);
    runMigrations(db);
    const keys = derivePolicyKeys("pc-note-dev");
    const ids = new AgentDirectory(db, keys);
    const chen = ids.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const bot = ids.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const botKey = ids.createKey({ agentId: bot, createdBy: chen }).keyId;
    const rid = `rule_${randomBytes(12).toString("hex")}`;
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(rid, WS, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, approvers, approval_timeout_s, created_by)
                VALUES (?,1,'t','["merge"]','require_approval',?,30,?)`).run(rid, JSON.stringify([chen]), chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(rid);
    db.exec("COMMIT;");
    const pe = new PolicyEnforcer({ db, keys });
    const call = (pr: number) => pe.enforce({
      ctx: { workspaceId: WS, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null,
        projectId: "p1", backendSlug: "gh", tool: "merge", qualifiedTool: "gh__merge", placement: "remote", deviceId: null },
      args: { pr }, dispatch: async () => ({ content: [{ type: "text", text: "ok" }] }),
    });
    const pending = async () => {
      for (let i = 0; i < 300; i++) {
        const r = db.prepare(`SELECT id FROM mcpflow_pending_call WHERE status='pending'`).get() as { id: string } | undefined;
        if (r) return r.id;
        await new Promise((res) => setTimeout(res, 10));
      }
      throw new Error("no pending call");
    };
    const note = (id: string) => (db.prepare(`SELECT note FROM mcpflow_pending_call WHERE id=?`).get(id) as { note: string | null } | undefined)?.note;

    const p1 = call(1);
    const id1 = await pending();
    expect(pe.decide(id1, chen, "denied", `no, password=${PW1}\n${"n".repeat(5000)}`)).toEqual({ ok: true });
    const n1 = note(id1);
    await p1;
    expect(n1).toBeTypeOf("string");
    expect(n1).not.toContain(PW1);
    expect(n1!.length).toBe(CALL_AUDIT_NOTE_MAX + 1);
    expect(n1).not.toContain("\n");

    const p2 = call(2);
    const id2 = await pending();
    const r2 = pe.approveSimilar(id2, chen, 5, { note: `ok, API_KEY=${PW2} for the release`, sameArgsOnly: true });
    expect(r2.ok).toBe(true);
    const n2 = note(id2);
    await p2;
    expect(n2).toBe("ok, API_KEY=[redacted]");

    for (const s of [PW1, PW2]) expect(filesWith(dir, s)).toEqual([]);
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
    for (const s of [PW1, PW2]) expect(filesWith(dir, s)).toEqual([]);
    db.close();
    for (const s of [PW1, PW2]) expect(filesWith(dir, s)).toEqual([]);
  });
});
