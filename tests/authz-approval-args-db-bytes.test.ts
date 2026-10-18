// SecOPS (afcbc646 block, MUST 1): a fake password in legacy approval arguments never reaches
// approvals.arguments_json, the .db file or its -wal, at any stage (pending, approved+consumed,
// denied, expired, swept). Fake values only; temp dirs.
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";

const master = Buffer.alloc(32, 23).toString("base64");
const SECRET = "FAKEAPPRPW9q7x";
const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function bytesHave(dir: string, needle: string): string[] {
  return readdirSync(dir).filter((f) => readFileSync(join(dir, f)).includes(Buffer.from(needle)));
}

describe("approval args: fake password absent from arguments_json, .db and -wal", () => {
  it("pending, approved + consumed, denied, expired and swept rows", () => {
    const dir = mkdtempSync(join(tmpdir(), "mf-apr-bytes-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    const rule = store.createAuthzRule(ws.id, { name: "r", match: { tools: ["up__run"] }, ttlSeconds: 60 });
    const key = store.createApiKey(ws.id, "agent");
    const make = () =>
      store.createApproval({
        workspaceId: ws.id, ruleId: rule.id, keyId: key.id, tool: "up__run",
        arguments: { cmd: `DB_PASS=${SECRET} ./run`, password: SECRET, note: `Bearer ${SECRET}` },
        backendSlug: "up", requirement: "notify_approve", ttlSeconds: 60,
      }).approval;
    const pending = make();
    const approved = make();
    const denied = make();
    const expired = make();
    const orphan = make(); // approved while no gate waits: left sealed until the startup sweep
    // WAL holds the inserts now (not checkpointed): sealed already
    expect(existsSync(join(dir, "t.db-wal"))).toBe(true);
    expect(bytesHave(dir, SECRET)).toEqual([]);

    store.decideApproval(ws.id, approved.id, { status: "approved" });
    const consumed = store.consumeApprovedArguments(ws.id, approved.id);
    expect(JSON.stringify(consumed)).toContain(SECRET); // the gate gets the raw args in memory only
    store.decideApproval(ws.id, denied.id, { status: "denied" });
    store.expireApproval(ws.id, expired.id);
    store.decideApproval(ws.id, orphan.id, { status: "approved" });
    expect(store.sweepResolvedSealedApprovalArgs()).toBeGreaterThanOrEqual(1);

    const rows = store.db.prepare(`SELECT id, arguments_json FROM approvals`).all() as Array<{ id: string; arguments_json: string }>;
    expect(rows).toHaveLength(5);
    for (const r of rows) {
      expect(r.arguments_json).not.toContain(SECRET);
      expect(r.arguments_json.startsWith("enc:v1:") || r.arguments_json.startsWith("san:v1:")).toBe(true);
    }
    expect(rows.find((r) => r.id === pending.id)!.arguments_json.startsWith("enc:v1:")).toBe(true);
    for (const id of [approved.id, denied.id, expired.id, orphan.id]) {
      expect(rows.find((r) => r.id === id)!.arguments_json.startsWith("san:v1:")).toBe(true);
    }
    expect(bytesHave(dir, SECRET)).toEqual([]); // .db and -wal, before checkpoint
    store.db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    expect(bytesHave(dir, SECRET)).toEqual([]);
    store.close();
    expect(bytesHave(dir, SECRET)).toEqual([]);
  });
});
