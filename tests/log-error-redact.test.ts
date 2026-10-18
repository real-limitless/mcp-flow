// SecOPS (afcbc646 block, SHOULD 5): internal error messages are passed through redactLog before
// they reach stderr. Fake values only.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it, vi } from "vitest";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";
import { PolicyEnforcer } from "../src/policy/enforcer.js";

const SRC = join(__dirname, "..", "src");
function tsFiles(d: string): string[] {
  return readdirSync(d).flatMap((f) => {
    const p = join(d, f);
    return statSync(p).isDirectory() ? tsFiles(p) : p.endsWith(".ts") ? [p] : [];
  });
}

afterEach(() => vi.restoreAllMocks());

describe("error messages in logs are redacted", () => {
  it("no console.* call interpolates a raw error .message", () => {
    const raw: string[] = [];
    for (const f of tsFiles(SRC)) {
      readFileSync(f, "utf8").split("\n").forEach((l, i) => {
        if (/console\.(error|warn|log|info)\(/.test(l) && /\.message\b/.test(l) && !/redact/i.test(l)) raw.push(`${f}:${i + 1}`);
      });
    }
    expect(raw).toEqual([]);
  });

  it("a failing completion audit write logs the error message redacted", async () => {
    const WS = "ws_" + "5".repeat(24);
    const keys = derivePolicyKeys("log-redact-dev");
    const db = new DatabaseSync(":memory:");
    applyConnectionPragmas(db);
    runMigrations(db);
    const dir = new AgentDirectory(db, keys);
    const chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const bot = dir.createAgent({ workspaceId: WS, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const botKey = dir.createKey({ agentId: bot, createdBy: chen }).keyId;
    const id = `rule_${randomBytes(12).toString("hex")}`;
    db.exec("BEGIN IMMEDIATE;");
    db.prepare(`INSERT INTO mcpflow_policy_rule (id, workspace_id, created_by) VALUES (?,?,?)`).run(id, WS, chen);
    db.prepare(`INSERT INTO mcpflow_policy_rule_version (rule_id, version, description, match_tools, effect, created_by) VALUES (?,1,'t','["*"]','allow',?)`).run(id, chen);
    db.prepare(`UPDATE mcpflow_policy_rule SET current_version=1 WHERE id=?`).run(id);
    db.exec("COMMIT;");
    // simulate a storage error whose message carries a secret
    db.exec(`CREATE TEMP TRIGGER t_fail BEFORE INSERT ON mcpflow_call_audit WHEN NEW.event_type = 'completion'
             BEGIN SELECT RAISE(ABORT, 'disk said password=FAKELOGPW55x'); END;`);
    const logs: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => void logs.push(a.map(String).join(" ")));
    const pe = new PolicyEnforcer({ db, keys });
    await pe.enforce({
      ctx: { workspaceId: WS, agentId: bot, agentName: "bot", keyId: botKey, keyPrefix: null, sessionId: null,
        projectId: "p1", backendSlug: "gh", tool: "echo", qualifiedTool: "gh__echo", placement: "remote", deviceId: null },
      args: {}, dispatch: async () => ({ content: [{ type: "text", text: "ok" }] }),
    }).catch(() => undefined);
    const line = logs.find((l) => l.includes("completion audit write failed"));
    expect(line).toBeDefined();
    expect(line).toContain("password=[redacted]");
    expect(logs.join("\n")).not.toContain("FAKELOGPW55x");
  });
});
