/**
 * QA v5.5 1b: args of a call refused with backend_unavailable (hung init, enforcer.ts refuseBeforePolicy)
 * were stored verbatim in mcpflow_call_audit.args_redacted and audit_events.detail_json because this
 * branch lacked the A0 KEY=value rules. With the sanitizer port (rulefix + ops-redact + armor fix)
 * neither table, nor the DB file bytes, carry any marker. Fake secrets only.
 */
import { mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

const PGP = [
  "-----BEGIN PGP PRIVATE KEY BLOCK-----",
  "",
  "lQOYBGFAKEPGPLINE1AAAAAAAAAAAAAAAAAAAAAAAAA",
  "FAKEPGPLINE2BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  "=FAKE",
  "-----END PGP PRIVATE KEY BLOCK-----",
].join("\n");
const MARKERS = ["FAKEC1SECRETBQ", "FAKEC1PW", "FAKEC1BEARER", "FAKEPGPLINE1", "FAKEPGPLINE2", "FAKEC1GHTOKEN"];

describe("QA v5.5 1b: hung-init refusal audit rows carry no secrets", () => {
  it("call_audit.args_redacted, audit_events.detail_json and the DB bytes are clean", () => {
    const dir = mkdtempSync(join(tmpdir(), "mf-qa55-1b-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), Buffer.alloc(32, 7).toString("base64"));
    const ws = "ws_" + "5".repeat(24);
    const chen = store.identity.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
    const bot = store.identity.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
    const keyId = store.identity.createKey({ agentId: bot, createdBy: chen }).keyId;
    const args = {
      password: "FAKEC1PW",
      cmd: "DB_PASS=FAKEC1SECRETBQ ./run",
      note: "Authorization: Bearer FAKEC1BEARER",
      env: "export GH_TOKEN=FAKEC1GHTOKEN",
      key: PGP,
    };
    const r = store.policy.refuseBeforePolicy(
      { workspaceId: ws, agentId: bot, agentName: "bot", keyId, projectId: "p1", backendSlug: "s2" },
      "backend_unavailable",
      "s2__echo",
      args,
    );
    // the gateway's own audit_events row for the same call
    store.writeAudit({ workspaceId: ws, keyId, action: "tools/call", backendSlug: "s2", tool: "s2__echo", detail: { arguments: args, result: r } });
    const ca = store.db.prepare(`SELECT args_redacted FROM mcpflow_call_audit WHERE error_code = 'backend_unavailable'`).all() as Array<{ args_redacted: string }>;
    expect(ca).toHaveLength(2);
    const ae = JSON.stringify(store.db.prepare(`SELECT detail_json FROM audit_events`).all());
    for (const m of MARKERS) {
      for (const row of ca) expect(row.args_redacted).not.toContain(m);
      expect(ae).not.toContain(m);
    }
    expect(ca[0]!.args_redacted).toContain("DB_PASS=[redacted]");
    store.db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    for (const f of readdirSync(dir)) {
      const bytes = readFileSync(join(dir, f)).toString("latin1");
      for (const m of MARKERS) expect(bytes.includes(m), `${m} in ${f}`).toBe(false);
    }
  });
});
