/** Secrets A1 §0.12: legacy authorization and approvals refuse secret://. */
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { EXACT_ADMIN_TOOL_NAMES } from "../src/audit/redact-admin-args.js";
import { runAuthzGate } from "../src/authz/gate.js";
import { Store } from "../src/db/store.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function openStore(): Store {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-legacy-ref-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), Buffer.alloc(32, 9).toString("base64"));
}

describe("legacy secret:// refusal", () => {
  it("refuses a secret:// ref on the authz gate before an exempt tool can proceed", async () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    const gate = await runAuthzGate({
      store,
      workspaceId: ws.id,
      keyId: null,
      tool: "mf_status",
      contexts: [],
      args: { note: "secret://proj/db" },
    });
    expect(gate.proceed).toBe(false);
    if (!gate.proceed) {
      const text = JSON.stringify(gate.result);
      expect(text).toContain("legacy_secret_ref");
      expect(text).not.toContain("secret://proj/db");
    }
    store.close();
  });

  it("refuses createApproval and does not store the ref", () => {
    const store = openStore();
    const ws = store.ensureWorkspace("default");
    expect(() =>
      store.createApproval({
        workspaceId: ws.id,
        ruleId: "rule",
        keyId: "key",
        tool: "echo",
        arguments: { token: "secret://proj/db" },
        backendSlug: null,
        requirement: "notify_approve",
        ttlSeconds: 60,
      }),
    ).toThrow(/refused on legacy authorization paths/);
    const n = store.db.prepare(`SELECT count(*) AS n FROM approvals`).get() as { n: number };
    expect(n.n).toBe(0);
    store.close();
  });

  it("registers secret writes as admin tools and keeps reveal and payload out", () => {
    for (const name of ["mf_secret_create", "mf_secret_rotate", "mf_secret_delete"]) {
      expect(EXACT_ADMIN_TOOL_NAMES.has(name)).toBe(true);
    }
    expect(EXACT_ADMIN_TOOL_NAMES.has("mf_secret_list")).toBe(false);
    for (const name of EXACT_ADMIN_TOOL_NAMES) {
      expect(name).not.toMatch(/payload|secret_reveal|secret_import/);
    }
  });
});
