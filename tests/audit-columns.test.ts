// audit_events identifier columns are sanitized / shape-checked at writeAudit. Fake values.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function open(): Store {
  const dir = mkdtempSync(join(tmpdir(), "mcp-flow-cols-"));
  dirs.push(dir);
  return new Store(join(dir, "t.db"), Buffer.alloc(32, 5).toString("base64"));
}

function last(store: Store): Record<string, unknown> {
  return store.db.prepare(`SELECT action, tool, backend_slug, placement, device_id, ip FROM audit_events ORDER BY rowid DESC LIMIT 1`).get() as Record<string, unknown>;
}

describe("audit_events columns", () => {
  it("tool / backend_slug / action / placement / device_id lose embedded secrets and control chars", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    store.writeAudit({
      workspaceId: ws.id, action: "tools/call DB_PASS=FAKEA1", tool: "up__run?token=FAKEA2", backendSlug: "b postgres://u:FAKEA3@h",
      placement: "remote\nGH_TOKEN=FAKEA4", deviceId: "dev Bearer FAKEA5", ip: "ip-FAKEA6", detail: { x: 1 },
    });
    const r = last(store);
    const s = JSON.stringify(r);
    for (let i = 1; i <= 6; i++) expect(s).not.toContain(`FAKEA${i}`);
    expect(r.tool).toBe("up__run?token=[redacted]");
    expect(r.ip).toBe("[invalid]");
    expect(r.backend_slug).toBe("[invalid]");
    expect(String(r.placement)).not.toContain("\n");
    store.close();
  });

  it("ordinary values are unchanged; ip literals kept; long values capped", () => {
    const store = open();
    const ws = store.ensureWorkspace("default");
    for (const ip of ["127.0.0.1", "::1", "::ffff:10.0.0.2", "fe80::1%eth0"]) {
      store.writeAudit({ workspaceId: ws.id, action: "tools/call", tool: "gh__list_issues", backendSlug: "gh", placement: "remote", ip });
      expect(last(store)).toEqual({ action: "tools/call", tool: "gh__list_issues", backend_slug: "gh", placement: "remote", device_id: null, ip });
    }
    store.writeAudit({ workspaceId: ws.id, action: "x", tool: "t".repeat(5000), ip: "10.0.0.1, 10.0.0.2" });
    const r = last(store);
    expect(String(r.tool).length).toBeLessThanOrEqual(257);
    expect(r.ip).toBe("[invalid]");
    store.writeAudit({ workspaceId: ws.id, action: "x" });
    expect(last(store).ip).toBeNull();
    store.close();
  });
});
