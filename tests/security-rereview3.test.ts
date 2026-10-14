/** Security T2.5 Re-review 3: R3-1..R3-4 and the M-5 cutover flag. */
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";

const tmp: string[] = [];
const cleanups: Array<() => Promise<void>> = [];
afterEach(async () => {
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});

async function boot(overrides: Record<string, unknown> = {}): Promise<RunningServer> {
  const d = mkdtempSync(join(tmpdir(), "rr3-")); tmp.push(d);
  const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: Buffer.alloc(32, 5).toString("base64"), adminToken: "rr3-admin", host: "127.0.0.1", allowPrivateUrls: true, workspaceName: "default", ...overrides });
  const probe = createServer();
  await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
  cfg.port = (probe.address() as { port: number }).port;
  await new Promise<void>((r) => probe.close(() => r()));
  const gw = await startServer(cfg);
  cleanups.push(() => gw.close());
  return gw;
}

const init = (gw: RunningServer, token: string) =>
  fetch(`${gw.url}/mcp`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "t", version: "1" } } }),
  });

describe("M-5 refuse legacy keys on /mcp (cutover flag)", () => {
  for (const on of [false, true]) {
    it(`flag ${on ? "ON" : "OFF (default)"}: legacy key ${on ? "refused 403" : "accepted"}; agent key accepted; bad token 401`, async () => {
      const gw = await boot(on ? { refuseLegacyMcpKeys: true } : {});
      expect(loadConfig({ masterKeyRaw: "x", adminToken: "y" }).refuseLegacyMcpKeys).toBe(false); // default off
      const ws = gw.store.ensureWorkspace("default").id;
      const legacy = gw.store.createApiKey(ws, "legacy", { projects: ["*"] } as never);
      const id = gw.store.identity;
      const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
      const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["p1"], createdBy: chen });
      const botTok = id.createKey({ agentId: bot, createdBy: chen }).token;
      const lr = await init(gw, legacy.token);
      if (on) {
        expect(lr.status).toBe(403);
        expect(await lr.text()).toMatch(/legacy keys are not accepted/);
      } else {
        expect(lr.status).toBe(200);
      }
      expect((await init(gw, botTok)).status).toBe(200);
      expect((await init(gw, "mf_" + "q".repeat(40))).status).toBe(401);
    });
  }
});
