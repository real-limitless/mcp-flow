/**
 * Architecture decision (one bootstrap human admin per workspace), conditions:
 * (a) workspace creation is ops-only: no mf_ tool and no admin API route creates a workspace;
 * (b) a workspace and its bootstrap human admin are created in one transaction (both or neither);
 * (c) every later admin in that workspace has a non-null created_by, enforced by the DB.
 */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";
import { createApp } from "../src/api/app.js";
import { applyConnectionPragmas, runMigrations } from "../src/db/migrations/index.js";
import { AgentDirectory } from "../src/identity/agents.js";
import { derivePolicyKeys } from "../src/identity/dev-keys.js";

const ROOT = join(__dirname, "..");
const srcFiles = (dir: string): string[] =>
  readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? srcFiles(p) : /\.(ts|js)$/.test(f) ? [p] : [];
  });

describe("(a) workspace creation is ops-only", () => {
  it("static: only bootstrapWorkspace / ensureWorkspace insert workspaces; no route or tool module calls bootstrapWorkspace", () => {
    const inserts: string[] = [];
    const bootstrapCalls: string[] = [];
    const ensureCalls: string[] = [];
    for (const f of srcFiles(join(ROOT, "src"))) {
      const rel = relative(ROOT, f);
      if (rel.startsWith("src/db/migrations/")) continue;
      const lines = readFileSync(f, "utf8").split("\n");
      lines.forEach((l, i) => {
        if (/INTO\s+(mcpflow_workspace|workspaces)\b/.test(l)) inserts.push(`${rel}:${i + 1}`);
        if (/\bbootstrapWorkspace\(/.test(l) && !/^\s*bootstrapWorkspace\(/.test(l)) bootstrapCalls.push(rel);
        if (/\bensureWorkspace\(/.test(l) && !/^\s*ensureWorkspace\(/.test(l)) ensureCalls.push(rel);
      });
    }
    // exactly two writers
    expect(inserts.map((s) => s.split(":")[0]).sort()).toEqual(["src/db/store.ts", "src/identity/agents.ts"]);
    // mcpflow_workspace (+ bootstrap admin) is created by no production code path at all: ops/CLI/test only
    expect(bootstrapCalls).toEqual([]);
    // the legacy `workspaces` row: never from MCP tool code; from the API only on the break-glass env admin
    // token path (ops secret; name from config, not the request)
    expect(ensureCalls.filter((f) => f.startsWith("src/mcp/") || f.startsWith("src/edge/") || f.startsWith("src/http/"))).toEqual([]);
    expect(ensureCalls.filter((f) => f.startsWith("src/api/"))).toEqual(["src/api/app.ts"]);
    expect(readFileSync(join(ROOT, "src/api/app.ts"), "utf8")).toMatch(/cfg\.adminToken && safeEqualStr\(token, cfg\.adminToken\)\) \{\s*const ws = store\.ensureWorkspace\(cfg\.workspaceName\)/);
  });

  describe("dynamic: every API route and every mf_ tool, as agent / human admin / anonymous, creates no workspace", () => {
    let gw: RunningServer | null = null;
    const dirs: string[] = [];
    afterEach(async () => {
      await gw?.close();
      gw = null;
      while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
    });

    it("enumerates routes and tools and calls each one", async () => {
      const d = mkdtempSync(join(tmpdir(), "mcp-flow-wsb-"));
      dirs.push(d);
      const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: Buffer.alloc(32, 41).toString("base64"), adminToken: randomBytes(32).toString("hex"), host: "127.0.0.1", allowPrivateUrls: false, workspaceName: "default" });
      const probe = createServer();
      await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
      cfg.port = (probe.address() as { port: number }).port;
      await new Promise<void>((r) => probe.close(() => r()));
      gw = await startServer(cfg);
      const ws = gw.store.ensureWorkspace("default").id;
      const id = gw.store.identity;
      const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
      const chenTok = id.createKey({ agentId: chen, createdBy: chen }).token;
      gw.store.db.prepare(`INSERT INTO mcpflow_agent_project (agent_id, project_id) VALUES (?, 'default')`).run(chen); // so the admin can open /mcp
      const bot = id.createAgent({ workspaceId: ws, name: "bot", owner: "chen", kind: "grokbot", projects: ["default"], createdBy: chen });
      const botTok = id.createKey({ agentId: bot, createdBy: chen }).token;
      const db = gw.store.db;
      const counts = () => db.prepare(`SELECT (SELECT count(*) FROM mcpflow_workspace) m, (SELECT count(*) FROM workspaces) w, (SELECT count(*) FROM mcpflow_agent WHERE created_by IS NULL) b`).get();
      const before = counts();
      expect(before).toEqual({ m: 1, w: 1, b: 1 });

      const evil = { workspace_id: "ws_" + "e".repeat(24), workspaceId: "ws_" + "e".repeat(24), workspace: "evil", name: "evil", workspaceName: "evil", owner: "evil" };
      const withTimeout = <T>(p: Promise<T>) => Promise.race([p.catch(() => null), new Promise((r) => setTimeout(() => r(null), 3000))]);

      // API: the routes of the real app, enumerated from Hono
      const app = createApp(gw.store, cfg, gw.pool);
      const routes = [...new Map(app.routes.filter((r) => r.path !== "/*" && r.path !== "*" && r.method !== "OPTIONS").map((r) => [`${r.method} ${r.path}`, r])).values()];
      expect(routes.length).toBeGreaterThan(20);
      let calls = 0;
      for (const r of routes) {
        if (r.path === "/mcp") continue; // MCP is exercised below with a real client
        const path = r.path.replace(/:([A-Za-z_]+)(\{[^}]*\})?/g, (_m, n: string) => (/work|ws/i.test(n) ? evil.workspace_id : `x_${n}`)).replace(/\*/g, "x");
        const methods = r.method === "ALL" ? ["GET", "POST"] : [r.method];
        for (const m of methods) for (const tok of [null, botTok, chenTok]) {
          const headers: Record<string, string> = { "content-type": "application/json" };
          if (tok) headers.authorization = `Bearer ${tok}`;
          await withTimeout(Promise.resolve(app.request(path, { method: m, headers, body: m === "GET" || m === "HEAD" ? undefined : JSON.stringify(evil) })));
          calls++;
        }
      }
      expect(calls).toBeGreaterThan(60);
      expect(counts()).toEqual(before);

      // MCP: every tool listed to the agent and to the human admin, called with workspace-ish args
      const toolNames = new Set<string>();
      for (const tok of [botTok, chenTok]) {
        const client = new Client({ name: "wsb", version: "1" });
        await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${cfg.port}/mcp`), { requestInit: { headers: { Authorization: `Bearer ${tok}` } } }));
        const { tools } = await client.listTools();
        for (const t of tools) {
          toolNames.add(t.name);
          await withTimeout(client.callTool({ name: t.name, arguments: evil }));
        }
        await client.close();
      }
      expect([...toolNames].some((n) => n.startsWith("mf_"))).toBe(true);
      expect([...toolNames].filter((n) => /workspace/i.test(n) && /create|bootstrap|new|add/i.test(n))).toEqual([]);
      expect(counts()).toEqual(before);
    }, 120_000);
  });
});

const fresh = () => {
  const db = new DatabaseSync(":memory:");
  applyConnectionPragmas(db);
  runMigrations(db);
  return { db, dir: new AgentDirectory(db, derivePolicyKeys("wsb")) };
};
const WS = "ws_" + "1".repeat(24);
const WS2 = "ws_" + "2".repeat(24);
const n = (db: DatabaseSync, sql: string) => (db.prepare(sql).get() as { n: number }).n;

describe("(b) workspace + bootstrap human admin: one transaction, both or neither", () => {
  it("happy path: both rows, the admin is human/is_admin/created_by NULL and owns the workspace", () => {
    const { db, dir } = fresh();
    const chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    expect(db.prepare(`SELECT owner_principal_id o FROM mcpflow_workspace WHERE id = ?`).get(WS)).toEqual({ o: chen });
    expect(db.prepare(`SELECT kind, is_admin, created_by, workspace_id FROM mcpflow_agent WHERE id = ?`).get(chen))
      .toEqual({ kind: "human", is_admin: 1, created_by: null, workspace_id: WS });
  });

  for (const [what, table] of [["admin insert", "mcpflow_agent"], ["workspace insert", "mcpflow_workspace"], ["bootstrap audit row", "mcpflow_call_audit"]] as const) {
    it(`if the ${what} fails, neither the workspace nor the admin exists`, () => {
      const { db, dir } = fresh();
      db.exec(`CREATE TEMP TRIGGER fail_${table} BEFORE INSERT ON main.${table} BEGIN SELECT RAISE(ABORT, 'injected'); END;`);
      expect(() => dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" })).toThrow(/injected/);
      expect(n(db, `SELECT count(*) n FROM mcpflow_workspace`)).toBe(0);
      expect(n(db, `SELECT count(*) n FROM mcpflow_agent`)).toBe(0);
      db.exec(`DROP TRIGGER temp.fail_${table};`);
      dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" }); // nothing half-made blocks a retry
      expect(n(db, `SELECT count(*) n FROM mcpflow_workspace`)).toBe(1);
    });
  }

  it("a duplicate bootstrap of an existing workspace leaves no orphan admin", () => {
    const { db, dir } = fresh();
    dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    expect(() => dir.bootstrapWorkspace(WS, { name: "mallory", owner: "m" })).toThrow();
    expect(db.prepare(`SELECT name FROM mcpflow_agent`).all()).toEqual([{ name: "chen" }]);
  });

  it("DB level: a workspace without its owner agent, or an agent without its workspace, cannot commit", () => {
    const { db } = fresh();
    db.exec("BEGIN;");
    db.prepare(`INSERT INTO mcpflow_workspace (id, owner_principal_id) VALUES (?, ?)`).run(WS, "agt_" + "a".repeat(24));
    expect(() => db.exec("COMMIT;")).toThrow(/FOREIGN KEY/);
    db.exec("ROLLBACK;");
    db.exec("BEGIN;");
    db.prepare(`INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by) VALUES (?, ?, 'x', 'x', 'human', 1, NULL)`).run("agt_" + "b".repeat(24), WS2);
    expect(() => db.exec("COMMIT;")).toThrow(/FOREIGN KEY/);
    db.exec("ROLLBACK;");
    expect(n(db, `SELECT count(*) n FROM mcpflow_workspace`) + n(db, `SELECT count(*) n FROM mcpflow_agent`)).toBe(0);
  });
});

describe("(c) every later admin in the workspace has a non-null created_by (DB-enforced)", () => {
  const ins = (db: DatabaseSync, name: string, kind: string, admin: number, createdBy: string | null, ws = WS) =>
    db.prepare(`INSERT INTO mcpflow_agent (id, workspace_id, name, owner, kind, is_admin, created_by) VALUES (?, ?, ?, 'o', ?, ?, ?)`)
      .run(`agt_${Buffer.from(name.padEnd(12, "_")).toString("hex").slice(0, 24)}`, ws, name, kind, admin, createdBy);

  it("a second created_by NULL agent (admin or not) is rejected; admins created by the bootstrap admin are fine", () => {
    const { db, dir } = fresh();
    const chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    expect(() => ins(db, "admin2", "human", 1, null)).toThrow(/UNIQUE|mcpflow_agent_one_bootstrap/);
    expect(() => ins(db, "bot2", "grokbot", 0, null)).toThrow(/only the bootstrap human admin/);
    expect(() => ins(db, "human2", "human", 0, null)).toThrow(/only the bootstrap human admin/);
    const ana = dir.createAgent({ workspaceId: WS, name: "ana", owner: "ana", kind: "human", isAdmin: true, projects: [], createdBy: chen });
    expect(db.prepare(`SELECT is_admin, created_by FROM mcpflow_agent WHERE id = ?`).get(ana)).toEqual({ is_admin: 1, created_by: chen });
    expect(n(db, `SELECT count(*) n FROM mcpflow_agent WHERE workspace_id = '${WS}' AND is_admin = 1 AND created_by IS NULL`)).toBe(1);
  });

  it("created_by can't be cleared later (no promoting an existing admin to a second bootstrap), and the bootstrap admin can't be demoted", () => {
    const { db, dir } = fresh();
    const chen = dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    const ana = dir.createAgent({ workspaceId: WS, name: "ana", owner: "ana", kind: "human", isAdmin: true, projects: [], createdBy: chen });
    expect(() => db.prepare(`UPDATE mcpflow_agent SET created_by = NULL WHERE id = ?`).run(ana)).toThrow(/immutable/);
    expect(() => db.prepare(`UPDATE mcpflow_agent SET is_admin = 0 WHERE id = ?`).run(chen)).toThrow(/demoted/);
    expect(() => db.prepare(`UPDATE mcpflow_agent SET created_by = ? WHERE id = ?`).run(ana, chen)).toThrow(/immutable/);
  });

  it("each workspace gets exactly one bootstrap admin of its own", () => {
    const { db, dir } = fresh();
    dir.bootstrapWorkspace(WS, { name: "chen", owner: "chen" });
    dir.bootstrapWorkspace(WS2, { name: "chen", owner: "chen" });
    expect(db.prepare(`SELECT workspace_id w, count(*) c FROM mcpflow_agent WHERE created_by IS NULL GROUP BY workspace_id ORDER BY w`).all())
      .toEqual([{ w: WS, c: 1 }, { w: WS2, c: 1 }]);
  });
});
