/** Security R5-1 (session maps partitioned per key) and R5-2 (a session id bound by one key is refused for another). */
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { startServer, type RunningServer } from "../src/server.js";
import { SessionProjectMap } from "../src/mcp/session-project.js";
import { SessionToolSetMap } from "../src/mcp/session-tools.js";
import { SESSION_MAP_PER_KEY_MAX, SessionIdInUseError } from "../src/mcp/ttl-lru.js";

const stops: Array<{ stop(): void }> = [];
const cleanups: Array<() => Promise<void>> = [];
const tmp: string[] = [];
afterEach(async () => {
  while (stops.length) stops.pop()!.stop();
  while (cleanups.length) await cleanups.pop()!().catch(() => {});
  while (tmp.length) rmSync(tmp.pop()!, { recursive: true, force: true });
});
const proj = (keyId: string, slug = "alpha") => ({ projectId: `p_${slug}`, projectSlug: slug, keyId });

describe("R5-1: one key can't evict another key's session entries", () => {
  it("project map: key A churning 10 000 session ids keeps at most its own quota; key B's binding survives", () => {
    const m = new SessionProjectMap(8);
    stops.push(m);
    m.set("victim", proj("key-b", "beta"));
    for (let i = 0; i < 10_000; i++) m.set(`spam-${i}`, proj("key-a"));
    expect(m.get("victim")).toMatchObject({ keyId: "key-b", projectSlug: "beta" });
    expect(m.sizeForKey("key-a")).toBe(8);
    expect(m.sizeForKey("key-b")).toBe(1);
    expect(m.size).toBe(9);
    // A's own LRU: its most recent ids are the ones kept
    expect(m.get("spam-9999")).not.toBeNull();
    expect(m.get("spam-0")).toBeNull();
  });

  it("tool-set map: the same per-key partitioning", () => {
    const m = new SessionToolSetMap(4);
    stops.push(m);
    m.add("victim", "key-b", ["gh__merge"]);
    for (let i = 0; i < 5000; i++) m.add(`spam-${i}`, "key-a", ["x__y"]);
    expect([...m.get("victim", "key-b")]).toEqual(["gh__merge"]);
    expect(m.sizeForKey("key-a")).toBe(4);
  });

  it("default per-key quota is SESSION_MAP_PER_KEY_MAX; the number of keys tracked is bounded too", () => {
    const m = new SessionProjectMap(undefined, 60_000, 3);
    stops.push(m);
    for (let i = 0; i < SESSION_MAP_PER_KEY_MAX + 10; i++) m.set(`s-${i}`, proj("key-a"));
    expect(m.sizeForKey("key-a")).toBe(SESSION_MAP_PER_KEY_MAX);
    // more distinct keys than maxKeys: the least recently active key's partition goes (needs that many real keys)
    m.set("b", proj("key-b"));
    m.set("c", proj("key-c"));
    m.get("s-20"); // key-a active again
    m.set("d", proj("key-d")); // 4 keys > 3: key-b (least recently active) dropped
    expect(m.get("b")).toBeNull();
    expect(m.get("c")).not.toBeNull();
    expect(m.get("s-20")).not.toBeNull();
  });
});

describe("R5-2: a session id bound by one key is refused for another (map level)", () => {
  it("set/add by another key throws SessionIdInUseError and leaves the owner's row untouched", () => {
    const p = new SessionProjectMap();
    const t = new SessionToolSetMap();
    stops.push(p, t);
    p.set("sid-1", proj("key-a", "alpha"));
    t.add("sid-1", "key-a", ["gh__read"]);
    expect(() => p.set("sid-1", proj("key-b", "evil"))).toThrow(SessionIdInUseError);
    expect(() => t.add("sid-1", "key-b", ["gh__merge"])).toThrow(SessionIdInUseError);
    expect(() => t.clear("sid-1", "key-b")).toThrow(SessionIdInUseError);
    expect(p.get("sid-1")).toMatchObject({ keyId: "key-a", projectSlug: "alpha" });
    expect([...t.get("sid-1", "key-a")]).toEqual(["gh__read"]);
    expect(p.ownedByOther("sid-1", "key-b")).toBe(true);
    expect(p.ownedByOther("sid-1", "key-a")).toBe(false);
    // the owner can re-bind; once the owner's row is gone, the id is free again
    p.set("sid-1", proj("key-a", "beta"));
    p.clearIfOwner("sid-1", "key-a");
    p.set("sid-1", proj("key-b", "gamma"));
    expect(p.get("sid-1")).toMatchObject({ keyId: "key-b" });
  });

  it("an expired row doesn't block a new owner", async () => {
    const p = new SessionProjectMap();
    stops.push(p);
    p.set("sid-x", proj("key-a"), 10);
    await new Promise((r) => setTimeout(r, 25));
    p.set("sid-x", proj("key-b"));
    expect(p.get("sid-x")).toMatchObject({ keyId: "key-b" });
  });
});

describe("R5-1/R5-2 through /mcp", () => {
  it("agent B reusing agent A's session id gets 409 and A keeps its project; B's churn doesn't evict A's binding", async () => {
    const d = mkdtempSync(join(tmpdir(), "mcp-flow-r5s-"));
    tmp.push(d);
    const cfg = loadConfig({ dbPath: join(d, "t.db"), masterKeyRaw: Buffer.alloc(32, 5).toString("base64"), adminToken: randomBytes(24).toString("hex"), host: "127.0.0.1", allowPrivateUrls: false, workspaceName: "default" });
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(0, "127.0.0.1", r));
    cfg.port = (probe.address() as { port: number }).port;
    await new Promise<void>((r) => probe.close(() => r()));
    const gw: RunningServer = await startServer(cfg);
    cleanups.push(() => gw.close());
    const ws = gw.store.ensureWorkspace("default").id;
    gw.store.createProject(ws, { slug: "p1", title: "P1", backendSlugs: [] });
    gw.store.createProject(ws, { slug: "p2", title: "P2", backendSlugs: [] });
    const id = gw.store.identity;
    const chen = id.bootstrapWorkspace(ws, { name: "chen", owner: "chen" });
    const mk = (name: string) => {
      const a = id.createAgent({ workspaceId: ws, name, owner: "chen", kind: "grokbot", projects: ["p1", "p2"], createdBy: chen });
      return id.createKey({ agentId: a, createdBy: chen }).token;
    };
    const A = mk("bot-a");
    const B = mk("bot-b");
    let n = 0;
    const call = async (tok: string, sid: string, tool: string, args: Record<string, unknown> = {}) => {
      const res = await fetch(`${gw.url}/mcp`, {
        method: "POST",
        headers: { Authorization: `Bearer ${tok}`, "Mcp-Session-Id": sid, "content-type": "application/json", accept: "application/json, text/event-stream" },
        body: JSON.stringify({ jsonrpc: "2.0", id: ++n, method: "tools/call", params: { name: tool, arguments: args } }),
      });
      const body = (await res.json()) as any;
      return { status: res.status, body };
    };
    const current = async (tok: string, sid: string) => {
      const r = await call(tok, sid, "mf_current_project");
      expect(r.status).toBe(200);
      return JSON.parse(r.body.result.content[0].text).project?.slug as string | undefined;
    };
    const SID = "client-chosen-session-1";
    expect((await call(A, SID, "mf_use_project", { project: "p2", mintSessionToken: false })).status).toBe(200);
    expect(await current(A, SID)).toBe("p2");
    // R5-2: B presents the same id -> refused, nothing re-bound
    const hijack = await call(B, SID, "mf_use_project", { project: "p1", mintSessionToken: false });
    expect(hijack.status).toBe(409);
    expect(JSON.stringify(hijack.body)).toMatch(/bound to another key/);
    expect((await call(B, SID, "mf_current_project")).status).toBe(409);
    expect(await current(A, SID)).toBe("p2");
    // R5-1: B binds many fresh ids; A's binding stays
    for (let i = 0; i < SESSION_MAP_PER_KEY_MAX + 20; i++) {
      expect((await call(B, `b-${i}`, "mf_use_project", { project: "p1", mintSessionToken: false })).status).toBe(200);
    }
    expect(await current(A, SID)).toBe("p2");
  }, 60_000);
});
