/**
 * QA v5.6 check 6: legacy backend slugs containing "__" (created before the rule). With backends "a"
 * and "a__b", "a__b__echo" must resolve to backend "a__b" (longest slug) everywhere names are parsed
 * or listed: listed once, routed to a__b; "a__b__only_ab" reachable; "a"'s own "b__echo" shadowed.
 * Temp dirs; fake values only.
 */
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import { parseNamespacedTool, UpstreamPool } from "../src/mcp/upstream.js";
import { overlappingSlugs, slugClashWarnings, splitQualifiedToolName, toolAllowedByProject, type Project } from "../src/types.js";

const MASTER = Buffer.alloc(32, 13).toString("base64");
const dirs: string[] = [];
const pools: UpstreamPool[] = [];
afterEach(async () => {
  while (pools.length) await pools.pop()!.closeAll();
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("longest-slug resolution (unit)", () => {
  const slugs = ["a", "a__b", "c"];
  it("splits on the longest known slug, else the first __", () => {
    expect(splitQualifiedToolName("a__b__echo", slugs)).toEqual({ slug: "a__b", tool: "echo" });
    expect(splitQualifiedToolName("a__echo", slugs)).toEqual({ slug: "a", tool: "echo" });
    expect(splitQualifiedToolName("a__b__x__y", slugs)).toEqual({ slug: "a__b", tool: "x__y" });
    expect(splitQualifiedToolName("a__b__", slugs)).toEqual({ slug: "a", tool: "b__" }); // a__b needs a non-empty tool
    expect(splitQualifiedToolName("zz__t", slugs)).toEqual({ slug: "zz", tool: "t" });
    expect(splitQualifiedToolName("a__b__echo")).toEqual({ slug: "a", tool: "b__echo" }); // no slug list: legacy split
    expect(parseNamespacedTool("a__b__echo", slugs)).toEqual({ slug: "a__b", tool: "echo" });
    expect(parseNamespacedTool("__x", slugs)).toBeNull();
    expect(parseNamespacedTool("nosep", slugs)).toBeNull();
  });
  it("project filter uses the resolved slug", () => {
    const p = (backendSlugs: string[]) => ({ slug: "p", backendSlugs } as unknown as Project);
    expect(toolAllowedByProject("a__b__echo", p(["a"]), slugs)).toBe(false); // owned by a__b
    expect(toolAllowedByProject("a__b__echo", p(["a__b"]), slugs)).toBe(true);
    expect(toolAllowedByProject("a__echo", p(["a"]), slugs)).toBe(true);
    expect(toolAllowedByProject("a__b__echo", p(["a__b"]))).toBe(true); // default: the project's own slugs
  });
  it("clash detection and the boot warning name both slugs", () => {
    expect(overlappingSlugs(["a__b", "a", "c", "a__b__c"])).toEqual([["a", "a__b"], ["a", "a__b__c"], ["a__b", "a__b__c"]]);
    expect(overlappingSlugs(["ab", "a_b", "a"])).toEqual([]);
    const w = slugClashWarnings(["a", "a__b"]);
    expect(w).toHaveLength(1);
    expect(w[0]).toContain('"a" and "a__b" clash');
    expect(w[0]).toContain('"b__*"');
  });
});

/** Raw JSON-RPC stdio MCP server: argv <label> <tool,tool,...>; tools/call answers "<label>:<tool>:<v>". */
function writeBackend(dir: string): string {
  const path = join(dir, "slug-backend.mjs");
  writeFileSync(path, `import { createInterface } from "node:readline";
const [, , label, list] = process.argv;
const tools = list.split(",");
const send = (m) => process.stdout.write(JSON.stringify(m) + "\\n");
createInterface({ input: process.stdin }).on("line", (line) => {
  let m; try { m = JSON.parse(line); } catch { return; }
  if (m.method === "initialize") send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: m.params.protocolVersion, capabilities: { tools: {} }, serverInfo: { name: label, version: "1" } } });
  else if (m.method === "tools/list") send({ jsonrpc: "2.0", id: m.id, result: { tools: tools.map((name) => ({ name, inputSchema: { type: "object" } })) } });
  else if (m.method === "tools/call") send({ jsonrpc: "2.0", id: m.id, result: { content: [{ type: "text", text: label + ":" + m.params.name + ":" + (m.params.arguments?.v ?? "") }] } });
  else if (m.id !== undefined) send({ jsonrpc: "2.0", id: m.id, result: {} });
});
`);
  return path;
}

describe("legacy a + a__b in an existing DB (QA c7-slugs)", () => {
  it("lists a__b__echo once, routes it and a__b__only_ab to a__b, shadows a's b__echo", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mf-slugs-"));
    dirs.push(dir);
    const be = writeBackend(dir);
    const store = new Store(join(dir, "t.db"), MASTER);
    const ws = store.ensureWorkspace("default").id;
    store.createBackend(ws, { slug: "a", transport: "stdio", command: [process.execPath, be, "a", "b__echo,echo"], enabled: true, placement: { mode: "central-sandbox" } } as never);
    // "a__b" can no longer be created; seed it the way an older release stored it
    const row = store.db.prepare(`SELECT * FROM backends WHERE workspace_id = ? AND slug = 'a'`).get(ws) as Record<string, unknown>;
    const cols = Object.keys(row);
    const legacy = { ...row, id: `be_${randomBytes(12).toString("hex")}`, slug: "a__b", name: "a__b", command_json: JSON.stringify([process.execPath, be, "a__b", "echo,only_ab"]) };
    for (const k of Object.keys(legacy)) if (!cols.includes(k)) delete (legacy as Record<string, unknown>)[k];
    store.db.prepare(`INSERT INTO backends (${cols.join(", ")}) VALUES (${cols.map(() => "?").join(", ")})`).run(...(cols.map((c) => (legacy as Record<string, unknown>)[c]) as never[]));
    expect(store.listBackends(ws).map((b) => b.slug)).toEqual(["a", "a__b"]);

    const pool = new UpstreamPool(store);
    pools.push(pool);
    const names = (await pool.listNamespacedTools(ws)).map((t) => `${t.name}@${t.backendSlug}`);
    expect(names).toEqual(["a__b__echo@a__b", "a__b__only_ab@a__b", "a__echo@a"]);
    // project-scoped listing (only "a"): a's shadowed b__echo is not offered either
    expect((await pool.listNamespacedTools(ws, new Set(["a"]))).map((t) => t.name)).toEqual(["a__echo"]);
    const text = async (n: string) => ((await pool.callTool(ws, n, { v: 1 })).content as Array<{ text: string }>)[0]!.text;
    expect(await text("a__b__echo")).toBe("a__b:echo:1");
    expect(await text("a__b__only_ab")).toBe("a__b:only_ab:1");
    expect(await text("a__echo")).toBe("a:echo:1");
    expect(pool.resolveCallContext(ws, "a__b__echo").backendSlug).toBe("a__b");
    store.close();
  }, 30_000);
});
