import { mkdtempSync, rmSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  entryFilename,
  loadAllEntries,
  loadIndex,
  migrateMonolithToShards,
  readEntryFile,
  upsertShardedEntries,
} from "../src/catalog/shard.js";
import type { McpGalleryEntry } from "../src/catalog/types.js";

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function tmpCatalog(): string {
  const d = mkdtempSync(join(tmpdir(), "mcp-cat-"));
  dirs.push(d);
  return d;
}

const sample = (id: string): McpGalleryEntry => ({
  id,
  title: id.split("/").pop() || id,
  description: `Full description for ${id} with enough text to summarize capabilities.`,
  transport: "streamable-http",
  endpointUrl: "https://example.com/mcp",
  provenance: "official-registry",
  flags: ["remote"],
});

describe("catalog shards", () => {
  it("maps id to safe filename", () => {
    expect(entryFilename("io.github.foo/bar")).toBe("io.github.foo--bar.json");
  });

  it("upserts individual entry files + index", async () => {
    const dir = tmpCatalog();
    const r = await upsertShardedEntries(
      dir,
      [sample("io.github.a/one"), sample("io.github.b/two")],
      "test",
    );
    expect(r.upserted).toBe(2);
    expect(r.total).toBe(2);
    expect(r.meta.storage).toBe("sharded");

    const e = readEntryFile(dir, "io.github.a/one");
    expect(e?.description).toContain("Full description");
    expect(e?.summary).toBeTruthy();
    expect(e?.offersHint || e?.summary).toBeTruthy();

    const idx = loadIndex(dir);
    expect(idx?.entries).toHaveLength(2);
    expect(idx?.entries[0]?.summary).toBeTruthy();
  });

  it("migrates monolith gallery.json to shards", async () => {
    const dir = tmpCatalog();
    mkdirSync(dir, { recursive: true });
    writeFileSync(
      join(dir, "gallery.json"),
      JSON.stringify([sample("com.example/x"), sample("com.example/y")]),
    );
    const m = await migrateMonolithToShards(dir);
    expect(m.migrated).toBe(2);
    expect(loadAllEntries(dir)).toHaveLength(2);
    const pointer = JSON.parse(readFileSync(join(dir, "gallery.json"), "utf8"));
    expect(pointer.deprecated).toBe(true);
  });
});
