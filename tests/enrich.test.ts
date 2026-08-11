import { describe, expect, it } from "vitest";
import { fetchReadmeFromSourceUrl } from "../src/catalog/enrich/readme.js";
import { formatEntryPretty, runEnrich } from "../src/catalog/enrich/run-enrich.js";
import {
  canonicalRepoUrl,
  probeSourceRepo,
} from "../src/catalog/enrich/source-repo.js";
import { probeToolsList } from "../src/catalog/enrich/tools-probe.js";
import type { McpGalleryEntry } from "../src/catalog/types.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("fetchReadmeFromSourceUrl", () => {
  it("rejects missing url", async () => {
    const r = await fetchReadmeFromSourceUrl(undefined);
    expect(r.source).toBe("none");
    expect(r.error).toMatch(/no sourceUrl/);
  });

  it("rejects non-allowlisted host", async () => {
    const r = await fetchReadmeFromSourceUrl("https://evil.example/repo");
    expect(r.source).toBe("none");
    expect(r.error).toMatch(/allowlisted/);
  });

  it("builds github raw candidates via getText mock", async () => {
    const urls: string[] = [];
    const r = await fetchReadmeFromSourceUrl(
      "https://github.com/acme/demo-mcp",
      {
        getText: async (url) => {
          urls.push(url);
          if (url.includes("/main/README.md")) {
            return "# Demo\n\nHello tools.";
          }
          throw new Error("nope");
        },
      },
    );
    expect(r.source).toBe("github");
    expect(r.markdown).toContain("Hello tools");
    expect(urls.some((u) => u.includes("raw.githubusercontent.com"))).toBe(
      true,
    );
  });
});

describe("probeToolsList", () => {
  it("marks stdio unsupported", async () => {
    const r = await probeToolsList(undefined, "stdio");
    expect(r.status).toBe("unsupported");
  });

  it("marks missing url unsupported", async () => {
    const r = await probeToolsList(undefined, "streamable-http");
    expect(r.status).toBe("unsupported");
  });
});

describe("probeSourceRepo", () => {
  it("canonicalizes github urls", () => {
    const c = canonicalRepoUrl("https://github.com/acme/demo-mcp/tree/main");
    expect(c).toEqual({
      probeUrl: "https://github.com/acme/demo-mcp",
      host: "github",
    });
  });

  it("marks 404 as not_found", async () => {
    const r = await probeSourceRepo("https://github.com/acme/gone-repo", {
      headOrGet: async () => ({ status: 404, ok: false }),
    });
    expect(r.status).toBe("not_found");
    expect(r.httpStatus).toBe(404);
  });

  it("marks 200 as ok", async () => {
    const r = await probeSourceRepo("https://github.com/acme/live", {
      headOrGet: async () => ({ status: 200, ok: true }),
    });
    expect(r.status).toBe("ok");
  });

  it("runEnrich sets inactive + repo-offline on 404", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mf-enrich-"));
    try {
      const result = await runEnrich({
        item: {
          server: {
            name: "com.example/dead-repo",
            title: "Dead",
            description: "gone",
            repository: { url: "https://github.com/example/does-not-exist-xyz" },
            remotes: [
              { type: "streamable-http", url: "https://example.com/mcp" },
            ],
          },
          _meta: {
            "io.modelcontextprotocol.registry/official": { status: "active" },
          },
        },
        opts: {
          catalogDir: dir,
          enrichReadme: false,
          enrichTools: false,
          enrichSourceRepo: true,
          headOrGet: async () => ({ status: 404, ok: false }),
          getJson: async () => {
            throw new Error("no registry");
          },
        },
      });
      expect(result.entry.status).toBe("inactive");
      expect(result.entry.flags).toContain("repo-offline");
      expect(result.entry.sourceRepo?.status).toBe("not_found");
      expect(result.stages.sourceRepo).toBe("done");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("formatEntryPretty", () => {
  it("includes tools and readme sections", () => {
    const e: McpGalleryEntry = {
      id: "com.example/demo",
      title: "Demo",
      description: "A demo server",
      transport: "streamable-http",
      endpointUrl: "https://example.com/mcp",
      provenance: "manual",
      toolsPreviewStatus: "ok",
      toolsPreview: [{ name: "ping", description: "Ping" }],
      readme: {
        source: "github",
        markdown: "# Hi\n\nBody",
        url: "https://raw.githubusercontent.com/x/y/main/README.md",
      },
    };
    const text = formatEntryPretty(e);
    expect(text).toContain("# Demo");
    expect(text).toContain("## Tools preview");
    expect(text).toContain("ping");
    expect(text).toContain("## README");
    expect(text).toContain("Body");
  });
});
