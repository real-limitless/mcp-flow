import { describe, expect, it } from "vitest";
import { fetchReadmeFromSourceUrl } from "../src/catalog/enrich/readme.js";
import { formatEntryPretty } from "../src/catalog/enrich/run-enrich.js";
import { probeToolsList } from "../src/catalog/enrich/tools-probe.js";
import type { McpGalleryEntry } from "../src/catalog/types.js";

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
