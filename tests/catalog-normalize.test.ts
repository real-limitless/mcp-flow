import { describe, expect, it } from "vitest";
import {
  normalizeRegistryItem,
  slugFromGalleryId,
} from "../src/catalog/normalize.js";

describe("catalog normalize", () => {
  it("maps remote streamable-http entry", () => {
    const e = normalizeRegistryItem({
      server: {
        name: "io.github.example/demo",
        title: "Demo",
        description: "A demo server",
        version: "1.2.3",
        remotes: [
          {
            type: "streamable-http",
            url: "https://example.com/mcp",
            headers: [
              { name: "Authorization", isSecret: true, isRequired: true },
            ],
          },
        ],
      },
      _meta: {
        "io.modelcontextprotocol.registry/official": {
          status: "active",
          isLatest: true,
          updatedAt: "2026-01-01T00:00:00Z",
        },
      },
    });
    expect(e).toMatchObject({
      id: "io.github.example/demo",
      title: "Demo",
      transport: "streamable-http",
      endpointUrl: "https://example.com/mcp",
      provenance: "official-registry",
      requiresHeaders: ["Authorization"],
    });
    expect(e?.flags).toContain("remote");
    expect(JSON.stringify(e)).not.toContain("Bearer");
  });

  it("maps stdio-only package as stdio flag", () => {
    const e = normalizeRegistryItem({
      server: {
        name: "com.example/stdio-tool",
        description: "local",
        packages: [{ registryType: "npm", identifier: "@ex/tool" }],
      },
    });
    expect(e?.transport).toBe("stdio");
    expect(e?.flags).toContain("stdio");
    expect(e?.endpointUrl).toBeUndefined();
    expect(e?.install?.package).toBe("@ex/tool");
  });

  it("slugFromGalleryId", () => {
    expect(slugFromGalleryId("io.github.foo/Bar_Baz")).toMatch(/^[a-z]/);
  });
});
