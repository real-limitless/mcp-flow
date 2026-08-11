import { describe, expect, it } from "vitest";
import {
  normalizeRegistryItem,
  sanitizeValueTemplate,
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
  });

  it("maps full bowmark-style registry detail", () => {
    const e = normalizeRegistryItem({
      server: {
        name: "ai.bowmark/bowmark",
        description:
          "Do things on live websites: prices, availability, quotes, bookings.",
        title: "Bowmark",
        repository: {
          url: "https://github.com/bowmark-ai/skill",
          source: "github",
          id: "1247917304",
        },
        version: "8.38.0",
        websiteUrl: "https://bowmark.ai",
        packages: [
          {
            registryType: "pypi",
            identifier: "bowmark-mcp",
            version: "2.1.0",
            transport: { type: "stdio" },
            environmentVariables: [
              {
                description: "Optional API key",
                isSecret: true,
                name: "BOWMARK_API_KEY",
              },
            ],
          },
          {
            registryType: "npm",
            identifier: "@bowmark/mcp",
            version: "2.1.0",
            transport: { type: "stdio" },
            environmentVariables: [
              {
                description: "Optional API key",
                isSecret: true,
                name: "BOWMARK_API_KEY",
              },
            ],
          },
        ],
        remotes: [
          {
            type: "streamable-http",
            url: "https://api.bowmark.ai/mcp/registry",
            headers: [
              {
                description: "Optional Bearer token",
                value: "Bearer {api_key}",
                variables: {
                  api_key: {
                    description: "Your Bowmark API key",
                    isSecret: true,
                  },
                },
                name: "Authorization",
              },
            ],
          },
        ],
      },
      _meta: {
        "io.modelcontextprotocol.registry/official": {
          status: "active",
          publishedAt: "2026-08-11T20:51:46.607133Z",
          updatedAt: "2026-08-11T20:51:46.607133Z",
          isLatest: true,
        },
      },
    });

    expect(e?.id).toBe("ai.bowmark/bowmark");
    expect(e?.homepage).toBe("https://bowmark.ai");
    expect(e?.sourceUrl).toBe("https://github.com/bowmark-ai/skill");
    expect(e?.repository).toEqual({
      url: "https://github.com/bowmark-ai/skill",
      source: "github",
      id: "1247917304",
    });
    expect(e?.version).toBe("8.38.0");
    expect(e?.publishedAt).toBe("2026-08-11T20:51:46.607133Z");
    expect(e?.transport).toBe("streamable-http");
    expect(e?.endpointUrl).toBe("https://api.bowmark.ai/mcp/registry");
    expect(e?.flags).toEqual(expect.arrayContaining(["remote", "stdio"]));

    // optional header — not in requiresHeaders
    expect(e?.requiresHeaders).toBeUndefined();
    expect(e?.headerDocs?.[0]).toMatchObject({
      name: "Authorization",
      secret: true,
      valueTemplate: "Bearer {api_key}",
    });
    expect(e?.headerDocs?.[0]?.variables?.[0]?.name).toBe("api_key");
    expect(e?.remotes?.[0]?.headers?.[0]?.valueTemplate).toBe(
      "Bearer {api_key}",
    );

    // both packages
    expect(e?.packages).toHaveLength(2);
    expect(e?.install?.kind).toBe("npm");
    expect(e?.install?.package).toBe("@bowmark/mcp");
    expect(e?.install?.version).toBe("2.1.0");
    expect(e?.environmentVariables).toEqual([
      expect.objectContaining({
        name: "BOWMARK_API_KEY",
        secret: true,
      }),
    ]);

    // no live secrets
    expect(JSON.stringify(e)).not.toMatch(/sk-[a-zA-Z0-9]+/);
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
    expect(e?.packages?.[0]?.package).toBe("@ex/tool");
  });

  it("sanitizeValueTemplate keeps placeholders, drops tokens", () => {
    expect(sanitizeValueTemplate("Bearer {api_key}")).toBe("Bearer {api_key}");
    expect(sanitizeValueTemplate("sk-live-abc123xyz789secrettokenvalue")).toBe(
      undefined,
    );
  });

  it("slugFromGalleryId", () => {
    expect(slugFromGalleryId("io.github.foo/Bar_Baz")).toMatch(/^[a-z]/);
  });
});
