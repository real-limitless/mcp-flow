import { describe, expect, it } from "vitest";
import {
  assertBackendShape,
  assertPlacementAllowed,
  PlacementError,
} from "../src/placement.js";
import { synthesizeFromGallery } from "../src/mcp/runners/catalog-command.js";
import type { McpGalleryEntry } from "../src/catalog/types.js";

describe("placement", () => {
  it("allows remote http and central-sandbox stdio", () => {
    expect(() =>
      assertPlacementAllowed(
        { mode: "remote" },
        { transport: "streamable-http" },
      ),
    ).not.toThrow();
    expect(() =>
      assertPlacementAllowed(
        { mode: "central-sandbox" },
        { transport: "stdio" },
      ),
    ).not.toThrow();
  });

  it("rejects edge without device", () => {
    expect(() =>
      assertPlacementAllowed(
        { mode: "edge-sandbox", deviceId: "dev_x" },
        { transport: "stdio", edgeEnabled: true, deviceExists: false },
      ),
    ).toThrow(PlacementError);
  });

  it("rejects edge-bare when policy false", () => {
    expect(() =>
      assertPlacementAllowed(
        { mode: "edge-bare", deviceId: "dev_x" },
        {
          transport: "stdio",
          edgeEnabled: true,
          deviceExists: true,
          deviceBare: true,
          policy: { allowEdgeBare: false },
        },
      ),
    ).toThrow(/allowEdgeBare/);
  });

  it("assertBackendShape", () => {
    expect(() =>
      assertBackendShape({ transport: "stdio", command: ["npx"] }),
    ).not.toThrow();
    expect(() => assertBackendShape({ transport: "oci" })).toThrow(/image/);
  });
});

describe("catalog command synth", () => {
  it("maps npm package to npx", () => {
    const entry: McpGalleryEntry = {
      id: "demo/pkg",
      title: "Demo",
      description: "d",
      transport: "stdio",
      provenance: "official-registry",
      install: { kind: "npm", package: "@scope/mcp-server", version: "1.0.0" },
    };
    const s = synthesizeFromGallery(entry);
    expect(s?.transport).toBe("stdio");
    expect(s?.command).toEqual(["npx", "-y", "@scope/mcp-server@1.0.0"]);
    expect(s?.placementMode).toBe("central-sandbox");
  });

  it("maps oci image", () => {
    const entry: McpGalleryEntry = {
      id: "demo/oci",
      title: "Oci",
      description: "d",
      transport: "stdio",
      provenance: "official-registry",
      install: { kind: "oci", package: "ghcr.io/example/mcp:latest" },
    };
    const s = synthesizeFromGallery(entry);
    expect(s?.transport).toBe("oci");
    expect(s?.image).toBe("ghcr.io/example/mcp:latest");
  });
});
