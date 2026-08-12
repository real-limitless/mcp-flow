import type { Store } from "../db/store.js";
import { synthesizeFromGallery } from "../mcp/runners/catalog-command.js";
import { assertSafeUrl } from "../ssrf.js";
import { DEFAULT_PLACEMENT, type BackendPublic } from "../types.js";
import { slugFromGalleryId } from "./normalize.js";
import type { McpGalleryEntry } from "./types.js";

export interface InstallFromGalleryInput {
  entry: McpGalleryEntry;
  slug?: string;
  enable?: boolean;
  headers?: Record<string, string>;
  env?: Record<string, string>;
  allowPrivateUrls: boolean;
}

export interface InstallFromGalleryResult {
  backend: BackendPublic;
  warnings: string[];
}

/**
 * Create a Backend from a gallery entry (remote URL or central-sandbox stdio/oci).
 */
export async function installFromGallery(
  store: Store,
  workspaceId: string,
  input: InstallFromGalleryInput,
): Promise<InstallFromGalleryResult> {
  const { entry } = input;
  const warnings: string[] = [];

  const url =
    entry.endpointUrl ??
    entry.remotes?.find((r) => r.type === "streamable-http")?.url ??
    entry.remotes?.find((r) => r.type === "sse")?.url;

  const slug = (input.slug?.trim() || slugFromGalleryId(entry.id)).toLowerCase();

  if (url) {
    await assertSafeUrl(url, input.allowPrivateUrls);

    let transport: "streamable-http" | "sse" = "streamable-http";
    if (entry.transport === "sse") transport = "sse";
    else if (
      entry.remotes?.some((r) => r.type === "sse") &&
      entry.transport !== "streamable-http"
    ) {
      transport = "sse";
    }

    if (entry.requiresHeaders?.length) {
      const have = new Set(Object.keys(input.headers ?? {}));
      const missing = entry.requiresHeaders.filter((h) => !have.has(h));
      if (missing.length) {
        warnings.push(
          `entry may require headers (not provided): ${missing.join(", ")}`,
        );
      }
    }

    const backend = store.createBackend(workspaceId, {
      slug,
      title: entry.title,
      url,
      transport,
      headers: input.headers,
      env: input.env,
      enabled: input.enable ?? false,
      placement: { ...DEFAULT_PLACEMENT },
    });

    return { backend, warnings };
  }

  const synth = synthesizeFromGallery(entry);
  if (!synth) {
    throw new Error(
      `gallery entry ${entry.id} has no remote URL and no installable package/command`,
    );
  }
  warnings.push(...synth.warnings);

  const backend = store.createBackend(workspaceId, {
    slug,
    title: entry.title,
    transport: synth.transport,
    command: synth.command,
    image: synth.image,
    env: input.env,
    enabled: input.enable ?? false,
    placement: { mode: "central-sandbox" },
  });

  return { backend, warnings };
}
