import { normalizeRegistryItem, type RegistryListItem } from "../normalize.js";
import {
  readEntryFile,
  upsertShardedEntries,
} from "../shard.js";
import type { McpGalleryEntry } from "../types.js";
import { DEFAULT_REGISTRY_URL } from "../types.js";
import { fetchReadmeFromSourceUrl } from "./readme.js";
import { fetchRegistryDetail } from "./registry-detail.js";
import { probeToolsList } from "./tools-probe.js";

export interface EnrichOptions {
  catalogDir: string;
  /** Run README stage (default true) */
  enrichReadme?: boolean;
  /** Run tools stage (default true) */
  enrichTools?: boolean;
  readmeMaxBytes?: number;
  toolsTimeoutMs?: number;
  /** Skip stage if data fresher than this many days */
  readmeRefreshDays?: number;
  toolsRefreshDays?: number;
  registryUrl?: string;
  /** Proxied HTTP helpers from factory */
  getText?: (url: string) => Promise<string>;
  getJson?: (url: string) => Promise<unknown>;
  log?: (msg: string) => void;
}

export interface EnrichResult {
  entry: McpGalleryEntry;
  stages: {
    normalize: "done" | "failed" | "skipped";
    readme: "done" | "failed" | "skipped";
    tools: "done" | "failed" | "skipped";
  };
  errors: string[];
}

function daysOld(iso?: string): number {
  if (!iso) return Infinity;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return Infinity;
  return (Date.now() - t) / (86400_000);
}

function mergeEntry(
  base: McpGalleryEntry,
  patch: Partial<McpGalleryEntry>,
): McpGalleryEntry {
  return {
    ...base,
    ...patch,
    enrichment: {
      ...base.enrichment,
      ...patch.enrichment,
    },
  };
}

/**
 * Full enrichment pipeline for one gallery id / registry item.
 */
export async function runEnrich(input: {
  id?: string;
  item?: RegistryListItem;
  existing?: McpGalleryEntry | null;
  opts: EnrichOptions;
}): Promise<EnrichResult> {
  const opts = input.opts;
  const log = opts.log ?? (() => undefined);
  const errors: string[] = [];
  const stages: EnrichResult["stages"] = {
    normalize: "skipped",
    readme: "skipped",
    tools: "skipped",
  };

  let entry: McpGalleryEntry | null =
    input.existing ??
    (input.id ? readEntryFile(opts.catalogDir, input.id) : null);

  // --- normalize ---
  try {
    let item = input.item;
    const id = input.id ?? item?.server?.name ?? entry?.id;
    if (id) {
      const detail = await fetchRegistryDetail(id, {
        registryBase: opts.registryUrl ?? DEFAULT_REGISTRY_URL,
        proxyGetJson: opts.getJson,
      });
      if (detail) item = detail;
    }
    if (item) {
      const normalized = normalizeRegistryItem(item);
      if (normalized) {
        entry = entry
          ? mergeEntry(entry, {
              ...normalized,
              // keep prior enrichment blobs
              readme: entry.readme,
              toolsPreview: entry.toolsPreview,
              toolsPreviewAt: entry.toolsPreviewAt,
              toolsPreviewError: entry.toolsPreviewError,
              toolsPreviewStatus: entry.toolsPreviewStatus,
              enrichment: {
                ...entry.enrichment,
                ...normalized.enrichment,
              },
            })
          : normalized;
        stages.normalize = "done";
        log(`normalize ok ${entry.id}`);
      } else {
        stages.normalize = "failed";
        errors.push("normalize returned null");
      }
    } else if (entry) {
      stages.normalize = "skipped";
    } else {
      stages.normalize = "failed";
      errors.push("no registry item or existing entry");
    }
  } catch (err) {
    stages.normalize = "failed";
    errors.push(
      `normalize: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!entry) {
    throw new Error(errors.join("; ") || "enrich failed: no entry");
  }

  // --- readme ---
  if (opts.enrichReadme !== false) {
    const refreshDays = opts.readmeRefreshDays ?? 30;
    const fresh =
      entry.readme?.markdown &&
      daysOld(entry.readme.fetchedAt) < refreshDays;
    if (fresh) {
      stages.readme = "skipped";
      log(`readme skip fresh ${entry.id}`);
    } else {
      try {
        const readme = await fetchReadmeFromSourceUrl(entry.sourceUrl, {
          maxBytes: opts.readmeMaxBytes ?? 200_000,
          getText: opts.getText,
        });
        entry = mergeEntry(entry, {
          readme,
          enrichment: {
            ...entry.enrichment,
            readmeAt: readme.fetchedAt,
          },
        });
        stages.readme = readme.markdown ? "done" : "failed";
        if (readme.error && !readme.markdown) errors.push(`readme: ${readme.error}`);
        log(
          `readme ${stages.readme} ${entry.id}${readme.error ? ` (${readme.error})` : ""}`,
        );
      } catch (err) {
        stages.readme = "failed";
        const msg = err instanceof Error ? err.message : String(err);
        errors.push(`readme: ${msg}`);
        entry = mergeEntry(entry, {
          readme: {
            source: "none",
            error: msg,
            fetchedAt: new Date().toISOString(),
          },
          enrichment: {
            ...entry.enrichment,
            readmeAt: new Date().toISOString(),
          },
        });
      }
    }
  }

  // --- tools ---
  if (opts.enrichTools !== false) {
    const refreshDays = opts.toolsRefreshDays ?? 14;
    const fresh =
      entry.toolsPreviewStatus === "ok" &&
      entry.toolsPreview?.length &&
      daysOld(entry.toolsPreviewAt) < refreshDays;
    if (fresh) {
      stages.tools = "skipped";
      log(`tools skip fresh ${entry.id}`);
    } else {
      try {
        const probe = await probeToolsList(
          entry.endpointUrl,
          entry.transport,
          { timeoutMs: opts.toolsTimeoutMs ?? 15_000 },
        );
        entry = mergeEntry(entry, {
          toolsPreview: probe.tools,
          toolsPreviewAt: probe.at,
          toolsPreviewError: probe.error,
          toolsPreviewStatus: probe.status,
          enrichment: {
            ...entry.enrichment,
            toolsAt: probe.at,
          },
        });
        // soft-fail auth/unreachable still "done" stage for pipeline
        stages.tools =
          probe.status === "ok" ||
          probe.status === "auth_required" ||
          probe.status === "unsupported" ||
          probe.status === "skipped"
            ? "done"
            : "failed";
        if (probe.status !== "ok" && probe.error) {
          errors.push(`tools: ${probe.status} ${probe.error}`);
        }
        log(
          `tools ${probe.status} ${entry.id} n=${probe.tools?.length ?? 0}`,
        );
      } catch (err) {
        stages.tools = "failed";
        const msg = err instanceof Error ? err.message : String(err);
        errors.push(`tools: ${msg}`);
        entry = mergeEntry(entry, {
          toolsPreviewStatus: "unreachable",
          toolsPreviewError: msg,
          toolsPreviewAt: new Date().toISOString(),
          enrichment: {
            ...entry.enrichment,
            toolsAt: new Date().toISOString(),
          },
        });
      }
    }
  }

  entry = mergeEntry(entry, {
    enrichment: {
      ...entry.enrichment,
      complete: true,
    },
  });

  await upsertShardedEntries(opts.catalogDir, [entry], "enrich");
  return { entry, stages, errors };
}

export function formatEntryPretty(entry: McpGalleryEntry): string {
  const lines: string[] = [];
  lines.push(`# ${entry.title}`);
  lines.push(`${entry.id} · v${entry.version ?? "?"} · ${entry.transport}`);
  if (entry.status) lines.push(`status: ${entry.status}`);
  lines.push("");
  if (entry.summary || entry.description) {
    lines.push(entry.summary || entry.description);
    lines.push("");
  }
  if (entry.offersHint) {
    lines.push(`Offers: ${entry.offersHint}`);
    lines.push("");
  }
  lines.push("## Connect");
  if (entry.endpointUrl) {
    lines.push(`${entry.transport}  ${entry.endpointUrl}`);
  } else {
    lines.push("(no remote endpoint)");
  }
  if (entry.install?.package) {
    lines.push(
      `install: ${entry.install.kind} ${entry.install.package}`,
    );
  }
  lines.push("");
  if (entry.headerDocs?.length || entry.requiresHeaders?.length) {
    lines.push("## Headers required");
    if (entry.headerDocs?.length) {
      for (const h of entry.headerDocs) {
        lines.push(
          `- ${h.name}${h.required ? " (required)" : ""}${h.description ? ` — ${h.description}` : ""}`,
        );
      }
    } else {
      for (const n of entry.requiresHeaders ?? []) lines.push(`- ${n}`);
    }
    lines.push("");
  }
  if (entry.toolsPreviewStatus || entry.toolsPreview?.length) {
    lines.push("## Tools preview");
    lines.push(
      `status: ${entry.toolsPreviewStatus ?? "unknown"}${entry.toolsPreviewAt ? ` @ ${entry.toolsPreviewAt}` : ""}`,
    );
    if (entry.toolsPreviewError) {
      lines.push(`note: ${entry.toolsPreviewError}`);
    }
    if (entry.toolsPreview?.length) {
      for (const t of entry.toolsPreview) {
        lines.push(
          `- **${t.name}**${t.description ? ` — ${t.description}` : ""}`,
        );
      }
    }
    lines.push("");
  }
  if (entry.readme?.markdown) {
    lines.push("## README");
    if (entry.readme.url) lines.push(`source: ${entry.readme.url}`);
    if (entry.readme.truncated) lines.push("(truncated)");
    lines.push("");
    const body = entry.readme.markdown;
    const max = 8000;
    lines.push(body.length > max ? `${body.slice(0, max)}\n\n…` : body);
    lines.push("");
  } else if (entry.readme?.error) {
    lines.push("## README");
    lines.push(`(unavailable: ${entry.readme.error})`);
    lines.push("");
  }
  lines.push("## Links");
  if (entry.sourceUrl) lines.push(`- repo: ${entry.sourceUrl}`);
  if (entry.homepage) lines.push(`- home: ${entry.homepage}`);
  return lines.join("\n");
}
