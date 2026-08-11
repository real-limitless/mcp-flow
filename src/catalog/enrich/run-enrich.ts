import { normalizeRegistryItem, type RegistryListItem } from "../normalize.js";
import {
  readEntryFile,
  upsertShardedEntries,
} from "../shard.js";
import type { McpGalleryEntry } from "../types.js";
import { DEFAULT_REGISTRY_URL } from "../types.js";
import { fetchReadmeFromSourceUrl } from "./readme.js";
import { fetchRegistryDetail } from "./registry-detail.js";
import { probeSourceRepo } from "./source-repo.js";
import { probeToolsList } from "./tools-probe.js";
import type { GalleryFlag, GalleryStatus, McpGalleryEntry as Entry } from "../types.js";

export interface EnrichOptions {
  catalogDir: string;
  /** Run README stage (default true) */
  enrichReadme?: boolean;
  /** Run tools stage (default true) */
  enrichTools?: boolean;
  /** Probe GitHub/GitLab source repo (default true) */
  enrichSourceRepo?: boolean;
  readmeMaxBytes?: number;
  toolsTimeoutMs?: number;
  sourceRepoTimeoutMs?: number;
  /** Skip stage if data fresher than this many days */
  readmeRefreshDays?: number;
  toolsRefreshDays?: number;
  sourceRepoRefreshDays?: number;
  registryUrl?: string;
  /** Proxied HTTP helpers from factory */
  getText?: (url: string) => Promise<string>;
  getJson?: (url: string) => Promise<unknown>;
  headOrGet?: (url: string) => Promise<{ status: number; ok: boolean }>;
  log?: (msg: string) => void;
}

export interface EnrichResult {
  entry: McpGalleryEntry;
  stages: {
    normalize: "done" | "failed" | "skipped";
    sourceRepo: "done" | "failed" | "skipped";
    readme: "done" | "failed" | "skipped";
    tools: "done" | "failed" | "skipped";
  };
  errors: string[];
}

function applySourceRepoFlags(
  entry: Entry,
  registryStatus: GalleryStatus | undefined,
): Entry {
  const flags = new Set<GalleryFlag>(entry.flags ?? []);
  flags.delete("repo-offline");
  if (entry.sourceRepo?.status === "not_found") {
    flags.add("repo-offline");
    return {
      ...entry,
      status: "inactive",
      flags: [...flags],
    };
  }
  // Repo ok/unknown — drop offline flag; restore registry status if we had forced inactive
  if (entry.status === "inactive" && entry.sourceRepo?.status === "ok") {
    return {
      ...entry,
      status: registryStatus && registryStatus !== "inactive" ? registryStatus : "active",
      flags: flags.size ? [...flags] : undefined,
    };
  }
  return {
    ...entry,
    flags: flags.size ? [...flags] : undefined,
  };
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
    sourceRepo: "skipped",
    readme: "skipped",
    tools: "skipped",
  };

  let entry: McpGalleryEntry | null =
    input.existing ??
    (input.id ? readEntryFile(opts.catalogDir, input.id) : null);

  /** Registry status before we force inactive for dead repos */
  let registryStatus: GalleryStatus | undefined = entry?.status;

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
        registryStatus = normalized.status;
        entry = entry
          ? mergeEntry(entry, {
              ...normalized,
              // keep prior enrichment blobs
              readme: entry.readme,
              sourceRepo: entry.sourceRepo,
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

  // --- source repo (404 → inactive) ---
  if (opts.enrichSourceRepo !== false) {
    const refreshDays = opts.sourceRepoRefreshDays ?? 7;
    const fresh =
      entry.sourceRepo?.status &&
      entry.sourceRepo.status !== "unreachable" &&
      daysOld(entry.sourceRepo.checkedAt) < refreshDays;
    if (fresh) {
      stages.sourceRepo = "skipped";
      entry = applySourceRepoFlags(entry, registryStatus);
      log(`sourceRepo skip fresh ${entry.id} (${entry.sourceRepo?.status})`);
    } else {
      try {
        const sourceUrl = entry.sourceUrl || entry.repository?.url;
        const probe = await probeSourceRepo(sourceUrl, {
          timeoutMs: opts.sourceRepoTimeoutMs ?? 12_000,
          headOrGet: opts.headOrGet,
        });
        entry = mergeEntry(entry, {
          sourceRepo: {
            status: probe.status,
            url: probe.url,
            checkedAt: probe.checkedAt,
            httpStatus: probe.httpStatus,
            error: probe.error,
            host: probe.host,
          },
          enrichment: {
            ...entry.enrichment,
            sourceRepoAt: probe.checkedAt,
          },
        });
        entry = applySourceRepoFlags(entry, registryStatus);
        stages.sourceRepo =
          probe.status === "unreachable" ? "failed" : "done";
        if (probe.status === "not_found") {
          errors.push(`sourceRepo: not_found ${probe.url ?? ""}`);
          log(`sourceRepo NOT FOUND → inactive ${entry.id}`);
        } else {
          log(`sourceRepo ${probe.status} ${entry.id}`);
        }
      } catch (err) {
        stages.sourceRepo = "failed";
        const msg = err instanceof Error ? err.message : String(err);
        errors.push(`sourceRepo: ${msg}`);
        entry = mergeEntry(entry, {
          sourceRepo: {
            status: "unreachable",
            checkedAt: new Date().toISOString(),
            error: msg,
          },
          enrichment: {
            ...entry.enrichment,
            sourceRepoAt: new Date().toISOString(),
          },
        });
      }
    }
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
  if (entry.sourceRepo?.status) {
    lines.push(
      `sourceRepo: ${entry.sourceRepo.status}${entry.sourceRepo.url ? ` ${entry.sourceRepo.url}` : ""}${entry.sourceRepo.httpStatus ? ` HTTP ${entry.sourceRepo.httpStatus}` : ""}`,
    );
  }
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
      `install: ${entry.install.kind} ${entry.install.package}${entry.install.version ? `@${entry.install.version}` : ""}`,
    );
  }
  lines.push("");
  if (entry.packages?.length) {
    lines.push("## Packages");
    for (const p of entry.packages) {
      lines.push(
        `- ${p.kind}:${p.package ?? "?"}${p.version ? `@${p.version}` : ""}${p.transport ? ` (${p.transport})` : ""}`,
      );
      for (const ev of p.environmentVariables ?? []) {
        lines.push(
          `  - env ${ev.name}${ev.secret ? " [secret]" : ""}${ev.required ? " required" : ""}${ev.description ? ` — ${ev.description}` : ""}`,
        );
      }
    }
    lines.push("");
  }
  if (entry.headerDocs?.length || entry.requiresHeaders?.length) {
    lines.push("## Headers");
    if (entry.headerDocs?.length) {
      for (const h of entry.headerDocs) {
        lines.push(
          `- ${h.name}${h.required ? " (required)" : " (optional)"}${h.secret ? " [secret]" : ""}${h.valueTemplate ? ` \`${h.valueTemplate}\`` : ""}${h.description ? ` — ${h.description}` : ""}`,
        );
        for (const v of h.variables ?? []) {
          lines.push(
            `  - {${v.name}}${v.secret ? " [secret]" : ""}${v.description ? ` — ${v.description}` : ""}`,
          );
        }
      }
    } else {
      for (const n of entry.requiresHeaders ?? []) lines.push(`- ${n}`);
    }
    lines.push("");
  }
  if (entry.repository?.url || entry.repository?.id) {
    lines.push("## Repository");
    lines.push(
      `- ${entry.repository.source ?? "repo"}: ${entry.repository.url ?? ""}${entry.repository.id ? ` (${entry.repository.id})` : ""}`,
    );
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
