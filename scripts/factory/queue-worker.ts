#!/usr/bin/env node
/**
 * Factory worker: enrich jobs (normalize → sourceRepo → readme → tools) → catalog
 *
 *   npm run factory:worker                 # drain queue, then exit
 *   npm run factory:worker -- --watch      # keep polling for new jobs
 *   npm run factory:worker -- --once       # single batch only (CI)
 *   npm run factory:worker -- --concurrency 6
 */
import { parseArgs } from "node:util";
import { runEnrich } from "../../src/catalog/enrich/run-enrich.js";
import { httpGetJson, httpGetText } from "./lib/http-util.js";
import {
  appendLog,
  claimPending,
  clearWorkerPid,
  listQueue,
  queueCounts,
  requeueStaleRunning,
  updateJob,
  writeWorkerPid,
  type FactoryJob,
} from "./lib/job-store.js";
import { CATALOG_DIR, ensureJobsDirs } from "./lib/paths.js";
import { ProxyPool } from "./lib/proxy-pool.js";
import { loadSettings, resolveProxyUrl } from "./lib/settings.js";

/** Hard wall-clock limit per enrich job (includes tools probe). */
const DEFAULT_JOB_TIMEOUT_MS = 90_000;
/** Re-queue running jobs older than this (hung worker / crash). */
const STALE_RUNNING_MS = 120_000;

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return new Promise<T>((resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label} timeout ${ms}ms`)),
      ms,
    );
    p.then(
      (v) => {
        if (timer) clearTimeout(timer);
        resolve(v);
      },
      (err) => {
        if (timer) clearTimeout(timer);
        reject(err);
      },
    );
  });
}

function makeHttpHelpers(settings: ReturnType<typeof loadSettings>, pool?: ProxyPool) {
  const pickProxy = (): string | undefined => {
    if (!settings.useProxy) return resolveProxyUrl(settings);
    return resolveProxyUrl(settings) || pool?.pick();
  };
  return {
    getText: async (url: string) => {
      const proxy = pickProxy();
      try {
        const t = await httpGetText(url, { timeout: 25_000, proxy });
        if (proxy) pool?.reportOk(proxy);
        return t;
      } catch (err) {
        if (proxy) pool?.reportFail(proxy);
        throw err;
      }
    },
    getJson: async (url: string) => {
      const proxy = pickProxy();
      try {
        const j = await httpGetJson(url, { timeout: 30_000, proxy });
        if (proxy) pool?.reportOk(proxy);
        return j;
      } catch (err) {
        if (proxy) pool?.reportFail(proxy);
        throw err;
      }
    },
    headOrGet: async (url: string) => {
      const proxy = pickProxy();
      try {
        // Prefer plain fetch for status (including 404); avoid throw-on-error helpers
        const res = await fetch(url, {
          method: "GET",
          redirect: "follow",
          signal: AbortSignal.timeout(12_000),
          headers: {
            Accept: "text/html",
            "User-Agent": "mcp-flow-catalog/0.1",
          },
        });
        if (proxy) pool?.reportOk(proxy);
        return { status: res.status, ok: res.ok };
      } catch (err) {
        if (proxy) pool?.reportFail(proxy);
        throw err;
      }
    },
  };
}

async function processJob(
  job: FactoryJob,
  helpers: ReturnType<typeof makeHttpHelpers>,
  jobTimeoutMs: number,
): Promise<void> {
  const settings = loadSettings();
  const id = job.galleryId ?? job.item?.server?.name;
  if (!id && !job.item) {
    updateJob(job.id, {
      status: "failed",
      error: "job missing galleryId/item",
      startedAt: undefined,
    });
    return;
  }

  const label = id || job.id;
  try {
    const toolsTimeoutMs = Math.min(
      settings.toolsTimeoutMs ?? 15_000,
      Math.max(5_000, jobTimeoutMs - 20_000),
    );
    const result = await withTimeout(
      runEnrich({
        id,
        item: job.item,
        opts: {
          catalogDir: CATALOG_DIR,
          enrichReadme: settings.enrichReadme,
          enrichTools: settings.enrichTools,
          readmeMaxBytes: settings.readmeMaxBytes,
          toolsTimeoutMs,
          sourceRepoTimeoutMs: 12_000,
          readmeRefreshDays: settings.readmeRefreshDays,
          toolsRefreshDays: settings.toolsRefreshDays,
          registryUrl: settings.registryUrl,
          getText: helpers.getText,
          getJson: helpers.getJson,
          headOrGet: helpers.headOrGet,
          log: (m) => appendLog(m),
        },
      }),
      jobTimeoutMs,
      `job ${label}`,
    );

    const hardFail =
      result.stages.normalize === "failed" && !result.entry?.id;
    updateJob(job.id, {
      status: hardFail ? "failed" : "done",
      galleryId: result.entry.id,
      startedAt: undefined,
      error: result.errors.length ? result.errors.join("; ") : undefined,
      stages: {
        normalize: result.stages.normalize,
        sourceRepo: result.stages.sourceRepo,
        readme: result.stages.readme,
        tools: result.stages.tools,
      },
    });
    appendLog(
      `job ${job.id} ${hardFail ? "fail" : "done"} ${result.entry.id} ` +
        `N=${result.stages.normalize} S=${result.stages.sourceRepo} R=${result.stages.readme} T=${result.stages.tools}`,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    updateJob(job.id, {
      status: "failed",
      error: msg,
      startedAt: undefined,
      galleryId: id,
    });
    appendLog(`job ${job.id} fail ${label}: ${msg}`);
  }
}

async function processBatch(
  concurrency: number,
  jobTimeoutMs: number,
): Promise<number> {
  // Recover hung jobs from prior crashes / stuck tools probes
  const stale = requeueStaleRunning(STALE_RUNNING_MS);
  if (stale) appendLog(`requeued ${stale} stale running jobs`);

  const settings = loadSettings();
  const pool = settings.useProxy ? new ProxyPool() : undefined;
  const helpers = makeHttpHelpers(settings, pool);
  const claimed = claimPending(concurrency);
  if (!claimed.length) return 0;

  // Cap parallel tools probes — high concurrency + hanging MCP endpoints starves the queue
  const effective = Math.min(concurrency, claimed.length, 8);
  let i = 0;
  async function runNext(): Promise<void> {
    while (i < claimed.length) {
      const job = claimed[i++]!;
      await processJob(job, helpers, jobTimeoutMs);
    }
  }
  const workers = Math.min(effective, claimed.length);
  await Promise.all(Array.from({ length: workers }, () => runNext()));
  return claimed.length;
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      concurrency: { type: "string" },
      /** Single claim batch then exit (CI loops) */
      once: { type: "boolean", default: false },
      /** Keep polling forever after queue is empty */
      watch: { type: "boolean", default: false },
      interval: { type: "string", default: "1500" },
      "job-timeout": { type: "string" },
      "requeue-stale": { type: "boolean", default: true },
      help: { type: "boolean", default: false },
    },
  });

  if (values.help) {
    console.log(
      "Usage: queue-worker [--concurrency N] [--once] [--watch] [--interval ms] [--job-timeout ms]\n" +
        "  Default: drain all pending jobs, then exit.\n" +
        "  --once         process one batch only\n" +
        "  --watch        keep running and poll for new jobs\n" +
        "  --job-timeout  hard per-job wall clock (default 90000)\n" +
        "  Pipeline: normalize → sourceRepo → README → tools/list\n" +
        "  Stale running jobs (>120s) are requeued automatically.",
    );
    process.exit(0);
  }

  ensureJobsDirs();
  const settings = loadSettings();
  // Cap default concurrency — tools/list hangs amplify with high parallelism
  const concurrency = Math.min(
    12,
    Math.max(1, Number(values.concurrency ?? settings.concurrency ?? 4)),
  );
  const interval = Number(values.interval ?? "1500");
  const jobTimeoutMs = Number(
    values["job-timeout"] ?? DEFAULT_JOB_TIMEOUT_MS,
  );
  const watch = Boolean(values.watch);
  const once = Boolean(values.once);

  writeWorkerPid(process.pid);
  if (values["requeue-stale"] !== false) {
    const n = requeueStaleRunning(STALE_RUNNING_MS);
    if (n) {
      appendLog(`startup requeued ${n} stale running`);
      console.error(`requeued ${n} stale running jobs`);
    }
  }
  appendLog(
    `worker start pid=${process.pid} concurrency=${concurrency} ` +
      `jobTimeoutMs=${jobTimeoutMs} ` +
      `mode=${once ? "once" : watch ? "watch" : "drain"} ` +
      `readme=${settings.enrichReadme} tools=${settings.enrichTools}`,
  );

  const shutdown = () => {
    appendLog("worker stop");
    clearWorkerPid();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  if (once) {
    const n = await processBatch(concurrency, jobTimeoutMs);
    console.log(JSON.stringify({ processed: n, counts: queueCounts() }, null, 2));
    clearWorkerPid();
    return;
  }

  if (watch) {
    console.error(
      `factory enrich worker watching (pid ${process.pid}); Ctrl+C to stop`,
    );
    for (;;) {
      requeueStaleRunning(STALE_RUNNING_MS);
      const pending = listQueue("pending").length;
      if (pending) {
        await processBatch(concurrency, jobTimeoutMs);
      } else {
        await new Promise((r) => setTimeout(r, interval));
      }
    }
  }

  // Default: drain entire queue, then exit
  let total = 0;
  for (;;) {
    const n = await processBatch(concurrency, jobTimeoutMs);
    total += n;
    if (n === 0) break;
  }
  console.log(
    JSON.stringify({ processed: total, counts: queueCounts(), mode: "drain" }, null, 2),
  );
  appendLog(`worker drain complete processed=${total}`);
  clearWorkerPid();
}

main().catch((err) => {
  appendLog(`worker crash: ${err instanceof Error ? err.message : err}`);
  clearWorkerPid();
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
