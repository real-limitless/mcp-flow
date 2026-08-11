#!/usr/bin/env node
/**
 * Factory worker: enrich jobs (normalize → readme → tools) → sharded catalog
 *
 *   npx tsx scripts/factory/queue-worker.ts --concurrency 2
 *   npx tsx scripts/factory/queue-worker.ts --once
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
  updateJob,
  writeWorkerPid,
  type FactoryJob,
} from "./lib/job-store.js";
import { CATALOG_DIR, ensureJobsDirs } from "./lib/paths.js";
import { ProxyPool } from "./lib/proxy-pool.js";
import { loadSettings, resolveProxyUrl } from "./lib/settings.js";

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
  };
}

async function processJob(
  job: FactoryJob,
  helpers: ReturnType<typeof makeHttpHelpers>,
): Promise<void> {
  const settings = loadSettings();
  const id = job.galleryId ?? job.item?.server?.name;
  if (!id && !job.item) {
    updateJob(job.id, {
      status: "failed",
      error: "job missing galleryId/item",
    });
    return;
  }

  try {
    const result = await runEnrich({
      id,
      item: job.item,
      opts: {
        catalogDir: CATALOG_DIR,
        enrichReadme: settings.enrichReadme,
        enrichTools: settings.enrichTools,
        readmeMaxBytes: settings.readmeMaxBytes,
        toolsTimeoutMs: settings.toolsTimeoutMs,
        readmeRefreshDays: settings.readmeRefreshDays,
        toolsRefreshDays: settings.toolsRefreshDays,
        registryUrl: settings.registryUrl,
        getText: helpers.getText,
        getJson: helpers.getJson,
        log: (m) => appendLog(m),
      },
    });

    const hardFail =
      result.stages.normalize === "failed" && !result.entry?.id;
    updateJob(job.id, {
      status: hardFail ? "failed" : "done",
      galleryId: result.entry.id,
      error: result.errors.length ? result.errors.join("; ") : undefined,
      stages: {
        normalize: result.stages.normalize,
        readme: result.stages.readme,
        tools: result.stages.tools,
      },
    });
    appendLog(
      `job ${job.id} ${hardFail ? "fail" : "done"} ${result.entry.id} ` +
        `N=${result.stages.normalize} R=${result.stages.readme} T=${result.stages.tools}`,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    updateJob(job.id, { status: "failed", error: msg });
    appendLog(`job ${job.id} fail: ${msg}`);
  }
}

async function processBatch(concurrency: number): Promise<number> {
  const settings = loadSettings();
  const pool = settings.useProxy ? new ProxyPool() : undefined;
  const helpers = makeHttpHelpers(settings, pool);
  const claimed = claimPending(concurrency);
  if (!claimed.length) return 0;

  // Sequential tools probes are heavy; still allow small parallel batch
  const queue: Promise<void>[] = [];
  let i = 0;
  async function runNext(): Promise<void> {
    while (i < claimed.length) {
      const job = claimed[i++]!;
      await processJob(job, helpers);
    }
  }
  const workers = Math.min(concurrency, claimed.length);
  for (let w = 0; w < workers; w++) queue.push(runNext());
  await Promise.all(queue);
  return claimed.length;
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      concurrency: { type: "string" },
      once: { type: "boolean", default: false },
      interval: { type: "string", default: "1500" },
      help: { type: "boolean", default: false },
    },
  });

  if (values.help) {
    console.log(
      "Usage: queue-worker [--concurrency N] [--once] [--interval ms]\n" +
        "  Runs enrich pipeline: normalize → README → tools/list → catalog/entries",
    );
    process.exit(0);
  }

  ensureJobsDirs();
  const settings = loadSettings();
  const concurrency = Number(
    values.concurrency ?? settings.concurrency ?? 2,
  );
  const interval = Number(values.interval ?? "1500");

  writeWorkerPid(process.pid);
  appendLog(
    `worker start pid=${process.pid} concurrency=${concurrency} ` +
      `readme=${settings.enrichReadme} tools=${settings.enrichTools}`,
  );

  const shutdown = () => {
    appendLog("worker stop");
    clearWorkerPid();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  if (values.once) {
    const n = await processBatch(concurrency);
    console.log(JSON.stringify({ processed: n, counts: queueCounts() }, null, 2));
    clearWorkerPid();
    return;
  }

  console.error(
    `factory enrich worker running (pid ${process.pid}); Ctrl+C to stop`,
  );
  for (;;) {
    const pending = listQueue("pending").length;
    if (pending) {
      await processBatch(concurrency);
    } else {
      await new Promise((r) => setTimeout(r, interval));
    }
  }
}

main().catch((err) => {
  appendLog(`worker crash: ${err instanceof Error ? err.message : err}`);
  clearWorkerPid();
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
