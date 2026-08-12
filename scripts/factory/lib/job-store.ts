import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
  appendFileSync,
} from "node:fs";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { RegistryListItem } from "../../../src/catalog/normalize.js";
import {
  QUEUE_DIR,
  SCANS_DIR,
  WORKER_LOG,
  WORKER_PID,
  ensureJobsDirs,
} from "./paths.js";

export type JobStatus = "pending" | "running" | "done" | "failed";
export type StageStatus = "pending" | "done" | "failed" | "skipped";

export type JobKind = "enrich";

export interface JobStages {
  normalize: StageStatus;
  sourceRepo: StageStatus;
  readme: StageStatus;
  tools: StageStatus;
}

export interface FactoryJob {
  id: string;
  kind: JobKind;
  status: JobStatus;
  createdAt: string;
  updatedAt: string;
  /** When claimPending moved job to running */
  startedAt?: string;
  galleryId?: string;
  error?: string;
  /** Registry payload when available (from scrape) */
  item?: RegistryListItem;
  stages: JobStages;
}

export interface ScanMeta {
  id: string;
  createdAt: string;
  source: string;
  counts: { items: number; enqueued?: number };
}

function nowIso(): string {
  return new Date().toISOString();
}

function jobPath(id: string): string {
  return join(QUEUE_DIR, `${id}.json`);
}

export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(6).toString("hex")}`;
}

export function defaultStages(): JobStages {
  return {
    normalize: "pending",
    sourceRepo: "pending",
    readme: "pending",
    tools: "pending",
  };
}

export function appendLog(line: string): void {
  ensureJobsDirs();
  appendFileSync(WORKER_LOG, `[${nowIso()}] ${line}\n`, "utf8");
}

export function tailLog(maxLines = 80): string[] {
  if (!existsSync(WORKER_LOG)) return [];
  const lines = readFileSync(WORKER_LOG, "utf8").split(/\r?\n/);
  return lines.filter(Boolean).slice(-maxLines);
}

/** Enqueue enrich job from registry list item */
export function enqueue(item: RegistryListItem): FactoryJob | null {
  return enqueueEnrich({
    galleryId: item.server?.name,
    item,
    skipIfQueued: true,
  });
}

/** True if galleryId already has pending or running job. */
export function hasActiveJob(galleryId: string): boolean {
  const id = galleryId.trim();
  if (!id) return false;
  for (const j of listQueue("pending")) {
    if ((j.galleryId || j.item?.server?.name) === id) return true;
  }
  for (const j of listQueue("running")) {
    if ((j.galleryId || j.item?.server?.name) === id) return true;
  }
  return false;
}

export function enqueueEnrich(input: {
  galleryId?: string;
  item?: RegistryListItem;
  /** If true, skip when pending/running already exists for this id */
  skipIfQueued?: boolean;
}): FactoryJob | null {
  ensureJobsDirs();
  const galleryId = input.galleryId ?? input.item?.server?.name;
  if (input.skipIfQueued !== false && galleryId && hasActiveJob(galleryId)) {
    return null;
  }
  const id = newId("job");
  const ts = nowIso();
  const job: FactoryJob = {
    id,
    kind: "enrich",
    status: "pending",
    createdAt: ts,
    updatedAt: ts,
    galleryId,
    item: input.item,
    stages: defaultStages(),
  };
  writeFileSync(jobPath(id), `${JSON.stringify(job, null, 2)}\n`, "utf8");
  return job;
}

export function updateJob(
  id: string,
  patch: Partial<FactoryJob>,
): FactoryJob | null {
  const p = jobPath(id);
  if (!existsSync(p)) return null;
  const job = JSON.parse(readFileSync(p, "utf8")) as FactoryJob;
  // migrate legacy jobs without kind/stages
  if (!job.kind) job.kind = "enrich";
  if (!job.stages) job.stages = defaultStages();
  const next = {
    ...job,
    ...patch,
    stages: patch.stages
      ? { ...job.stages, ...patch.stages }
      : job.stages,
    updatedAt: nowIso(),
  };
  writeFileSync(p, `${JSON.stringify(next, null, 2)}\n`, "utf8");
  return next;
}

function normalizeJob(j: FactoryJob): FactoryJob {
  if (!j.kind) j.kind = "enrich";
  if (!j.stages) j.stages = defaultStages();
  // legacy jobs always had item
  return j;
}

export function listQueue(filter: JobStatus | "all" = "all"): FactoryJob[] {
  ensureJobsDirs();
  const files = readdirSync(QUEUE_DIR).filter((f) => f.endsWith(".json"));
  const jobs: FactoryJob[] = [];
  for (const f of files) {
    try {
      const j = normalizeJob(
        JSON.parse(readFileSync(join(QUEUE_DIR, f), "utf8")) as FactoryJob,
      );
      if (filter === "all" || j.status === filter) jobs.push(j);
    } catch {
      /* skip corrupt */
    }
  }
  jobs.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return jobs;
}

export function queueCounts(): Record<JobStatus | "total", number> {
  const all = listQueue("all");
  const c = { pending: 0, running: 0, done: 0, failed: 0, total: all.length };
  for (const j of all) c[j.status]++;
  return c;
}

export function requeueFailed(): number {
  let n = 0;
  for (const j of listQueue("failed")) {
    updateJob(j.id, {
      status: "pending",
      error: undefined,
      stages: defaultStages(),
    });
    n++;
  }
  return n;
}

export function dropDone(): number {
  let n = 0;
  for (const j of listQueue("done")) {
    try {
      unlinkSync(jobPath(j.id));
      n++;
    } catch {
      /* ignore */
    }
  }
  return n;
}

export function claimPending(limit: number): FactoryJob[] {
  const pending = listQueue("pending").slice(0, limit);
  const claimed: FactoryJob[] = [];
  const startedAt = nowIso();
  for (const j of pending) {
    const u = updateJob(j.id, { status: "running", startedAt, error: undefined });
    if (u) claimed.push(u);
  }
  return claimed;
}

/**
 * Re-queue jobs stuck in `running` longer than maxAgeMs (crashed worker / hung probe).
 * Returns number requeued.
 */
export function requeueStaleRunning(maxAgeMs = 90_000): number {
  const cutoff = Date.now() - maxAgeMs;
  let n = 0;
  for (const j of listQueue("running")) {
    const started = Date.parse(j.startedAt || j.updatedAt || j.createdAt);
    if (Number.isNaN(started) || started > cutoff) continue;
    updateJob(j.id, {
      status: "pending",
      startedAt: undefined,
      error: `requeued: stale running (>${Math.round(maxAgeMs / 1000)}s)`,
      stages: defaultStages(),
    });
    n++;
  }
  return n;
}

/** Force-fail specific running jobs by gallery id substring (ops escape hatch). */
export function failRunningMatching(
  pred: (j: FactoryJob) => boolean,
  error: string,
): number {
  let n = 0;
  for (const j of listQueue("running")) {
    if (!pred(j)) continue;
    updateJob(j.id, {
      status: "failed",
      error,
      startedAt: undefined,
    });
    n++;
  }
  return n;
}

export function saveScan(
  id: string,
  meta: ScanMeta,
  items: RegistryListItem[],
): void {
  ensureJobsDirs();
  const dir = join(SCANS_DIR, id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "meta.json"), `${JSON.stringify(meta, null, 2)}\n`);
  writeFileSync(join(dir, "items.json"), `${JSON.stringify(items, null, 2)}\n`);
}

export function loadScanItems(id: string): RegistryListItem[] {
  const p = join(SCANS_DIR, id, "items.json");
  if (!existsSync(p)) return [];
  return JSON.parse(readFileSync(p, "utf8")) as RegistryListItem[];
}

export function listScans(): ScanMeta[] {
  ensureJobsDirs();
  if (!existsSync(SCANS_DIR)) return [];
  const out: ScanMeta[] = [];
  for (const name of readdirSync(SCANS_DIR)) {
    const mp = join(SCANS_DIR, name, "meta.json");
    if (!existsSync(mp)) continue;
    try {
      out.push(JSON.parse(readFileSync(mp, "utf8")) as ScanMeta);
    } catch {
      /* skip */
    }
  }
  out.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  return out;
}

export function lastScanId(): string | null {
  return listScans()[0]?.id ?? null;
}

export function isWorkerAlive(): boolean {
  if (!existsSync(WORKER_PID)) return false;
  try {
    const pid = Number(readFileSync(WORKER_PID, "utf8").trim());
    if (!pid) return false;
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export function writeWorkerPid(pid: number): void {
  ensureJobsDirs();
  writeFileSync(WORKER_PID, `${pid}\n`, "utf8");
}

export function clearWorkerPid(): void {
  try {
    unlinkSync(WORKER_PID);
  } catch {
    /* ignore */
  }
}
