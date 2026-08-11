#!/usr/bin/env node
/**
 * MCP Flow catalog factory TUI
 *
 * SCAN → LIST → QUEUE → PROXIES → SETTINGS → LOG
 *   npx tsx scripts/factory/tui.ts
 *   npm run factory:tui
 */
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { RegistryListItem } from "../../src/catalog/normalize.js";
import {
  c,
  clearScreen,
  cols,
  enterAltScreen,
  hideCursor,
  isTty,
  leaveAltScreen,
  pad,
  rows,
  setKeyHandler,
  showCursor,
  startInput,
  stopInput,
  truncate,
  type Key,
  writeAt,
} from "../../src/tui/term.js";
import { galleryIds, repairGallery } from "./lib/catalog-io.js";
import {
  appendLog,
  dropDone,
  enqueue,
  isWorkerAlive,
  lastScanId,
  listQueue,
  loadScanItems,
  newId,
  queueCounts,
  requeueFailed,
  saveScan,
  tailLog,
  type FactoryJob,
} from "./lib/job-store.js";
import {
  DEFAULT_SETTINGS,
  FACTORY_ROOT,
  WORKER_PID,
  ensureJobsDirs,
  type FactorySettings,
} from "./lib/paths.js";
import { ProxyPool } from "./lib/proxy-pool.js";
import { RegistryClient } from "./lib/registry-client.js";
import { loadSettings, saveSettings } from "./lib/settings.js";

const MODES = [
  "scan",
  "list",
  "queue",
  "proxies",
  "settings",
  "log",
  "help",
] as const;
type Mode = (typeof MODES)[number];

interface AppState {
  mode: Mode;
  message: string;
  settings: FactorySettings;
  // scan
  scanRunning: boolean;
  scanProgress: string;
  activeScanId: string | null;
  items: RegistryListItem[];
  itemSel: Set<string>;
  scanCursor: number;
  scanScroll: number;
  // list
  listFilter: string;
  listFilterMode: boolean;
  listHideKnown: boolean;
  listCursor: number;
  listScroll: number;
  listSel: Set<string>;
  // queue
  queueFilter: "all" | "pending" | "running" | "done" | "failed";
  queueCursor: number;
  queueScroll: number;
  queueRows: FactoryJob[];
  // proxies
  pool: ProxyPool;
  proxyBusy: boolean;
  proxyInputMode: boolean;
  proxyInputBuf: string;
  proxySummary: ReturnType<ProxyPool["summary"]>;
  // settings
  settingsKeys: (keyof FactorySettings)[];
  settingsCursor: number;
  settingsEdit: boolean;
  settingsBuf: string;
  // log
  logLines: string[];
  logScroll: number;
  logFollow: boolean;
  known: Set<string>;
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.max(lo, Math.min(hi, n));
}

function itemName(it: RegistryListItem): string {
  return it.server?.name ?? "";
}

function itemTitle(it: RegistryListItem): string {
  return it.server?.title || itemName(it).split("/").pop() || itemName(it);
}

function hasRemote(it: RegistryListItem): boolean {
  return Boolean(it.server?.remotes?.some((r) => r.url));
}

async function runFactoryTui(): Promise<void> {
  if (!isTty()) {
    console.error("factory tui requires a TTY");
    process.exit(1);
  }

  ensureJobsDirs();
  try {
    await repairGallery();
  } catch {
    /* ignore */
  }

  const settings = loadSettings();
  const state: AppState = {
    mode: "scan",
    message: "Tab cycle · ? help · q quit",
    settings,
    scanRunning: false,
    scanProgress: "",
    activeScanId: lastScanId(),
    items: [],
    itemSel: new Set(),
    scanCursor: 0,
    scanScroll: 0,
    listFilter: "",
    listFilterMode: false,
    listHideKnown: true,
    listCursor: 0,
    listScroll: 0,
    listSel: new Set(),
    queueFilter: "all",
    queueCursor: 0,
    queueScroll: 0,
    queueRows: [],
    pool: new ProxyPool(),
    proxyBusy: false,
    proxyInputMode: false,
    proxyInputBuf: "",
    proxySummary: { listed: 0, alive: 0, dead: 0, sampleAlive: [] },
    settingsKeys: Object.keys(DEFAULT_SETTINGS) as (keyof FactorySettings)[],
    settingsCursor: 0,
    settingsEdit: false,
    settingsBuf: "",
    logLines: [],
    logScroll: 0,
    logFollow: true,
    known: galleryIds(),
  };

  if (state.activeScanId) {
    state.items = loadScanItems(state.activeScanId);
  }
  state.proxySummary = state.pool.summary();
  state.queueRows = listQueue(state.queueFilter === "all" ? "all" : state.queueFilter);
  state.logLines = tailLog(120);

  let alive = true;
  let paintScheduled = false;

  const quit = () => {
    alive = false;
    stopInput();
    showCursor();
    leaveAltScreen();
  };

  const schedulePaint = () => {
    if (paintScheduled || !alive) return;
    paintScheduled = true;
    setImmediate(() => {
      paintScheduled = false;
      if (alive) paint();
    });
  };

  const refreshSoft = () => {
    state.known = galleryIds();
    state.queueRows = listQueue(
      state.queueFilter === "all" ? "all" : state.queueFilter,
    );
    state.proxySummary = state.pool.summary();
    if (state.logFollow) state.logLines = tailLog(120);
    schedulePaint();
  };

  const visibleList = (): RegistryListItem[] => {
    let rows = state.items;
    if (state.listHideKnown) {
      rows = rows.filter((it) => !state.known.has(itemName(it)));
    }
    if (state.settings.preferRemoteOnly) {
      rows = rows.filter(hasRemote);
    }
    const q = state.listFilter.trim().toLowerCase();
    if (q) {
      rows = rows.filter((it) => {
        const hay = `${itemName(it)} ${itemTitle(it)} ${it.server?.description ?? ""}`.toLowerCase();
        return hay.includes(q);
      });
    }
    return rows;
  };

  const runScan = async () => {
    if (state.scanRunning) return;
    state.scanRunning = true;
    state.scanProgress = "starting…";
    state.message = "scan running…";
    schedulePaint();
    try {
      const client = new RegistryClient(
        state.settings,
        state.settings.useProxy ? state.pool : undefined,
      );
      const items: RegistryListItem[] = [];
      const seen = new Set<string>();
      for await (const page of client.paginate({
        maxPages: state.settings.maxPages,
        search: state.settings.search || undefined,
        onPage: (n, c) => {
          state.scanProgress = `page ${n} (+${c}) total ${items.length}`;
          schedulePaint();
        },
      })) {
        for (const item of page) {
          const name = item.server?.name;
          if (!name || seen.has(name)) continue;
          const official =
            item._meta?.["io.modelcontextprotocol.registry/official"];
          if (
            state.settings.latestOnly &&
            official &&
            official.isLatest === false
          ) {
            continue;
          }
          seen.add(name);
          items.push(item);
        }
      }
      const scanId = newId("scan");
      saveScan(
        scanId,
        {
          id: scanId,
          createdAt: new Date().toISOString(),
          source: state.settings.registryUrl,
          counts: { items: items.length },
        },
        items,
      );
      state.activeScanId = scanId;
      state.items = items;
      state.itemSel = new Set();
      state.scanCursor = 0;
      state.scanScroll = 0;
      state.message = `scan ${scanId}: ${items.length} servers`;
      appendLog(state.message);
    } catch (err) {
      state.message = `scan failed: ${err instanceof Error ? err.message : err}`;
      appendLog(state.message);
    } finally {
      state.scanRunning = false;
      state.scanProgress = "";
      refreshSoft();
    }
  };

  const enqueueNames = (names: string[]) => {
    let n = 0;
    const byName = new Map(
      state.items.map((it) => [itemName(it), it] as const),
    );
    for (const name of names) {
      const it = byName.get(name);
      if (!it) continue;
      enqueue(it);
      n++;
    }
    state.message = `enqueued ${n}`;
    appendLog(state.message);
    refreshSoft();
  };

  const startWorkerReliable = () => {
    if (isWorkerAlive()) {
      state.message = "worker already running";
      schedulePaint();
      return;
    }
    const repo = join(FACTORY_ROOT, "../..");
    const child = spawn(
      "npx",
      [
        "tsx",
        "scripts/factory/queue-worker.ts",
        "--concurrency",
        String(state.settings.concurrency),
      ],
      { cwd: repo, detached: true, stdio: "ignore", shell: false },
    );
    child.unref();
    state.message = `worker started pid=${child.pid ?? "?"}`;
    appendLog(state.message);
    setTimeout(refreshSoft, 500);
    schedulePaint();
  };

  const stopWorker = () => {
    if (!isWorkerAlive()) {
      state.message = "no worker pid";
      schedulePaint();
      return;
    }
    try {
      const pid = Number(readFileSync(WORKER_PID, "utf8").trim());
      process.kill(pid, "SIGTERM");
      state.message = `sent SIGTERM to ${pid}`;
    } catch (err) {
      state.message = `stop failed: ${err instanceof Error ? err.message : err}`;
    }
    schedulePaint();
  };

  function paint(): void {
    const w = cols();
    const h = rows();
    clearScreen();
    const modeIdx = MODES.indexOf(state.mode);
    const tabs = MODES.map((m, i) =>
      i === modeIdx
        ? `${c.reverse} ${m.toUpperCase()} ${c.reset}`
        : ` ${m.toUpperCase()} `,
    ).join("");
    writeAt(1, 1, pad(`${c.bold}${c.cyan} mcp-flow factory${c.reset}  ${tabs}`, w));
    writeAt(2, 1, c.dim + "─".repeat(Math.max(0, w - 1)) + c.reset);

    let body = 3;
    const line = (t: string) => {
      if (body >= h - 2) return;
      writeAt(body, 1, pad(t, w));
      body++;
    };
    const blank = () => line("");

    const worker = isWorkerAlive() ? `${c.green}on${c.reset}` : `${c.dim}off${c.reset}`;
    const counts = queueCounts();
    line(
      `${c.dim}gallery:${c.reset} ${state.known.size}  ${c.dim}queue:${c.reset} p${counts.pending}/r${counts.running}/d${counts.done}/f${counts.failed}  ${c.dim}worker:${c.reset} ${worker}  ${c.dim}proxy:${c.reset} ${state.settings.useProxy ? c.yellow + "on" + c.reset : "off"}`,
    );
    blank();

    if (state.mode === "scan") {
      line(`${c.bold}SCAN${c.reset}  registry → inventory`);
      line(
        `${c.dim}maxPages=${state.settings.maxPages} latestOnly=${state.settings.latestOnly} search=${state.settings.search || "—"}${c.reset}`,
      );
      if (state.scanRunning)
        line(`${c.yellow}${state.scanProgress || "…"}${c.reset}`);
      line(
        `scan: ${state.activeScanId ?? "—"}  items: ${state.items.length}  selected: ${state.itemSel.size}`,
      );
      blank();
      const viewH = Math.max(3, h - body - 3);
      state.scanScroll = clamp(
        state.scanScroll,
        0,
        Math.max(0, state.items.length - viewH),
      );
      state.scanCursor = clamp(state.scanCursor, 0, Math.max(0, state.items.length - 1));
      if (state.scanCursor < state.scanScroll) state.scanScroll = state.scanCursor;
      if (state.scanCursor >= state.scanScroll + viewH)
        state.scanScroll = state.scanCursor - viewH + 1;
      for (let i = 0; i < viewH; i++) {
        const idx = state.scanScroll + i;
        const it = state.items[idx];
        if (!it) {
          line("");
          continue;
        }
        const name = itemName(it);
        const mark = state.itemSel.has(name) ? "*" : " ";
        const remote = hasRemote(it) ? "R" : " ";
        const known = state.known.has(name) ? "G" : " ";
        const sel = idx === state.scanCursor;
        const text = `${mark}${remote}${known} ${pad(itemTitle(it), 24)} ${truncate(name, Math.max(10, w - 36))}`;
        line(sel ? `${c.reverse} › ${text}${c.reset}` : `   ${text}`);
      }
      writeAt(
        h,
        1,
        pad(
          `${c.bgGray}${c.white} Enter scan · Space toggle · e enqueue sel · E all new · Tab · ${state.message} ${c.reset}`,
          w,
        ),
      );
      return;
    }

    if (state.mode === "list") {
      const rowsList = visibleList();
      line(
        `${c.bold}LIST${c.reset}  filter=${state.listFilterMode ? c.reverse + (state.listFilter || " ") + c.reset : state.listFilter || "—"}  hideKnown=${state.listHideKnown}  showing ${rowsList.length}`,
      );
      blank();
      const viewH = Math.max(3, h - body - 3);
      state.listScroll = clamp(
        state.listScroll,
        0,
        Math.max(0, rowsList.length - viewH),
      );
      state.listCursor = clamp(state.listCursor, 0, Math.max(0, rowsList.length - 1));
      if (state.listCursor < state.listScroll) state.listScroll = state.listCursor;
      if (state.listCursor >= state.listScroll + viewH)
        state.listScroll = state.listCursor - viewH + 1;
      for (let i = 0; i < viewH; i++) {
        const idx = state.listScroll + i;
        const it = rowsList[idx];
        if (!it) {
          line("");
          continue;
        }
        const name = itemName(it);
        const mark = state.listSel.has(name) ? "*" : " ";
        const sel = idx === state.listCursor;
        const text = `${mark} ${pad(itemTitle(it), 22)} ${hasRemote(it) ? "remote" : "stdio "} ${truncate(name, Math.max(8, w - 40))}`;
        line(sel ? `${c.reverse} › ${text}${c.reset}` : `   ${text}`);
      }
      writeAt(
        h,
        1,
        pad(
          `${c.bgGray}${c.white} / filter · k hideKnown · Space · e/E enqueue · n enqueue+worker · ${state.message} ${c.reset}`,
          w,
        ),
      );
      return;
    }

    if (state.mode === "queue") {
      line(
        `${c.bold}QUEUE${c.reset}  filter=${state.queueFilter}  ${JSON.stringify(counts)}`,
      );
      blank();
      const viewH = Math.max(3, h - body - 3);
      const qrows = state.queueRows;
      state.queueScroll = clamp(
        state.queueScroll,
        0,
        Math.max(0, qrows.length - viewH),
      );
      state.queueCursor = clamp(state.queueCursor, 0, Math.max(0, qrows.length - 1));
      for (let i = 0; i < viewH; i++) {
        const idx = state.queueScroll + i;
        const j = qrows[idx];
        if (!j) {
          line("");
          continue;
        }
        const sel = idx === state.queueCursor;
        const st =
          j.status === "done"
            ? c.green
            : j.status === "failed"
              ? c.red
              : j.status === "running"
                ? c.yellow
                : c.dim;
        const text = `${st}${pad(j.status, 8)}${c.reset} ${truncate(j.galleryId ?? j.id, Math.max(10, w - 30))} ${j.error ? c.dim + truncate(j.error, 20) + c.reset : ""}`;
        line(sel ? `${c.reverse} › ${text}${c.reset}` : `   ${text}`);
      }
      writeAt(
        h,
        1,
        pad(
          `${c.bgGray}${c.white} S start worker · X stop · r requeue fail · d drop done · f cycle filter · ${state.message} ${c.reset}`,
          w,
        ),
      );
      return;
    }

    if (state.mode === "proxies") {
      line(`${c.bold}PROXIES${c.reset}  useProxy=${state.settings.useProxy}`);
      line(
        `fixed: ${state.settings.proxy || c.dim + "(none — rotate pool)" + c.reset}`,
      );
      line(
        `listUrl: ${truncate(state.settings.proxyListUrl, Math.max(20, w - 12))}`,
      );
      const s = state.proxySummary;
      line(
        `listed=${s.listed}  alive=${s.alive}  dead=${s.dead}${state.proxyBusy ? c.yellow + "  busy…" + c.reset : ""}`,
      );
      if (s.sampleAlive.length) {
        line(`${c.dim}alive sample:${c.reset}`);
        for (const p of s.sampleAlive) line(`  ${p}`);
      }
      if (state.proxyInputMode) {
        blank();
        line(`add proxy: ${c.reverse}${state.proxyInputBuf || " "}${c.reset}`);
      }
      blank();
      line(
        `${c.dim}t/Space toggle · R refresh list · H health · a add · c clear fixed · s save${c.reset}`,
      );
      writeAt(
        h,
        1,
        pad(`${c.bgGray}${c.white} ${state.message} ${c.reset}`, w),
      );
      return;
    }

    if (state.mode === "settings") {
      line(`${c.bold}SETTINGS${c.reset}  (Enter edit · s save)`);
      blank();
      state.settingsKeys.forEach((k, i) => {
        const sel = i === state.settingsCursor;
        const val =
          state.settingsEdit && sel
            ? c.reverse + (state.settingsBuf || " ") + c.reset
            : String(state.settings[k]);
        const text = `${pad(k, 22)} ${val}`;
        line(sel ? `${c.cyan}>${c.reset} ${text}` : `  ${text}`);
      });
      writeAt(
        h,
        1,
        pad(`${c.bgGray}${c.white} ${state.message} ${c.reset}`, w),
      );
      return;
    }

    if (state.mode === "log") {
      line(
        `${c.bold}LOG${c.reset}  follow=${state.logFollow}  (f toggle follow · r refresh)`,
      );
      blank();
      const viewH = Math.max(3, h - body - 2);
      const lines = state.logLines;
      const maxScroll = Math.max(0, lines.length - viewH);
      if (state.logFollow) state.logScroll = maxScroll;
      state.logScroll = clamp(state.logScroll, 0, maxScroll);
      for (let i = 0; i < viewH; i++) {
        line(truncate(lines[state.logScroll + i] ?? "", w - 2));
      }
      writeAt(
        h,
        1,
        pad(`${c.bgGray}${c.white} ${state.message} ${c.reset}`, w),
      );
      return;
    }

    if (state.mode === "help") {
      line(`${c.bold}HELP${c.reset}`);
      blank();
      const help = [
        "Tab / ← →   cycle screens",
        "SCAN  Enter=scrape registry  Space=toggle  e=enqueue  E=all unknown",
        "LIST  /=filter  k=hide known  e/E enqueue  n=enqueue+start worker",
        "QUEUE S=start worker  X=stop  r=requeue failed  d=drop done",
        "PROXIES t=useProxy  R=refresh  H=health  a=add  c=clear fixed",
        "SETTINGS Enter edit value  s save to .jobs/settings.json",
        "q quit TUI (worker may keep running)",
      ];
      for (const hline of help) line(`  ${hline}`);
      writeAt(
        h,
        1,
        pad(`${c.bgGray}${c.white} esc back · ${state.message} ${c.reset}`, w),
      );
    }
  }

  async function handle(key: Key): Promise<void> {
    if (key.name === "ctrl" && (key.sequence === "c" || key.sequence === "d")) {
      quit();
      return;
    }

    // proxy input mode
    if (state.proxyInputMode) {
      if (key.name === "escape") {
        state.proxyInputMode = false;
        state.proxyInputBuf = "";
        schedulePaint();
        return;
      }
      if (key.name === "backspace") {
        state.proxyInputBuf = state.proxyInputBuf.slice(0, -1);
        schedulePaint();
        return;
      }
      if (key.name === "return") {
        try {
          state.pool.addProxy(state.proxyInputBuf);
          state.settings.proxy = state.proxyInputBuf.trim();
          saveSettings(state.settings);
          state.message = "proxy added + set as fixed";
          state.proxySummary = state.pool.summary();
        } catch (err) {
          state.message = err instanceof Error ? err.message : String(err);
        }
        state.proxyInputMode = false;
        state.proxyInputBuf = "";
        schedulePaint();
        return;
      }
      if (key.name === "char" && key.sequence.length === 1 && key.sequence >= " ") {
        state.proxyInputBuf += key.sequence;
        schedulePaint();
      }
      return;
    }

    // settings edit
    if (state.settingsEdit) {
      if (key.name === "escape") {
        state.settingsEdit = false;
        schedulePaint();
        return;
      }
      if (key.name === "backspace") {
        state.settingsBuf = state.settingsBuf.slice(0, -1);
        schedulePaint();
        return;
      }
      if (key.name === "return") {
        const k = state.settingsKeys[state.settingsCursor]!;
        const raw = state.settingsBuf;
        const cur = state.settings[k];
        if (typeof cur === "boolean") {
          state.settings[k] = /^(1|true|yes|on)$/i.test(raw) as never;
        } else if (typeof cur === "number") {
          state.settings[k] = Number(raw) as never;
        } else {
          state.settings[k] = raw as never;
        }
        saveSettings(state.settings);
        state.settingsEdit = false;
        state.message = `saved ${k}`;
        schedulePaint();
        return;
      }
      if (key.name === "char" && key.sequence.length === 1 && key.sequence >= " ") {
        state.settingsBuf += key.sequence;
        schedulePaint();
      }
      return;
    }

    // list filter mode
    if (state.listFilterMode) {
      if (key.name === "escape" || key.name === "return") {
        state.listFilterMode = false;
        schedulePaint();
        return;
      }
      if (key.name === "backspace") {
        state.listFilter = state.listFilter.slice(0, -1);
        schedulePaint();
        return;
      }
      if (key.name === "char" && key.sequence.length === 1 && key.sequence >= " ") {
        state.listFilter += key.sequence;
        schedulePaint();
      }
      return;
    }

    if (key.name === "char" && key.sequence === "q") {
      quit();
      return;
    }
    if (key.name === "char" && key.sequence === "?") {
      state.mode = "help";
      schedulePaint();
      return;
    }
    if (key.name === "tab" || key.name === "right") {
      const i = MODES.indexOf(state.mode);
      state.mode = MODES[(i + 1) % MODES.length]!;
      refreshSoft();
      return;
    }
    if (key.name === "left") {
      const i = MODES.indexOf(state.mode);
      state.mode = MODES[(i - 1 + MODES.length) % MODES.length]!;
      refreshSoft();
      return;
    }

    if (state.mode === "help") {
      if (key.name === "escape") state.mode = "scan";
      schedulePaint();
      return;
    }

    if (state.mode === "scan") {
      if (key.name === "up")
        state.scanCursor = Math.max(0, state.scanCursor - 1);
      if (key.name === "down")
        state.scanCursor = Math.min(
          Math.max(0, state.items.length - 1),
          state.scanCursor + 1,
        );
      if (key.name === "return") void runScan();
      if (key.name === "char" && key.sequence === " ") {
        const it = state.items[state.scanCursor];
        if (it) {
          const n = itemName(it);
          if (state.itemSel.has(n)) state.itemSel.delete(n);
          else state.itemSel.add(n);
        }
      }
      if (key.name === "char" && key.sequence === "e") {
        enqueueNames([...state.itemSel]);
      }
      if (key.name === "char" && key.sequence === "E") {
        const names = state.items
          .filter((it) => !state.known.has(itemName(it)))
          .filter((it) => !state.settings.preferRemoteOnly || hasRemote(it))
          .map(itemName);
        enqueueNames(names);
      }
      schedulePaint();
      return;
    }

    if (state.mode === "list") {
      const rowsList = visibleList();
      if (key.name === "up")
        state.listCursor = Math.max(0, state.listCursor - 1);
      if (key.name === "down")
        state.listCursor = Math.min(
          Math.max(0, rowsList.length - 1),
          state.listCursor + 1,
        );
      if (key.name === "char" && key.sequence === "/") {
        state.listFilterMode = true;
        schedulePaint();
        return;
      }
      if (key.name === "char" && key.sequence === "k") {
        state.listHideKnown = !state.listHideKnown;
      }
      if (key.name === "char" && key.sequence === " ") {
        const it = rowsList[state.listCursor];
        if (it) {
          const n = itemName(it);
          if (state.listSel.has(n)) state.listSel.delete(n);
          else state.listSel.add(n);
        }
      }
      if (key.name === "char" && key.sequence === "e") {
        enqueueNames([...state.listSel]);
      }
      if (key.name === "char" && key.sequence === "E") {
        enqueueNames(rowsList.map(itemName));
      }
      if (key.name === "char" && key.sequence === "n") {
        enqueueNames(
          state.listSel.size
            ? [...state.listSel]
            : rowsList.map(itemName),
        );
        startWorkerReliable();
      }
      schedulePaint();
      return;
    }

    if (state.mode === "queue") {
      if (key.name === "up")
        state.queueCursor = Math.max(0, state.queueCursor - 1);
      if (key.name === "down")
        state.queueCursor = Math.min(
          Math.max(0, state.queueRows.length - 1),
          state.queueCursor + 1,
        );
      if (key.name === "char" && key.sequence === "S") startWorkerReliable();
      if (key.name === "char" && key.sequence === "X") stopWorker();
      if (key.name === "char" && key.sequence === "r") {
        const n = requeueFailed();
        state.message = `requeued ${n}`;
        refreshSoft();
      }
      if (key.name === "char" && key.sequence === "d") {
        const n = dropDone();
        state.message = `dropped ${n} done`;
        refreshSoft();
      }
      if (key.name === "char" && key.sequence === "f") {
        const order = ["all", "pending", "running", "done", "failed"] as const;
        const i = order.indexOf(state.queueFilter);
        state.queueFilter = order[(i + 1) % order.length]!;
        refreshSoft();
      }
      schedulePaint();
      return;
    }

    if (state.mode === "proxies") {
      if (
        (key.name === "char" && key.sequence === "t") ||
        (key.name === "char" && key.sequence === " ")
      ) {
        state.settings.useProxy = !state.settings.useProxy;
        saveSettings(state.settings);
        state.message = `useProxy=${state.settings.useProxy}`;
      }
      if (key.name === "char" && key.sequence === "R") {
        state.proxyBusy = true;
        schedulePaint();
        try {
          const n = await state.pool.refresh(
            state.settings.proxyListUrl,
            state.settings.useProxy
              ? state.settings.proxy || state.pool.pick()
              : undefined,
          );
          state.message = `refreshed ${n} proxies`;
          state.proxySummary = state.pool.summary();
        } catch (err) {
          state.message = `refresh fail: ${err instanceof Error ? err.message : err}`;
        }
        state.proxyBusy = false;
      }
      if (key.name === "char" && key.sequence === "H") {
        state.proxyBusy = true;
        schedulePaint();
        try {
          const r = await state.pool.healthCheck({
            limit: state.settings.proxyProbeLimit,
            timeout: state.settings.proxyProbeTimeout,
          });
          state.message = `health tested=${r.tested} alive=${r.alive} dead=${r.dead}`;
          state.proxySummary = state.pool.summary();
        } catch (err) {
          state.message = `health fail: ${err instanceof Error ? err.message : err}`;
        }
        state.proxyBusy = false;
      }
      if (key.name === "char" && key.sequence === "a") {
        state.proxyInputMode = true;
        state.proxyInputBuf = state.settings.proxy || "socks5h://";
      }
      if (key.name === "char" && key.sequence === "c") {
        state.settings.proxy = "";
        saveSettings(state.settings);
        state.message = "cleared fixed proxy";
      }
      if (key.name === "char" && key.sequence === "s") {
        saveSettings(state.settings);
        state.message = "settings saved";
      }
      schedulePaint();
      return;
    }

    if (state.mode === "settings") {
      if (key.name === "up")
        state.settingsCursor = Math.max(0, state.settingsCursor - 1);
      if (key.name === "down")
        state.settingsCursor = Math.min(
          state.settingsKeys.length - 1,
          state.settingsCursor + 1,
        );
      if (key.name === "return") {
        const k = state.settingsKeys[state.settingsCursor]!;
        state.settingsEdit = true;
        state.settingsBuf = String(state.settings[k]);
      }
      if (key.name === "char" && key.sequence === "s") {
        saveSettings(state.settings);
        state.message = "settings saved";
      }
      schedulePaint();
      return;
    }

    if (state.mode === "log") {
      if (key.name === "up") {
        state.logFollow = false;
        state.logScroll = Math.max(0, state.logScroll - 1);
      }
      if (key.name === "down") {
        state.logFollow = false;
        state.logScroll++;
      }
      if (key.name === "char" && key.sequence === "f") {
        state.logFollow = !state.logFollow;
      }
      if (key.name === "char" && key.sequence === "r") {
        state.logLines = tailLog(120);
      }
      schedulePaint();
    }
  }

  enterAltScreen();
  hideCursor();
  startInput((k) => {
    void handle(k);
  });
  setKeyHandler((k) => {
    void handle(k);
  });
  process.stdout.on("resize", schedulePaint);
  paint();

  const tick = setInterval(() => {
    if (!alive) return;
    if (state.mode === "queue" || state.mode === "log" || state.mode === "scan") {
      refreshSoft();
    }
  }, 2000);

  await new Promise<void>((resolve) => {
    const iv = setInterval(() => {
      if (!alive) {
        clearInterval(iv);
        clearInterval(tick);
        resolve();
      }
    }, 100);
  });
}

runFactoryTui().catch((err) => {
  leaveAltScreen();
  showCursor();
  console.error(err);
  process.exit(1);
});
