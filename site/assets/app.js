import { escapeHtml, markdownToHtml } from "./md.js";

const cfg = () =>
  window.__SITE__ || {
    base: "",
    catalogBase: "catalog",
    repo: "https://github.com/real-limitless/mcp-flow",
  };

export function siteHref(path) {
  const base = (cfg().base || "").replace(/\/$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${base}${p}` || "/";
}

export function catalogUrl(rel) {
  const base = (cfg().base || "").replace(/\/$/, "");
  const cat = (cfg().catalogBase || "catalog")
    .replace(/^\//, "")
    .replace(/\/$/, "");
  const r = rel.replace(/^\//, "");
  return `${base}/${cat}/${r}`.replace(/([^:]\/)\/+/g, "$1");
}

export function safeId(id) {
  const base = String(id)
    .trim()
    .replace(/\//g, "--")
    .replace(/[^a-zA-Z0-9._@+-]/g, "_");
  return base || "unknown";
}

export function entryPath(id) {
  return `entries/${safeId(id)}.json`;
}

export function serverPageHref(id) {
  return `${siteHref("/server.html")}?id=${encodeURIComponent(id)}`;
}

function badge(text, kind = "") {
  return `<span class="badge ${kind}">${escapeHtml(text)}</span>`;
}

export function toolsBadges(row) {
  const st = row.toolsPreviewStatus;
  const n = row.toolsCount;
  if (st === "ok" || (n && n > 0)) return badge(`${n ?? 0} tools`, "on");
  if (st === "auth_required") return badge("auth", "seal");
  if (st === "unreachable") return badge("unreachable", "deny");
  if (st === "unsupported") return badge("stdio", "off");
  if (row.hasToolsPreview) return badge("tools", "on");
  return "";
}

export function statusBadges(row) {
  const bits = [];
  if (
    row.status === "inactive" ||
    row.sourceRepoStatus === "not_found" ||
    (row.flags || []).includes("repo-offline")
  ) {
    bits.push(badge("inactive", "deny"));
  } else if (row.status === "deprecated") {
    bits.push(badge("deprecated", "warn"));
  } else if (row.status === "active") {
    bits.push(badge("active", "on"));
  }
  return bits.join(" ");
}

export function transportBadge(t) {
  return badge(t || "unknown", "place");
}

export function isInactiveRow(r) {
  if (!r) return false;
  if (r.status === "inactive" || r.status === "deleted") return true;
  if (r.sourceRepoStatus === "not_found") return true;
  if ((r.flags || []).includes("repo-offline")) return true;
  return false;
}

async function loadMeta() {
  try {
    const res = await fetch(catalogUrl("meta.json"));
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

async function loadEntry(id) {
  const url = catalogUrl(entryPath(id));
  const res = await fetch(url);
  if (!res.ok) throw new Error(`entry HTTP ${res.status} (${url})`);
  return res.json();
}

const PAGE_SIZES = [24, 48, 96];
const DEFAULT_PAGE_SIZE = 48;

function workerUrl() {
  // Resolve relative to this module so SITE_BASE works
  return new URL("./search-worker.js", import.meta.url).href;
}

function readFiltersFromDom() {
  const psRaw = Number(
    document.getElementById("f-page-size")?.value || DEFAULT_PAGE_SIZE,
  );
  const pageSize = PAGE_SIZES.includes(psRaw) ? psRaw : DEFAULT_PAGE_SIZE;
  const view =
    document.getElementById("results-body")?.dataset.view === "cards"
      ? "cards"
      : "list";
  return {
    q: (document.getElementById("q")?.value || "").trim().toLowerCase(),
    hideInactive: Boolean(
      document.getElementById("f-hide-inactive")?.checked ?? true,
    ),
    transport: document.getElementById("f-transport")?.value || "",
    flag: document.getElementById("f-flag")?.value || "",
    tools: document.getElementById("f-tools")?.value || "",
    onlyRemote: Boolean(document.getElementById("f-only-remote")?.checked),
    onlyActiveStatus: Boolean(
      document.getElementById("f-only-active-status")?.checked,
    ),
    pageSize,
    view,
  };
}

function applyFiltersFromUrl(state) {
  const sp = new URLSearchParams(location.search);
  const q = document.getElementById("q");
  const hide = document.getElementById("f-hide-inactive");
  const transport = document.getElementById("f-transport");
  const flag = document.getElementById("f-flag");
  const tools = document.getElementById("f-tools");
  const onlyRemote = document.getElementById("f-only-remote");
  const onlyActive = document.getElementById("f-only-active-status");
  const pageSizeEl = document.getElementById("f-page-size");

  if (q && sp.has("q")) q.value = sp.get("q") || "";
  if (hide) {
    hide.checked = !(
      sp.get("showInactive") === "1" ||
      sp.get("inactive") === "1" ||
      sp.get("hideInactive") === "0"
    );
  }
  if (transport && sp.get("transport")) transport.value = sp.get("transport");
  if (flag && sp.get("flag")) flag.value = sp.get("flag");
  if (tools && sp.get("tools")) tools.value = sp.get("tools");
  if (onlyRemote) onlyRemote.checked = sp.get("remote") === "1";
  if (onlyActive) onlyActive.checked = sp.get("activeOnly") === "1";
  const ps = Number(sp.get("pageSize") || DEFAULT_PAGE_SIZE);
  if (pageSizeEl && PAGE_SIZES.includes(ps)) pageSizeEl.value = String(ps);
  const page = Math.max(1, Number(sp.get("page") || 1) || 1);
  if (state) state.page = page;
  setViewMode(sp.get("view") === "cards" ? "cards" : "list");
  if (
    sp.get("showInactive") === "1" ||
    sp.get("remote") === "1" ||
    sp.get("activeOnly") === "1"
  ) {
    openAdvanced(true);
  }
}

function writeFiltersToUrl(f, page) {
  const sp = new URLSearchParams();
  if (f.q) sp.set("q", f.q);
  if (!f.hideInactive) sp.set("showInactive", "1");
  if (f.transport) sp.set("transport", f.transport);
  if (f.flag) sp.set("flag", f.flag);
  if (f.tools) sp.set("tools", f.tools);
  if (f.onlyRemote) sp.set("remote", "1");
  if (f.onlyActiveStatus) sp.set("activeOnly", "1");
  if (f.pageSize && f.pageSize !== DEFAULT_PAGE_SIZE)
    sp.set("pageSize", String(f.pageSize));
  if (f.view === "cards") sp.set("view", "cards");
  if (page > 1) sp.set("page", String(page));
  const qs = sp.toString();
  history.replaceState(
    null,
    "",
    `${location.pathname}${qs ? `?${qs}` : ""}${location.hash || ""}`,
  );
}

function setViewMode(view) {
  const body = document.getElementById("results-body");
  const list = document.getElementById("list-view");
  const cards = document.getElementById("card-grid");
  const btnList = document.getElementById("view-list");
  const btnCards = document.getElementById("view-cards");
  const v = view === "cards" ? "cards" : "list";
  if (body) body.dataset.view = v;
  list?.classList.toggle("hidden", v !== "list");
  cards?.classList.toggle("hidden", v !== "cards");
  btnList?.classList.toggle("on", v === "list");
  btnCards?.classList.toggle("on", v === "cards");
}

function openAdvanced(open) {
  const adv = document.getElementById("f-advanced");
  const tog = document.getElementById("f-adv-toggle");
  if (!adv) return;
  adv.classList.toggle("hidden", !open);
  tog?.setAttribute("aria-expanded", open ? "true" : "false");
  tog?.classList.toggle("on", open);
}

function rowSignalsHtml(r) {
  const inactive = isInactiveRow(r);
  const flags = (r.flags || [])
    .filter((fl) => fl !== "repo-offline" || inactive)
    .slice(0, 3)
    .map((fl) =>
      badge(
        fl,
        fl === "remote" ? "place" : fl === "repo-offline" ? "deny" : "off",
      ),
    )
    .join(" ");
  return `${statusBadges(r)} ${toolsBadges(r)} ${r.hasReadme ? badge("readme", "on") : ""} ${flags}`;
}

function renderListRows(slice) {
  return slice
    .map((r) => {
      const href = serverPageHref(r.id);
      const inactive = isInactiveRow(r);
      return `<tr class="row-link${inactive ? " row-inactive" : ""}" data-href="${escapeHtml(href)}">
  <td><div class="title-cell">${escapeHtml(r.title)}</div>
      <div class="slug">${escapeHtml(r.id)}</div></td>
  <td class="col-hide"><div class="sum">${escapeHtml(r.summary || "")}</div></td>
  <td>${transportBadge(r.transport)}</td>
  <td><div class="badge-row">${rowSignalsHtml(r)}</div></td>
</tr>`;
    })
    .join("");
}

function renderCards(slice) {
  return slice
    .map((r) => {
      const href = serverPageHref(r.id);
      const inactive = isInactiveRow(r);
      return `<button type="button" class="server-card${inactive ? " inactive" : ""}" data-href="${escapeHtml(href)}">
  <div class="card-title">${escapeHtml(r.title)}</div>
  <div class="card-id">${escapeHtml(r.id)}</div>
  <div class="badge-row">${transportBadge(r.transport)} ${rowSignalsHtml(r)}</div>
  <div class="card-sum">${escapeHtml(r.summary || "")}</div>
</button>`;
    })
    .join("");
}

function bindNavClicks(root) {
  root?.querySelectorAll("[data-href]").forEach((el) => {
    el.addEventListener("click", () => {
      const h = el.getAttribute("data-href");
      if (h) location.href = h;
    });
  });
}

function updatePager(page, totalPages, totalFiltered) {
  const top = document.getElementById("pager-top");
  const bot = document.getElementById("pager");
  for (const pager of [top, bot]) {
    if (!pager) continue;
    if (totalFiltered === 0) {
      pager.hidden = true;
      continue;
    }
    // Always show pager chrome once we have results (even 1 page)
    pager.hidden = false;
    const info = pager.querySelector(".pager-info");
    const prev = pager.querySelector(".page-prev");
    const next = pager.querySelector(".page-next");
    const jump = pager.querySelector(".page-jump-input");
    if (info) {
      info.textContent =
        totalPages <= 1
          ? `${totalFiltered} result${totalFiltered === 1 ? "" : "s"}`
          : `Page ${page} / ${totalPages}`;
    }
    if (prev) prev.disabled = page <= 1 || totalPages <= 1;
    if (next) next.disabled = page >= totalPages || totalPages <= 1;
    if (jump) {
      jump.max = String(Math.max(1, totalPages));
      jump.value = String(page);
      jump.disabled = totalPages <= 1;
    }
  }
}

function setSkeleton(on) {
  document.getElementById("skeleton")?.classList.toggle("hidden", !on);
}

function renderHome() {
  const tbody = document.getElementById("rows");
  const cardGrid = document.getElementById("card-grid");
  const empty = document.getElementById("empty");
  const status = document.getElementById("status");
  const resultCount = document.getElementById("result-count");
  const loadBar = document.getElementById("load-bar");
  const q = document.getElementById("q");

  const state = {
    page: 1,
    queryId: 0,
    loaded: false,
    corpus: 0,
    inactiveTotal: 0,
    debounce: null,
  };

  applyFiltersFromUrl(state);
  setSkeleton(true);

  // Classic worker (no imports) — works on GitHub Pages
  const worker = new Worker(workerUrl());

  worker.onmessage = (ev) => {
    const msg = ev.data || {};
    if (msg.type === "progress") {
      state.corpus = msg.total;
      state.inactiveTotal = msg.inactiveTotal;
      state.loaded = Boolean(msg.loaded);
      if (loadBar) {
        loadBar.classList.toggle("hidden", state.loaded);
        loadBar.textContent = state.loaded
          ? ""
          : `Loading catalog index… ${msg.total.toLocaleString()} rows`;
      }
      if (status && !state.loaded) {
        status.textContent = `Indexed ${msg.total.toLocaleString()}…`;
      }
      // refresh current page as more data arrives
      scheduleQuery({ immediate: false });
      return;
    }
    if (msg.type === "result") {
      if (msg.id !== state.queryId) return;
      applyResult(msg);
    }
  };

  worker.onerror = (err) => {
    console.error(err);
    if (status) status.textContent = "Search worker failed — see console";
  };

  function applyResult(msg) {
    setSkeleton(false);
    const f = readFiltersFromDom();
    setViewMode(f.view);
    state.page = msg.page;
    writeFiltersToUrl(f, msg.page);

    if (resultCount) {
      const start = msg.total === 0 ? 0 : (msg.page - 1) * msg.pageSize + 1;
      const end = Math.min(msg.page * msg.pageSize, msg.total);
      const range =
        msg.total === 0 ? "0 results" : `${start}–${end} of ${msg.total}`;
      const bits = [range];
      if (msg.inactiveHidden)
        bits.push(`${msg.inactiveHidden} inactive hidden`);
      if (!msg.loaded && msg.corpus)
        bits.push(`index ${msg.corpus.toLocaleString()}`);
      resultCount.textContent = bits.join(" · ");
    }

    if (!msg.total) {
      if (tbody) tbody.innerHTML = "";
      if (cardGrid) cardGrid.innerHTML = "";
      empty?.classList.remove("hidden");
      if (empty) {
        empty.textContent = f.hideInactive
          ? "No servers match. Try clearing filters or show inactive."
          : "No servers match.";
      }
      updatePager(1, 1, 0);
      return;
    }
    empty?.classList.add("hidden");

    if (f.view === "cards") {
      if (tbody) tbody.innerHTML = "";
      if (cardGrid) {
        cardGrid.innerHTML = renderCards(msg.rows);
        bindNavClicks(cardGrid);
      }
    } else {
      if (cardGrid) cardGrid.innerHTML = "";
      if (tbody) {
        tbody.innerHTML = renderListRows(msg.rows);
        bindNavClicks(tbody);
      }
    }
    updatePager(msg.page, msg.totalPages, msg.total);
  }

  function runQuery(opts = {}) {
    if (opts.resetPage) state.page = 1;
    const f = readFiltersFromDom();
    state.queryId += 1;
    worker.postMessage({
      type: "query",
      id: state.queryId,
      filters: f,
      page: state.page,
      pageSize: f.pageSize,
      loaded: state.loaded,
    });
  }

  function scheduleQuery(opts = {}) {
    if (opts.immediate) {
      if (state.debounce) clearTimeout(state.debounce);
      runQuery(opts);
      return;
    }
    if (state.debounce) clearTimeout(state.debounce);
    state.debounce = setTimeout(() => runQuery(opts), 220);
  }

  async function loadBrowseShards() {
    worker.postMessage({ type: "reset" });
    const manifestUrl = catalogUrl("browse/manifest.json");
    let manifest;
    try {
      const res = await fetch(manifestUrl);
      if (!res.ok) throw new Error(`manifest HTTP ${res.status}`);
      manifest = await res.json();
    } catch (err) {
      // Fallback: monolithic index (dev / old deploys)
      if (status)
        status.textContent = `Browse shards missing — falling back to index.json (${err.message})`;
      await loadMonolithFallback();
      return;
    }

    if (status) {
      status.textContent = `${manifest.total?.toLocaleString?.() || manifest.total} servers · ${manifest.inactive || 0} inactive · loading…`;
    }
    if (loadBar) {
      loadBar.classList.remove("hidden");
      loadBar.textContent = `Loading catalog index… 0/${manifest.shardCount} shards`;
    }

    const shards = manifest.shards || [];
    // First shard ASAP for first paint
    for (let i = 0; i < shards.length; i++) {
      const name = shards[i];
      const res = await fetch(catalogUrl(`browse/${name}`));
      if (!res.ok) continue;
      const rows = await res.json();
      const done = i === shards.length - 1;
      worker.postMessage({ type: "add", rows, done });
      if (loadBar) {
        loadBar.textContent = done
          ? ""
          : `Loading catalog index… ${i + 1}/${shards.length} shards`;
        if (done) loadBar.classList.add("hidden");
      }
      if (i === 0) {
        // first interactive results
        scheduleQuery({ immediate: true, resetPage: true });
      }
      // yield to UI between shards
      await new Promise((r) => setTimeout(r, 0));
    }
    state.loaded = true;
    const meta = await loadMeta();
    const parts = [
      `${(manifest.total || 0).toLocaleString()} servers`,
    ];
    if (manifest.inactive) parts.push(`${manifest.inactive} inactive`);
    if (meta?.counts?.withReadme != null)
      parts.push(`${meta.counts.withReadme} readme`);
    if (meta?.counts?.withTools != null)
      parts.push(`${meta.counts.withTools} tools`);
    if (meta?.syncedAt) parts.push(`synced ${meta.syncedAt}`);
    if (status) status.textContent = parts.join(" · ");
    scheduleQuery({ immediate: true });
  }

  async function loadMonolithFallback() {
    try {
      const res = await fetch(catalogUrl("index.json"));
      if (!res.ok) throw new Error(`index HTTP ${res.status}`);
      const index = await res.json();
      const rows = (index.entries || []).map((r) => ({
        ...r,
        remote: Boolean(r.endpointUrl) || (r.flags || []).includes("remote"),
        summary: (r.summary || "").slice(0, 100),
      }));
      worker.postMessage({ type: "add", rows, done: true });
      state.loaded = true;
      setSkeleton(false);
      scheduleQuery({ immediate: true, resetPage: true });
      if (status) status.textContent = `${rows.length} servers (legacy index)`;
    } catch (err) {
      setSkeleton(false);
      empty?.classList.remove("hidden");
      if (empty)
        empty.innerHTML = `No catalog browse data. Publish <code class="mono">catalog/browse</code> via factory.<br/><span class="dim">${escapeHtml(err.message)}</span>`;
      if (status) status.textContent = "Catalog unavailable";
    }
  }

  // controls
  q?.addEventListener("input", () =>
    scheduleQuery({ resetPage: true }),
  );
  [
    "f-hide-inactive",
    "f-transport",
    "f-flag",
    "f-tools",
    "f-only-remote",
    "f-only-active-status",
    "f-page-size",
  ].forEach((id) => {
    document.getElementById(id)?.addEventListener("change", () =>
      scheduleQuery({ immediate: true, resetPage: true }),
    );
  });

  document.getElementById("view-list")?.addEventListener("click", () => {
    setViewMode("list");
    scheduleQuery({ immediate: true });
  });
  document.getElementById("view-cards")?.addEventListener("click", () => {
    setViewMode("cards");
    scheduleQuery({ immediate: true });
  });

  function bindPager(rootId) {
    const root = document.getElementById(rootId);
    if (!root) return;
    root.querySelector(".page-prev")?.addEventListener("click", () => {
      state.page = Math.max(1, state.page - 1);
      scheduleQuery({ immediate: true });
      document
        .getElementById("results-body")
        ?.scrollIntoView({ block: "start", behavior: "smooth" });
    });
    root.querySelector(".page-next")?.addEventListener("click", () => {
      state.page += 1;
      scheduleQuery({ immediate: true });
      document
        .getElementById("results-body")
        ?.scrollIntoView({ block: "start", behavior: "smooth" });
    });
    root.querySelector(".page-go")?.addEventListener("click", () => {
      const jump = Number(
        root.querySelector(".page-jump-input")?.value || 1,
      );
      state.page = Math.max(1, jump || 1);
      scheduleQuery({ immediate: true });
    });
  }
  bindPager("pager-top");
  bindPager("pager");

  document.getElementById("f-reset")?.addEventListener("click", () => {
    if (q) q.value = "";
    const hide = document.getElementById("f-hide-inactive");
    if (hide) hide.checked = true;
    for (const id of ["f-transport", "f-flag", "f-tools"]) {
      const el = document.getElementById(id);
      if (el) el.value = "";
    }
    const onlyRemote = document.getElementById("f-only-remote");
    if (onlyRemote) onlyRemote.checked = false;
    const onlyActive = document.getElementById("f-only-active-status");
    if (onlyActive) onlyActive.checked = false;
    const pageSizeEl = document.getElementById("f-page-size");
    if (pageSizeEl) pageSizeEl.value = String(DEFAULT_PAGE_SIZE);
    setViewMode("list");
    openAdvanced(false);
    state.page = 1;
    scheduleQuery({ immediate: true, resetPage: true });
  });

  document.getElementById("f-adv-toggle")?.addEventListener("click", () => {
    const adv = document.getElementById("f-advanced");
    const open = adv?.classList.contains("hidden");
    openAdvanced(Boolean(open));
  });

  loadBrowseShards();
}

/* —— dossier (unchanged path, still lazy per entry) —— */

function copyConfigSnippet(e) {
  if (
    e.endpointUrl &&
    (e.transport === "streamable-http" || e.transport === "sse")
  ) {
    const name = (e.id.split("/").pop() || e.id).replace(
      /[^a-zA-Z0-9_-]/g,
      "-",
    );
    const headers = {};
    for (const h of e.requiresHeaders || []) {
      headers[h] = `YOUR_${h.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
    }
    for (const h of e.headerDocs || []) {
      if (h.required && h.name)
        headers[h.name] = `YOUR_${h.name.toUpperCase()}`;
    }
    return JSON.stringify(
      {
        mcpServers: {
          [name]: {
            type: "remote",
            url: e.endpointUrl,
            ...(Object.keys(headers).length ? { headers } : {}),
          },
        },
      },
      null,
      2,
    );
  }
  if (e.install?.kind === "npm" && e.install.package) {
    const name = e.id.split("/").pop() || e.id;
    return JSON.stringify(
      {
        mcpServers: {
          [name]: { command: "npx", args: ["-y", e.install.package] },
        },
      },
      null,
      2,
    );
  }
  return JSON.stringify(
    {
      note: "Install via self-hosted mcp-flow gateway",
      id: e.id,
      command: `npx mcp-flow catalog install '${e.id}' --enable`,
    },
    null,
    2,
  );
}

function renderDossier() {
  const root = document.getElementById("dossier");
  if (!root) return;
  const params = new URLSearchParams(location.search);
  const id = params.get("id");
  if (!id) {
    root.innerHTML = `<div class="empty-state">Missing <code>?id=</code></div>`;
    return;
  }
  root.innerHTML = `<p class="status-line">Loading ${escapeHtml(id)}…</p>`;
  loadEntry(id)
    .then((e) => {
      document.title = `${e.title} · mcp-flow catalog`;
      const headerDocs =
        e.headerDocs?.length || e.requiresHeaders?.length
          ? `<div class="panel">
  <div class="panel-head"><span class="title">Headers</span><span class="title" style="color:var(--vault-hot)">names only</span></div>
  <ul class="docs">${(
    e.headerDocs?.length
      ? e.headerDocs
      : (e.requiresHeaders || []).map((name) => ({ name, required: true }))
  )
    .map((h) => {
      const bits = [
        h.required ? "required" : "optional",
        h.secret ? "secret" : "",
      ]
        .filter(Boolean)
        .join(", ");
      const tmpl = h.valueTemplate
        ? `<div class="mono dim" style="margin-top:4px">${escapeHtml(h.valueTemplate)}</div>`
        : "";
      const vars = (h.variables || [])
        .map(
          (v) =>
            `<li><code>{${escapeHtml(v.name)}}</code>${v.secret ? " secret" : ""}${v.description ? ` — ${escapeHtml(v.description)}` : ""}</li>`,
        )
        .join("");
      return `<li><code>${escapeHtml(h.name)}</code> <span class="dim">(${escapeHtml(bits)})</span>${h.description ? ` — ${escapeHtml(h.description)}` : ""}${tmpl}${vars ? `<ul class="sub">${vars}</ul>` : ""}</li>`;
    })
    .join("")}</ul>
</div>`
          : "";

      const packages = e.packages?.length
        ? `<div class="panel">
  <div class="panel-head"><span class="title">Packages</span><span class="title">${e.packages.length}</span></div>
  <ul class="docs">${e.packages
    .map((p) => {
      const envs = (p.environmentVariables || [])
        .map(
          (ev) =>
            `<li><code>${escapeHtml(ev.name)}</code>${ev.secret ? ' <span class="badge seal">secret</span>' : ""}${ev.description ? ` — ${escapeHtml(ev.description)}` : ""}</li>`,
        )
        .join("");
      return `<li><code>${escapeHtml(p.kind)}</code> <span class="mono" style="color:var(--ink)">${escapeHtml(p.package || "")}</span>${p.version ? ` @ ${escapeHtml(p.version)}` : ""}${envs ? `<ul class="sub">${envs}</ul>` : ""}</li>`;
    })
    .join("")}</ul>
</div>`
        : "";

      let tools = "";
      if (e.toolsPreview?.length) {
        tools = `<div class="panel span-2">
  <div class="panel-head"><span class="title">Tools preview</span><span class="title" style="color:var(--phosphor)">${e.toolsPreview.length}</span></div>
  <ul class="docs">${e.toolsPreview
    .map(
      (t) =>
        `<li><code>${escapeHtml(t.name)}</code>${t.description ? ` — ${escapeHtml(t.description)}` : ""}</li>`,
    )
    .join("")}</ul>
</div>`;
      } else {
        const st = e.toolsPreviewStatus || "skipped";
        const kind =
          st === "auth_required"
            ? "seal"
            : st === "unreachable"
              ? "deny"
              : "off";
        tools = `<div class="panel span-2">
  <div class="panel-head"><span class="title">Tools preview</span><span class="badge ${kind}">${escapeHtml(st)}</span></div>
  <div class="panel-pad muted">${e.toolsPreviewError ? escapeHtml(String(e.toolsPreviewError).slice(0, 240)) : "No live tools list."}</div>
</div>`;
      }

      const readme = e.readme?.markdown
        ? `<div class="panel span-2">
  <div class="panel-head"><span class="title">README</span></div>
  <div class="md">${markdownToHtml(e.readme.markdown)}</div>
</div>`
        : "";

      const snippet = copyConfigSnippet(e);
      const flags = (e.flags || [])
        .map((f) => badge(f, f === "remote" ? "place" : "off"))
        .join(" ");

      root.innerHTML = `
<p class="crumb"><a href="${siteHref("/")}">Catalog</a> / server</p>
<div class="dossier-head">
  <p class="eyebrow">Registry entry</p>
  <h1>${escapeHtml(e.title)}</h1>
  <p class="dossier-id">${escapeHtml(e.id)}${e.version ? ` · v${escapeHtml(e.version)}` : ""}</p>
  <div class="badge-row" style="margin-top:12px">
    ${transportBadge(e.transport)}
    ${statusBadges({ status: e.status, sourceRepoStatus: e.sourceRepo?.status, flags: e.flags })}
    ${toolsBadges({ toolsPreviewStatus: e.toolsPreviewStatus, toolsCount: e.toolsPreview?.length })}
    ${e.readme?.markdown ? badge("readme", "on") : ""}
    ${flags}
  </div>
  ${
    e.sourceRepo?.status === "not_found"
      ? `<p class="lede" style="color:var(--deny);margin-top:12px">Source repository offline${e.sourceRepo.url ? ` — ${escapeHtml(e.sourceRepo.url)}` : ""}. Marked <strong>inactive</strong>.</p>`
      : ""
  }
  <p class="lede" style="max-width:52ch;margin-top:16px">${escapeHtml(e.description || e.summary || "")}</p>
</div>
<div class="dossier-grid">
  <div class="panel">
    <div class="panel-head"><span class="title">Connect</span></div>
    <div class="kv">
      <span class="k">transport</span><span class="v">${escapeHtml(e.transport)}</span>
      <span class="k">endpoint</span><span class="v">${e.endpointUrl ? escapeHtml(e.endpointUrl) : "—"}</span>
      <span class="k">source</span><span class="v">${e.sourceUrl ? `<a href="${escapeHtml(e.sourceUrl)}" rel="noopener noreferrer">${escapeHtml(e.sourceUrl)}</a>` : "—"}</span>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><span class="title">Install · mcp-flow</span></div>
    <div class="panel-pad">
      <div class="codeblock">npx mcp-flow catalog install '${escapeHtml(e.id)}' --enable</div>
      <div class="codeblock" id="cfg" style="margin-top:10px">${escapeHtml(snippet)}</div>
      <button type="button" class="pill-btn" data-copy="cfg">Copy JSON</button>
    </div>
  </div>
  ${packages}
  ${headerDocs}
  ${tools}
  ${readme}
</div>`;

      root.querySelector("[data-copy]")?.addEventListener("click", async (ev) => {
        const btn = ev.currentTarget;
        const el = document.getElementById("cfg");
        try {
          await navigator.clipboard.writeText(el?.innerText || "");
          btn.textContent = "Copied";
          setTimeout(() => {
            btn.textContent = "Copy JSON";
          }, 1200);
        } catch {
          btn.textContent = "Copy failed";
        }
      });
    })
    .catch((err) => {
      root.innerHTML = `<div class="empty-state">Failed to load entry.<br/><span class="dim">${escapeHtml(err.message)}</span></div>`;
    });
}

function wireChrome() {
  document.querySelectorAll("[data-site-href]").forEach((a) => {
    const p = a.getAttribute("data-site-href") || "/";
    a.setAttribute("href", siteHref(p));
  });
  const repo = cfg().repo;
  document.querySelectorAll("[data-repo]").forEach((a) => {
    a.setAttribute("href", repo);
  });
}

wireChrome();
if (document.body.dataset.page === "home") renderHome();
if (document.body.dataset.page === "server") renderDossier();
