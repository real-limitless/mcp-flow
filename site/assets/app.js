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
  const cat = (cfg().catalogBase || "catalog").replace(/^\//, "").replace(/\/$/, "");
  const r = rel.replace(/^\//, "");
  return `${base}/${cat}/${r}`.replace(/([^:]\/)\/+/g, "$1");
}

/** Match src/catalog/shard entryFilename (without .json) */
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
  return badge("tools ?", "off");
}

export function statusBadges(row) {
  const bits = [];
  if (row.status === "inactive" || row.sourceRepoStatus === "not_found" || (row.flags || []).includes("repo-offline")) {
    bits.push(badge("inactive", "deny"));
    bits.push(badge("repo offline", "deny"));
  } else if (row.status === "deprecated") {
    bits.push(badge("deprecated", "warn"));
  } else if (row.status === "active") {
    bits.push(badge("active", "on"));
  } else if (row.status) {
    bits.push(badge(row.status, "off"));
  }
  return bits.join(" ");
}

export function transportBadge(t) {
  return badge(t || "unknown", "place");
}

async function loadIndex() {
  const url = catalogUrl("index.json");
  const res = await fetch(url);
  if (!res.ok) throw new Error(`catalog index HTTP ${res.status} (${url})`);
  return res.json();
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

/** Inactive = dead source repo / catalog-marked inactive */
export function isInactiveRow(r) {
  if (!r) return false;
  if (r.status === "inactive" || r.status === "deleted") return true;
  if (r.sourceRepoStatus === "not_found") return true;
  if ((r.flags || []).includes("repo-offline")) return true;
  return false;
}

const PAGE_SIZES = [24, 48, 96];
const DEFAULT_PAGE_SIZE = 48;

function readFiltersFromDom() {
  const psRaw = Number(document.getElementById("f-page-size")?.value || DEFAULT_PAGE_SIZE);
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
  // default hide inactive unless showInactive=1
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

  const view = sp.get("view") === "cards" ? "cards" : "list";
  setViewMode(view);

  if (
    sp.get("showInactive") === "1" ||
    sp.get("remote") === "1" ||
    sp.get("activeOnly") === "1" ||
    sp.get("flag") ||
    sp.get("tools")
  ) {
    const adv = document.getElementById("f-advanced");
    const tog = document.getElementById("f-adv-toggle");
    if (adv) adv.classList.remove("hidden");
    if (tog) tog.setAttribute("aria-expanded", "true");
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
  const next = `${location.pathname}${qs ? `?${qs}` : ""}${location.hash || ""}`;
  history.replaceState(null, "", next);
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

function updatePager(pager, page, totalPages, totalFiltered) {
  if (!pager) return;
  if (totalFiltered === 0 || totalPages <= 1) {
    pager.hidden = true;
    return;
  }
  pager.hidden = false;
  const info = document.getElementById("page-info");
  const prev = document.getElementById("page-prev");
  const next = document.getElementById("page-next");
  const jump = document.getElementById("page-jump");
  if (info) info.textContent = `Page ${page} / ${totalPages}`;
  if (prev) prev.disabled = page <= 1;
  if (next) next.disabled = page >= totalPages;
  if (jump) {
    jump.max = String(totalPages);
    jump.value = String(page);
  }
}

function filterRows(rows, f) {
  return rows.filter((r) => {
    if (f.hideInactive && isInactiveRow(r)) return false;
    if (f.onlyActiveStatus && r.status && r.status !== "active") return false;
    if (f.onlyRemote && !r.endpointUrl && !(r.flags || []).includes("remote"))
      return false;
    if (f.transport && r.transport !== f.transport) return false;
    if (f.flag && !(r.flags || []).includes(f.flag)) return false;
    if (f.tools === "ok" && r.toolsPreviewStatus !== "ok") return false;
    if (f.tools === "auth_required" && r.toolsPreviewStatus !== "auth_required")
      return false;
    if (f.tools === "unreachable" && r.toolsPreviewStatus !== "unreachable")
      return false;
    if (f.tools === "unsupported" && r.toolsPreviewStatus !== "unsupported")
      return false;
    if (f.tools === "has" && !(r.toolsCount > 0 || r.hasToolsPreview))
      return false;
    if (f.tools === "readme" && !r.hasReadme) return false;
    if (f.q) {
      const hay = [
        r.id,
        r.title,
        r.summary,
        r.transport,
        r.status,
        ...(r.flags || []),
      ]
        .join(" ")
        .toLowerCase();
      if (!hay.includes(f.q)) return false;
    }
    return true;
  });
}

function renderHome() {
  const tbody = document.getElementById("rows");
  const cardGrid = document.getElementById("card-grid");
  const empty = document.getElementById("empty");
  const status = document.getElementById("status");
  const resultCount = document.getElementById("result-count");
  const pager = document.getElementById("pager");
  const q = document.getElementById("q");
  if (!tbody && !cardGrid) return;

  let rows = [];
  let inactiveTotal = 0;
  const state = { page: 1 };

  applyFiltersFromUrl(state);

  const paint = (opts = {}) => {
    if (opts.resetPage) state.page = 1;
    const f = readFiltersFromDom();
    setViewMode(f.view);
    const filtered = filterRows(rows, f);
    const totalPages = Math.max(1, Math.ceil(filtered.length / f.pageSize) || 1);
    if (state.page > totalPages) state.page = totalPages;
    if (state.page < 1) state.page = 1;

    writeFiltersToUrl(f, state.page);

    if (resultCount) {
      const hidden = f.hideInactive ? inactiveTotal : 0;
      const start =
        filtered.length === 0 ? 0 : (state.page - 1) * f.pageSize + 1;
      const end = Math.min(state.page * f.pageSize, filtered.length);
      const range =
        filtered.length === 0 ? "0" : `${start}–${end} of ${filtered.length}`;
      resultCount.textContent =
        hidden > 0
          ? `${range} · ${hidden} inactive hidden`
          : range;
    }

    if (!filtered.length) {
      if (tbody) tbody.innerHTML = "";
      if (cardGrid) cardGrid.innerHTML = "";
      empty?.classList.remove("hidden");
      if (empty) {
        empty.textContent = f.hideInactive
          ? "No servers match. Try clearing filters or show inactive."
          : "No servers match.";
      }
      updatePager(pager, 1, 1, 0);
      return;
    }
    empty?.classList.add("hidden");

    const startIdx = (state.page - 1) * f.pageSize;
    const slice = filtered.slice(startIdx, startIdx + f.pageSize);

    if (f.view === "cards") {
      if (tbody) tbody.innerHTML = "";
      if (cardGrid) {
        cardGrid.innerHTML = renderCards(slice);
        bindNavClicks(cardGrid);
      }
    } else {
      if (cardGrid) cardGrid.innerHTML = "";
      if (tbody) {
        tbody.innerHTML = renderListRows(slice);
        bindNavClicks(tbody);
      }
    }

    updatePager(pager, state.page, totalPages, filtered.length);
  };

  Promise.all([loadIndex(), loadMeta()])
    .then(([index, meta]) => {
      rows = index.entries || [];
      inactiveTotal = rows.filter(isInactiveRow).length;
      const parts = [`${rows.length} servers`];
      if (inactiveTotal) parts.push(`${inactiveTotal} inactive`);
      if (meta?.counts?.withReadme != null)
        parts.push(`${meta.counts.withReadme} readme`);
      if (meta?.counts?.withTools != null)
        parts.push(`${meta.counts.withTools} tools`);
      if (meta?.syncedAt) parts.push(`synced ${meta.syncedAt}`);
      if (status) status.textContent = parts.join(" · ");
      paint();
    })
    .catch((err) => {
      if (status)
        status.textContent = `Failed to load catalog: ${err.message}`;
      empty?.classList.remove("hidden");
      if (empty)
        empty.innerHTML = `No catalog data. Run <code class="mono">catalog sync</code> / factory, or deploy with <code class="mono">catalog-data</code> branch.<br/><span class="dim">${escapeHtml(String(err.message))}</span>`;
    });

  const onFilter = () => paint({ resetPage: true });
  q?.addEventListener("input", onFilter);
  [
    "f-hide-inactive",
    "f-transport",
    "f-flag",
    "f-tools",
    "f-only-remote",
    "f-only-active-status",
    "f-page-size",
  ].forEach((id) => {
    document.getElementById(id)?.addEventListener("change", onFilter);
  });

  document.getElementById("view-list")?.addEventListener("click", () => {
    setViewMode("list");
    paint();
  });
  document.getElementById("view-cards")?.addEventListener("click", () => {
    setViewMode("cards");
    paint();
  });

  document.getElementById("page-prev")?.addEventListener("click", () => {
    state.page = Math.max(1, state.page - 1);
    paint();
    document.getElementById("results-body")?.scrollIntoView({ block: "start" });
  });
  document.getElementById("page-next")?.addEventListener("click", () => {
    state.page += 1;
    paint();
    document.getElementById("results-body")?.scrollIntoView({ block: "start" });
  });
  document.getElementById("page-go")?.addEventListener("click", () => {
    const jump = Number(document.getElementById("page-jump")?.value || 1);
    state.page = Math.max(1, jump || 1);
    paint();
  });
  document.getElementById("page-jump")?.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      const jump = Number(ev.target.value || 1);
      state.page = Math.max(1, jump || 1);
      paint();
    }
  });

  document.getElementById("f-reset")?.addEventListener("click", () => {
    if (q) q.value = "";
    const hide = document.getElementById("f-hide-inactive");
    if (hide) hide.checked = true;
    const transport = document.getElementById("f-transport");
    if (transport) transport.value = "";
    const flag = document.getElementById("f-flag");
    if (flag) flag.value = "";
    const tools = document.getElementById("f-tools");
    if (tools) tools.value = "";
    const onlyRemote = document.getElementById("f-only-remote");
    if (onlyRemote) onlyRemote.checked = false;
    const onlyActive = document.getElementById("f-only-active-status");
    if (onlyActive) onlyActive.checked = false;
    const pageSizeEl = document.getElementById("f-page-size");
    if (pageSizeEl) pageSizeEl.value = String(DEFAULT_PAGE_SIZE);
    setViewMode("list");
    state.page = 1;
    paint({ resetPage: true });
  });

  document.getElementById("f-adv-toggle")?.addEventListener("click", () => {
    const adv = document.getElementById("f-advanced");
    const tog = document.getElementById("f-adv-toggle");
    if (!adv) return;
    const open = adv.classList.toggle("hidden") === false;
    tog?.setAttribute("aria-expanded", open ? "true" : "false");
  });
}

function copyConfigSnippet(e) {
  if (
    e.endpointUrl &&
    (e.transport === "streamable-http" || e.transport === "sse")
  ) {
    const name = (e.id.split("/").pop() || e.id).replace(/[^a-zA-Z0-9_-]/g, "-");
    const headers = {};
    for (const h of e.requiresHeaders || []) {
      headers[h] = `YOUR_${h.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
    }
    for (const h of e.headerDocs || []) {
      if (h.required && h.name) headers[h.name] = `YOUR_${h.name.toUpperCase()}`;
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
          [name]: {
            command: "npx",
            args: ["-y", e.install.package],
          },
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
  <div class="panel-pad muted" style="border-top:1px solid var(--rail)">Templates and names only — secrets stay in the gateway vault.</div>
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
      return `<li><code>${escapeHtml(p.kind)}</code> <span class="mono" style="color:var(--ink)">${escapeHtml(p.package || "")}</span>${p.version ? ` @ ${escapeHtml(p.version)}` : ""}${p.transport ? ` · ${escapeHtml(p.transport)}` : ""}${envs ? `<ul class="sub">${envs}</ul>` : ""}</li>`;
    })
    .join("")}</ul>
</div>`
        : "";

      let tools = "";
      if (e.toolsPreview?.length) {
        tools = `<div class="panel span-2">
  <div class="panel-head"><span class="title">Tools preview</span><span class="title" style="color:var(--phosphor)">${e.toolsPreview.length} · live</span></div>
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
  <div class="panel-pad muted">${e.toolsPreviewError ? escapeHtml(e.toolsPreviewError.slice(0, 240)) : "Live tools/list when remote is reachable without secrets."}</div>
</div>`;
      }

      const readme = e.readme?.markdown
        ? `<div class="panel span-2">
  <div class="panel-head"><span class="title">README</span>${e.readme.url ? `<a class="title" href="${escapeHtml(e.readme.url)}" rel="noopener noreferrer">source</a>` : ""}</div>
  <div class="md">${markdownToHtml(e.readme.markdown)}</div>
</div>`
        : e.readme?.error
          ? `<div class="panel span-2"><div class="panel-head"><span class="title">README</span></div><div class="panel-pad muted">${escapeHtml(e.readme.error)}</div></div>`
          : "";

      const snippet = copyConfigSnippet(e);
      const flags = (e.flags || [])
        .map((f) => badge(f, f === "remote" ? "place" : "off"))
        .join(" ");

      root.innerHTML = `
<p class="crumb"><a href="${siteHref("/")}">Catalog</a> / server</p>
<div class="dossier-head">
  <p class="eyebrow">Registry entry · ${escapeHtml(e.provenance || "official-registry")}</p>
  <h1>${escapeHtml(e.title)}</h1>
  <p class="dossier-id">${escapeHtml(e.id)}${e.version ? ` · v${escapeHtml(e.version)}` : ""}</p>
  <div class="badge-row" style="margin-top:12px">
    ${transportBadge(e.transport)}
    ${statusBadges({ status: e.status, sourceRepoStatus: e.sourceRepo?.status, flags: e.flags })}
    ${toolsBadges({ toolsPreviewStatus: e.toolsPreviewStatus, toolsCount: e.toolsPreview?.length, hasToolsPreview: !!e.toolsPreview?.length })}
    ${e.readme?.markdown ? badge("readme", "on") : ""}
    ${flags}
  </div>
  ${
    e.sourceRepo?.status === "not_found"
      ? `<p class="lede" style="color:var(--deny);margin-top:12px">Source repository is offline (HTTP ${e.sourceRepo.httpStatus ?? 404})${e.sourceRepo.url ? ` — ${escapeHtml(e.sourceRepo.url)}` : ""}. Marked <strong>inactive</strong>.</p>`
      : ""
  }
  <p class="lede" style="max-width:52ch;margin-top:16px">${escapeHtml(e.description || e.summary || "")}</p>
</div>
<div class="dossier-grid">
  <div class="panel">
    <div class="panel-head"><span class="title">Connect</span><span class="title" style="color:var(--phosphor)">public metadata</span></div>
    <div class="kv">
      <span class="k">transport</span><span class="v">${escapeHtml(e.transport)}</span>
      <span class="k">endpoint</span><span class="v">${e.endpointUrl ? escapeHtml(e.endpointUrl) : "—"}</span>
      <span class="k">homepage</span><span class="v">${e.homepage ? `<a href="${escapeHtml(e.homepage)}" rel="noopener noreferrer">${escapeHtml(e.homepage)}</a>` : "—"}</span>
      <span class="k">source</span><span class="v">${e.sourceUrl ? `<a href="${escapeHtml(e.sourceUrl)}" rel="noopener noreferrer">${escapeHtml(e.sourceUrl)}</a>` : "—"}</span>
      <span class="k">install</span><span class="v">${e.install?.package ? `${escapeHtml(e.install.kind)}:${escapeHtml(e.install.package)}${e.install.version ? `@${escapeHtml(e.install.version)}` : ""}` : "—"}</span>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><span class="title">Install · mcp-flow</span><span class="title vault" style="color:var(--vault-hot)">sealed path</span></div>
    <div class="panel-pad">
      <p class="muted" style="margin-bottom:10px">Prefer the gateway so harnesses never see upstream secrets:</p>
      <div class="codeblock">npx mcp-flow catalog install '${escapeHtml(e.id)}' --enable</div>
      <p class="muted" style="margin:14px 0 8px">Harness snippet (direct — fill your own secrets):</p>
      <div class="codeblock" id="cfg">${escapeHtml(snippet)}</div>
      <button type="button" class="btn" data-copy="cfg">Copy JSON</button>
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
