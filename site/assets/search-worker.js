/**
 * Browse filter/paginate off the main thread.
 * Messages:
 *   { type: 'reset' }
 *   { type: 'add', rows: BrowseRow[] }
 *   { type: 'query', id, filters, page, pageSize }
 * → { type: 'result', id, total, inactiveHidden, page, pageSize, totalPages, rows }
 */

function isInactive(r) {
  if (!r) return false;
  if (r.status === "inactive" || r.status === "deleted") return true;
  if (r.sourceRepoStatus === "not_found") return true;
  if ((r.flags || []).includes("repo-offline")) return true;
  return false;
}

/** @type {object[]} */
let all = [];
let inactiveTotal = 0;

function filterRows(rows, f) {
  const q = (f.q || "").trim().toLowerCase();
  const out = [];
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (f.hideInactive && isInactive(r)) continue;
    if (f.onlyActiveStatus && r.status && r.status !== "active") continue;
    if (f.onlyRemote && !r.remote && !(r.flags || []).includes("remote"))
      continue;
    if (f.transport && r.transport !== f.transport) continue;
    if (f.flag && !(r.flags || []).includes(f.flag)) continue;
    if (f.tools === "ok" && r.toolsPreviewStatus !== "ok") continue;
    if (f.tools === "auth_required" && r.toolsPreviewStatus !== "auth_required")
      continue;
    if (f.tools === "unreachable" && r.toolsPreviewStatus !== "unreachable")
      continue;
    if (f.tools === "unsupported" && r.toolsPreviewStatus !== "unsupported")
      continue;
    if (f.tools === "has" && !(r.toolsCount > 0)) continue;
    if (f.tools === "readme" && !r.hasReadme) continue;
    if (q) {
      const hay = `${r.id} ${r.title} ${r.summary || ""} ${r.transport} ${r.status || ""} ${(r.flags || []).join(" ")}`.toLowerCase();
      if (!hay.includes(q)) continue;
    }
    out.push(r);
  }
  return out;
}

self.onmessage = (ev) => {
  const msg = ev.data || {};
  if (msg.type === "reset") {
    all = [];
    inactiveTotal = 0;
    self.postMessage({ type: 'ready', total: 0, inactiveTotal: 0, loaded: true });
    return;
  }
  if (msg.type === "add" && Array.isArray(msg.rows)) {
    for (const r of msg.rows) {
      all.push(r);
      if (isInactive(r)) inactiveTotal++;
    }
    self.postMessage({
      type: "progress",
      total: all.length,
      inactiveTotal,
      loaded: Boolean(msg.done),
    });
    return;
  }
  if (msg.type === "query") {
    const f = msg.filters || {};
    const pageSize = Math.max(1, Number(msg.pageSize) || 48);
    let page = Math.max(1, Number(msg.page) || 1);
    const filtered = filterRows(all, f);
    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize) || 1);
    if (page > totalPages) page = totalPages;
    const start = (page - 1) * pageSize;
    const rows = filtered.slice(start, start + pageSize);
    self.postMessage({
      type: "result",
      id: msg.id,
      total: filtered.length,
      corpus: all.length,
      inactiveTotal,
      inactiveHidden: f.hideInactive ? inactiveTotal : 0,
      page,
      pageSize,
      totalPages,
      rows,
      loaded: Boolean(msg.loaded),
    });
  }
};
