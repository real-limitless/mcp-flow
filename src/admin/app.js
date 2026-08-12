const $ = (s) => document.querySelector(s);
const errEl = $("#err");
const TOKEN_KEY = "mcp_flow_admin_token";

function token() {
  return sessionStorage.getItem(TOKEN_KEY) || "";
}

function setToken(t) {
  sessionStorage.setItem(TOKEN_KEY, t);
}

function showErr(msg) {
  errEl.hidden = !msg;
  errEl.textContent = msg || "";
}

async function api(path, opts = {}) {
  const t = token();
  if (!t) throw new Error("Set admin token first");
  const res = await fetch(path, {
    ...opts,
    headers: {
      Authorization: `Bearer ${t}`,
      "Content-Type": "application/json",
      ...(opts.headers || {}),
    },
  });
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = { raw: text };
  }
  if (!res.ok) {
    throw new Error(body.error || res.statusText || String(res.status));
  }
  return body;
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function surface(title, bodyHtml, rightTitle = "") {
  return `
    <div class="surface">
      <div class="panel-head">
        <span class="title">${esc(title)}</span>
        ${rightTitle ? `<span class="title mute">${esc(rightTitle)}</span>` : ""}
      </div>
      <div class="panel-pad">${bodyHtml}</div>
    </div>`;
}

async function renderStatus() {
  const { workspace, placementModes } = await api("/v1/workspace");
  const health = await fetch("/health").then((r) => r.json());
  const bare = !!workspace?.policy?.allowEdgeBare;
  const ok = health?.ok !== false;
  $("#tab-status").innerHTML = `
    ${surface(
      "Workspace",
      `
      <div class="stat-grid">
        <div class="stat">
          <span class="label">Name</span>
          <span class="value">${esc(workspace?.name)}</span>
        </div>
        <div class="stat">
          <span class="label">Workspace id</span>
          <span class="value mono">${esc(workspace?.id)}</span>
        </div>
        <div class="stat">
          <span class="label">Edge-bare</span>
          <span class="value"><span class="pill ${bare ? "on" : "off"}">${bare ? "allowed" : "denied"}</span></span>
        </div>
        <div class="stat">
          <span class="label">Health</span>
          <span class="value"><span class="pill ${ok ? "on" : "deny"}">${ok ? "ok" : "degraded"}</span></span>
        </div>
      </div>
      <div class="row-actions" style="margin-top:14px">
        <label class="form-check">
          <input type="checkbox" id="barePolicy" ${bare ? "checked" : ""}/>
          <span>Allow edge-bare</span>
        </label>
        <button type="button" id="savePolicy" class="pill-btn primary">Save policy</button>
      </div>
    `,
      "policy",
    )}
    ${surface(
      "Gateway",
      `
      <div class="kv">
        <div class="kv-row">
          <span class="k">Placement</span>
          <span class="v mono">${esc((placementModes || []).join(" · ") || "—")}</span>
        </div>
        <div class="kv-row">
          <span class="k">Service</span>
          <span class="v mono">${esc(health?.service || "mcp-flow")}</span>
        </div>
      </div>
      <details class="fold">
        <summary>Raw /health</summary>
        <pre>${esc(JSON.stringify(health, null, 2))}</pre>
      </details>
    `,
      "live",
    )}`;
  $("#savePolicy")?.addEventListener("click", async () => {
    try {
      await api("/v1/workspace/policy", {
        method: "PATCH",
        body: JSON.stringify({ allowEdgeBare: $("#barePolicy").checked }),
      });
      await refresh();
    } catch (e) {
      showErr(e.message);
    }
  });
}

async function renderKeys() {
  const { keys } = await api("/v1/keys");
  $("#tab-keys").innerHTML = `
    ${surface(
      "Create key",
      `
      <p class="muted" style="margin-bottom:12px">
        Agent keys use <span class="mono">/mcp</span>. Operator keys get <span class="mono">mf_admin_*</span> tools and can call <span class="mono">/v1/*</span>.
      </p>
      <div class="form-grid">
        <div class="form-field">
          <label class="field-label" for="keyName">Name</label>
          <input id="keyName" placeholder="default" />
        </div>
        <div class="form-field">
          <label class="field-label" for="keyScope">Scope prefix</label>
          <input id="keyScope" placeholder="e.g. demo__ (optional)" />
        </div>
        <div class="form-field">
          <span class="field-label">Role</span>
          <label class="form-check">
            <input type="checkbox" id="keyAdmin" />
            <span>Operator (admin MCP)</span>
          </label>
        </div>
        <div class="form-field">
          <span class="field-label">&nbsp;</span>
          <button type="button" id="createKey" class="pill-btn primary">Create</button>
        </div>
      </div>
      <div id="keyOnce" class="once-callout" hidden>
        <div class="once-label">Token · shown once</div>
        <pre id="keyOnceText"></pre>
      </div>
    `,
      "mf_*",
    )}
    ${surface(
      "Keys",
      `
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>name</th><th>prefix</th><th>role</th><th>scopes</th><th></th></tr></thead>
          <tbody>
            ${
              keys.length
                ? keys
                    .map(
                      (k) => `<tr>
              <td>${esc(k.name)}</td>
              <td class="mono">${esc(k.prefix)}</td>
              <td>${k.scopes?.admin ? '<span class="pill vault">operator</span>' : '<span class="pill off">agent</span>'}</td>
              <td class="mono">${esc(JSON.stringify(k.scopes))}</td>
              <td class="row-actions">
                <button type="button" class="pill-btn danger" data-revoke="${esc(k.id)}">Revoke</button>
              </td>
            </tr>`,
                    )
                    .join("")
                : `<tr><td colspan="5" class="muted">No keys yet</td></tr>`
            }
          </tbody>
        </table>
      </div>
    `,
      `${keys.length} total`,
    )}`;
  $("#createKey")?.addEventListener("click", async () => {
    try {
      const name = $("#keyName").value.trim() || "default";
      const scope = $("#keyScope").value.trim();
      const body = { name };
      if (scope) body.toolPrefixAllowlist = [scope];
      if ($("#keyAdmin")?.checked) body.admin = true;
      const res = await api("/v1/keys", { method: "POST", body: JSON.stringify(body) });
      const onceToken = res.key.token;
      await renderKeys();
      const box = $("#keyOnce");
      const text = $("#keyOnceText");
      if (box && text) {
        box.hidden = false;
        text.textContent = onceToken;
      }
    } catch (e) {
      showErr(e.message);
    }
  });
  document.querySelectorAll("[data-revoke]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/v1/keys/${btn.getAttribute("data-revoke")}`, { method: "DELETE" });
        await renderKeys();
      } catch (e) {
        showErr(e.message);
      }
    });
  });
}

function truncateUrl(u, n = 48) {
  const s = String(u ?? "");
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + "…";
}

function backendTargetLabel(b) {
  if (b.url) return b.url;
  if (b.image) return b.image;
  if (b.command?.length) return b.command.join(" ");
  return "—";
}

function collectKvPairs(root, rowSel, nameSel, valueSel) {
  const out = {};
  root.querySelectorAll(rowSel).forEach((row) => {
    const name = row.querySelector(nameSel)?.value?.trim();
    const value = row.querySelector(valueSel)?.value ?? "";
    if (name) out[name] = value;
  });
  return out;
}

function collectHeaderPairs(root) {
  return collectKvPairs(root, "[data-hdr-row]", "[data-hdr-name]", "[data-hdr-value]");
}

function collectEnvPairs(root) {
  return collectKvPairs(root, "[data-env-row]", "[data-env-name]", "[data-env-value]");
}

function kvRowHtml(kind, name = "", value = "", namePh = "NAME", valuePh = "value") {
  const n = kind === "env" ? "env" : "hdr";
  const type = kind === "env" || kind === "hdr" ? "password" : "text";
  return `
    <div class="hdr-row" data-${n}-row>
      <input data-${n}-name type="text" placeholder="${esc(namePh)}" value="${esc(name)}" autocomplete="off" />
      <input data-${n}-value type="${type}" placeholder="${esc(valuePh)}" value="${esc(value)}" autocomplete="off" />
      <button type="button" class="pill-btn ghost" data-${n}-rm title="Remove">×</button>
    </div>`;
}

function wireKvEditor(container, kind) {
  if (!container) return;
  const n = kind === "env" ? "env" : "hdr";
  const list = container.querySelector(`[data-${n}-list]`);
  const addBtn = container.querySelector(`[data-${n}-add]`);
  const bindRm = (btn) => {
    btn.addEventListener("click", () => btn.closest(`[data-${n}-row]`)?.remove());
  };
  addBtn?.addEventListener("click", () => {
    const ph =
      kind === "env"
        ? kvRowHtml("env", "", "", "ENV_NAME", "value (sealed)")
        : kvRowHtml("hdr", "", "", "Header-Name", "value (sealed)");
    list.insertAdjacentHTML("beforeend", ph);
    list.querySelector(`[data-${n}-row]:last-child [data-${n}-rm]`)?.addEventListener(
      "click",
      (ev) => ev.currentTarget.closest(`[data-${n}-row]`)?.remove(),
    );
  });
  list?.querySelectorAll(`[data-${n}-rm]`).forEach(bindRm);
}

function parseCommandLine(raw) {
  const s = raw.trim();
  if (!s) return [];
  // simple whitespace split; support basic double-quoted tokens
  const out = [];
  let cur = "";
  let q = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (ch === '"') {
      q = !q;
      continue;
    }
    if (!q && /\s/.test(ch)) {
      if (cur) out.push(cur);
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

function syncBackendFormFields() {
  const mode = $("#beMode")?.value || "remote";
  const isRemote = mode === "remote";
  const isEdge = mode === "edge-sandbox" || mode === "edge-bare";
  const localSel = $("#beLocalTransport");
  if (localSel && !isRemote) {
    [...localSel.options].forEach((opt) => {
      if (mode === "edge-bare") {
        opt.disabled = opt.value !== "stdio";
      } else {
        opt.disabled = false;
      }
    });
    if (mode === "edge-bare" && localSel.value !== "stdio") {
      localSel.value = "stdio";
    }
  }
  const transport = isRemote
    ? $("#beTransport")?.value || "streamable-http"
    : localSel?.value || "stdio";
  const isOci = transport === "oci";
  const isStdio = transport === "stdio" || mode === "edge-bare";

  const show = (sel, on) => {
    const el = $(sel);
    if (el) el.hidden = !on;
  };

  show("#beFieldUrl", isRemote);
  show("#beFieldRemoteTransport", isRemote);
  show("#beHdrEditor", isRemote);
  show("#beFieldDevice", isEdge);
  show("#beFieldLocalTransport", !isRemote && mode !== "edge-bare");
  show("#beFieldCommand", !isRemote && isStdio);
  show("#beFieldImage", !isRemote && isOci);
  show("#beEnvEditor", !isRemote);

  const hint = $("#beModeHint");
  if (hint) {
    const hints = {
      remote: "HTTP/SSE upstream. Headers sealed at rest.",
      "central-sandbox": "Spawn stdio/oci on the gateway host.",
      "edge-sandbox": "Run on an enrolled edge device (sandbox cap required).",
      "edge-bare": "Host process on edge — needs allowEdgeBare + device bare.",
    };
    hint.textContent = hints[mode] || "";
  }
}

function backendEndpointCell(b) {
  const label = backendTargetLabel(b);
  return `<td class="mono" title="${esc(label)}">${esc(truncateUrl(label, 40))}</td>`;
}

async function renderBackends() {
  const [{ backends }, devicesRes, wsRes] = await Promise.all([
    api("/v1/backends"),
    api("/v1/devices").catch(() => ({ devices: [] })),
    api("/v1/workspace").catch(() => ({ placementModes: ["remote", "central-sandbox"] })),
  ]);
  const devices = devicesRes.devices || [];
  const modes = wsRes.placementModes || ["remote", "central-sandbox"];
  const modeOpts = ["remote", "central-sandbox", "edge-sandbox", "edge-bare"]
    .filter((m) => modes.includes(m) || m === "remote" || m === "central-sandbox")
    .map((m) => `<option value="${m}">${m}</option>`)
    .join("");

  const deviceOpts =
    devices.length === 0
      ? `<option value="">— enroll a device first —</option>`
      : devices
          .map(
            (d) =>
              `<option value="${esc(d.id)}">${esc(d.name)} (${esc(d.status)}) · ${esc(d.id.slice(0, 8))}…</option>`,
          )
          .join("");

  $("#tab-backends").innerHTML = `
    ${surface(
      "Add backend",
      `
      <p class="muted" id="beModeHint" style="margin-bottom:12px">
        HTTP/SSE upstream. Headers sealed at rest.
      </p>
      <div class="form-grid">
        <div class="form-field">
          <label class="field-label" for="beSlug">Slug</label>
          <input id="beSlug" placeholder="my-server" autocomplete="off" />
        </div>
        <div class="form-field">
          <label class="field-label" for="beMode">Placement</label>
          <select id="beMode">${modeOpts}</select>
        </div>
        <div class="form-field" id="beFieldRemoteTransport">
          <label class="field-label" for="beTransport">Transport</label>
          <select id="beTransport">
            <option value="streamable-http">streamable-http</option>
            <option value="sse">sse</option>
          </select>
        </div>
        <div class="form-field" id="beFieldLocalTransport" hidden>
          <label class="field-label" for="beLocalTransport">Transport</label>
          <select id="beLocalTransport">
            <option value="stdio">stdio</option>
            <option value="oci">oci</option>
          </select>
        </div>
        <div class="form-field" id="beFieldDevice" hidden style="grid-column: span 2">
          <label class="field-label" for="beDevice">Edge device</label>
          <select id="beDevice">${deviceOpts}</select>
        </div>
        <div class="form-field" id="beFieldUrl" style="grid-column: 1 / -1">
          <label class="field-label" for="beUrl">URL</label>
          <input id="beUrl" placeholder="https://mcp.example.com/mcp" autocomplete="off" />
        </div>
        <div class="form-field" id="beFieldCommand" hidden style="grid-column: 1 / -1">
          <label class="field-label" for="beCommand">Command</label>
          <input id="beCommand" class="mono" placeholder='npx -y @modelcontextprotocol/server-filesystem /tmp' autocomplete="off" />
          <span class="dim" style="font-size:11px;margin-top:4px">argv · quote tokens with "double quotes"</span>
        </div>
        <div class="form-field" id="beFieldImage" hidden style="grid-column: 1 / -1">
          <label class="field-label" for="beImage">OCI image</label>
          <input id="beImage" class="mono" placeholder="ghcr.io/org/mcp-server:latest" autocomplete="off" />
          <label class="field-label" for="beImageCmd" style="margin-top:10px">Image command (optional)</label>
          <input id="beImageCmd" class="mono" placeholder="node dist/index.js" autocomplete="off" />
        </div>
        <div class="form-field">
          <span class="field-label">Enabled</span>
          <label class="form-check">
            <input type="checkbox" id="beEnable" checked />
            <span>enable on create</span>
          </label>
        </div>
      </div>
      <div class="hdr-editor" id="beHdrEditor">
        <div class="hdr-editor-head">
          <span class="field-label" style="margin:0">Request headers</span>
          <button type="button" class="pill-btn ghost" data-hdr-add>+ Add header</button>
        </div>
        <div data-hdr-list class="hdr-list">
          ${kvRowHtml("hdr", "Authorization", "", "Header-Name", "value (sealed)")}
        </div>
      </div>
      <div class="hdr-editor" id="beEnvEditor" hidden style="margin-top:12px">
        <div class="hdr-editor-head">
          <span class="field-label" style="margin:0">Environment (sealed)</span>
          <button type="button" class="pill-btn ghost" data-env-add>+ Add env</button>
        </div>
        <div data-env-list class="hdr-list"></div>
      </div>
      <div class="row-actions" style="margin-top:14px">
        <button type="button" id="beCreate" class="pill-btn primary">Create backend</button>
      </div>
    `,
      "remote · stdio · edge",
    )}
    ${surface(
      "Backends",
      `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>slug</th>
              <th>target</th>
              <th>transport</th>
              <th>placement</th>
              <th>secrets</th>
              <th>enabled</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${
              backends.length
                ? backends
                    .map((b) => {
                      const secrets = [
                        b.hasHeaders ? "hdr" : null,
                        b.hasEnv ? "env" : null,
                      ]
                        .filter(Boolean)
                        .join("+");
                      return `<tr>
              <td class="mono">${esc(b.slug)}</td>
              ${backendEndpointCell(b)}
              <td>${esc(b.transport)}</td>
              <td class="mono">${esc(b.placement?.mode)}${b.placement?.deviceId ? " @" + esc(String(b.placement.deviceId).slice(0, 8)) : ""}</td>
              <td>${secrets ? `<span class="pill vault">${esc(secrets)}</span>` : '<span class="pill off">none</span>'}</td>
              <td><span class="pill ${b.enabled ? "on" : "off"}">${b.enabled ? "on" : "off"}</span></td>
              <td class="row-actions">
                <button type="button" class="pill-btn" data-test="${esc(b.id)}">Test</button>
                <button type="button" class="pill-btn ghost" data-toggle="${esc(b.id)}" data-en="${b.enabled ? "0" : "1"}">${b.enabled ? "Disable" : "Enable"}</button>
                <button type="button" class="pill-btn danger" data-del="${esc(b.id)}" data-slug="${esc(b.slug)}">Delete</button>
              </td>
            </tr>`;
                    })
                    .join("")
                : `<tr><td colspan="7" class="muted">No backends — add one above</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div id="beOutWrap" class="once-callout" hidden style="border-color: rgba(91,141,239,0.35)">
        <div class="once-label" style="color: var(--accent-hot)">Test result</div>
        <pre id="beOut"></pre>
      </div>
    `,
      `${backends.length} registered`,
    )}`;

  wireKvEditor($("#beHdrEditor"), "hdr");
  wireKvEditor($("#beEnvEditor"), "env");
  $("#beMode")?.addEventListener("change", () => syncBackendFormFields());
  $("#beLocalTransport")?.addEventListener("change", () => syncBackendFormFields());
  syncBackendFormFields();

  $("#beCreate")?.addEventListener("click", async () => {
    try {
      const slug = $("#beSlug").value.trim();
      if (!slug) throw new Error("slug required");
      const mode = $("#beMode").value || "remote";
      const enabled = $("#beEnable").checked;
      const body = { slug, enabled, placement: { mode } };

      if (mode === "remote") {
        const url = $("#beUrl").value.trim();
        if (!url) throw new Error("url required");
        body.url = url;
        body.transport = $("#beTransport").value || "streamable-http";
        const headers = collectHeaderPairs($("#beHdrEditor") || document);
        if (Object.keys(headers).length) body.headers = headers;
      } else {
        const transport =
          mode === "edge-bare"
            ? "stdio"
            : $("#beLocalTransport")?.value || "stdio";
        body.transport = transport;
        if (mode === "edge-sandbox" || mode === "edge-bare") {
          const deviceId = $("#beDevice")?.value?.trim();
          if (!deviceId) throw new Error("edge device required");
          body.placement.deviceId = deviceId;
        }
        if (transport === "oci") {
          const image = $("#beImage")?.value?.trim();
          if (!image) throw new Error("image required for oci");
          body.image = image;
          const extra = parseCommandLine($("#beImageCmd")?.value || "");
          if (extra.length) body.command = extra;
        } else {
          const command = parseCommandLine($("#beCommand")?.value || "");
          if (!command.length) throw new Error("command required for stdio");
          body.command = command;
        }
        const env = collectEnvPairs($("#beEnvEditor") || document);
        if (Object.keys(env).length) body.env = env;
      }

      await api("/v1/backends", { method: "POST", body: JSON.stringify(body) });
      await renderBackends();
    } catch (e) {
      showErr(e.message);
    }
  });

  document.querySelectorAll("[data-test]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        const r = await api(`/v1/backends/${btn.getAttribute("data-test")}/test`, {
          method: "POST",
          body: "{}",
        });
        const wrap = $("#beOutWrap");
        const out = $("#beOut");
        wrap.hidden = false;
        out.textContent = JSON.stringify(r, null, 2);
      } catch (e) {
        showErr(e.message);
      }
    });
  });
  document.querySelectorAll("[data-toggle]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/v1/backends/${btn.getAttribute("data-toggle")}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled: btn.getAttribute("data-en") === "1" }),
        });
        await renderBackends();
      } catch (e) {
        showErr(e.message);
      }
    });
  });
  document.querySelectorAll("[data-del]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const slug = btn.getAttribute("data-slug") || "backend";
      if (!confirm(`Delete backend “${slug}”?`)) return;
      try {
        await api(`/v1/backends/${btn.getAttribute("data-del")}`, {
          method: "DELETE",
        });
        await renderBackends();
      } catch (e) {
        showErr(e.message);
      }
    });
  });
}

async function renderDevices() {
  const { devices } = await api("/v1/devices");
  $("#tab-devices").innerHTML = `
    ${surface(
      "Enroll device",
      `
      <div class="form-grid">
        <div class="form-field">
          <label class="field-label" for="devName">Name</label>
          <input id="devName" placeholder="edge" />
        </div>
        <div class="form-field">
          <label class="field-label" for="devTags">Tags</label>
          <input id="devTags" placeholder="comma-separated" />
        </div>
        <div class="form-field">
          <span class="field-label">Caps</span>
          <label class="form-check">
            <input type="checkbox" id="devBare" />
            <span>bare capable</span>
          </label>
        </div>
        <div class="form-field">
          <span class="field-label">&nbsp;</span>
          <button type="button" id="enrollDev" class="pill-btn primary">Enroll</button>
        </div>
      </div>
      <div id="devOnce" class="once-callout" hidden>
        <div class="once-label">Device token · shown once</div>
        <pre id="devOnceText"></pre>
      </div>
    `,
      "edge",
    )}
    ${surface(
      "Devices",
      `
      <div class="table-wrap">
        <table class="data-table">
          <thead><tr><th>name</th><th>id</th><th>status</th><th>caps</th><th></th></tr></thead>
          <tbody>
            ${
              devices.length
                ? devices
                    .map(
                      (d) => `<tr>
              <td>${esc(d.name)}</td>
              <td class="mono">${esc(d.id)}</td>
              <td><span class="pill ${d.status === "online" ? "on" : "off"}">${esc(d.status)}</span></td>
              <td class="mono">${esc(JSON.stringify(d.capabilities))}</td>
              <td class="row-actions">
                <button type="button" class="pill-btn danger" data-rmdev="${esc(d.id)}">Revoke</button>
              </td>
            </tr>`,
                    )
                    .join("")
                : `<tr><td colspan="5" class="muted">No devices</td></tr>`
            }
          </tbody>
        </table>
      </div>
    `,
      `${devices.length} enrolled`,
    )}`;
  $("#enrollDev")?.addEventListener("click", async () => {
    try {
      const tags = $("#devTags")
        .value.split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await api("/v1/devices", {
        method: "POST",
        body: JSON.stringify({
          name: $("#devName").value.trim() || "edge",
          tags,
          capabilities: {
            sandbox: "docker",
            bare: $("#devBare").checked,
          },
        }),
      });
      const tokenLine = `${res.device.token}\n\nrun: mcp-flow edge --url <gateway> --token <token>`;
      await renderDevices();
      const box = $("#devOnce");
      const text = $("#devOnceText");
      if (box && text) {
        box.hidden = false;
        text.textContent = tokenLine;
      }
    } catch (e) {
      showErr(e.message);
    }
  });
  document.querySelectorAll("[data-rmdev]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/v1/devices/${btn.getAttribute("data-rmdev")}`, { method: "DELETE" });
        await renderDevices();
      } catch (e) {
        showErr(e.message);
      }
    });
  });
}

function prettyJson(v) {
  if (v === undefined) return null;
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function auditStatusPills(detail) {
  const d = detail || {};
  const pills = [];
  if (d.denied) {
    pills.push(
      `<span class="pill deny">denied${d.reason ? ": " + esc(d.reason) : ""}</span>`,
    );
  }
  if (d.meta) pills.push(`<span class="pill vault">meta</span>`);
  if (d.isError === true) pills.push(`<span class="pill deny">error</span>`);
  else if (d.isError === false && !d.denied)
    pills.push(`<span class="pill on">ok</span>`);
  if (d.durationMs != null)
    pills.push(`<span class="pill">${esc(d.durationMs)} ms</span>`);
  return pills.join("") || `<span class="pill off">—</span>`;
}

function auditExpandBody(detail) {
  const d = detail || {};
  const hasArgs = d.arguments !== undefined;
  const hasResult = d.result !== undefined;
  const known = new Set([
    "denied",
    "reason",
    "meta",
    "durationMs",
    "isError",
    "arguments",
    "result",
  ]);
  const rest = {};
  for (const k of Object.keys(d)) {
    if (!known.has(k)) rest[k] = d[k];
  }
  const hasRest = Object.keys(rest).length > 0;

  if (!hasArgs && !hasResult && !hasRest) {
    return `<div class="audit-empty muted">No detail payload</div>`;
  }

  const reqPre = hasArgs
    ? `<pre class="audit-payload">${esc(prettyJson(d.arguments))}</pre>`
    : `<div class="audit-empty muted">No request arguments</div>`;
  const resPre = hasResult
    ? `<pre class="audit-payload">${esc(prettyJson(d.result))}</pre>`
    : `<div class="audit-empty muted">No response body</div>`;

  let html = `
    <div class="audit-split">
      <div class="audit-pane">
        <div class="audit-pane-head">
          <span>Request</span>
          <span class="mute">arguments</span>
        </div>
        <div class="audit-pane-body">${reqPre}</div>
      </div>
      <div class="audit-pane">
        <div class="audit-pane-head">
          <span>Response</span>
          <span class="mute">result</span>
        </div>
        <div class="audit-pane-body">${resPre}</div>
      </div>
    </div>`;

  if (hasRest) {
    html += `
      <div class="audit-pane audit-pane-full">
        <div class="audit-pane-head">
          <span>Other</span>
          <span class="mute">detail</span>
        </div>
        <div class="audit-pane-body">
          <pre class="audit-payload">${esc(prettyJson(rest))}</pre>
        </div>
      </div>`;
  }
  return html;
}

function wireAuditList(root) {
  const expandCalls = () => {
    root.querySelectorAll("[data-audit-item]").forEach((item) => {
      const isCall = item.getAttribute("data-action") === "tools/call";
      const body = item.querySelector("[data-audit-body]");
      const chev = item.querySelector("[data-audit-chev]");
      if (!body) return;
      if (isCall) {
        item.classList.add("open");
        body.hidden = false;
        if (chev) chev.textContent = "▾";
      }
    });
  };
  const collapseAll = () => {
    root.querySelectorAll("[data-audit-item]").forEach((item) => {
      item.classList.remove("open");
      const body = item.querySelector("[data-audit-body]");
      const chev = item.querySelector("[data-audit-chev]");
      if (body) body.hidden = true;
      if (chev) chev.textContent = "▸";
    });
  };

  root.querySelector("[data-audit-expand-calls]")?.addEventListener("click", expandCalls);
  root.querySelector("[data-audit-collapse]")?.addEventListener("click", collapseAll);

  root.querySelectorAll("[data-audit-toggle]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const item = btn.closest("[data-audit-item]");
      if (!item) return;
      const body = item.querySelector("[data-audit-body]");
      const chev = item.querySelector("[data-audit-chev]");
      const open = !item.classList.contains("open");
      item.classList.toggle("open", open);
      if (body) body.hidden = !open;
      if (chev) chev.textContent = open ? "▾" : "▸";
    });
  });
}

async function renderAudit() {
  const { events } = await api("/v1/audit?limit=80");
  const listHtml = events.length
    ? events
        .map((e, i) => {
          const d = e.detail || {};
          const expandable =
            d.arguments !== undefined ||
            d.result !== undefined ||
            (d && Object.keys(d).some(
              (k) =>
                !["denied", "reason", "meta", "durationMs", "isError"].includes(k),
            ));
          return `
          <article class="audit-item" data-audit-item data-action="${esc(e.action)}" data-idx="${i}">
            <button type="button" class="audit-summary" data-audit-toggle ${expandable ? "" : "disabled"}>
              <span class="audit-chev" data-audit-chev aria-hidden="true">${expandable ? "▸" : "·"}</span>
              <span class="audit-sum-main">
                <span class="mono nowrap audit-ts">${esc(e.ts)}</span>
                <span class="audit-action">${esc(e.action)}</span>
                <span class="mono audit-tool">${esc(e.tool || "—")}</span>
              </span>
              <span class="audit-sum-meta">
                <span class="mono dim">${esc(e.backendSlug || "")}</span>
                <span class="mono dim">${esc(e.deviceId || "")}</span>
                <span class="audit-meta">${auditStatusPills(d)}</span>
              </span>
            </button>
            <div class="audit-expand" data-audit-body hidden>
              ${expandable ? auditExpandBody(d) : ""}
            </div>
          </article>`;
        })
        .join("")
    : `<p class="muted">No events yet</p>`;

  $("#tab-audit").innerHTML = `
    ${surface(
      "Audit",
      `
      <div class="audit-toolbar">
        <p class="muted" style="margin:0;flex:1">
          Click a row to expand full-width request / response (redacted, size-capped).
        </p>
        <div class="row-actions">
          <button type="button" class="pill-btn ghost" data-audit-expand-calls>Expand calls</button>
          <button type="button" class="pill-btn ghost" data-audit-collapse>Collapse all</button>
        </div>
      </div>
      <div class="audit-list" id="auditList">
        ${listHtml}
      </div>
    `,
      `${events.length} recent`,
    )}`;

  const list = $("#auditList");
  if (list) wireAuditList(list.closest(".panel-pad") || list.parentElement);
}

async function refresh() {
  showErr("");
  const tab =
    document.querySelector(".tabs .seg-btn.active, .tabs button.active")?.dataset
      .tab || "status";
  try {
    if (tab === "status") await renderStatus();
    if (tab === "keys") await renderKeys();
    if (tab === "backends") await renderBackends();
    if (tab === "devices") await renderDevices();
    if (tab === "audit") await renderAudit();
  } catch (e) {
    showErr(e.message);
  }
}

document.querySelectorAll(".tabs .seg-btn, .tabs button").forEach((btn) => {
  btn.addEventListener("click", () => {
    document
      .querySelectorAll(".tabs .seg-btn, .tabs button")
      .forEach((b) => b.classList.remove("active", "on"));
    document.querySelectorAll("main .panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    $(`#tab-${btn.dataset.tab}`).classList.add("active");
    void refresh();
  });
});

$("#saveToken").addEventListener("click", () => {
  setToken($("#token").value.trim());
  void refresh();
});
$("#refresh").addEventListener("click", () => void refresh());
$("#token").value = token();
if (token()) void refresh();
