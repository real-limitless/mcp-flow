const $ = (s) => document.querySelector(s);
const errEl = $("#err");
const TOKEN_KEY = "mcp_flow_admin_token";

// R-5: credentials live in sessionStorage at most, never localStorage. Purge
// any leftover copies an older build (or another tab) may have written.
try {
  for (const k of ["mcp_flow_admin_token", "mcp_flow_approver_token", "mcp_flow_harness_url"]) {
    globalThis.localStorage?.removeItem(k);
  }
} catch {
  /* storage may be blocked; nothing to purge */
}

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
    const code = body.error || res.statusText || String(res.status);
    // 401 = missing/bad token: unchanged (error shown, token prompt stays).
    // 403 = valid token that isn't permitted: report it, never clear the token.
    // 401: drop ONLY the admin token (memory + sessionStorage), re-prompt in
    // place. No retry with the old token, no reload, tab kept.
    if (res.status === 401 && token() === t) promptAdminToken();
    const err = new Error(
      res.status === 401 ? REPROMPT_MSG : res.status === 403 ? notPermittedMsg(body.error) : code,
    );
    err.status = res.status;
    err.code = code;
    throw err;
  }
  return body;
}

// Secondary requests in a panel: never let a failure look like "empty".
// soft() records the failure for that panel; withIssues() renders a banner at
// the top of the panel after each render (403 = "not permitted").
const panelIssues = new Map(); // tab -> [{ label, text }]
async function soft(tab, label, promise, fallback) {
  try {
    return await promise;
  } catch (e) {
    if (e.status === 401) throw e; // 401 handled by the re-prompt path
    const text = e.status === 403 ? "not permitted (403)" : `failed to load (${e.message})`;
    if (!panelIssues.has(tab)) panelIssues.set(tab, []);
    panelIssues.get(tab).push({ label, text });
    return fallback();
  }
}
function withIssues(tab, fn) {
  return async (...args) => {
    panelIssues.set(tab, []);
    try {
      return await fn(...args);
    } finally {
      const panel = $(`#tab-${tab}`);
      const issues = panelIssues.get(tab) || [];
      let el = panel?.querySelector(":scope > .sec-issues");
      if (panel && issues.length) {
        if (!el) {
          el = document.createElement("div");
          el.className = "sec-issues";
          panel.prepend(el);
        }
        el.innerHTML = issues
          .map((i) => `<p class="pa-banner" role="status"><span><strong>${esc(i.label)}:</strong> ${esc(i.text)} — shown below as unavailable, not empty.</span></p>`)
          .join("");
      } else el?.remove();
    }
  };
}

const REPROMPT_MSG = "Expired or invalid key — enter it again";

function promptAdminToken() {
  sessionStorage.removeItem(TOKEN_KEY);
  const input = $("#token");
  if (input) {
    input.value = "";
    input.placeholder = "Admin token — expired or invalid, enter it again";
  }
  let msg = $("#tokenMsg");
  if (!msg) {
    msg = document.createElement("p");
    msg.id = "tokenMsg";
    msg.className = "pa-warn";
    msg.setAttribute("role", "alert");
    $(".auth-row")?.after(msg);
  }
  msg.textContent = REPROMPT_MSG;
  msg.hidden = false;
  input?.focus();
}

function notPermittedMsg(code) {
  return `Not permitted (403${code ? `: ${code}` : ""}). Your key is valid but isn't allowed to do this; you're still signed in.`;
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

const PLACEHOLDER_TOKEN = "mf_YOUR_AGENT_KEY";
const HARNESS_URL_KEY = "mcp_flow_harness_url";
let harnessTabId = "cursor";

function defaultMcpUrl() {
  const origin = (
    typeof location !== "undefined" ? location.origin : "http://127.0.0.1:8787"
  ).replace(/\/$/, "");
  return `${origin}/mcp`;
}

function storedHarnessUrl() {
  try {
    return sessionStorage.getItem(HARNESS_URL_KEY) || defaultMcpUrl();
  } catch {
    return defaultMcpUrl();
  }
}

function setStoredHarnessUrl(url) {
  try {
    sessionStorage.setItem(HARNESS_URL_KEY, url);
  } catch {
    /* ignore quota / private mode */
  }
}

function normalizeMcpUrl(raw) {
  const s = String(raw || "").trim() || defaultMcpUrl();
  return s.replace(/\/+$/, "");
}

/** Full client JSON files for Cursor, OpenCode, Claude, VS Code, stdio. */
function clientConfigs({ url, token }) {
  const mcpUrl = normalizeMcpUrl(url);
  const auth = `Bearer ${token}`;
  const httpHeaders = { Authorization: auth };
  const cursorJson = {
    mcpServers: {
      "mcp-flow": {
        url: mcpUrl,
        headers: httpHeaders,
      },
    },
  };
  const opencodeJson = {
    $schema: "https://opencode.ai/config.json",
    mcp: {
      "mcp-flow": {
        type: "remote",
        url: mcpUrl,
        enabled: true,
        oauth: false,
        headers: httpHeaders,
      },
    },
  };
  const claudeCodeJson = {
    mcpServers: {
      "mcp-flow": {
        type: "http",
        url: mcpUrl,
        headers: httpHeaders,
      },
    },
  };
  const stdioJson = {
    mcpServers: {
      "mcp-flow": {
        command: "npx",
        args: ["-y", "mcp-flow", "stdio"],
        env: {
          MCP_FLOW_URL: mcpUrl,
          MCP_FLOW_API_KEY: token,
        },
      },
    },
  };
  const vscodeJson = {
    servers: {
      "mcp-flow": {
        type: "http",
        url: mcpUrl,
        headers: httpHeaders,
      },
    },
  };
  return [
    {
      id: "cursor",
      name: "Cursor",
      file: "~/.cursor/mcp.json or .cursor/mcp.json",
      json: cursorJson,
    },
    {
      id: "opencode",
      name: "OpenCode",
      file: "opencode.json or ~/.config/opencode/opencode.json",
      json: opencodeJson,
    },
    {
      id: "claude-code",
      name: "Claude Code",
      file: "project .mcp.json",
      json: claudeCodeJson,
    },
    {
      id: "claude-desktop",
      name: "Claude Desktop",
      file: "claude_desktop_config.json",
      json: stdioJson,
    },
    {
      id: "vscode",
      name: "VS Code",
      file: ".vscode/mcp.json",
      json: vscodeJson,
    },
    {
      id: "stdio",
      name: "Stdio shim",
      file: "env + command",
      json: stdioJson,
      extra: `MCP_FLOW_URL=${mcpUrl} MCP_FLOW_API_KEY=${token} npx mcp-flow stdio`,
    },
  ];
}

function snippetJsonText(cfg) {
  return JSON.stringify(cfg.json, null, 2);
}

function harnessSnippetsHtml({ url, token, showUrlField, idPrefix }) {
  const configs = clientConfigs({ url, token });
  const selected =
    configs.find((c) => c.id === harnessTabId) || configs[0];
  const tabs = configs
    .map(
      (c) =>
        `<button type="button" class="seg-btn${c.id === selected.id ? " active" : ""}" data-snippet-tab="${esc(c.id)}">${esc(c.name)}</button>`,
    )
    .join("");
  const urlField = showUrlField
    ? `<div class="form-field harness-url-field">
        <label class="field-label" for="${esc(idPrefix)}-url">Gateway MCP URL</label>
        <input id="${esc(idPrefix)}-url" data-harness-url class="mono" value="${esc(url)}" autocomplete="off" spellcheck="false" />
      </div>`
    : "";
  const extraHidden = selected.extra ? "" : " hidden";
  return `
    <div class="harness-snips" data-harness-snips data-token="${esc(token)}" data-url="${esc(url)}">
      ${urlField}
      <div class="harness-snip-head">
        <div class="seg harness-snip-tabs" role="tablist" aria-label="Harness config">${tabs}</div>
        <button type="button" class="pill-btn ghost" data-snippet-copy>Copy</button>
      </div>
      <p class="dim harness-snip-file" data-snippet-file>${esc(selected.file)}</p>
      <pre data-snippet-json>${esc(snippetJsonText(selected))}</pre>
      <p class="muted harness-snip-extra" data-snippet-extra${extraHidden}>${esc(selected.extra || "")}</p>
    </div>`;
}

function applyHarnessTab(root, id) {
  const token = root.getAttribute("data-token") || PLACEHOLDER_TOKEN;
  const urlInput = root.querySelector("[data-harness-url]");
  const url = normalizeMcpUrl(
    urlInput?.value || root.getAttribute("data-url") || defaultMcpUrl(),
  );
  root.setAttribute("data-url", url);
  const configs = clientConfigs({ url, token });
  const cfg = configs.find((c) => c.id === id) || configs[0];
  harnessTabId = cfg.id;
  root.querySelectorAll("[data-snippet-tab]").forEach((b) => {
    b.classList.toggle("active", b.getAttribute("data-snippet-tab") === cfg.id);
  });
  const file = root.querySelector("[data-snippet-file]");
  const pre = root.querySelector("[data-snippet-json]");
  const extra = root.querySelector("[data-snippet-extra]");
  if (file) file.textContent = cfg.file;
  if (pre) pre.textContent = snippetJsonText(cfg);
  if (extra) {
    extra.textContent = cfg.extra || "";
    extra.hidden = !cfg.extra;
  }
}

function wireHarnessSnippets(root) {
  if (!root) return;
  root.querySelectorAll("[data-snippet-tab]").forEach((btn) => {
    btn.addEventListener("click", () => {
      applyHarnessTab(root, btn.getAttribute("data-snippet-tab") || "cursor");
    });
  });
  const urlInput = root.querySelector("[data-harness-url]");
  urlInput?.addEventListener("input", () => {
    const url = normalizeMcpUrl(urlInput.value || defaultMcpUrl());
    setStoredHarnessUrl(url);
    applyHarnessTab(root, harnessTabId);
  });
  urlInput?.addEventListener("change", () => {
    const url = normalizeMcpUrl(urlInput.value || defaultMcpUrl());
    urlInput.value = url;
    setStoredHarnessUrl(url);
    applyHarnessTab(root, harnessTabId);
  });
  const copyBtn = root.querySelector("[data-snippet-copy]");
  copyBtn?.addEventListener("click", async () => {
    const pre = root.querySelector("[data-snippet-json]");
    const text = pre?.textContent || "";
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      ok = false;
    }
    const label = copyBtn.textContent;
    copyBtn.textContent = ok ? "Copied" : "Copy failed";
    copyBtn.classList.toggle("copied", ok);
    setTimeout(() => {
      copyBtn.textContent = label || "Copy";
      copyBtn.classList.remove("copied");
    }, 1400);
  });
}

async function renderStatus() {
  const { workspace, placementModes } = await api("/v1/workspace");
  const health = await fetch("/health").then((r) => r.json());
  const [pendingRes, mfa] = await Promise.all([
    soft("status", "Pending approvals", api("/v1/approvals?status=pending"), () => ({
      approvals: [],
      pendingCount: 0,
      waiting: 0,
    })),
    soft("status", "Operator MFA", api("/v1/operators/mfa"), () => ({ enrolled: false })),
  ]);
  const pendingN = pendingRes.pendingCount ?? pendingRes.approvals?.length ?? 0;
  const waitingN = pendingRes.waiting ?? 0;
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
        <div class="stat">
          <span class="label">Pending approvals</span>
          <span class="value"><span class="pill ${pendingN ? "warn" : "off"}">${esc(String(pendingN))}</span>
            ${waitingN ? `<span class="muted"> · ${esc(String(waitingN))} waiting</span>` : ""}</span>
        </div>
        <div class="stat">
          <span class="label">Operator MFA</span>
          <span class="value"><span class="pill ${mfa?.enrolled ? "on" : "off"}">${mfa?.enrolled ? "enrolled" : "not enrolled"}</span></span>
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
    )}
    ${surface(
      "Connect a harness",
      `
      <p class="muted" style="margin-bottom:12px">
        Full JSON for Cursor, OpenCode, Claude, and VS Code. Paste into the file shown —
        only this gateway URL and an agent key; upstream secrets stay sealed here.
      </p>
      ${harnessSnippetsHtml({
        url: storedHarnessUrl(),
        token: PLACEHOLDER_TOKEN,
        showUrlField: true,
        idPrefix: "statusHarness",
      })}
    `,
      "mcp.json",
    )}`;
  wireHarnessSnippets($("#tab-status [data-harness-snips]"));
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

function collectCheckedSlugs(rootSel, attr) {
  return [...document.querySelectorAll(`${rootSel} [${attr}]:checked`)].map(
    (el) => el.getAttribute(attr),
  );
}

function projectCheckboxesHtml(projects, selected, attr = "data-key-proj") {
  if (!projects.length) {
    return '<span class="muted">No projects yet — create one under Projects</span>';
  }
  const set = new Set(selected || []);
  return projects
    .map(
      (p) =>
        `<label class="form-check"><input type="checkbox" ${attr}="${esc(p.slug)}" ${set.has(p.slug) ? "checked" : ""}/> <span class="mono">${esc(p.slug)}</span>${p.isDefault ? ' <span class="pill on">default</span>' : ""}</label>`,
    )
    .join("");
}

function projectSelectOptions(projects, selected) {
  const opts = [
    `<option value="">— workspace default —</option>`,
    ...projects.map(
      (p) =>
        `<option value="${esc(p.slug)}" ${selected === p.slug ? "selected" : ""}>${esc(p.slug)}${p.isDefault ? " (default)" : ""}</option>`,
    ),
  ];
  return opts.join("");
}

function formatKeyProjects(scopes) {
  if (!scopes) return '<span class="pill off">all projects</span>';
  const parts = [];
  if (scopes.projects?.length) {
    parts.push(
      scopes.projects.map((s) => `<span class="pill accent">${esc(s)}</span>`).join(" "),
    );
  } else {
    parts.push('<span class="pill off">all</span>');
  }
  if (scopes.defaultProject) {
    parts.push(
      `<span class="muted">start:</span> <span class="pill vault">${esc(scopes.defaultProject)}</span>`,
    );
  }
  return `<div class="key-proj-cell">${parts.join(" ")}</div>`;
}

async function renderKeys() {
  const [{ keys }, projRes] = await Promise.all([
    api("/v1/keys"),
    soft("keys", "Projects", api("/v1/projects"), () => ({ projects: [] })),
  ]);
  const projects = projRes.projects || [];

  $("#tab-keys").innerHTML = `
    ${surface(
      "Create key",
      `
      <div class="form-grid">
        <div class="form-field">
          <label class="field-label" for="keyName">Name</label>
          <input id="keyName" placeholder="cursor / openflow-ops" autocomplete="off" />
        </div>
        <div class="form-field" style="grid-column: span 2">
          <span class="field-label">Role</span>
          <div class="seg role-seg" id="keyRoleSeg" role="group" aria-label="Key role">
            <button type="button" class="seg-btn active" data-role="agent">Agent</button>
            <button type="button" class="seg-btn" data-role="operator">Operator</button>
          </div>
          <p class="dim role-hint" id="keyRoleHint" style="font-size:12px;margin-top:8px;max-width:42rem">
            Agent: use upstream tools on <span class="mono">/mcp</span> only (optional tool-prefix scopes).
          </p>
          <input type="hidden" id="keyAdmin" value="0" />
        </div>
        <div class="form-field">
          <label class="field-label" for="keyScope">Tool scope prefix</label>
          <input id="keyScope" placeholder="optional e.g. demo__" autocomplete="off" />
        </div>
        <div class="form-field" style="grid-column:1/-1">
          <span class="field-label">Projects</span>
          <p class="dim" style="font-size:12px;margin-bottom:6px">
            Leave unchecked = key may use <strong>all</strong> projects. Check to restrict.
          </p>
          <div class="proj-be-grid" id="keyProjGrid">
            ${projectCheckboxesHtml(projects, [], "data-key-proj")}
          </div>
        </div>
        <div class="form-field">
          <label class="field-label" for="keyDefaultProj">Default project</label>
          <select id="keyDefaultProj">
            ${projectSelectOptions(projects, "")}
          </select>
        </div>
        <div class="form-field" style="grid-column:1/-1">
          <label class="field-label" for="keyDynamicTools" style="display:flex;align-items:center;gap:8px">
            <input type="checkbox" id="keyDynamicTools" />
            Dynamic tool discovery
          </label>
          <p class="dim" style="font-size:12px;margin-top:6px;max-width:42rem">
            Hide upstream tools from <span class="mono">tools/list</span> (harness 200-tool caps).
            Agent searches with <span class="mono">mf_list_tools</span>, then
            <span class="mono">mf_enable_tools</span> / <span class="mono">mf_call_tool</span>.
          </p>
        </div>
        <div class="form-field">
          <span class="field-label">&nbsp;</span>
          <button type="button" id="createKey" class="pill-btn primary">Create key</button>
        </div>
      </div>
      <div id="keyOnce" class="once-callout" hidden>
        <div class="once-label" id="keyOnceLabel">Token · shown once</div>
        <pre id="keyOnceText"></pre>
        <p class="muted" id="keyOnceHint" style="margin-top:8px;font-size:12px"></p>
        <div id="keyOnceSnips" hidden></div>
      </div>
    `,
      "mf_* · projects",
    )}
    ${surface(
      "Keys",
      `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>name</th>
              <th>prefix</th>
              <th>role</th>
              <th>discovery</th>
              <th>projects</th>
              <th>scopes</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${
              keys.length
                ? keys
                    .map(
                      (k) => `<tr>
              <td>${esc(k.name)}</td>
              <td class="mono">${esc(k.prefix)}</td>
              <td>${k.scopes?.admin ? '<span class="pill vault">operator</span>' : '<span class="pill off">agent</span>'}</td>
              <td>${
                k.revokedAt
                  ? '<span class="pill off">revoked</span>'
                  : `<button type="button" class="dyn-switch" data-key-dyn="${esc(k.id)}" aria-pressed="${k.scopes?.dynamicTools ? "true" : "false"}" title="Toggle dynamic tool discovery">
                      <span class="dyn-switch-track" aria-hidden="true"><span class="dyn-switch-knob"></span></span>
                      <span>${k.scopes?.dynamicTools ? "on" : "off"}</span>
                    </button>`
              }</td>
              <td>${formatKeyProjects(k.scopes)}</td>
              <td class="mono">${esc(
                JSON.stringify({
                  toolPrefixAllowlist: k.scopes?.toolPrefixAllowlist,
                  admin: k.scopes?.admin,
                  dynamicTools: k.scopes?.dynamicTools,
                }),
              )}</td>
              <td class="row-actions">
                <button type="button" class="pill-btn ghost" data-key-edit="${esc(k.id)}">Edit</button>
                <button type="button" class="pill-btn danger" data-revoke="${esc(k.id)}">Revoke</button>
              </td>
            </tr>`,
                    )
                    .join("")
                : `<tr><td colspan="7" class="muted">No keys yet</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div id="keyEdit" class="once-callout" hidden style="border-color: rgba(91,141,239,0.35);margin-top:12px">
        <div class="once-label" style="color:var(--accent-hot)">
          Edit key · <span id="keyEditName"></span>
        </div>
        <p class="muted" style="margin-bottom:8px;font-size:12px">
          Uncheck all projects = allow every project. Default project is used until the agent calls mf_use_project.
        </p>
        <div class="proj-be-grid" id="keyEditProjGrid"></div>
        <div class="form-field" style="margin-top:12px;max-width:16rem">
          <label class="field-label" for="keyEditDefault">Default project</label>
          <select id="keyEditDefault"></select>
        </div>
        <div class="form-field" style="margin-top:12px">
          <label class="field-label" for="keyEditDynamic" style="display:flex;align-items:center;gap:8px">
            <input type="checkbox" id="keyEditDynamic" />
            Dynamic tool discovery
          </label>
          <p class="dim" style="font-size:12px;margin-top:6px;max-width:42rem">
            Hide upstream tools from <span class="mono">tools/list</span> (harness 200-tool caps).
            Agent searches with <span class="mono">mf_list_tools</span>, then
            <span class="mono">mf_enable_tools</span> / <span class="mono">mf_call_tool</span>.
          </p>
        </div>
        <div class="row-actions" style="margin-top:12px">
          <button type="button" id="keySaveEdit" class="pill-btn primary">Save</button>
          <button type="button" id="keyCancelEdit" class="pill-btn ghost">Cancel</button>
        </div>
        <input type="hidden" id="keyEditId" />
      </div>
    `,
      `${keys.length} total`,
    )}`;

  const roleSeg = $("#keyRoleSeg");
  const roleHint = $("#keyRoleHint");
  const keyAdmin = $("#keyAdmin");
  const setRole = (role) => {
    const isOp = role === "operator";
    keyAdmin.value = isOp ? "1" : "0";
    roleSeg?.querySelectorAll("[data-role]").forEach((b) => {
      b.classList.toggle("active", b.getAttribute("data-role") === role);
    });
    if (roleHint) {
      roleHint.innerHTML = isOp
        ? `Operator: full <span class="mono">mf_admin_*</span> management tools on <span class="mono">/mcp</span> and access to <span class="mono">/v1/*</span>. Treat like root — revocable unlike the env admin token.`
        : `Agent: use upstream tools on <span class="mono">/mcp</span> only (optional tool-prefix + project attachments).`;
    }
  };
  roleSeg?.querySelectorAll("[data-role]").forEach((btn) => {
    btn.addEventListener("click", () => setRole(btn.getAttribute("data-role") || "agent"));
  });

  $("#createKey")?.addEventListener("click", async () => {
    try {
      const name = $("#keyName").value.trim() || "default";
      const scope = $("#keyScope").value.trim();
      const isOp = $("#keyAdmin")?.value === "1";
      const projSlugs = collectCheckedSlugs("#keyProjGrid", "data-key-proj");
      const defaultProject = $("#keyDefaultProj")?.value?.trim() || "";
      const body = { name };
      if (scope) body.toolPrefixAllowlist = [scope];
      if (isOp) body.admin = true;
      if (projSlugs.length) body.projects = projSlugs;
      if (defaultProject) body.defaultProject = defaultProject;
      if ($("#keyDynamicTools")?.checked) body.dynamicTools = true;
      const res = await api("/v1/keys", { method: "POST", body: JSON.stringify(body) });
      const onceToken = res.key.token;
      const wasOp = Boolean(res.key.scopes?.admin);
      await renderKeys();
      const box = $("#keyOnce");
      const text = $("#keyOnceText");
      const label = $("#keyOnceLabel");
      const hint = $("#keyOnceHint");
      if (box && text) {
        box.hidden = false;
        text.textContent = onceToken;
        if (label) {
          label.textContent = wasOp
            ? "Operator token · shown once"
            : "Agent token · shown once";
        }
        if (hint) {
          const projNote = res.key.scopes?.projects?.length
            ? ` Projects: ${res.key.scopes.projects.join(", ")}.`
            : " All projects allowed.";
          hint.textContent = wasOp
            ? "Copy a harness JSON below with this bearer token to manage backends, keys, and catalog." +
              projNote
            : "Copy a harness JSON below with this bearer token." + projNote;
        }
        const snips = $("#keyOnceSnips");
        if (snips) {
          snips.hidden = false;
          snips.innerHTML = harnessSnippetsHtml({
            url: storedHarnessUrl(),
            token: onceToken,
            showUrlField: true,
            idPrefix: "keyHarness",
          });
          wireHarnessSnippets(snips.querySelector("[data-harness-snips]"));
        }
      }
    } catch (e) {
      showErr(e.message);
    }
  });

  document.querySelectorAll("[data-key-dyn]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-key-dyn");
      const k = keys.find((x) => x.id === id);
      if (!k || k.revokedAt) return;
      const next = !Boolean(k.scopes?.dynamicTools);
      btn.disabled = true;
      try {
        await api(`/v1/keys/${id}`, {
          method: "PATCH",
          body: JSON.stringify({ dynamicTools: next }),
        });
        await renderKeys();
      } catch (e) {
        showErr(e.message);
        btn.disabled = false;
      }
    });
  });

  document.querySelectorAll("[data-key-edit]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-key-edit");
      const k = keys.find((x) => x.id === id);
      if (!k) return;
      $("#keyEdit").hidden = false;
      $("#keyEditId").value = id;
      $("#keyEditName").textContent = k.name;
      $("#keyEditProjGrid").innerHTML = projectCheckboxesHtml(
        projects,
        k.scopes?.projects || [],
        "data-edit-key-proj",
      );
      $("#keyEditDefault").innerHTML = projectSelectOptions(
        projects,
        k.scopes?.defaultProject || "",
      );
      const dyn = $("#keyEditDynamic");
      if (dyn) dyn.checked = Boolean(k.scopes?.dynamicTools);
    });
  });

  $("#keyCancelEdit")?.addEventListener("click", () => {
    $("#keyEdit").hidden = true;
  });

  $("#keySaveEdit")?.addEventListener("click", async () => {
    try {
      const id = $("#keyEditId").value;
      const k = keys.find((x) => x.id === id);
      if (!k) throw new Error("key not found");
      const projSlugs = collectCheckedSlugs("#keyEditProjGrid", "data-edit-key-proj");
      const defaultProject = $("#keyEditDefault")?.value?.trim() || null;
      await api(`/v1/keys/${id}`, {
        method: "PATCH",
        body: JSON.stringify({
          admin: Boolean(k.scopes?.admin),
          toolPrefixAllowlist: k.scopes?.toolPrefixAllowlist ?? null,
          projects: projSlugs,
          defaultProject,
          dynamicTools: Boolean($("#keyEditDynamic")?.checked),
        }),
      });
      await renderKeys();
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
    const value = (row.querySelector(valueSel)?.value ?? "").trim();
    if (name && value) out[name] = value;
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

const ALL_PLACEMENT_MODES = [
  "remote",
  "central-sandbox",
  "edge-sandbox",
  "edge-bare",
];
const REMOTE_TRANSPORTS = ["streamable-http", "sse"];
const LOCAL_TRANSPORTS = ["stdio", "oci"];
const BE_MODE_HINTS = {
  remote: "HTTP/SSE upstream. Headers sealed at rest.",
  "central-sandbox": "Spawn stdio/oci on the gateway host.",
  "edge-sandbox": "Run on an enrolled edge device (sandbox cap required).",
  "edge-bare": "Host process on edge — needs allowEdgeBare + device bare.",
};

let beLastRemoteTransport = "streamable-http";
let beLastLocalTransport = "stdio";
let beTransportKind = "";

function allowedPlacementModes(modes) {
  const have = modes || [];
  return ALL_PLACEMENT_MODES.filter(
    (m) => have.includes(m) || m === "remote" || m === "central-sandbox",
  );
}

function deviceOptionsHtml(devices) {
  if (!devices.length) {
    return `<option value="">— enroll a device first —</option>`;
  }
  return devices
    .map(
      (d) =>
        `<option value="${esc(d.id)}">${esc(d.name)} (${esc(d.status)}) · ${esc(d.id.slice(0, 8))}…</option>`,
    )
    .join("");
}

function placementSegHtml(modes, selected) {
  const allowed = allowedPlacementModes(modes);
  const current = allowed.includes(selected) ? selected : "remote";
  return allowed
    .map(
      (m) =>
        `<button type="button" class="seg-btn${m === current ? " active" : ""}" data-mode="${m}">${m}</button>`,
    )
    .join("");
}

function transportSegHtml(mode, selected) {
  const remote = mode === "remote";
  const opts = remote ? REMOTE_TRANSPORTS : LOCAL_TRANSPORTS;
  const locked = mode === "edge-bare";
  const current = locked
    ? "stdio"
    : opts.includes(selected)
      ? selected
      : opts[0];
  return opts
    .map(
      (t) =>
        `<button type="button" class="seg-btn${t === current ? " active" : ""}" data-transport="${t}"${locked && t !== "stdio" ? " disabled" : ""}>${t}</button>`,
    )
    .join("");
}

function setSegActive(root, attr, value) {
  root?.querySelectorAll(".seg-btn").forEach((b) => {
    b.classList.toggle("active", b.getAttribute(attr) === value);
  });
}

function wirePlacementSeg(seg) {
  if (!seg) return;
  seg.querySelectorAll("[data-mode]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const mode = btn.getAttribute("data-mode") || "remote";
      const hidden = $("#beMode");
      if (hidden) hidden.value = mode;
      setSegActive(seg, "data-mode", mode);
      syncBackendFormFields();
    });
  });
}

function wireTransportSeg(seg) {
  if (!seg) return;
  seg.querySelectorAll("[data-transport]").forEach((btn) => {
    btn.addEventListener("click", () => {
      if (btn.disabled) return;
      const v = btn.getAttribute("data-transport");
      const hidden = $("#beTransport");
      if (hidden) hidden.value = v;
      const mode = $("#beMode")?.value || "remote";
      if (mode === "remote") beLastRemoteTransport = v;
      else beLastLocalTransport = v;
      setSegActive(seg, "data-transport", v);
      syncBackendFormFields();
    });
  });
}

function ensureTransportSeg(mode) {
  const seg = $("#beTransportSeg");
  const hidden = $("#beTransport");
  if (!seg || !hidden) return;
  const kind = mode === "remote" ? "remote" : "local";
  if (beTransportKind !== kind || !seg.children.length) {
    beTransportKind = kind;
    const next =
      mode === "remote"
        ? beLastRemoteTransport
        : mode === "edge-bare"
          ? "stdio"
          : beLastLocalTransport;
    hidden.value = next;
    seg.innerHTML = transportSegHtml(mode, next);
    wireTransportSeg(seg);
    return;
  }
  if (mode === "edge-bare") hidden.value = "stdio";
  setSegActive(seg, "data-transport", hidden.value);
  seg.querySelectorAll("[data-transport]").forEach((b) => {
    b.disabled = mode === "edge-bare" && b.getAttribute("data-transport") !== "stdio";
  });
}

function updatePlacementSeg(modes) {
  const seg = $("#beModeSeg");
  const hidden = $("#beMode");
  if (!seg || !hidden) return;
  const allowed = allowedPlacementModes(modes);
  const current = [...seg.querySelectorAll("[data-mode]")].map((b) =>
    b.getAttribute("data-mode"),
  );
  if (current.join(",") === allowed.join(",")) return;
  if (!allowed.includes(hidden.value)) hidden.value = "remote";
  seg.innerHTML = placementSegHtml(modes, hidden.value);
  wirePlacementSeg(seg);
}

function updateDeviceSelect(devices) {
  const sel = $("#beDevice");
  if (!sel) return;
  const prev = sel.value;
  sel.innerHTML = deviceOptionsHtml(devices);
  if (prev && [...sel.options].some((o) => o.value === prev)) {
    sel.value = prev;
  }
}

function syncBackendFormFields() {
  const mode = $("#beMode")?.value || "remote";
  const isRemote = mode === "remote";
  const isEdge = mode === "edge-sandbox" || mode === "edge-bare";

  ensureTransportSeg(mode);

  const transport = $("#beTransport")?.value || (isRemote ? "streamable-http" : "stdio");
  const isOci = transport === "oci";
  const isStdio = transport === "stdio" || mode === "edge-bare";

  const show = (sel, on) => {
    const el = $(sel);
    if (el) el.hidden = !on;
  };

  show("#beFieldUrl", isRemote);
  show("#beFieldApiKey", isRemote);
  show("#beHdrEditor", isRemote);
  show("#beFieldDevice", isEdge);
  show("#beFieldCommand", !isRemote && isStdio);
  show("#beFieldImage", !isRemote && isOci);
  show("#beEnvEditor", !isRemote);

  const hint = $("#beModeHint");
  if (hint) hint.textContent = BE_MODE_HINTS[mode] || "";
}

function backendEndpointCell(b) {
  const label = backendTargetLabel(b);
  return `<td class="mono" title="${esc(label)}">${esc(truncateUrl(label, 40))}</td>`;
}

function addBackendFormHtml(modes, devices) {
  return surface(
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
          <span class="field-label">Enabled</span>
          <label class="form-check">
            <input type="checkbox" id="beEnable" checked />
            <span>enable on create</span>
          </label>
        </div>
        <div class="form-field" style="grid-column: 1 / -1">
          <span class="field-label">Placement</span>
          <div class="seg role-seg" id="beModeSeg" role="group" aria-label="Placement">
            ${placementSegHtml(modes, "remote")}
          </div>
          <input type="hidden" id="beMode" value="remote" />
        </div>
        <div class="form-field" id="beFieldTransport" style="grid-column: 1 / -1">
          <span class="field-label">Transport</span>
          <div class="seg role-seg" id="beTransportSeg" role="group" aria-label="Transport">
            ${transportSegHtml("remote", "streamable-http")}
          </div>
          <input type="hidden" id="beTransport" value="streamable-http" />
        </div>
        <div class="form-field" id="beFieldDevice" hidden style="grid-column: 1 / -1">
          <label class="field-label" for="beDevice">Edge device</label>
          <select id="beDevice">${deviceOptionsHtml(devices)}</select>
        </div>
        <div class="form-field" id="beFieldUrl" style="grid-column: 1 / -1">
          <label class="field-label" for="beUrl">URL</label>
          <input id="beUrl" placeholder="https://mcp.example.com/mcp" autocomplete="off" />
        </div>
        <div class="form-field" id="beFieldApiKey" style="grid-column: 1 / -1">
          <label class="field-label" for="beApiKey">API key</label>
          <input id="beApiKey" type="password" placeholder="of_…  (Bearer added automatically)" autocomplete="off" />
          <span class="dim" style="font-size:11px;margin-top:4px">Sealed as Authorization. Extra headers below are optional.</span>
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
      </div>
      <div class="hdr-editor" id="beHdrEditor">
        <div class="hdr-editor-head">
          <span class="field-label" style="margin:0">Request headers</span>
          <button type="button" class="pill-btn ghost" data-hdr-add>+ Add header</button>
        </div>
        <div data-hdr-list class="hdr-list"></div>
        <p class="dim hdr-hint">
          Empty rows are ignored. A raw API key is sent as
          <span class="mono">Authorization: Bearer &lt;token&gt;</span>.
        </p>
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
  );
}

function backendsTableHtml(backends) {
  return surface(
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
  );
}

async function onCreateBackend() {
  try {
    const slug = $("#beSlug").value.trim();
    if (!slug) throw new Error("slug required");
    const mode = $("#beMode").value || "remote";
    const enabled = $("#beEnable").checked;
    const body = { slug, enabled, placement: { mode } };
    const transport = $("#beTransport")?.value || (mode === "remote" ? "streamable-http" : "stdio");
    body.transport = mode === "edge-bare" ? "stdio" : transport;

    if (mode === "remote") {
      const url = $("#beUrl").value.trim();
      if (!url) throw new Error("url required");
      body.url = url;
      const headers = collectHeaderPairs($("#beHdrEditor") || document);
      const apiKey = $("#beApiKey")?.value?.trim();
      if (apiKey) body.apiKey = apiKey;
      if (Object.keys(headers).length) body.headers = headers;
    } else {
      if (mode === "edge-sandbox" || mode === "edge-bare") {
        const deviceId = $("#beDevice")?.value?.trim();
        if (!deviceId) throw new Error("edge device required");
        body.placement.deviceId = deviceId;
      }
      if (body.transport === "oci") {
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
    const apiKeyEl = $("#beApiKey");
    if (apiKeyEl) apiKeyEl.value = "";
    await renderBackends();
  } catch (e) {
    showErr(e.message);
  }
}

function wireBackendForm() {
  beTransportKind = "";
  wireKvEditor($("#beHdrEditor"), "hdr");
  wireKvEditor($("#beEnvEditor"), "env");
  wirePlacementSeg($("#beModeSeg"));
  wireTransportSeg($("#beTransportSeg"));
  $("#beCreate")?.addEventListener("click", () => void onCreateBackend());
  syncBackendFormFields();
}

function wireBackendTable(root) {
  const scope = root || $("#beListMount") || document;
  scope.querySelectorAll("[data-test]").forEach((btn) => {
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
  scope.querySelectorAll("[data-toggle]").forEach((btn) => {
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
  scope.querySelectorAll("[data-del]").forEach((btn) => {
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

async function renderBackends() {
  const [{ backends }, devicesRes, wsRes] = await Promise.all([
    api("/v1/backends"),
    soft("backends", "Devices", api("/v1/devices"), () => ({ devices: [] })),
    soft("backends", "Workspace placement modes", api("/v1/workspace"), () => ({ placementModes: ["remote", "central-sandbox"] })),
  ]);
  const devices = devicesRes.devices || [];
  const modes = wsRes.placementModes || ["remote", "central-sandbox"];
  const formMounted = Boolean($("#beAddForm"));

  if (!formMounted) {
    $("#tab-backends").innerHTML = `
      <div id="beAddForm">${addBackendFormHtml(modes, devices)}</div>
      <div id="beListMount"></div>
    `;
    wireBackendForm();
  } else {
    updatePlacementSeg(modes);
    updateDeviceSelect(devices);
  }

  const list = $("#beListMount");
  if (list) {
    list.innerHTML = backendsTableHtml(backends);
    wireBackendTable(list);
  }
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

async function renderProjects() {
  const [{ projects }, { backends }] = await Promise.all([
    api("/v1/projects"),
    api("/v1/backends"),
  ]);
  const beOpts = backends
    .map(
      (b) =>
        `<label class="form-check"><input type="checkbox" data-be-slug="${esc(b.slug)}" /> <span class="mono">${esc(b.slug)}</span></label>`,
    )
    .join("");

  $("#tab-projects").innerHTML = `
    ${surface(
      "Create project",
      `
      <p class="muted" style="margin-bottom:12px">
        Projects are tool collections. Agents call <span class="mono">mf_use_project</span> to switch;
        only member backends appear in tools/list.
      </p>
      <div class="form-grid">
        <div class="form-field">
          <label class="field-label" for="projSlug">Slug</label>
          <input id="projSlug" placeholder="webdevelopment" autocomplete="off" />
        </div>
        <div class="form-field">
          <label class="field-label" for="projTitle">Title</label>
          <input id="projTitle" placeholder="Web development" autocomplete="off" />
        </div>
        <div class="form-field" style="grid-column:1/-1">
          <span class="field-label">Backends</span>
          <div class="proj-be-grid" id="projBeGrid">${beOpts || '<span class="muted">No backends yet</span>'}</div>
        </div>
        <div class="form-field">
          <span class="field-label">&nbsp;</span>
          <button type="button" id="projCreate" class="pill-btn primary">Create project</button>
        </div>
      </div>
    `,
      "collections",
    )}
    ${surface(
      "Projects",
      `
      <div class="table-wrap">
        <table class="data-table">
          <thead>
            <tr><th>slug</th><th>title</th><th>backends</th><th></th><th></th></tr>
          </thead>
          <tbody>
            ${
              projects.length
                ? projects
                    .map(
                      (p) => `<tr>
              <td class="mono">${esc(p.slug)}${p.isDefault ? ' <span class="pill on">default</span>' : ""}</td>
              <td>${esc(p.title)}</td>
              <td class="mono">${esc((p.backendSlugs || []).join(", ") || "—")}</td>
              <td class="row-actions">
                <button type="button" class="pill-btn ghost" data-proj-edit="${esc(p.id)}" data-slug="${esc(p.slug)}">Edit backends</button>
              </td>
              <td>
                ${
                  p.slug === "default" || p.isDefault
                    ? '<span class="dim">—</span>'
                    : `<button type="button" class="pill-btn danger" data-proj-del="${esc(p.id)}" data-slug="${esc(p.slug)}">Delete</button>`
                }
              </td>
            </tr>`,
                    )
                    .join("")
                : `<tr><td colspan="5" class="muted">No projects</td></tr>`
            }
          </tbody>
        </table>
      </div>
      <div id="projEdit" class="once-callout" hidden style="border-color: rgba(91,141,239,0.35);margin-top:12px">
        <div class="once-label" style="color:var(--accent-hot)">Edit · <span id="projEditSlug"></span></div>
        <div class="proj-be-grid" id="projEditGrid"></div>
        <div class="row-actions" style="margin-top:12px">
          <button type="button" id="projSaveEdit" class="pill-btn primary">Save</button>
          <button type="button" id="projCancelEdit" class="pill-btn ghost">Cancel</button>
        </div>
        <input type="hidden" id="projEditId" />
      </div>
    `,
      `${projects.length} total`,
    )}`;

  $("#projCreate")?.addEventListener("click", async () => {
    try {
      const slug = $("#projSlug").value.trim();
      if (!slug) throw new Error("slug required");
      const backendSlugs = [
        ...document.querySelectorAll("#projBeGrid [data-be-slug]:checked"),
      ].map((el) => el.getAttribute("data-be-slug"));
      await api("/v1/projects", {
        method: "POST",
        body: JSON.stringify({
          slug,
          title: $("#projTitle").value.trim() || slug,
          backendSlugs,
        }),
      });
      await renderProjects();
    } catch (e) {
      showErr(e.message);
    }
  });

  document.querySelectorAll("[data-proj-del]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Delete project “${btn.getAttribute("data-slug")}”?`)) return;
      try {
        await api(`/v1/projects/${btn.getAttribute("data-proj-del")}`, {
          method: "DELETE",
        });
        await renderProjects();
      } catch (e) {
        showErr(e.message);
      }
    });
  });

  document.querySelectorAll("[data-proj-edit]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-proj-edit");
      const p = projects.find((x) => x.id === id);
      if (!p) return;
      $("#projEdit").hidden = false;
      $("#projEditId").value = id;
      $("#projEditSlug").textContent = p.slug;
      const set = new Set(p.backendSlugs || []);
      $("#projEditGrid").innerHTML = backends
        .map(
          (b) =>
            `<label class="form-check"><input type="checkbox" data-edit-be="${esc(b.slug)}" ${set.has(b.slug) ? "checked" : ""}/> <span class="mono">${esc(b.slug)}</span></label>`,
        )
        .join("");
    });
  });

  $("#projCancelEdit")?.addEventListener("click", () => {
    $("#projEdit").hidden = true;
  });
  $("#projSaveEdit")?.addEventListener("click", async () => {
    try {
      const id = $("#projEditId").value;
      const backendSlugs = [
        ...document.querySelectorAll("#projEditGrid [data-edit-be]:checked"),
      ].map((el) => el.getAttribute("data-edit-be"));
      await api(`/v1/projects/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ backendSlugs }),
      });
      await renderProjects();
    } catch (e) {
      showErr(e.message);
    }
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

function auditKeyHtml(e) {
  if (e.keyName) {
    return `<span class="audit-key" title="${esc(e.keyId || "")}">
      <span class="audit-key-name">${esc(e.keyName)}</span>
      ${e.keyPrefix ? `<span class="mono audit-key-prefix">${esc(e.keyPrefix)}</span>` : ""}
    </span>`;
  }
  if (e.keyId) {
    const short = String(e.keyId).length > 14 ? `${String(e.keyId).slice(0, 12)}…` : e.keyId;
    return `<span class="pill off" title="${esc(e.keyId)}">key ${esc(short)}</span>`;
  }
  return `<span class="pill off">env / system</span>`;
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
                ${auditKeyHtml(e)}
                <span class="mono dim">${esc(e.backendSlug || "")}</span>
                <span class="mono dim">${esc(e.deviceId || "")}</span>
                <span class="audit-meta">${auditStatusPills(d)}</span>
              </span>
            </button>
            <div class="audit-expand" data-audit-body hidden>
              ${
                expandable
                  ? `<div class="audit-actor">
                      <span class="mute">actor</span>
                      ${auditKeyHtml(e)}
                      <span class="mono dim">${esc(e.keyId || "no key id")}</span>
                    </div>${auditExpandBody(d)}`
                  : ""
              }
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
          Actor is the API key that performed the action. Click a row to expand request / response (redacted, size-capped).
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

let approvalsPoll = null;
let approvalsTick = null;
let lastPendingSig = "";
let lastMfaBeginSecret = "";
let lastPushNote = "";
let deferredInstallPrompt = null;
let adminSwReg = null;

function approvalsDeepId() {
  const m = /^#approvals\/([^/?#]+)/.exec(location.hash || "");
  return m ? decodeURIComponent(m[1]) : "";
}

function isIosSafari() {
  const ua = navigator.userAgent || "";
  return (
    /iPad|iPhone|iPod/.test(ua) ||
    (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1)
  );
}

function urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i += 1) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function pushCapabilityNote() {
  if (!window.isSecureContext) {
    return "Push needs HTTPS (or localhost). This origin is not a secure context.";
  }
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    return "This browser does not support Web Push.";
  }
  if (isIosSafari()) {
    return "iPhone/iPad: Share → Add to Home Screen, open the installed Admin, then Enable push. Notification buttons may be missing — tap the banner to open Admin. TOTP is never in the payload.";
  }
  return "Enable push on this device. For notify_approve, Approve/Deny is on the notification. MFA still opens Admin — TOTP is never in the payload.";
}

async function ensureAdminServiceWorker() {
  if (!("serviceWorker" in navigator)) return null;
  if (adminSwReg) return adminSwReg;
  adminSwReg = await navigator.serviceWorker.register("/admin/sw.js", {
    scope: "/admin/",
  });
  return adminSwReg;
}

async function enablePushOnThisDevice() {
  if (!window.isSecureContext) {
    throw new Error("Push needs HTTPS (or localhost)");
  }
  if (!("Notification" in window) || !("PushManager" in window)) {
    throw new Error("Web Push is not available in this browser");
  }
  const reg = await ensureAdminServiceWorker();
  if (!reg) throw new Error("Service worker not available");
  const perm = await Notification.requestPermission();
  if (perm !== "granted") throw new Error("Notification permission denied");
  const vapid = await api("/v1/push/vapid");
  const sub = await reg.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: urlBase64ToUint8Array(vapid.publicKey),
  });
  const json = sub.toJSON();
  await api("/v1/push/subscriptions", {
    method: "POST",
    body: JSON.stringify({
      endpoint: json.endpoint,
      keys: json.keys,
    }),
  });
}

function stopApprovalsPoll() {
  if (approvalsPoll) {
    clearInterval(approvalsPoll);
    approvalsPoll = null;
  }
  if (approvalsTick) {
    clearInterval(approvalsTick);
    approvalsTick = null;
  }
}

function needsMfa(req) {
  return req === "mfa" || req === "mfa_and_approve";
}

function csvList(raw) {
  return String(raw || "")
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function matchSummary(match) {
  const m = match || {};
  const parts = [];
  if (m.tools?.length) parts.push(`tools ${m.tools.join(", ")}`);
  if (m.prefixes?.length) parts.push(`prefix ${m.prefixes.join(", ")}`);
  if (m.backends?.length) parts.push(`backend ${m.backends.join(", ")}`);
  if (m.placements?.length) parts.push(`place ${m.placements.join(", ")}`);
  if (m.keyIds?.length) parts.push(`${m.keyIds.length} key(s)`);
  return parts.join(" · ") || "—";
}

async function renderApprovals(force = false) {
  const highlight = approvalsDeepId();
  const [inbox, rulesRes, mfa, vapidRes, subsRes] = await Promise.all([
    api("/v1/approvals?status=pending"),
    api("/v1/authz/rules"),
    api("/v1/operators/mfa"),
    soft("approvals", "Web Push key", api("/v1/push/vapid"), () => null),
    soft("approvals", "Push subscriptions", api("/v1/push/subscriptions"), () => ({ subscriptions: [] })),
  ]);
  const pending = inbox.approvals || [];
  const rules = rulesRes.rules || [];
  const enrolled = !!mfa?.enrolled;
  const pushSubs = subsRes?.subscriptions || [];
  const sig = pending.map((a) => a.id).join(",");
  const focusIn =
    document.activeElement &&
    $("#tab-approvals")?.contains(document.activeElement);
  if (!force && sig === lastPendingSig && focusIn) {
    return;
  }
  lastPendingSig = sig;

  const cards = pending.length
    ? pending
        .map((a) => {
          const mfaNeed = needsMfa(a.requirement);
          const hi = a.id === highlight ? " highlight" : "";
          const args = a.arguments
            ? esc(JSON.stringify(a.arguments, null, 2))
            : "<span class='muted'>(none)</span>";
          return `
          <article class="approval-card${hi}" data-approval-id="${esc(a.id)}">
            <div class="approval-head">
              <span class="approval-tool">${esc(a.tool)}</span>
              <span class="approval-count" data-remain="${esc(a.expiresAt)}">${esc(String(a.remainingSeconds ?? 0))}s</span>
            </div>
            <div class="approval-meta">
              <span class="pill vault">${esc(a.requirement)}</span>
              ${a.ruleName ? `<span class="pill accent">${esc(a.ruleName)}</span>` : ""}
              <span class="pill">${esc(a.keyName || "key")} <span class="mono">${esc(a.keyPrefix || "")}</span></span>
              ${a.backendSlug ? `<span class="pill">${esc(a.backendSlug)}</span>` : ""}
            </div>
            <pre class="approval-args">${args}</pre>
            ${
              mfaNeed
                ? `<label class="form-field"><span>TOTP</span><input class="mono" data-appr-totp="${esc(a.id)}" inputmode="numeric" maxlength="8" placeholder="123456" autocomplete="one-time-code" /></label>`
                : ""
            }
            <div class="row-actions">
              <button type="button" class="pill-btn primary" data-appr-decide="approve" data-id="${esc(a.id)}">Approve</button>
              <button type="button" class="pill-btn deny" data-appr-decide="deny" data-id="${esc(a.id)}">Deny</button>
            </div>
          </article>`;
        })
        .join("")
    : `<p class="muted">No pending approvals. Gated tools hold <span class="mono">tools/call</span> for up to 3 minutes until you tap Approve.</p>`;

  const ruleRows = rules.length
    ? rules
        .map(
          (r) => `
        <tr>
          <td>${esc(r.name)}</td>
          <td class="mono">${esc(matchSummary(r.match))}</td>
          <td><span class="pill ${r.enabled ? "on" : "off"}">${r.enabled ? "on" : "off"}</span></td>
          <td class="mono">${esc(r.requirement)}</td>
          <td class="mono">${esc(String(r.ttlSeconds))}s</td>
          <td>
            <div class="row-actions">
              <button type="button" class="pill-btn ghost" data-rule-toggle="${esc(r.id)}" data-enabled="${r.enabled ? "1" : "0"}">${r.enabled ? "Disable" : "Enable"}</button>
              <button type="button" class="pill-btn deny" data-rule-del="${esc(r.id)}">Delete</button>
            </div>
          </td>
        </tr>`,
        )
        .join("")
    : `<tr><td colspan="6" class="muted">No rules. Default workspace: no extra gates.</td></tr>`;

  $("#tab-approvals").innerHTML = `
    ${surface(
      "Inbox",
      `<div class="inbox-stack">${cards}</div>`,
      `${pending.length} pending · ${inbox.waiting ?? 0} waiting`,
    )}
    ${surface(
      "This device",
      `
      <p class="muted">${esc(pushCapabilityNote())}</p>
      <div class="row-actions" style="margin-top:10px">
        <button type="button" class="pill-btn primary" id="pushEnable">Enable push</button>
        <button type="button" class="pill-btn ghost" id="pwaInstall" ${deferredInstallPrompt ? "" : "hidden"}>Install Admin</button>
      </div>
      <p class="muted push-status" id="pushStatus">${esc(
        lastPushNote ||
          (pushSubs.length
            ? `${pushSubs.length} push subscription${pushSubs.length === 1 ? "" : "s"} on this workspace.`
            : vapidRes?.publicKey
              ? "VAPID ready. Install Admin on a phone, then Enable push."
              : ""),
      )}</p>
      ${
        pushSubs.length
          ? `<ul class="push-sub-list">${pushSubs
              .map(
                (s) => `
            <li>
              <span class="mono">${esc(s.endpointHint)}</span>
              <button type="button" class="pill-btn ghost" data-push-del="${esc(s.id)}">Remove</button>
            </li>`,
              )
              .join("")}</ul>`
          : `<p class="muted" style="margin-top:10px">No push subscriptions on this workspace yet.</p>`
      }`,
      `${pushSubs.length} subscription${pushSubs.length === 1 ? "" : "s"}`,
    )}
    ${surface(
      "Operator MFA (TOTP)",
      enrolled
        ? `
        <p class="muted">Enrolled. Required when a rule uses <span class="mono">mfa</span> or <span class="mono">mfa_and_approve</span>.</p>
        <div class="form-grid">
          <label class="form-field"><span>Current TOTP to disable</span><input id="mfaDisableTotp" class="mono" inputmode="numeric" maxlength="8" /></label>
        </div>
        <div class="row-actions" style="margin-top:10px">
          <button type="button" class="pill-btn deny" id="mfaDisable">Disable MFA</button>
        </div>`
        : `
        <p class="muted">Enroll a TOTP app for this operator (env admin or admin key). Secret is shown once.</p>
        <div class="row-actions">
          <button type="button" class="pill-btn primary" id="mfaBegin">Begin enroll</button>
        </div>
        <div id="mfaBeginOut" ${lastMfaBeginSecret ? "" : "hidden"}>
          ${
            lastMfaBeginSecret
              ? `<p class="muted" style="margin:12px 0 6px">Secret (once)</p><div class="mfa-secret">${esc(lastMfaBeginSecret)}</div>`
              : ""
          }
          <div class="form-grid" style="margin-top:12px">
            <label class="form-field"><span>Confirm TOTP</span><input id="mfaConfirmTotp" class="mono" inputmode="numeric" maxlength="8" /></label>
          </div>
          <div class="row-actions" style="margin-top:10px">
            <button type="button" class="pill-btn primary" id="mfaConfirm">Confirm</button>
          </div>
        </div>`,
      enrolled ? "enrolled" : "not enrolled",
    )}
    ${surface(
      "Rules",
      `
      <p class="muted" style="margin-bottom:12px">
        Extra gate after scopes / projects. Empty match is rejected. Discovery metas stay ungated.
        Wait default 180s (proxy idle timeout should be ≥ 4 minutes).
        Many MCP clients abort at 60s — raise the client timeout or lower wait seconds.
      </p>
      <form id="ruleForm" class="form-grid">
        <label class="form-field"><span>Name</span><input name="name" required placeholder="Destructive github" /></label>
        <label class="form-field"><span>Requirement</span>
          <select name="requirement">
            <option value="notify_approve">notify_approve</option>
            <option value="mfa">mfa</option>
            <option value="mfa_and_approve">mfa_and_approve</option>
          </select>
        </label>
        <label class="form-field"><span>Wait seconds</span><input name="ttlSeconds" type="number" min="1" max="600" value="180" /></label>
        <label class="form-field"><span>Priority</span><input name="priority" type="number" value="0" /></label>
        <label class="form-field" style="grid-column:1/-1"><span>Exact tools (comma)</span><input name="tools" class="mono" placeholder="github__delete_repo" /></label>
        <label class="form-field"><span>Prefixes</span><input name="prefixes" class="mono" placeholder="shell__, fs__" /></label>
        <label class="form-field"><span>Backends</span><input name="backends" class="mono" placeholder="github" /></label>
        <label class="form-field"><span>Placements</span><input name="placements" class="mono" placeholder="edge-bare" /></label>
        <div class="row-actions" style="grid-column:1/-1">
          <button type="submit" class="pill-btn primary">Add rule</button>
        </div>
      </form>
      <table class="data-table" style="margin-top:16px">
        <thead><tr><th>Name</th><th>Match</th><th>On</th><th>Req</th><th>TTL</th><th></th></tr></thead>
        <tbody>${ruleRows}</tbody>
      </table>`,
      `${rules.length} rules`,
    )}`;

  $("#tab-approvals")?.querySelectorAll("[data-appr-decide]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-id");
      const decision = btn.getAttribute("data-appr-decide");
      const totpEl = $(`[data-appr-totp="${CSS.escape(id)}"]`);
      try {
        await api(`/v1/approvals/${id}/decision`, {
          method: "POST",
          body: JSON.stringify({
            decision,
            totp: totpEl ? totpEl.value.trim() : undefined,
          }),
        });
        await renderApprovals(true);
      } catch (e) {
        showErr(e.message);
      }
    });
  });

  $("#ruleForm")?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const fd = new FormData(ev.target);
    const match = {
      tools: csvList(fd.get("tools")),
      prefixes: csvList(fd.get("prefixes")),
      backends: csvList(fd.get("backends")),
      placements: csvList(fd.get("placements")),
    };
    try {
      await api("/v1/authz/rules", {
        method: "POST",
        body: JSON.stringify({
          name: fd.get("name"),
          requirement: fd.get("requirement"),
          ttlSeconds: Number(fd.get("ttlSeconds") || 180),
          priority: Number(fd.get("priority") || 0),
          match,
        }),
      });
      await renderApprovals(true);
    } catch (e) {
      showErr(e.message);
    }
  });

  $("#tab-approvals")?.querySelectorAll("[data-rule-del]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/v1/authz/rules/${btn.getAttribute("data-rule-del")}`, {
          method: "DELETE",
        });
        await renderApprovals(true);
      } catch (e) {
        showErr(e.message);
      }
    });
  });

  $("#tab-approvals")?.querySelectorAll("[data-rule-toggle]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.getAttribute("data-rule-toggle");
      const enabled = btn.getAttribute("data-enabled") !== "1";
      try {
        await api(`/v1/authz/rules/${id}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled }),
        });
        await renderApprovals(true);
      } catch (e) {
        showErr(e.message);
      }
    });
  });

  $("#mfaBegin")?.addEventListener("click", async () => {
    try {
      const body = await api("/v1/operators/mfa/begin", {
        method: "POST",
        body: JSON.stringify({}),
      });
      lastMfaBeginSecret = body.secret || "";
      await renderApprovals(true);
    } catch (e) {
      showErr(e.message);
    }
  });

  $("#mfaConfirm")?.addEventListener("click", async () => {
    try {
      await api("/v1/operators/mfa/confirm", {
        method: "POST",
        body: JSON.stringify({ totp: $("#mfaConfirmTotp")?.value?.trim() }),
      });
      lastMfaBeginSecret = "";
      await renderApprovals(true);
    } catch (e) {
      showErr(e.message);
    }
  });

  $("#mfaDisable")?.addEventListener("click", async () => {
    try {
      await api("/v1/operators/mfa/disable", {
        method: "POST",
        body: JSON.stringify({ totp: $("#mfaDisableTotp")?.value?.trim() }),
      });
      await renderApprovals(true);
    } catch (e) {
      showErr(e.message);
    }
  });

  $("#pushEnable")?.addEventListener("click", async () => {
    try {
      await enablePushOnThisDevice();
      lastPushNote = "Push enabled on this device.";
      await renderApprovals(true);
    } catch (e) {
      lastPushNote = e.message || String(e);
      showErr(e.message);
      const statusEl = $("#pushStatus");
      if (statusEl) statusEl.textContent = lastPushNote;
    }
  });

  $("#pwaInstall")?.addEventListener("click", async () => {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    const btn = $("#pwaInstall");
    if (btn) btn.hidden = true;
  });

  $("#tab-approvals")?.querySelectorAll("[data-push-del]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/v1/push/subscriptions/${btn.getAttribute("data-push-del")}`, {
          method: "DELETE",
        });
        lastPushNote = "Subscription removed.";
        await renderApprovals(true);
      } catch (e) {
        showErr(e.message);
      }
    });
  });

  if (highlight) {
    const el = $(`[data-approval-id="${CSS.escape(highlight)}"]`);
    el?.scrollIntoView({ block: "center" });
  }

  const tickRemain = () => {
    document.querySelectorAll("[data-remain]").forEach((el) => {
      const exp = Date.parse(el.getAttribute("data-remain") || "");
      const sec = Number.isFinite(exp)
        ? Math.max(0, Math.ceil((exp - Date.now()) / 1000))
        : 0;
      el.textContent = `${sec}s`;
    });
  };
  if (approvalsTick) clearInterval(approvalsTick);
  approvalsTick = setInterval(tickRemain, 1000);

  if (!approvalsPoll) {
    approvalsPoll = setInterval(() => {
      const tab =
        document.querySelector(".tabs .seg-btn.active")?.dataset.tab;
      if (tab === "approvals") void renderApprovals();
    }, 2000);
  }
}

// ---------------------------------------------------------------------------
// T2.3 Call approvals (per-call policy, /v1/policy/approvals)
//
// These routes authenticate a *human agent* (mf_… key or mf_sess_… session),
// NOT the admin token, so this panel keeps its own approver credential in
// sessionStorage. Only the documented endpoints are used:
//   GET /pending, GET /history, GET /:id, POST /:id/approve|deny|approve-similar
// ---------------------------------------------------------------------------
const APPROVER_TOKEN_KEY = "mcp_flow_approver_token";
const PA_BASE = "/v1/policy/approvals";
let paPollTimer = null;
let paView = "pending";
let paReprompt = false;
// H-1: per-call detail from GET /:id (args_full + args_sha256), keyed by call id.
// Approve / deny / approve-similar stay disabled until a detail for that id is
// loaded and usable. Held in memory only; cleared on any stale/mismatch error.
const paDetails = new Map(); // id -> { call, err, code, notice, hashCheck }
// 404 = "not visible to you" (not stale): hide the item, no retry.
const paHidden = new Set();
// V3-F1: decision notices (404 / 409 not_pending|expired) persist as
// dismissible banners. List refreshes, the 8 s poll and later successful
// decisions never clear them; only the user's "Dismiss" does.
const paNotices = []; // { key, text }
let paNoticeSeq = 0;
function addPaNotice(text) {
  if (!text || paNotices.some((n) => n.text === text)) return;
  paNotices.push({ key: String(++paNoticeSeq), text });
  if (paNotices.length > 5) paNotices.shift();
}
function paNoticesHtml() {
  return paNotices
    .map((n) => `<div class="pa-banner" role="status"><span>${esc(n.text)}</span><button type="button" class="pill-btn ghost" data-pa-dismiss="${esc(n.key)}">Dismiss</button></div>`)
    .join("");
}

function approverToken() {
  return sessionStorage.getItem(APPROVER_TOKEN_KEY) || "";
}

async function approverApi(path, opts = {}) {
  const t = approverToken();
  if (!t) throw new Error("Set an approver key (human agent mf_… key or session) first");
  const res = await fetch(`${PA_BASE}${path}`, {
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
    const code = body.error || res.statusText || String(res.status);
    // 401: drop ONLY the approver key; the admin token is untouched.
    if (res.status === 401 && approverToken() === t) {
      sessionStorage.removeItem(APPROVER_TOKEN_KEY);
      paDetails.clear();
      paReprompt = true;
      stopPolicyApprovalsPoll();
    }
    const friendly = {
      unauthorized: `${REPROMPT_MSG}. (Approver key rejected — use a human agent key or session; the admin token isn't accepted here.)`,
      "approvers must be human agents": "This key belongs to a non-human agent; only human agents can approve.",
      self_approval: "You can't approve your own call.",
      not_approver: "You are not an approver for this call.",
      not_found: "This call isn't available to you.",
      args_sha256_required: "The request was missing a valid args hash (400). Nothing was approved — reload the call and try again.",
      not_pending: "Already decided by another approver.",
      args_mismatch: "The call's arguments changed since you reviewed them. Reloaded the exact payload — review it again before deciding.",
      args_integrity: "The stored payload failed its integrity check. Nothing will run; this call can't be approved.",
      expired: "This call expired (a timeout counts as deny).",
    }[code];
    const err = new Error(friendly || (res.status === 403 ? notPermittedMsg(code) : code));
    err.code = code;
    err.status = res.status;
    throw err;
  }
  return body;
}

function stopPolicyApprovalsPoll() {
  if (paPollTimer) {
    clearInterval(paPollTimer);
    paPollTimer = null;
  }
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}

function fmtRemaining(iso) {
  const ms = new Date(iso).getTime() - Date.now();
  if (!Number.isFinite(ms)) return "";
  if (ms <= 0) return "expired";
  const s = Math.round(ms / 1000);
  return s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s left` : `${s}s left`;
}

/**
 * matched_rules item shape is ILLUSTRATIVE per the API doc. Render known-ish
 * fields when present, otherwise fall back to readable JSON. Never assume.
 */
function matchedRulesHtml(rules) {
  if (rules == null) return '<span class="muted">none reported</span>';
  if (!Array.isArray(rules)) return `<pre class="audit-payload">${esc(prettyJson(rules))}</pre>`;
  if (!rules.length) return '<span class="muted">none</span>';
  return rules
    .map((r) => {
      if (r == null || typeof r !== "object") {
        return `<div class="pa-rule"><span class="mono">${esc(String(r))}</span></div>`;
      }
      const id = r.rule_id ?? r.id ?? r.ruleId;
      const name = r.name ?? r.rule_name;
      const effect = r.effect ?? r.action ?? r.decision;
      const version = r.version;
      const known = new Set(["rule_id", "id", "ruleId", "name", "rule_name", "effect", "action", "decision", "version"]);
      const extra = Object.fromEntries(Object.entries(r).filter(([k]) => !known.has(k)));
      const head = [
        effect != null ? `<span class="pill ${effect === "deny" ? "deny" : effect === "allow" ? "on" : "warn"}">${esc(String(effect))}</span>` : "",
        name != null ? `<span>${esc(String(name))}</span>` : "",
        id != null ? `<span class="mono muted">${esc(String(id))}</span>` : "",
        version != null ? `<span class="muted">v${esc(String(version))}</span>` : "",
      ].filter(Boolean).join(" ");
      const extraHtml = Object.keys(extra).length
        ? `<pre class="audit-payload">${esc(prettyJson(extra))}</pre>`
        : "";
      return `<div class="pa-rule">${head || `<pre class="audit-payload">${esc(prettyJson(r))}</pre>`}${head ? extraHtml : ""}</div>`;
    })
    .join("");
}

function paStatusPill(st) {
  const cls = { pending: "warn", approved: "on", denied: "deny", expired: "off", cancelled: "off" }[st] || "off";
  return `<span class="pill ${cls}">${esc(st || "unknown")}</span>`;
}

// Mirrors src/policy/crypto.ts exactly: JSON.stringify(sortDeep(v)). Keys
// sorted recursively by default Array.prototype.sort (UTF-16 code units),
// array order kept, no whitespace, JS number formatting, no Unicode
// normalization, standard JSON.stringify escaping. Hashed as UTF-8, lowercase hex.
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortDeep(v[k]);
    return out;
  }
  return v;
}

function canonicalJson(v) {
  return JSON.stringify(sortDeep(v));
}

/** Advisory client-side check; the server is authoritative (409 args_mismatch). */
async function sha256Hex(text) {
  if (!globalThis.crypto?.subtle) return null;
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function loadPaDetail(id, notice = "") {
  try {
    const call = await approverApi(`/${encodeURIComponent(id)}`);
    let hashCheck = "unavailable";
    if (call && call.args_full != null && typeof call.args_sha256 === "string") {
      const h = await sha256Hex(canonicalJson(call.args_full)).catch(() => null);
      hashCheck = h == null ? "unavailable" : h === call.args_sha256 ? "match" : "differs";
    }
    paDetails.set(id, { call, err: "", notice, hashCheck });
  } catch (e) {
    if (e.code === "not_found") {
      paDetails.delete(id);
      paHidden.add(id);
      addPaNotice("A call was removed: it isn't available to you.");
      return;
    }
    if (e.code === "not_pending" || e.code === "expired") {
      paDetails.delete(id);
      addPaNotice(e.code === "expired" ? "A call expired (timeout counts as deny)." : "A call was already resolved.");
      return;
    }
    paDetails.set(id, { call: null, err: e.message, code: e.code, notice, hashCheck: "unavailable" });
  }
}

/** Derive what the card may do from the GET /:id result. Fail closed. */
function paDetailState(id) {
  const d = paDetails.get(id);
  if (!d) return { ok: false, canDeny: false, msg: "Loading the exact payload…" };
  if (d.err && d.code === "args_integrity") {
    return { ...d, ok: false, canDeny: true, msg: "The stored args failed their integrity check. Nothing will run; approval is blocked — deny this call." };
  }
  if (d.err) return { ...d, ok: false, canDeny: false, msg: `Couldn't load the exact payload: ${d.err}. Approval is blocked.` };
  const c = d.call || {};
  if (c.status && c.status !== "pending") {
    return { ...d, ok: false, canDeny: false, msg: `This call is now ${c.status}; nothing to decide.` };
  }
  if (c.args_full === null) {
    // Per Q&A: args_full null on GET /:id means resolved and purged.
    return { ...d, ok: false, canDeny: false, msg: "This call was already resolved; its args were purged." };
  }
  if (c.args_full === undefined) {
    // Deny is still safe without the payload, but we only allow it once /:id loaded.
    return { ...d, ok: false, canDeny: true, msg: "The server didn't return the full args (args_full). Approval is blocked — you can still deny." };
  }
  if (typeof c.args_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(c.args_sha256)) {
    return { ...d, ok: false, canDeny: true, msg: "The server didn't return a valid args_sha256. Approval is blocked — you can still deny." };
  }
  if (d.hashCheck === "differs") {
    // R2-5: the payload shown doesn't hash to what the server will run. Fail closed.
    return { ...d, ok: false, canDeny: true, showPayload: true, msg: "The payload shown doesn't match the server's args_sha256 (local hash differs). Approval is blocked — you can still deny." };
  }
  return { ...d, ok: true, canDeny: true, msg: "" };
}

function paFullArgsHtml(det) {
  const c = det?.call;
  const notice = det?.notice ? `<p class="pa-warn">${esc(det.notice)}</p>` : "";
  if (!det?.ok && !det?.showPayload) {
    return `${notice}<div class="pa-full pa-blocked"><span class="field-label">Exact payload</span><p class="pa-warn">${esc(det?.msg || "")}</p></div>`;
  }
  const hidden = c.args_hidden_in_summary
    ? '<p class="pa-warn"><strong>Heads up:</strong> some of these args are hidden in the redacted summary. Review the full payload below before approving.</p>'
    : "";
  const hashNote = det.hashCheck === "differs"
    ? ' <span class="pill deny">local hash differs</span>'
    : det.hashCheck === "match" ? ' <span class="pill on">hash verified</span>' : "";
  // No crypto.subtle (plain HTTP, not localhost): approval stays allowed — the
  // server requires args_sha256 and returns 409 on mismatch — but say so.
  const noLocal = det.hashCheck === "unavailable"
    ? '<p class="pa-warn pa-nolocal">Local hash check unavailable on plain HTTP — the server still verifies the hash.</p>'
    : "";
  const blocked = det.ok ? "" : `<p class="pa-warn"><strong>${esc(det.msg)}</strong></p>`;
  return `${notice}
    <div class="pa-full ${det.ok ? "" : "pa-blocked"}"><span class="field-label">Exact payload that will run</span>${blocked}${hidden}
      <div class="pa-hash"><span class="muted">args_sha256</span> <span class="mono">${esc(c.args_sha256)}</span>${hashNote}</div>${noLocal}
      <details class="pa-full-details" open><summary>Full args (approvers only)</summary>
        <pre class="audit-payload">${esc(prettyJson(c.args_full))}</pre></details>
    </div>`;
}

function paCardHtml(c, actionable) {
  const id = String(c?.id ?? "");
  const agent = c?.agent && typeof c.agent === "object"
    ? `${esc(c.agent.name ?? "")} <span class="mono muted">${esc(c.agent.id ?? "")}</span>`
    : esc(c?.agent ?? "unknown agent");
  const tool = c?.qualified_tool ?? [c?.backend_slug, c?.tool].filter(Boolean).join("__");
  const args = c?.args_redacted;
  const det = actionable ? paDetailState(id) : null;
  const ready = !!det?.ok;
  const dis = ready ? "" : "disabled";
  return `
    <article class="approval-card pa-card" data-pa-id="${esc(id)}">
      <div class="approval-head">
        <div>
          <div class="mono pa-tool">${esc(tool || "unknown tool")}</div>
          <div class="muted">${agent} · project <span class="mono">${esc(c?.project_id ?? "—")}</span> · ${esc(c?.placement ?? "")}</div>
        </div>
        <div class="pa-head-right">
          ${paStatusPill(c?.status)}
          ${c?.status === "pending" && c?.expires_at ? `<span class="muted nowrap" data-pa-exp="${esc(c.expires_at)}">${esc(fmtRemaining(c.expires_at))}</span>` : ""}
        </div>
      </div>
      <div class="pa-reason"><span class="field-label">Reason</span>
        ${c?.reason ? `<div>${esc(c.reason)}</div>` : '<div class="muted">No reason given</div>'}
      </div>
      <div class="audit-split">
        <div class="audit-pane"><div class="audit-pane-head">Args (redacted)</div>
          <pre class="audit-payload">${esc(args === undefined ? "—" : prettyJson(args))}</pre></div>
        <div class="audit-pane"><div class="audit-pane-head">Matched rules</div>
          <div class="audit-pane-body">${matchedRulesHtml(c?.matched_rules)}</div></div>
      </div>
      ${actionable ? paFullArgsHtml(det) : ""}
      <div class="muted pa-meta">Requested ${esc(fmtTime(c?.created_at))}${c?.decided_at ? ` · decided ${esc(fmtTime(c.decided_at))} by <span class="mono">${esc(c.decided_by ?? "")}</span>` : ""}${c?.note ? ` · note: ${esc(c.note)}` : ""}${c?.grant_id ? ` · grant <span class="mono">${esc(c.grant_id)}</span>` : ""}</div>
      ${actionable ? `
      <div class="pa-actions">
        <input type="text" class="pa-note" maxlength="500" placeholder="Note (optional, ≤500 chars)" ${dis} />
        <div class="row-actions">
          <button type="button" class="pill-btn primary" data-pa-approve="${esc(id)}" ${dis}>Approve exact payload</button>
          <button type="button" class="pill-btn danger" data-pa-deny="${esc(id)}" ${det?.canDeny ? "" : "disabled"}>Deny</button>
        </div>
        <div class="row-actions pa-similar">
          <span class="muted">Approve similar calls (same agent, project, backend, tool) for</span>
          <input type="number" class="pa-minutes" min="1" max="60" step="1" value="15" aria-label="Minutes" ${dis} /> <span class="muted">min</span>
          <input type="number" class="pa-maxuses" min="1" step="1" placeholder="max uses" aria-label="Max uses" ${dis} />
          <label class="form-check" title="Broader grants need match_args matchers, which this UI doesn't offer yet"><input type="checkbox" class="pa-sameargs" checked disabled /> exact same args only</label>
          <button type="button" class="pill-btn ghost" data-pa-similar="${esc(id)}" ${dis}>Approve similar</button>
        </div>
        <p class="muted pa-hint">Scope: same agent, project, backend and tool, with exactly these args (hash above). Grants never override a deny rule.</p>
      </div>` : ""}
    </article>`;
}

async function renderPolicyApprovals() {
  const root = $("#tab-policy-approvals");
  const has = !!approverToken();
  let list = [];
  let loadErr = "";
  if (has) {
    try {
      if (paView === "pending") {
        const r = await approverApi("/pending?limit=50");
        list = (Array.isArray(r?.pending) ? r.pending : []).filter((c) => !paHidden.has(String(c?.id ?? "")));
        const live = new Set(list.map((c) => String(c?.id ?? "")));
        for (const k of [...paDetails.keys()]) if (!live.has(k)) paDetails.delete(k);
        await Promise.all(
          list
            .map((c) => String(c?.id ?? ""))
            .filter((cid) => cid && !paDetails.has(cid))
            .map((cid) => loadPaDetail(cid)),
        );
        list = list.filter((c) => !paHidden.has(String(c?.id ?? "")));
      } else {
        const r = await approverApi("/history?limit=50");
        list = Array.isArray(r?.calls) ? r.calls : [];
      }
    } catch (e) {
      loadErr = e.message;
    }
  }
  const hasNow = !!approverToken(); // may have been cleared by a 401 above
  const authHtml = `
    <div class="auth-row pa-auth">
      <input id="approverToken" type="password" placeholder="Approver key (human agent mf_… or mf_sess_…)" autocomplete="off" value="${hasNow ? "••••••••" : ""}" />
      <button id="saveApproverToken" type="button" class="pill-btn primary">Use key</button>
      ${hasNow ? '<button id="clearApproverToken" type="button" class="pill-btn ghost">Forget</button>' : ""}
    </div>
    <p class="muted">Per-call policy approvals use a human agent's key, not the admin token. Stored for this tab only.</p>
    <nav class="seg pa-seg" aria-label="Approval view">
      <button type="button" class="seg-btn ${paView === "pending" ? "active" : ""}" data-pa-view="pending">Pending</button>
      <button type="button" class="seg-btn ${paView === "history" ? "active" : ""}" data-pa-view="history">History</button>
    </nav>`;
  let body;
  if (!hasNow && paReprompt) body = `<p class="pa-warn" role="alert">${esc(REPROMPT_MSG)}</p>`;
  else if (!hasNow) body = '<p class="audit-empty">Enter an approver key to load calls.</p>';
  else if (loadErr) body = `<p class="err-inline">${esc(loadErr)}</p>`;
  else if (!list.length) body = `<p class="audit-empty">${paView === "pending" ? "Nothing waiting on you." : "No history yet."}</p>`;
  else body = list.map((c) => paCardHtml(c, paView === "pending" && c?.status === "pending")).join("");
  root.innerHTML = surface(
    "Call approvals",
    authHtml + paNoticesHtml() + `<div class="pa-list">${body}</div>`,
    hasNow && !loadErr ? `${list.length} ${paView}` : "",
  );

  $("#saveApproverToken")?.addEventListener("click", () => {
    const v = $("#approverToken").value.trim();
    if (v && v !== "••••••••") {
      sessionStorage.setItem(APPROVER_TOKEN_KEY, v);
      paDetails.clear();
      paReprompt = false;
    }
    void renderPolicyApprovals().catch((e) => showErr(e.message));
  });
  $("#clearApproverToken")?.addEventListener("click", () => {
    sessionStorage.removeItem(APPROVER_TOKEN_KEY);
    paDetails.clear();
    void renderPolicyApprovals();
  });
  root.querySelectorAll("[data-pa-dismiss]").forEach((b) =>
    b.addEventListener("click", () => {
      const i = paNotices.findIndex((n) => n.key === b.getAttribute("data-pa-dismiss"));
      if (i >= 0) paNotices.splice(i, 1);
      b.closest(".pa-banner")?.remove();
    }),
  );
  root.querySelectorAll("[data-pa-view]").forEach((b) =>
    b.addEventListener("click", () => {
      paView = b.getAttribute("data-pa-view");
      void renderPolicyApprovals();
    }),
  );

  // Never retries or auto-approves: on a stale/mismatch error we drop the
  // cached detail, refetch GET /:id and make the human review again.
  const decide = async (btn, id, action, body) => {
    btn.closest(".pa-card")?.querySelectorAll("button, input").forEach((el) => { el.disabled = true; });
    try {
      await approverApi(`/${encodeURIComponent(id)}/${action}`, { method: "POST", body: JSON.stringify(body) });
      paDetails.delete(id);
      showErr("");
    } catch (e) {
      if (e.code === "not_found") {
        paDetails.delete(id);
        paHidden.add(id);
        addPaNotice(e.message);
        showErr("");
      } else if (e.code === "not_pending" || e.code === "expired") {
        paDetails.delete(id);
        addPaNotice(e.code === "expired" ? "That call expired (timeout counts as deny)." : "That call was already resolved by another approver.");
        showErr("");
      } else if (e.code === "args_mismatch" || e.code === "args_integrity") {
        paDetails.delete(id);
        await loadPaDetail(id, e.message);
        if (e.code === "args_integrity" && paDetails.get(id) && !paDetails.get(id).err) {
          paDetails.set(id, { ...paDetails.get(id), err: e.message, code: "args_integrity" });
        }
        showErr("");
      } else {
        showErr(e.message);
      }
    }
    await renderPolicyApprovals();
  };
  const readyHash = (id) => {
    const st = paDetailState(id);
    if (!st.ok) {
      showErr(st.msg || "Approval blocked: exact payload not loaded");
      return null;
    }
    return st.call.args_sha256;
  };
  const noteOf = (btn) => {
    const v = btn.closest(".pa-card")?.querySelector(".pa-note")?.value.trim();
    return v ? { note: v } : {};
  };
  root.querySelectorAll("[data-pa-approve]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-pa-approve");
      const args_sha256 = readyHash(id);
      if (!args_sha256) return;
      void decide(btn, id, "approve", { ...noteOf(btn), args_sha256 });
    }),
  );
  root.querySelectorAll("[data-pa-deny]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const id = btn.getAttribute("data-pa-deny");
      if (!paDetailState(id).canDeny) {
        showErr("Load the exact payload before deciding");
        return;
      }
      void decide(btn, id, "deny", noteOf(btn));
    }),
  );
  root.querySelectorAll("[data-pa-similar]").forEach((btn) =>
    btn.addEventListener("click", () => {
      const card = btn.closest(".pa-card");
      const id = btn.getAttribute("data-pa-similar");
      const args_sha256 = readyHash(id);
      if (!args_sha256) return;
      const minutes = Number(card.querySelector(".pa-minutes").value);
      if (!Number.isInteger(minutes) || minutes < 1 || minutes > 60) {
        showErr("Minutes must be a whole number from 1 to 60");
        return;
      }
      // Exact-args grant only (API default; sent explicitly). Broader grants
      // need same_args_only:false + match_args, which this UI doesn't build.
      const body = { minutes, same_args_only: true, args_sha256, ...noteOf(btn) };
      const mu = card.querySelector(".pa-maxuses").value.trim();
      if (mu) {
        const n = Number(mu);
        if (!Number.isInteger(n) || n < 1) {
          showErr("Max uses must be a whole number ≥ 1");
          return;
        }
        body.max_uses = n;
      }
      void decide(btn, id, "approve-similar", body);
    }),
  );

  // Poll /pending every ~8 s while visible (doc suggests 5–10 s). Skip while
  // the user is typing in a card so inputs aren't wiped.
  stopPolicyApprovalsPoll();
  if (hasNow && paView === "pending") {
    paPollTimer = setInterval(() => {
      if (document.hidden) return;
      const active = document.activeElement;
      if (active && root.contains(active) && active.tagName === "INPUT") {
        root.querySelectorAll("[data-pa-exp]").forEach((el) => {
          el.textContent = fmtRemaining(el.getAttribute("data-pa-exp"));
        });
        return;
      }
      void renderPolicyApprovals().catch(() => undefined);
    }, 8000);
  }
}

// ---------------------------------------------------------------------------
// T3.4 Access map — which agent can reach which tool. (Legacy key-based
// fallback below; used only when GET /v1/agents is unavailable.)
//
// Built ONLY from existing admin read endpoints:
//   GET /v1/keys        (key scopes: projects, toolPrefixAllowlist, admin)
//   GET /v1/projects    (project → backendSlugs, toolPrefixAllowlist)
//   GET /v1/backends    (enabled, toolAllowlist)
//   GET /v1/authz/rules (legacy authz rules: which calls need approval)
//
// DATA GAPS (no read endpoint exists; intentionally NOT created here):
//   GAP-1: No REST list of agents (T1.1 `agents` table). Keys are the closest
//          proxy, so rows are API keys, not agents; human/bot kind unknown.
//   GAP-2: No REST list of per-call policy rules (T2.1 `policy_rules`, the
//          rules behind /v1/policy/approvals). Only legacy /v1/authz/rules is
//          shown; deny/require_approval from the new engine is not reflected.
//   GAP-3: No endpoint lists a backend's discovered tools. Unless a backend
//          has a toolAllowlist, the map can only say "all tools on <backend>".
//   GAP-4: Session-level dynamicTools / project selection isn't resolvable
//          server-side here; the map shows the static upper bound of reach.
// ---------------------------------------------------------------------------
function prefixOk(prefixes, name) {
  return !prefixes || !prefixes.length || prefixes.some((p) => name.startsWith(p));
}

function accessCell(key, backend, projects, rules) {
  const sc = key.scopes || {};
  if (!backend.enabled) return { level: "off", label: "backend disabled", tools: [] };
  const allowedProjects = sc.projects && sc.projects.length
    ? projects.filter((p) => sc.projects.includes(p.slug))
    : projects;
  const viaProjects = allowedProjects.filter((p) => (p.backendSlugs || []).includes(backend.slug));
  if (!viaProjects.length) return { level: "none", label: "—", tools: [] };
  const keyPrefixes = sc.toolPrefixAllowlist;
  const projPrefixSets = viaProjects.map((p) => p.toolPrefixAllowlist);
  const known = Array.isArray(backend.toolAllowlist) && backend.toolAllowlist.length
    ? backend.toolAllowlist.map((t) => `${backend.slug}__${t}`)
    : null;
  const ruleFor = (q) =>
    rules.filter((r) => {
      if (r.enabled === false) return false;
      const m = r.match || {};
      if (m.keyIds?.length && !m.keyIds.includes(key.id)) return false;
      if (m.backends?.length && !m.backends.includes(backend.slug)) return false;
      if (m.tools?.length || m.prefixes?.length) {
        if (!q) {
          // GAP-3: tool list unknown — rule may apply if it names this backend's namespace.
          const ns = `${backend.slug}__`;
          return (m.tools || []).some((t) => t.startsWith(ns)) ||
            (m.prefixes || []).some((p) => p.startsWith(ns) || ns.startsWith(p));
        }
        return (m.tools || []).includes(q) || (m.prefixes || []).some((p) => q.startsWith(p));
      }
      return true;
    });
  const passes = (q) => prefixOk(keyPrefixes, q) && projPrefixSets.some((ps) => prefixOk(ps, q));
  if (known) {
    const tools = known.filter(passes).map((q) => ({ name: q, gated: ruleFor(q).length > 0 }));
    if (!tools.length) return { level: "none", label: "filtered out", tools: [], via: viaProjects };
    return { level: tools.some((t) => t.gated) ? "gated" : "full", label: `${tools.length} tool${tools.length === 1 ? "" : "s"}`, tools, via: viaProjects };
  }
  // GAP-3: tool names unknown — describe reach by prefix filters instead.
  const filters = [...(keyPrefixes || []), ...projPrefixSets.flat().filter(Boolean)];
  const scoped = filters.length > 0;
  const prefixLive = !scoped || filters.some((f) => `${backend.slug}__`.startsWith(f) || f.startsWith(`${backend.slug}__`));
  if (!prefixLive) return { level: "none", label: "filtered out", tools: [], via: viaProjects };
  const gated = ruleFor(null).length > 0;
  return {
    level: gated ? "gated" : scoped ? "partial" : "full",
    label: scoped ? "prefix-limited" : "all tools",
    tools: [],
    filters,
    via: viaProjects,
  };
}

// ---- v2: agents × backends from the GAP-1..4 read endpoints (admin bearer) ----
//   GET /v1/agents               (GAP-1) rows = real agents
//   GET /v1/policy/rules         (GAP-2) new-engine rules (allow / require_approval / deny)
//   GET /v1/backends/:id/tools   (GAP-3) discovered tools per backend (column totals)
//   GET /v1/agents/:id/reach     per-tool effect computed server-side by the policy engine
// GAP-4 limitation (still): reach is static per agent+project. It ignores args
// ("conditional" = an arg-dependent rule decides) and doesn't model which
// project a live session has selected or dynamicTools enablement.
// Falls back to the key-based map below if /v1/agents isn't available.
const REACH_EFFECTS = [
  ["allow", "on", "allow"],
  ["require_approval", "warn", "approval"],
  ["conditional", "accent", "conditional"],
  ["denied", "deny", "denied"],
];

function ruleVersionSummary(v) {
  if (!v || typeof v !== "object") return `<pre class="audit-payload">${esc(prettyJson(v))}</pre>`;
  const list = (x) => (Array.isArray(x) && x.length ? x.map((i) => `<span class="mono">${esc(typeof i === "string" ? i : JSON.stringify(i))}</span>`).join(", ") : '<span class="muted">any</span>');
  return `agents ${list(v.match_agents)} · projects ${list(v.match_projects)} · backends ${list(v.match_backends)} · tools ${list(v.match_tools)}${Array.isArray(v.match_args) && v.match_args.length ? ` · args <span class="mono">${esc(JSON.stringify(v.match_args))}</span>` : ""}`;
}

const REACH_BATCH_MAX = 50;

/**
 * Batch reach: GET /v1/agents/reach?ids=… in chunks of 50 (human admins only).
 * Falls back to per-agent GET /v1/agents/:id/reach only if the batch route is
 * missing (404). Returns reach per id plus not_found ids and catalog errors.
 */
async function loadReach(ids) {
  const reach = new Map();
  const notFound = [];
  const catalogErrors = new Set();
  let reachErr = "";
  let needsHumanAdmin = false;
  const chunks = [];
  for (let i = 0; i < ids.length; i += REACH_BATCH_MAX) chunks.push(ids.slice(i, i + REACH_BATCH_MAX));
  let batchMissing = false;
  for (const chunk of chunks) {
    try {
      const r = await api(`/v1/agents/reach?ids=${chunk.map(encodeURIComponent).join(",")}`);
      for (const item of Array.isArray(r?.agents) ? r.agents : []) {
        const id = item?.agent?.id;
        if (id) reach.set(id, item);
        if (item?.catalog_error) catalogErrors.add(String(item.catalog_error));
      }
      for (const id of Array.isArray(r?.not_found) ? r.not_found : []) notFound.push(String(id));
      if (r?.catalog_error) catalogErrors.add(String(r.catalog_error));
    } catch (e) {
      if (e.status === 404) {
        batchMissing = true;
        break;
      }
      if (e.status === 403) {
        needsHumanAdmin = true;
        break;
      }
      reachErr = e.message;
      for (const id of chunk) reach.set(id, { err: e.status === 403 ? "not permitted" : "unavailable" });
    }
  }
  if (batchMissing) {
    await Promise.all(ids.map(async (id) => {
      try {
        const r = await api(`/v1/agents/${encodeURIComponent(id)}/reach`);
        reach.set(id, r);
        if (r?.catalog_error) catalogErrors.add(String(r.catalog_error));
      } catch (e) {
        if (e.status === 404) notFound.push(id);
        else if (e.status === 403) needsHumanAdmin = true;
        reach.set(id, { err: e.status === 403 ? "not permitted" : e.status === 404 ? "not found" : "unavailable" });
      }
    }));
  }
  return { reach, notFound, catalogErrors: [...catalogErrors], reachErr, needsHumanAdmin };
}

async function renderAccessMap() {
  let agentsRes;
  try {
    agentsRes = await api("/v1/agents");
  } catch {
    return renderAccessMapLegacy();
  }
  const root = $("#tab-access-map");
  const agents = (Array.isArray(agentsRes?.agents) ? agentsRes.agents : []).filter((a) => !a?.revoked_at);
  const [{ backends }, rulesRes] = await Promise.all([
    api("/v1/backends"),
    api("/v1/policy/rules").catch((e) => ({ rules: [], err: e.status === 403 ? "not permitted (403)" : e.message })),
  ]);
  const bks = Array.isArray(backends) ? backends : [];
  const toolsBy = new Map();
  await Promise.all(bks.map(async (b) => {
    try {
      const r = await api(`/v1/backends/${encodeURIComponent(b.id)}/tools`);
      toolsBy.set(b.slug, { tools: Array.isArray(r?.tools) ? r.tools : [] });
    } catch (e) {
      toolsBy.set(b.slug, { err: e.message, forbidden: e.status === 403 });
    }
  }));
  const { reach, notFound, catalogErrors, reachErr, needsHumanAdmin } = await loadReach(agents.map((a) => a.id));

  const head = bks.map((b) => {
    const t = toolsBy.get(b.slug);
    const n = t?.err ? `<span class="pill deny">${t.forbidden ? "tools not permitted" : "tools unavailable"}</span>` : `<span class="muted">${t.tools.length} tools</span>`;
    return `<th><span class="mono">${esc(b.slug)}</span>${b.enabled ? "" : ' <span class="pill off">off</span>'}<div>${n}</div></th>`;
  }).join("");

  const rows = agents.map((a) => {
    const r = reach.get(a.id) || {};
    // Union across the agent's projects; the strictest effect per tool is not
    // assumed — each project's effect is listed in the tooltip.
    const perTool = new Map(); // name -> [{project, effect}]
    for (const p of Array.isArray(r.projects) ? r.projects : []) {
      for (const t of Array.isArray(p?.tools) ? p.tools : []) {
        if (!perTool.has(t.name)) perTool.set(t.name, []);
        perTool.get(t.name).push({ project: p.project, effect: t.effect });
      }
    }
    const projs = (Array.isArray(r.projects) ? r.projects : []).map((p) => p.project);
    const cells = bks.map((b) => {
      if (r.err) return `<td><span class="pill deny">${esc(r.err)}</span></td>`;
      const ns = `${b.slug}__`;
      const names = [...perTool.keys()].filter((n) => n.startsWith(ns));
      if (!names.length) return '<td><span class="pill off">—</span></td>';
      const counts = {};
      for (const n of names) for (const { effect } of perTool.get(n)) counts[effect] = (counts[effect] || 0) + 1;
      const pills = REACH_EFFECTS.filter(([k]) => counts[k]).map(([k, cls, label]) => `<span class="pill ${cls}">${counts[k]} ${label}</span>`).join(" ");
      const other = Object.keys(counts).filter((k) => !REACH_EFFECTS.some(([e]) => e === k));
      const title = names.sort().map((n) => `${n}: ${perTool.get(n).map((x) => `${x.effect} (${x.project})`).join(", ")}`).join("\n");
      return `<td title="${esc(title)}"><div class="am-pills">${pills}${other.map((k) => ` <span class="pill off">${esc(k)}</span>`).join("")}</div></td>`;
    }).join("");
    return `<tr><td><div>${esc(a.name)}</div><div class="mono muted">${esc(a.id)}</div>
        <div class="muted">${projs.length ? projs.map((p) => `<span class="pill accent">${esc(p)}</span>`).join(" ") : "no projects"}${r.catalog_error ? ` <span class="pill deny">${esc(r.catalog_error)}</span>` : ""}</div></td>
      <td><span class="pill ${a.kind === "human" ? "vault" : "off"}">${esc(a.kind ?? "?")}</span>${a.is_admin ? ' <span class="pill vault">admin</span>' : ""}</td>
      <td><span class="pill ${a.status === "active" ? "on" : "off"}">${esc(a.status ?? "?")}</span></td>
      ${cells}</tr>`;
  }).join("");

  const warnings = [
    reachErr ? `<p class="pa-warn">Reach unavailable: ${esc(reachErr)}</p>` : "",
    catalogErrors.length ? `<p class="pa-warn"><strong>Tool catalog warning:</strong> ${esc(catalogErrors.join("; "))} — reach may be incomplete.</p>` : "",
    notFound.length ? `<p class="pa-warn">Agents not found by the reach endpoint: ${notFound.map((i) => `<span class="mono">${esc(i)}</span>`).join(", ")}</p>` : "",
  ].join("");
  const table = agents.length && bks.length
    ? `<div class="table-wrap"><table class="data-table access-map"><thead><tr><th>Agent</th><th>Kind</th><th>Status</th>${head}</tr></thead><tbody>${rows}</tbody></table></div>`
    : '<p class="audit-empty">Need at least one agent and one backend.</p>';
  const legend = `<p class="row-actions">${REACH_EFFECTS.map(([, cls, label]) => `<span class="pill ${cls}">${label}</span>`).join("")}
      <span class="muted">counts = tool × project pairs · hover a cell for each tool · — = no reachable tools</span></p>`;

  const rules = Array.isArray(rulesRes?.rules) ? rulesRes.rules : [];
  const effCls = { allow: "on", require_approval: "warn", deny: "deny" };
  const rulesHtml = rulesRes?.err
    ? `<p class="pa-warn">Policy rules unavailable: ${esc(rulesRes.err)}</p>`
    : rules.length
      ? `<div class="table-wrap"><table class="data-table"><thead><tr><th>Rule</th><th>Effect</th><th>Priority</th><th>Scope</th></tr></thead><tbody>${rules.map((rl) => {
          const v = rl?.current || {};
          return `<tr><td><div class="mono">${esc(rl?.id)}</div><div class="muted">${esc(v.description ?? "")} v${esc(rl?.current_version ?? v.version ?? "?")}</div>${rl?.active === false ? ' <span class="pill off">inactive</span>' : ""}</td>
            <td><span class="pill ${effCls[v.effect] || "off"}">${esc(v.effect ?? "?")}</span></td>
            <td>${esc(v.priority ?? "")}</td><td>${ruleVersionSummary(v)}</td></tr>`;
        }).join("")}</tbody></table></div>`
      : '<p class="audit-empty">No policy rules.</p>';
  const limits = `<div class="once-callout"><strong>Limitation (GAP-4).</strong>
      <span class="muted">Reach is static per agent and project. "Conditional" means a rule depending on args decides at call time; the session's selected project and dynamic-tool enablement aren't modelled.</span></div>`;
  // V4-F1: reach is human-admin only (403 human_admin_required, e.g. env admin
  // token). Show one panel notice instead of a grid of per-cell errors.
  const mapBody = needsHumanAdmin
    ? '<div class="pa-banner" role="status"><span><strong>Access map needs a human admin key.</strong> This token can list agents and rules but not per-agent reach (403 human_admin_required).</span></div>'
    : legend + warnings + table + limits;
  root.innerHTML =
    surface("Access map", mapBody, `${agents.length} agents × ${bks.length} backends`) +
    surface("Policy rules", rulesHtml, `${rules.length} rules`);
}

async function renderAccessMapLegacy() {
  const root = $("#tab-access-map");
  const [{ keys }, { projects }, { backends }, rulesRes] = await Promise.all([
    api("/v1/keys"),
    soft("access-map", "Projects", api("/v1/projects"), () => ({ projects: [] })),
    api("/v1/backends"),
    soft("access-map", "Authz rules", api("/v1/authz/rules"), () => ({ rules: [] })),
  ]);
  const rules = Array.isArray(rulesRes?.rules) ? rulesRes.rules : [];
  const live = (keys || []).filter((k) => !k.revokedAt);
  const cls = { full: "on", partial: "accent", gated: "warn", none: "off", off: "off" };
  const head = (backends || [])
    .map((b) => `<th class="mono">${esc(b.slug)}${b.enabled ? "" : ' <span class="pill off">off</span>'}</th>`)
    .join("");
  const rows = live.map((k) => {
    const cells = (backends || []).map((b) => {
      const c = accessCell(k, b, projects || [], rules);
      const title = [
        c.via?.length ? `via ${c.via.map((p) => p.slug).join(", ")}` : "",
        c.filters?.length ? `prefixes: ${c.filters.join(", ")}` : "",
        c.tools?.length ? c.tools.map((t) => `${t.name}${t.gated ? " (approval)" : ""}`).join("\n") : "",
      ].filter(Boolean).join("\n");
      return `<td title="${esc(title)}"><span class="pill ${cls[c.level]}">${esc(c.label)}</span>${c.level === "gated" ? ' <span class="muted">approval</span>' : ""}</td>`;
    }).join("");
    return `<tr><td><div>${esc(k.name)}</div><div class="mono muted">${esc(k.prefix)}…</div></td>
      <td>${k.scopes?.admin ? '<span class="pill vault">operator</span>' : '<span class="pill off">agent</span>'}</td>
      ${cells}</tr>`;
  }).join("");
  const table = live.length && (backends || []).length
    ? `<div class="table-wrap"><table class="data-table access-map"><thead><tr><th>Key (agent proxy)</th><th>Role</th>${head}</tr></thead><tbody>${rows}</tbody></table></div>`
    : '<p class="audit-empty">Need at least one active key and one backend.</p>';
  const legend = `<p class="row-actions">
      <span class="pill on">all tools</span><span class="pill accent">prefix-limited</span>
      <span class="pill warn">gated</span> <span class="muted">= an authz rule may require approval</span>
      <span class="pill off">—</span> <span class="muted">= no project grants this backend</span></p>`;
  const gaps = `<div class="once-callout"><strong>Partial picture.</strong>
      <ul class="muted">
        <li>Rows are API keys — there's no read endpoint for agents yet.</li>
        <li>Per-call policy rules (deny / require approval) have no read endpoint; only legacy authz rules are shown.</li>
        <li>Backend tool lists aren't exposed, so cells show "all tools" unless the backend has an allowlist.</li>
      </ul></div>`;
  root.innerHTML = surface("Access map", legend + table + gaps, `${live.length} keys × ${(backends || []).length} backends`);
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
    if (tab === "projects") await renderProjects();
    if (tab === "devices") await renderDevices();
    if (tab === "approvals") await renderApprovals(true);
    else stopApprovalsPoll();
    if (tab === "audit") await renderAudit();
    if (tab === "policy-approvals") await renderPolicyApprovals();
    else stopPolicyApprovalsPoll();
    if (tab === "access-map") await renderAccessMap();
  } catch (e) {
    if (e.status === 403) {
      // Panel-level "not permitted"; token is kept (no logout).
      const panel = $(`#tab-${tab}`);
      if (panel) panel.innerHTML = surface("Not permitted", `<p class="pa-warn">${esc(e.message)}</p>`);
    }
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
    if (btn.dataset.tab === "approvals") {
      const id = approvalsDeepId();
      if (!id) history.replaceState(null, "", "#approvals");
    }
    void refresh();
  });
});

function activateTab(tab) {
  const btn = document.querySelector(`.tabs .seg-btn[data-tab="${tab}"]`);
  if (!btn) return;
  document
    .querySelectorAll(".tabs .seg-btn, .tabs button")
    .forEach((b) => b.classList.remove("active", "on"));
  document.querySelectorAll("main .panel").forEach((p) => p.classList.remove("active"));
  btn.classList.add("active");
  $(`#tab-${tab}`)?.classList.add("active");
}

window.addEventListener("hashchange", () => {
  if (location.hash.startsWith("#approvals")) {
    activateTab("approvals");
    void refresh();
  }
});

window.addEventListener("beforeinstallprompt", (ev) => {
  ev.preventDefault();
  deferredInstallPrompt = ev;
  const btn = $("#pwaInstall");
  if (btn) btn.hidden = false;
});

window.addEventListener("appinstalled", () => {
  deferredInstallPrompt = null;
  const btn = $("#pwaInstall");
  if (btn) btn.hidden = true;
});

if (navigator.serviceWorker) {
  navigator.serviceWorker.addEventListener("message", (ev) => {
    const msg = ev.data || {};
    if (msg.type === "authz-open" && msg.approvalId) {
      history.replaceState(
        null,
        "",
        `#approvals/${encodeURIComponent(msg.approvalId)}`,
      );
      activateTab("approvals");
      void refresh();
    }
    if (msg.type === "authz-decided") {
      activateTab("approvals");
      void refresh();
    }
  });
  void ensureAdminServiceWorker().catch(() => undefined);
}

// Wrap renderers so secondary-request failures surface as a panel banner.
renderStatus = withIssues("status", renderStatus);
renderKeys = withIssues("keys", renderKeys);
renderBackends = withIssues("backends", renderBackends);
renderApprovals = withIssues("approvals", renderApprovals);
renderAccessMapLegacy = withIssues("access-map", renderAccessMapLegacy);

$("#saveToken").addEventListener("click", () => {
  setToken($("#token").value.trim());
  const msg = $("#tokenMsg");
  if (msg) msg.hidden = true;
  void refresh(); // re-renders the current tab with the new key
});
$("#refresh").addEventListener("click", () => void refresh());
$("#token").value = token();
if (location.hash.startsWith("#approvals")) activateTab("approvals");
if (token()) void refresh();

