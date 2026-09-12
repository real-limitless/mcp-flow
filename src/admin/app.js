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
    api("/v1/approvals?status=pending").catch(() => ({
      approvals: [],
      pendingCount: 0,
      waiting: 0,
    })),
    api("/v1/operators/mfa").catch(() => ({ enrolled: false })),
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
    api("/v1/projects").catch(() => ({ projects: [] })),
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
    api("/v1/push/vapid").catch(() => null),
    api("/v1/push/subscriptions").catch(() => ({ subscriptions: [] })),
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

$("#saveToken").addEventListener("click", () => {
  setToken($("#token").value.trim());
  void refresh();
});
$("#refresh").addEventListener("click", () => void refresh());
$("#token").value = token();
if (location.hash.startsWith("#approvals")) activateTab("approvals");
if (token()) void refresh();
