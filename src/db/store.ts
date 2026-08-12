import { DatabaseSync } from "node:sqlite";
import {
  deriveMasterKey,
  hashToken,
  mintApiToken,
  newId,
  seal,
  unseal,
} from "../crypto.js";
import type {
  ApiKeyCreated,
  ApiKeyPublic,
  ApiKeyRecord,
  ApiKeyScopes,
  AuditAction,
  AuditEvent,
  BackendPublic,
  BackendRecord,
  CreateBackendInput,
  DeviceCapabilities,
  DeviceEnrolled,
  DevicePublic,
  Placement,
  SandboxConfig,
  UpdateBackendInput,
  Workspace,
  WorkspacePolicy,
} from "../types.js";
import { sanitizeForAudit } from "../audit/sanitize.js";
import {
  DEFAULT_PLACEMENT,
  DEFAULT_WORKSPACE_POLICY,
} from "../types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  policy_json TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  scopes_json TEXT,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS backends (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  slug TEXT NOT NULL,
  title TEXT NOT NULL,
  transport TEXT NOT NULL,
  url TEXT,
  image TEXT,
  command_json TEXT,
  headers_enc TEXT,
  env_enc TEXT,
  enabled INTEGER NOT NULL DEFAULT 0,
  tool_allowlist_json TEXT,
  placement_json TEXT NOT NULL,
  sandbox_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, slug)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  key_id TEXT,
  action TEXT NOT NULL,
  backend_slug TEXT,
  tool TEXT,
  placement TEXT,
  device_id TEXT,
  detail_json TEXT,
  ip TEXT
);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  tags_json TEXT NOT NULL DEFAULT '[]',
  capabilities_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'offline',
  last_seen TEXT,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(token_hash);
CREATE INDEX IF NOT EXISTS idx_backends_ws ON backends(workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_ws_ts ON audit_events(workspace_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_devices_ws ON devices(workspace_id);
CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token_hash);
`;

function nowIso(): string {
  return new Date().toISOString();
}

function parseScopes(raw: unknown): ApiKeyScopes | null {
  if (raw == null || raw === "") return null;
  try {
    const s = JSON.parse(String(raw)) as ApiKeyScopes;
    if (!s || typeof s !== "object") return null;
    if (s.toolPrefixAllowlist && !Array.isArray(s.toolPrefixAllowlist)) {
      return null;
    }
    const out: ApiKeyScopes = {};
    if (Array.isArray(s.toolPrefixAllowlist) && s.toolPrefixAllowlist.length) {
      out.toolPrefixAllowlist = s.toolPrefixAllowlist.map(String);
    }
    if (s.admin === true) out.admin = true;
    if (!out.toolPrefixAllowlist && !out.admin) {
      // empty object → treat as full non-admin access (null)
      return null;
    }
    return out;
  } catch {
    return null;
  }
}

function rowKey(r: Record<string, unknown>): ApiKeyRecord {
  return {
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    name: String(r.name),
    tokenHash: String(r.token_hash),
    prefix: String(r.prefix),
    scopes: parseScopes(r.scopes_json),
    createdAt: String(r.created_at),
    revokedAt: r.revoked_at == null ? null : String(r.revoked_at),
  };
}

function parsePolicy(raw: unknown): WorkspacePolicy {
  if (raw == null || raw === "") return { ...DEFAULT_WORKSPACE_POLICY };
  try {
    const p = JSON.parse(String(raw)) as WorkspacePolicy;
    if (!p || typeof p !== "object") return { ...DEFAULT_WORKSPACE_POLICY };
    return {
      allowEdgeBare: Boolean(p.allowEdgeBare),
    };
  } catch {
    return { ...DEFAULT_WORKSPACE_POLICY };
  }
}

function parseSandbox(raw: unknown): SandboxConfig | null {
  if (raw == null || raw === "") return null;
  try {
    const s = JSON.parse(String(raw)) as SandboxConfig;
    if (!s || typeof s !== "object") return null;
    return s;
  } catch {
    return null;
  }
}

function rowBackend(r: Record<string, unknown>): BackendRecord {
  return {
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    slug: String(r.slug),
    title: String(r.title),
    transport: r.transport as BackendRecord["transport"],
    url: r.url == null ? null : String(r.url),
    image: r.image == null ? null : String(r.image),
    commandJson: r.command_json == null ? null : String(r.command_json),
    headersEnc: r.headers_enc == null ? null : String(r.headers_enc),
    envEnc: r.env_enc == null ? null : String(r.env_enc),
    enabled: Boolean(r.enabled),
    toolAllowlistJson:
      r.tool_allowlist_json == null ? null : String(r.tool_allowlist_json),
    placementJson: String(r.placement_json),
    sandboxJson: r.sandbox_json == null ? null : String(r.sandbox_json),
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
}

function rowWorkspace(r: Record<string, unknown>): Workspace {
  return {
    id: String(r.id),
    name: String(r.name),
    createdAt: String(r.created_at),
    policy: parsePolicy(r.policy_json),
  };
}

function rowDevice(r: Record<string, unknown>): DevicePublic {
  let tags: string[] = [];
  try {
    tags = JSON.parse(String(r.tags_json ?? "[]")) as string[];
  } catch {
    tags = [];
  }
  let capabilities: DeviceCapabilities = { sandbox: "none", bare: false };
  try {
    capabilities = JSON.parse(
      String(r.capabilities_json),
    ) as DeviceCapabilities;
  } catch {
    /* default */
  }
  return {
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    name: String(r.name),
    tags,
    capabilities,
    status: r.status === "online" ? "online" : "offline",
    lastSeen: r.last_seen == null ? null : String(r.last_seen),
    createdAt: String(r.created_at),
  };
}

function toPublicKey(k: ApiKeyRecord): ApiKeyPublic {
  return {
    id: k.id,
    workspaceId: k.workspaceId,
    name: k.name,
    prefix: k.prefix,
    scopes: k.scopes,
    createdAt: k.createdAt,
    revokedAt: k.revokedAt,
  };
}

function parsePlacement(json: string): Placement {
  try {
    const p = JSON.parse(json) as Placement;
    if (!p?.mode) return { ...DEFAULT_PLACEMENT };
    return p;
  } catch {
    return { ...DEFAULT_PLACEMENT };
  }
}

export function toPublicBackend(b: BackendRecord): BackendPublic {
  return {
    id: b.id,
    workspaceId: b.workspaceId,
    slug: b.slug,
    title: b.title,
    transport: b.transport,
    url: b.url,
    image: b.image,
    command: b.commandJson ? (JSON.parse(b.commandJson) as string[]) : null,
    hasHeaders: Boolean(b.headersEnc),
    hasEnv: Boolean(b.envEnc),
    enabled: b.enabled,
    toolAllowlist: b.toolAllowlistJson
      ? (JSON.parse(b.toolAllowlistJson) as string[])
      : null,
    placement: parsePlacement(b.placementJson),
    sandbox: parseSandbox(b.sandboxJson),
    createdAt: b.createdAt,
    updatedAt: b.updatedAt,
  };
}

export class Store {
  readonly db: DatabaseSync;
  readonly masterKey: Buffer;

  constructor(dbPath: string, masterKeyRaw: string) {
    this.masterKey = deriveMasterKey(masterKeyRaw);
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA);
    this.migrate();
  }

  private migrate(): void {
    const keyCols = this.db
      .prepare(`PRAGMA table_info(api_keys)`)
      .all() as Array<{ name: string }>;
    if (!keyCols.some((c) => c.name === "scopes_json")) {
      this.db.exec(`ALTER TABLE api_keys ADD COLUMN scopes_json TEXT`);
    }

    const wsCols = this.db
      .prepare(`PRAGMA table_info(workspaces)`)
      .all() as Array<{ name: string }>;
    if (!wsCols.some((c) => c.name === "policy_json")) {
      this.db.exec(`ALTER TABLE workspaces ADD COLUMN policy_json TEXT`);
    }

    const beCols = this.db
      .prepare(`PRAGMA table_info(backends)`)
      .all() as Array<{ name: string }>;
    if (!beCols.some((c) => c.name === "sandbox_json")) {
      this.db.exec(`ALTER TABLE backends ADD COLUMN sandbox_json TEXT`);
    }

    const audCols = this.db
      .prepare(`PRAGMA table_info(audit_events)`)
      .all() as Array<{ name: string }>;
    if (!audCols.some((c) => c.name === "device_id")) {
      this.db.exec(`ALTER TABLE audit_events ADD COLUMN device_id TEXT`);
    }
  }

  close(): void {
    this.db.close();
  }

  ensureWorkspace(name: string): Workspace {
    const existing = this.db
      .prepare(
        "SELECT id, name, created_at, policy_json FROM workspaces WHERE name = ?",
      )
      .get(name) as Record<string, unknown> | undefined;
    if (existing) {
      return rowWorkspace(existing);
    }
    const ws: Workspace = {
      id: newId("ws"),
      name,
      createdAt: nowIso(),
      policy: { ...DEFAULT_WORKSPACE_POLICY },
    };
    this.db
      .prepare(
        "INSERT INTO workspaces (id, name, created_at, policy_json) VALUES (?, ?, ?, ?)",
      )
      .run(
        ws.id,
        ws.name,
        ws.createdAt,
        JSON.stringify(ws.policy),
      );
    return ws;
  }

  getWorkspace(id: string): Workspace | null {
    const row = this.db
      .prepare(
        "SELECT id, name, created_at, policy_json FROM workspaces WHERE id = ?",
      )
      .get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return rowWorkspace(row);
  }

  updateWorkspacePolicy(
    workspaceId: string,
    policy: WorkspacePolicy,
  ): Workspace | null {
    const existing = this.getWorkspace(workspaceId);
    if (!existing) return null;
    const next: WorkspacePolicy = {
      allowEdgeBare: Boolean(policy.allowEdgeBare),
    };
    this.db
      .prepare(`UPDATE workspaces SET policy_json = ? WHERE id = ?`)
      .run(JSON.stringify(next), workspaceId);
    return this.getWorkspace(workspaceId);
  }

  createApiKey(
    workspaceId: string,
    name: string,
    scopes?: ApiKeyScopes | null,
  ): ApiKeyCreated {
    const { token, prefix, hash } = mintApiToken();
    const rec: ApiKeyRecord = {
      id: newId("key"),
      workspaceId,
      name,
      tokenHash: hash,
      prefix,
      scopes: scopes ?? null,
      createdAt: nowIso(),
      revokedAt: null,
    };
    this.db
      .prepare(
        `INSERT INTO api_keys (id, workspace_id, name, token_hash, prefix, scopes_json, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        rec.id,
        rec.workspaceId,
        rec.name,
        rec.tokenHash,
        rec.prefix,
        rec.scopes ? JSON.stringify(rec.scopes) : null,
        rec.createdAt,
      );
    return { ...toPublicKey(rec), token };
  }

  updateApiKeyScopes(
    workspaceId: string,
    id: string,
    scopes: ApiKeyScopes | null,
  ): ApiKeyPublic | null {
    const res = this.db
      .prepare(
        `UPDATE api_keys SET scopes_json = ?
         WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL`,
      )
      .run(scopes ? JSON.stringify(scopes) : null, id, workspaceId);
    if (Number(res.changes) === 0) return null;
    const row = this.db
      .prepare(`SELECT * FROM api_keys WHERE id = ?`)
      .get(id) as Record<string, unknown> | undefined;
    return row ? toPublicKey(rowKey(row)) : null;
  }

  listApiKeys(workspaceId: string): ApiKeyPublic[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM api_keys WHERE workspace_id = ? ORDER BY created_at DESC`,
      )
      .all(workspaceId) as Record<string, unknown>[];
    return rows.map((r) => toPublicKey(rowKey(r)));
  }

  revokeApiKey(workspaceId: string, id: string): boolean {
    const res = this.db
      .prepare(
        `UPDATE api_keys SET revoked_at = ?
         WHERE id = ? AND workspace_id = ? AND revoked_at IS NULL`,
      )
      .run(nowIso(), id, workspaceId);
    return Number(res.changes) > 0;
  }

  authenticateApiKey(token: string): {
    workspaceId: string;
    keyId: string;
    keyName: string;
    scopes: ApiKeyScopes | null;
  } | null {
    const hash = hashToken(token);
    const row = this.db
      .prepare(
        `SELECT id, workspace_id, name, revoked_at, scopes_json FROM api_keys WHERE token_hash = ?`,
      )
      .get(hash) as Record<string, unknown> | undefined;
    if (!row || row.revoked_at != null) return null;
    return {
      workspaceId: String(row.workspace_id),
      keyId: String(row.id),
      keyName: String(row.name),
      scopes: parseScopes(row.scopes_json),
    };
  }

  writeAudit(input: {
    workspaceId: string;
    keyId?: string | null;
    action: AuditAction | string;
    backendSlug?: string | null;
    tool?: string | null;
    placement?: string | null;
    deviceId?: string | null;
    detail?: Record<string, unknown> | null;
    ip?: string | null;
  }): void {
    let detailJson: string | null = null;
    if (input.detail) {
      const safe = sanitizeForAudit(input.detail);
      detailJson = JSON.stringify(safe ?? null);
    }
    this.db
      .prepare(
        `INSERT INTO audit_events (
          id, ts, workspace_id, key_id, action, backend_slug, tool, placement,
          device_id, detail_json, ip
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        newId("aud"),
        nowIso(),
        input.workspaceId,
        input.keyId ?? null,
        input.action,
        input.backendSlug ?? null,
        input.tool ?? null,
        input.placement ?? null,
        input.deviceId ?? null,
        detailJson,
        input.ip ?? null,
      );
  }

  listAudit(
    workspaceId: string,
    opts: { limit?: number; before?: string } = {},
  ): AuditEvent[] {
    const limit = Math.min(Math.max(opts.limit ?? 50, 1), 500);
    const rows = (
      opts.before
        ? (this.db
            .prepare(
              `SELECT * FROM audit_events
               WHERE workspace_id = ? AND ts < ?
               ORDER BY ts DESC LIMIT ?`,
            )
            .all(workspaceId, opts.before, limit) as Record<string, unknown>[])
        : (this.db
            .prepare(
              `SELECT * FROM audit_events
               WHERE workspace_id = ?
               ORDER BY ts DESC LIMIT ?`,
            )
            .all(workspaceId, limit) as Record<string, unknown>[])
    );
    return rows.map((r) => ({
      id: String(r.id),
      ts: String(r.ts),
      workspaceId: String(r.workspace_id),
      keyId: r.key_id == null ? null : String(r.key_id),
      action: String(r.action),
      backendSlug: r.backend_slug == null ? null : String(r.backend_slug),
      tool: r.tool == null ? null : String(r.tool),
      placement: r.placement == null ? null : String(r.placement),
      deviceId: r.device_id == null ? null : String(r.device_id),
      detail: r.detail_json
        ? (JSON.parse(String(r.detail_json)) as Record<string, unknown>)
        : null,
      ip: r.ip == null ? null : String(r.ip),
    }));
  }

  createBackend(
    workspaceId: string,
    input: CreateBackendInput,
  ): BackendPublic {
    const slug = input.slug.trim().toLowerCase();
    if (!/^[a-z][a-z0-9_-]{0,63}$/.test(slug)) {
      throw new Error(
        "slug must be lowercase alphanumeric/underscore/hyphen, start with a letter",
      );
    }
    const placement = input.placement ?? { ...DEFAULT_PLACEMENT };
    const transport = input.transport ?? "streamable-http";
    const ts = nowIso();
    const sandboxJson =
      input.sandbox !== undefined && input.sandbox !== null
        ? JSON.stringify(input.sandbox)
        : null;
    const rec: BackendRecord = {
      id: newId("be"),
      workspaceId,
      slug,
      title: input.title?.trim() || slug,
      transport,
      url: input.url ?? null,
      image: input.image ?? null,
      commandJson: input.command ? JSON.stringify(input.command) : null,
      headersEnc: input.headers
        ? seal(this.masterKey, input.headers)
        : null,
      envEnc: input.env ? seal(this.masterKey, input.env) : null,
      enabled: input.enabled ?? false,
      toolAllowlistJson: input.toolAllowlist
        ? JSON.stringify(input.toolAllowlist)
        : null,
      placementJson: JSON.stringify(placement),
      sandboxJson,
      createdAt: ts,
      updatedAt: ts,
    };
    this.db
      .prepare(
        `INSERT INTO backends (
          id, workspace_id, slug, title, transport, url, image, command_json,
          headers_enc, env_enc, enabled, tool_allowlist_json, placement_json,
          sandbox_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        rec.id,
        rec.workspaceId,
        rec.slug,
        rec.title,
        rec.transport,
        rec.url,
        rec.image,
        rec.commandJson,
        rec.headersEnc,
        rec.envEnc,
        rec.enabled ? 1 : 0,
        rec.toolAllowlistJson,
        rec.placementJson,
        rec.sandboxJson,
        rec.createdAt,
        rec.updatedAt,
      );
    return toPublicBackend(rec);
  }

  listBackends(workspaceId: string): BackendPublic[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM backends WHERE workspace_id = ? ORDER BY slug ASC`,
      )
      .all(workspaceId) as Record<string, unknown>[];
    return rows.map((r) => toPublicBackend(rowBackend(r)));
  }

  getBackend(
    workspaceId: string,
    idOrSlug: string,
  ): BackendRecord | null {
    const row = this.db
      .prepare(
        `SELECT * FROM backends WHERE workspace_id = ? AND (id = ? OR slug = ?)`,
      )
      .get(workspaceId, idOrSlug, idOrSlug) as
      | Record<string, unknown>
      | undefined;
    return row ? rowBackend(row) : null;
  }

  getBackendPublic(
    workspaceId: string,
    idOrSlug: string,
  ): BackendPublic | null {
    const b = this.getBackend(workspaceId, idOrSlug);
    return b ? toPublicBackend(b) : null;
  }

  updateBackend(
    workspaceId: string,
    idOrSlug: string,
    input: UpdateBackendInput,
  ): BackendPublic | null {
    const existing = this.getBackend(workspaceId, idOrSlug);
    if (!existing) return null;

    const title = input.title ?? existing.title;
    const transport = input.transport ?? existing.transport;
    const url =
      input.url !== undefined ? input.url : existing.url;
    const image =
      input.image !== undefined ? input.image : existing.image;
    const commandJson =
      input.command !== undefined
        ? input.command
          ? JSON.stringify(input.command)
          : null
        : existing.commandJson;
    let headersEnc = existing.headersEnc;
    if (input.headers !== undefined) {
      headersEnc =
        input.headers === null
          ? null
          : seal(this.masterKey, input.headers);
    }
    let envEnc = existing.envEnc;
    if (input.env !== undefined) {
      envEnc =
        input.env === null ? null : seal(this.masterKey, input.env);
    }
    const enabled =
      input.enabled !== undefined ? input.enabled : existing.enabled;
    const toolAllowlistJson =
      input.toolAllowlist !== undefined
        ? input.toolAllowlist
          ? JSON.stringify(input.toolAllowlist)
          : null
        : existing.toolAllowlistJson;
    const placementJson = input.placement
      ? JSON.stringify(input.placement)
      : existing.placementJson;
    const sandboxJson =
      input.sandbox !== undefined
        ? input.sandbox
          ? JSON.stringify(input.sandbox)
          : null
        : existing.sandboxJson;
    const updatedAt = nowIso();

    this.db
      .prepare(
        `UPDATE backends SET
          title = ?, transport = ?, url = ?, image = ?, command_json = ?,
          headers_enc = ?, env_enc = ?, enabled = ?, tool_allowlist_json = ?,
          placement_json = ?, sandbox_json = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(
        title,
        transport,
        url,
        image,
        commandJson,
        headersEnc,
        envEnc,
        enabled ? 1 : 0,
        toolAllowlistJson,
        placementJson,
        sandboxJson,
        updatedAt,
        existing.id,
      );
    return this.getBackendPublic(workspaceId, existing.id);
  }

  deleteBackend(workspaceId: string, idOrSlug: string): boolean {
    const existing = this.getBackend(workspaceId, idOrSlug);
    if (!existing) return false;
    const res = this.db
      .prepare(`DELETE FROM backends WHERE id = ? AND workspace_id = ?`)
      .run(existing.id, workspaceId);
    return Number(res.changes) > 0;
  }

  listEnabledBackends(workspaceId: string): BackendRecord[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM backends WHERE workspace_id = ? AND enabled = 1 ORDER BY slug ASC`,
      )
      .all(workspaceId) as Record<string, unknown>[];
    return rows.map(rowBackend);
  }

  decryptHeaders(b: BackendRecord): Record<string, string> {
    if (!b.headersEnc) return {};
    return unseal<Record<string, string>>(this.masterKey, b.headersEnc);
  }

  decryptEnv(b: BackendRecord): Record<string, string> {
    if (!b.envEnc) return {};
    return unseal<Record<string, string>>(this.masterKey, b.envEnc);
  }

  /** Merge into sealed headers (does not remove unspecified keys). */
  mergeBackendHeaders(
    workspaceId: string,
    idOrSlug: string,
    partial: Record<string, string>,
  ): BackendPublic | null {
    const existing = this.getBackend(workspaceId, idOrSlug);
    if (!existing) return null;
    const current = this.decryptHeaders(existing);
    return this.updateBackend(workspaceId, existing.id, {
      headers: { ...current, ...partial },
    });
  }

  /** Header names only — never values (for TUI/status). */
  listBackendHeaderNames(
    workspaceId: string,
    idOrSlug: string,
  ): string[] | null {
    const existing = this.getBackend(workspaceId, idOrSlug);
    if (!existing) return null;
    return Object.keys(this.decryptHeaders(existing)).sort();
  }

  // --- Devices (P4+) ---

  enrollDevice(
    workspaceId: string,
    input: {
      name: string;
      tags?: string[];
      capabilities?: DeviceCapabilities;
    },
  ): DeviceEnrolled {
    const { token, hash } = mintApiToken();
    const id = newId("dev");
    const createdAt = nowIso();
    const capabilities: DeviceCapabilities = input.capabilities ?? {
      sandbox: "docker",
      bare: false,
    };
    const tags = input.tags ?? [];
    this.db
      .prepare(
        `INSERT INTO devices (
          id, workspace_id, name, tags_json, capabilities_json, status,
          last_seen, token_hash, created_at
        ) VALUES (?, ?, ?, ?, ?, 'offline', NULL, ?, ?)`,
      )
      .run(
        id,
        workspaceId,
        input.name.trim() || id,
        JSON.stringify(tags),
        JSON.stringify(capabilities),
        hash,
        createdAt,
      );
    const pub = this.getDevice(workspaceId, id)!;
    return { ...pub, token };
  }

  listDevices(workspaceId: string): DevicePublic[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM devices WHERE workspace_id = ? ORDER BY name ASC`,
      )
      .all(workspaceId) as Record<string, unknown>[];
    return rows.map(rowDevice);
  }

  getDevice(workspaceId: string, id: string): DevicePublic | null {
    const row = this.db
      .prepare(`SELECT * FROM devices WHERE workspace_id = ? AND id = ?`)
      .get(workspaceId, id) as Record<string, unknown> | undefined;
    return row ? rowDevice(row) : null;
  }

  updateDevice(
    workspaceId: string,
    id: string,
    input: {
      name?: string;
      tags?: string[];
      capabilities?: DeviceCapabilities;
      status?: "online" | "offline";
      lastSeen?: string | null;
    },
  ): DevicePublic | null {
    const existing = this.getDevice(workspaceId, id);
    if (!existing) return null;
    const name = input.name ?? existing.name;
    const tags = input.tags ?? existing.tags;
    const capabilities = input.capabilities ?? existing.capabilities;
    const status = input.status ?? existing.status;
    const lastSeen =
      input.lastSeen !== undefined ? input.lastSeen : existing.lastSeen;
    this.db
      .prepare(
        `UPDATE devices SET name = ?, tags_json = ?, capabilities_json = ?,
         status = ?, last_seen = ? WHERE id = ? AND workspace_id = ?`,
      )
      .run(
        name,
        JSON.stringify(tags),
        JSON.stringify(capabilities),
        status,
        lastSeen,
        id,
        workspaceId,
      );
    return this.getDevice(workspaceId, id);
  }

  revokeDevice(workspaceId: string, id: string): boolean {
    const res = this.db
      .prepare(`DELETE FROM devices WHERE id = ? AND workspace_id = ?`)
      .run(id, workspaceId);
    return Number(res.changes) > 0;
  }

  authenticateDevice(token: string): {
    workspaceId: string;
    deviceId: string;
    name: string;
  } | null {
    const hash = hashToken(token);
    const row = this.db
      .prepare(
        `SELECT id, workspace_id, name FROM devices WHERE token_hash = ?`,
      )
      .get(hash) as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      workspaceId: String(row.workspace_id),
      deviceId: String(row.id),
      name: String(row.name),
    };
  }

  touchDeviceOnline(deviceId: string): void {
    this.db
      .prepare(
        `UPDATE devices SET status = 'online', last_seen = ? WHERE id = ?`,
      )
      .run(nowIso(), deviceId);
  }

  markDeviceOffline(deviceId: string): void {
    this.db
      .prepare(`UPDATE devices SET status = 'offline' WHERE id = ?`)
      .run(deviceId);
  }
}
