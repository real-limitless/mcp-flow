import { DatabaseSync } from "node:sqlite";
import {
  deriveMasterKey,
  hashToken,
  mintApiToken,
  mintSessionToken,
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
  CreateProjectInput,
  DeviceCapabilities,
  DeviceEnrolled,
  DevicePublic,
  Placement,
  Project,
  ProjectSessionCreated,
  SandboxConfig,
  UpdateBackendInput,
  UpdateProjectInput,
  Workspace,
  WorkspacePolicy,
} from "../types.js";
import { sanitizeForAudit } from "../audit/sanitize.js";
import {
  authzMatchHasConstraint,
  clampAuthzTtl,
  parseAuthzRequirement,
  type Approval,
  type ApprovalStatus,
  type AuthzMatch,
  type AuthzRequirement,
  type AuthzRule,
  type CreateAuthzRuleInput,
  type UpdateAuthzRuleInput,
} from "../authz/types.js";
import { normalizeMatch } from "../authz/match.js";
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

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  slug TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  backend_slugs_json TEXT NOT NULL DEFAULT '[]',
  tool_prefix_json TEXT,
  is_default INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, slug)
);

CREATE TABLE IF NOT EXISTS project_sessions (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS authz_rules (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 0,
  match_json TEXT NOT NULL,
  requirement TEXT NOT NULL,
  ttl_seconds INTEGER NOT NULL,
  mfa_reuse_seconds INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  key_id TEXT NOT NULL,
  tool TEXT NOT NULL,
  arguments_json TEXT,
  backend_slug TEXT,
  status TEXT NOT NULL,
  requirement TEXT NOT NULL,
  mfa_satisfied_at TEXT,
  decided_by_key_id TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_at TEXT
);

CREATE TABLE IF NOT EXISTS operator_mfa (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  operator_key_id TEXT NOT NULL DEFAULT '',
  kind TEXT NOT NULL DEFAULT 'totp',
  secret_enc TEXT NOT NULL,
  enrolled_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, operator_key_id)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(token_hash);
CREATE INDEX IF NOT EXISTS idx_backends_ws ON backends(workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_ws_ts ON audit_events(workspace_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_devices_ws ON devices(workspace_id);
CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token_hash);
CREATE INDEX IF NOT EXISTS idx_projects_ws ON projects(workspace_id);
CREATE INDEX IF NOT EXISTS idx_project_sessions_hash ON project_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_authz_rules_ws ON authz_rules(workspace_id);
CREATE INDEX IF NOT EXISTS idx_approvals_ws_status ON approvals(workspace_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_operator_mfa_ws ON operator_mfa(workspace_id, operator_key_id);
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
    if (Array.isArray(s.projects) && s.projects.length) {
      out.projects = s.projects.map(String);
    }
    if (typeof s.defaultProject === "string" && s.defaultProject.trim()) {
      out.defaultProject = s.defaultProject.trim();
    }
    if (s.dynamicTools === true) out.dynamicTools = true;
    if (Array.isArray(s.dynamicToolsHot) && s.dynamicToolsHot.length) {
      out.dynamicToolsHot = s.dynamicToolsHot.map(String).filter(Boolean);
    }
    if (
      !out.toolPrefixAllowlist &&
      !out.admin &&
      !out.projects &&
      !out.defaultProject &&
      !out.dynamicTools &&
      !out.dynamicToolsHot?.length
    ) {
      return null;
    }
    return out;
  } catch {
    return null;
  }
}

function rowProject(r: Record<string, unknown>): Project {
  let backendSlugs: string[] = [];
  try {
    const raw = r.backend_slugs_json;
    backendSlugs = raw ? (JSON.parse(String(raw)) as string[]) : [];
  } catch {
    backendSlugs = [];
  }
  let toolPrefixAllowlist: string[] | null = null;
  try {
    const raw = r.tool_prefix_json;
    if (raw != null && raw !== "") {
      const p = JSON.parse(String(raw)) as string[];
      if (Array.isArray(p) && p.length) toolPrefixAllowlist = p.map(String);
    }
  } catch {
    toolPrefixAllowlist = null;
  }
  return {
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    slug: String(r.slug),
    title: String(r.title),
    description: r.description == null ? null : String(r.description),
    backendSlugs,
    toolPrefixAllowlist,
    isDefault: Boolean(r.is_default),
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
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

function nullableStr(v: unknown): string | null {
  if (v == null || v === "") return null;
  return String(v);
}

function mapAuditRow(r: Record<string, unknown>): AuditEvent {
  return {
    id: String(r.id),
    ts: String(r.ts),
    workspaceId: String(r.workspace_id),
    keyId: r.key_id == null ? null : String(r.key_id),
    keyName: nullableStr(r.key_name),
    keyPrefix: nullableStr(r.key_prefix),
    action: String(r.action),
    backendSlug: r.backend_slug == null ? null : String(r.backend_slug),
    tool: r.tool == null ? null : String(r.tool),
    placement: r.placement == null ? null : String(r.placement),
    deviceId: r.device_id == null ? null : String(r.device_id),
    detail: r.detail_json
      ? (JSON.parse(String(r.detail_json)) as Record<string, unknown>)
      : null,
    ip: r.ip == null ? null : String(r.ip),
  };
}

function clampPriority(raw: unknown, fallback = 0): number {
  const n = Number(raw ?? fallback);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(1000, Math.max(-1000, Math.floor(n)));
}

function clampMfaReuse(raw: unknown): number {
  const n = Number(raw ?? 0);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(3600, Math.floor(n));
}

function rowAuthzRule(r: Record<string, unknown>): AuthzRule {
  let match: AuthzMatch = {};
  try {
    match = normalizeMatch(
      r.match_json ? JSON.parse(String(r.match_json)) : {},
    );
  } catch {
    match = {};
  }
  const requirement =
    parseAuthzRequirement(r.requirement) ?? "notify_approve";
  return {
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    name: String(r.name),
    enabled: Boolean(r.enabled),
    priority: Number(r.priority) || 0,
    match,
    requirement,
    ttlSeconds: clampAuthzTtl(r.ttl_seconds),
    mfaReuseSeconds: clampMfaReuse(r.mfa_reuse_seconds),
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
}

function parseArgsJson(raw: unknown): Record<string, unknown> | null {
  if (raw == null || raw === "") return null;
  try {
    const v = JSON.parse(String(raw));
    if (v && typeof v === "object" && !Array.isArray(v)) {
      return v as Record<string, unknown>;
    }
    return { value: v };
  } catch {
    return null;
  }
}

function remainingSeconds(expiresAt: string, status: ApprovalStatus): number {
  if (status !== "pending") return 0;
  const ms = Date.parse(expiresAt) - Date.now();
  if (!Number.isFinite(ms)) return 0;
  return Math.max(0, Math.ceil(ms / 1000));
}

function rowApproval(
  r: Record<string, unknown>,
  redactArgs: boolean,
): Approval {
  const status = String(r.status) as ApprovalStatus;
  const args = parseArgsJson(r.arguments_json);
  const redacted =
    redactArgs && args
      ? (sanitizeForAudit(args) as Record<string, unknown>)
      : args;
  const requirement =
    parseAuthzRequirement(r.requirement) ?? "notify_approve";
  const expiresAt = String(r.expires_at);
  return {
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    ruleId: String(r.rule_id),
    keyId: String(r.key_id),
    keyName: nullableStr(r.key_name),
    keyPrefix: nullableStr(r.key_prefix),
    tool: String(r.tool),
    arguments: redacted,
    backendSlug: r.backend_slug == null ? null : String(r.backend_slug),
    status,
    requirement,
    mfaSatisfiedAt:
      r.mfa_satisfied_at == null ? null : String(r.mfa_satisfied_at),
    decidedByKeyId:
      r.decided_by_key_id == null ? null : String(r.decided_by_key_id),
    expiresAt,
    createdAt: String(r.created_at),
    decidedAt: r.decided_at == null ? null : String(r.decided_at),
  };
}

export function toPublicApproval(
  a: Approval,
  extras?: { ruleName?: string | null },
): Approval & { remainingSeconds: number; ruleName: string | null } {
  return {
    ...a,
    arguments: a.arguments
      ? (sanitizeForAudit(a.arguments) as Record<string, unknown>)
      : null,
    remainingSeconds: remainingSeconds(a.expiresAt, a.status),
    ruleName: extras?.ruleName ?? null,
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

    // Ensure schema tables exist on older DBs (CREATE IF NOT EXISTS in SCHEMA)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        slug TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        backend_slugs_json TEXT NOT NULL DEFAULT '[]',
        tool_prefix_json TEXT,
        is_default INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(workspace_id, slug)
      );
      CREATE TABLE IF NOT EXISTS project_sessions (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        prefix TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        revoked_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_projects_ws ON projects(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_project_sessions_hash ON project_sessions(token_hash);
      CREATE TABLE IF NOT EXISTS authz_rules (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        name TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        priority INTEGER NOT NULL DEFAULT 0,
        match_json TEXT NOT NULL,
        requirement TEXT NOT NULL,
        ttl_seconds INTEGER NOT NULL,
        mfa_reuse_seconds INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        tool TEXT NOT NULL,
        arguments_json TEXT,
        backend_slug TEXT,
        status TEXT NOT NULL,
        requirement TEXT NOT NULL,
        mfa_satisfied_at TEXT,
        decided_by_key_id TEXT,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL,
        decided_at TEXT
      );
      CREATE TABLE IF NOT EXISTS operator_mfa (
        id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        operator_key_id TEXT NOT NULL DEFAULT '',
        kind TEXT NOT NULL DEFAULT 'totp',
        secret_enc TEXT NOT NULL,
        enrolled_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(workspace_id, operator_key_id)
      );
      CREATE INDEX IF NOT EXISTS idx_authz_rules_ws ON authz_rules(workspace_id);
      CREATE INDEX IF NOT EXISTS idx_approvals_ws_status ON approvals(workspace_id, status, created_at DESC);
      CREATE INDEX IF NOT EXISTS idx_operator_mfa_ws ON operator_mfa(workspace_id, operator_key_id);
    `);
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
      const ws = rowWorkspace(existing);
      this.ensureDefaultProject(ws.id);
      return ws;
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
    this.ensureDefaultProject(ws.id);
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
    const select = `SELECT
          a.id, a.ts, a.workspace_id, a.key_id, a.action, a.backend_slug, a.tool,
          a.placement, a.device_id, a.detail_json, a.ip,
          k.name AS key_name, k.prefix AS key_prefix
        FROM audit_events a
        LEFT JOIN api_keys k ON k.id = a.key_id`;
    const rows = (
      opts.before
        ? (this.db
            .prepare(
              `${select}
               WHERE a.workspace_id = ? AND a.ts < ?
               ORDER BY a.ts DESC LIMIT ?`,
            )
            .all(workspaceId, opts.before, limit) as Record<string, unknown>[])
        : (this.db
            .prepare(
              `${select}
               WHERE a.workspace_id = ?
               ORDER BY a.ts DESC LIMIT ?`,
            )
            .all(workspaceId, limit) as Record<string, unknown>[])
    );
    return rows.map((r) => mapAuditRow(r));
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
    this.addBackendToDefaultProject(workspaceId, slug);
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

  // --- Projects (collections) ---

  ensureDefaultProject(workspaceId: string): Project {
    const existing = this.getProjectBySlug(workspaceId, "default");
    if (existing) return existing;
    const slugs = this.listBackends(workspaceId).map((b) => b.slug);
    return this.createProject(workspaceId, {
      slug: "default",
      title: "Default",
      description: "All backends (auto-maintained membership for new backends)",
      backendSlugs: slugs,
      isDefault: true,
    });
  }

  private addBackendToDefaultProject(
    workspaceId: string,
    slug: string,
  ): void {
    const def = this.getDefaultProject(workspaceId);
    if (!def) return;
    if (def.backendSlugs.includes(slug)) return;
    this.updateProject(workspaceId, def.id, {
      backendSlugs: [...def.backendSlugs, slug],
    });
  }

  listProjects(workspaceId: string): Project[] {
    this.ensureDefaultProject(workspaceId);
    const rows = this.db
      .prepare(
        `SELECT * FROM projects WHERE workspace_id = ? ORDER BY is_default DESC, slug ASC`,
      )
      .all(workspaceId) as Record<string, unknown>[];
    return rows.map(rowProject);
  }

  getProject(workspaceId: string, idOrSlug: string): Project | null {
    const byId = this.db
      .prepare(`SELECT * FROM projects WHERE workspace_id = ? AND id = ?`)
      .get(workspaceId, idOrSlug) as Record<string, unknown> | undefined;
    if (byId) return rowProject(byId);
    return this.getProjectBySlug(workspaceId, idOrSlug);
  }

  getProjectBySlug(workspaceId: string, slug: string): Project | null {
    const row = this.db
      .prepare(
        `SELECT * FROM projects WHERE workspace_id = ? AND slug = ?`,
      )
      .get(workspaceId, slug) as Record<string, unknown> | undefined;
    return row ? rowProject(row) : null;
  }

  getDefaultProject(workspaceId: string): Project | null {
    const row = this.db
      .prepare(
        `SELECT * FROM projects WHERE workspace_id = ? AND is_default = 1 LIMIT 1`,
      )
      .get(workspaceId) as Record<string, unknown> | undefined;
    if (row) return rowProject(row);
    return this.getProjectBySlug(workspaceId, "default");
  }

  createProject(workspaceId: string, input: CreateProjectInput): Project {
    const slug = input.slug.trim().toLowerCase();
    if (!/^[a-z][a-z0-9_-]{0,63}$/.test(slug)) {
      throw new Error(
        "project slug must be lowercase alphanumeric/underscore/hyphen",
      );
    }
    const ts = nowIso();
    const id = newId("proj");
    const isDefault = Boolean(input.isDefault);
    if (isDefault) {
      this.db
        .prepare(
          `UPDATE projects SET is_default = 0 WHERE workspace_id = ?`,
        )
        .run(workspaceId);
    }
    this.db
      .prepare(
        `INSERT INTO projects (
          id, workspace_id, slug, title, description, backend_slugs_json,
          tool_prefix_json, is_default, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        workspaceId,
        slug,
        input.title?.trim() || slug,
        input.description ?? null,
        JSON.stringify(input.backendSlugs ?? []),
        input.toolPrefixAllowlist?.length
          ? JSON.stringify(input.toolPrefixAllowlist)
          : null,
        isDefault ? 1 : 0,
        ts,
        ts,
      );
    return this.getProject(workspaceId, id)!;
  }

  updateProject(
    workspaceId: string,
    idOrSlug: string,
    input: UpdateProjectInput,
  ): Project | null {
    const existing = this.getProject(workspaceId, idOrSlug);
    if (!existing) return null;
    if (input.isDefault === true) {
      this.db
        .prepare(
          `UPDATE projects SET is_default = 0 WHERE workspace_id = ?`,
        )
        .run(workspaceId);
    }
    const title = input.title ?? existing.title;
    const description =
      input.description !== undefined ? input.description : existing.description;
    const backendSlugs =
      input.backendSlugs !== undefined
        ? input.backendSlugs
        : existing.backendSlugs;
    const toolPrefix =
      input.toolPrefixAllowlist !== undefined
        ? input.toolPrefixAllowlist
        : existing.toolPrefixAllowlist;
    const isDefault =
      input.isDefault !== undefined ? input.isDefault : existing.isDefault;
    this.db
      .prepare(
        `UPDATE projects SET title = ?, description = ?, backend_slugs_json = ?,
         tool_prefix_json = ?, is_default = ?, updated_at = ?
         WHERE id = ? AND workspace_id = ?`,
      )
      .run(
        title,
        description,
        JSON.stringify(backendSlugs),
        toolPrefix?.length ? JSON.stringify(toolPrefix) : null,
        isDefault ? 1 : 0,
        nowIso(),
        existing.id,
        workspaceId,
      );
    return this.getProject(workspaceId, existing.id);
  }

  deleteProject(workspaceId: string, idOrSlug: string): boolean {
    const existing = this.getProject(workspaceId, idOrSlug);
    if (!existing) return false;
    if (existing.slug === "default" || existing.isDefault) {
      throw new Error("cannot delete the default project");
    }
    const res = this.db
      .prepare(`DELETE FROM projects WHERE id = ? AND workspace_id = ?`)
      .run(existing.id, workspaceId);
    return Number(res.changes) > 0;
  }

  /** Mint short-lived mf_sess_* bound to key + project */
  createProjectSession(
    workspaceId: string,
    keyId: string,
    projectId: string,
    ttlMs = 12 * 60 * 60 * 1000,
  ): ProjectSessionCreated {
    const project = this.getProject(workspaceId, projectId);
    if (!project) throw new Error("project not found");
    const { token, prefix, hash } = mintSessionToken();
    const id = newId("mss");
    const createdAt = nowIso();
    const expiresAt = new Date(Date.now() + ttlMs).toISOString();
    this.db
      .prepare(
        `INSERT INTO project_sessions (
          id, workspace_id, key_id, project_id, token_hash, prefix,
          expires_at, created_at, revoked_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        id,
        workspaceId,
        keyId,
        project.id,
        hash,
        prefix,
        expiresAt,
        createdAt,
      );
    return {
      id,
      keyId,
      projectId: project.id,
      projectSlug: project.slug,
      expiresAt,
      createdAt,
      token,
    };
  }

  authenticateProjectSession(token: string): {
    workspaceId: string;
    keyId: string;
    keyName: string;
    scopes: ApiKeyScopes | null;
    projectId: string;
    projectSlug: string;
    projectSessionId: string;
  } | null {
    if (!token.startsWith("mf_sess_")) return null;
    const hash = hashToken(token);
    const row = this.db
      .prepare(
        `SELECT s.*, k.name AS key_name, k.scopes_json, k.revoked_at AS key_revoked,
                p.slug AS project_slug
         FROM project_sessions s
         JOIN api_keys k ON k.id = s.key_id
         JOIN projects p ON p.id = s.project_id
         WHERE s.token_hash = ?`,
      )
      .get(hash) as Record<string, unknown> | undefined;
    if (!row || row.revoked_at != null || row.key_revoked != null) return null;
    if (String(row.expires_at) < nowIso()) return null;
    return {
      workspaceId: String(row.workspace_id),
      keyId: String(row.key_id),
      keyName: String(row.key_name),
      scopes: parseScopes(row.scopes_json),
      projectId: String(row.project_id),
      projectSlug: String(row.project_slug),
      projectSessionId: String(row.id),
    };
  }

  listAuthzRules(workspaceId: string): AuthzRule[] {
    const rows = this.db
      .prepare(
        `SELECT * FROM authz_rules WHERE workspace_id = ? ORDER BY priority DESC, name ASC`,
      )
      .all(workspaceId) as Record<string, unknown>[];
    return rows.map(rowAuthzRule);
  }

  getAuthzRule(workspaceId: string, id: string): AuthzRule | null {
    const row = this.db
      .prepare(`SELECT * FROM authz_rules WHERE id = ? AND workspace_id = ?`)
      .get(id, workspaceId) as Record<string, unknown> | undefined;
    return row ? rowAuthzRule(row) : null;
  }

  createAuthzRule(workspaceId: string, input: CreateAuthzRuleInput): AuthzRule {
    const name = String(input.name ?? "").trim();
    if (!name) throw new Error("name required");
    const match = normalizeMatch(input.match);
    if (!authzMatchHasConstraint(match)) {
      throw new Error(
        "authz rule match must include tools, prefixes, backends, placements, or keyIds",
      );
    }
    const requirement = parseAuthzRequirement(input.requirement) ?? "notify_approve";
    const now = nowIso();
    const rec: AuthzRule = {
      id: newId("azr"),
      workspaceId,
      name,
      enabled: input.enabled !== false,
      priority: clampPriority(input.priority, 0),
      match,
      requirement,
      ttlSeconds: clampAuthzTtl(input.ttlSeconds),
      mfaReuseSeconds: clampMfaReuse(input.mfaReuseSeconds),
      createdAt: now,
      updatedAt: now,
    };
    this.db
      .prepare(
        `INSERT INTO authz_rules (
          id, workspace_id, name, enabled, priority, match_json, requirement,
          ttl_seconds, mfa_reuse_seconds, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        rec.id,
        rec.workspaceId,
        rec.name,
        rec.enabled ? 1 : 0,
        rec.priority,
        JSON.stringify(rec.match),
        rec.requirement,
        rec.ttlSeconds,
        rec.mfaReuseSeconds,
        rec.createdAt,
        rec.updatedAt,
      );
    return rec;
  }

  updateAuthzRule(
    workspaceId: string,
    id: string,
    input: UpdateAuthzRuleInput,
  ): AuthzRule | null {
    const existing = this.getAuthzRule(workspaceId, id);
    if (!existing) return null;
    const name =
      input.name !== undefined ? String(input.name).trim() : existing.name;
    if (!name) throw new Error("name required");
    const match =
      input.match !== undefined ? normalizeMatch(input.match) : existing.match;
    if (!authzMatchHasConstraint(match)) {
      throw new Error(
        "authz rule match must include tools, prefixes, backends, placements, or keyIds",
      );
    }
    const requirement =
      input.requirement !== undefined
        ? (parseAuthzRequirement(input.requirement) ?? existing.requirement)
        : existing.requirement;
    const updated: AuthzRule = {
      ...existing,
      name,
      enabled:
        input.enabled !== undefined ? Boolean(input.enabled) : existing.enabled,
      priority:
        input.priority !== undefined
          ? clampPriority(input.priority, existing.priority)
          : existing.priority,
      match,
      requirement,
      ttlSeconds:
        input.ttlSeconds !== undefined
          ? clampAuthzTtl(input.ttlSeconds)
          : existing.ttlSeconds,
      mfaReuseSeconds:
        input.mfaReuseSeconds !== undefined
          ? clampMfaReuse(input.mfaReuseSeconds)
          : existing.mfaReuseSeconds,
      updatedAt: nowIso(),
    };
    this.db
      .prepare(
        `UPDATE authz_rules SET
          name = ?, enabled = ?, priority = ?, match_json = ?, requirement = ?,
          ttl_seconds = ?, mfa_reuse_seconds = ?, updated_at = ?
         WHERE id = ? AND workspace_id = ?`,
      )
      .run(
        updated.name,
        updated.enabled ? 1 : 0,
        updated.priority,
        JSON.stringify(updated.match),
        updated.requirement,
        updated.ttlSeconds,
        updated.mfaReuseSeconds,
        updated.updatedAt,
        id,
        workspaceId,
      );
    return updated;
  }

  deleteAuthzRule(workspaceId: string, id: string): boolean {
    const res = this.db
      .prepare(`DELETE FROM authz_rules WHERE id = ? AND workspace_id = ?`)
      .run(id, workspaceId);
    return Number(res.changes) > 0;
  }

  createApproval(input: {
    workspaceId: string;
    ruleId: string;
    keyId: string;
    tool: string;
    arguments: Record<string, unknown> | null;
    backendSlug: string | null;
    requirement: AuthzRequirement;
    ttlSeconds: number;
  }): Approval {
    const now = nowIso();
    const ttl = clampAuthzTtl(input.ttlSeconds);
    const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();
    const id = newId("appr");
    this.db
      .prepare(
        `INSERT INTO approvals (
          id, workspace_id, rule_id, key_id, tool, arguments_json, backend_slug,
          status, requirement, mfa_satisfied_at, decided_by_key_id, expires_at,
          created_at, decided_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, ?, ?, NULL)`,
      )
      .run(
        id,
        input.workspaceId,
        input.ruleId,
        input.keyId,
        input.tool,
        input.arguments ? JSON.stringify(input.arguments) : null,
        input.backendSlug,
        input.requirement,
        expiresAt,
        now,
      );
    return this.getApproval(input.workspaceId, id, { redact: false })!;
  }

  getApproval(
    workspaceId: string,
    id: string,
    opts: { redact?: boolean } = {},
  ): Approval | null {
    const row = this.db
      .prepare(
        `SELECT a.*, k.name AS key_name, k.prefix AS key_prefix
         FROM approvals a
         LEFT JOIN api_keys k ON k.id = a.key_id
         WHERE a.id = ? AND a.workspace_id = ?`,
      )
      .get(id, workspaceId) as Record<string, unknown> | undefined;
    if (!row) return null;
    return rowApproval(row, opts.redact !== false);
  }

  listApprovals(
    workspaceId: string,
    opts: { status?: ApprovalStatus | "all"; limit?: number } = {},
  ): Array<
    Approval & { remainingSeconds: number; ruleName: string | null }
  > {
    this.expireOverdueApprovals(workspaceId);
    const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
    const status = opts.status && opts.status !== "all" ? opts.status : null;
    const rows = (
      status
        ? (this.db
            .prepare(
              `SELECT a.*, k.name AS key_name, k.prefix AS key_prefix, r.name AS rule_name
               FROM approvals a
               LEFT JOIN api_keys k ON k.id = a.key_id
               LEFT JOIN authz_rules r ON r.id = a.rule_id
               WHERE a.workspace_id = ? AND a.status = ?
               ORDER BY a.created_at DESC LIMIT ?`,
            )
            .all(workspaceId, status, limit) as Record<string, unknown>[])
        : (this.db
            .prepare(
              `SELECT a.*, k.name AS key_name, k.prefix AS key_prefix, r.name AS rule_name
               FROM approvals a
               LEFT JOIN api_keys k ON k.id = a.key_id
               LEFT JOIN authz_rules r ON r.id = a.rule_id
               WHERE a.workspace_id = ?
               ORDER BY a.created_at DESC LIMIT ?`,
            )
            .all(workspaceId, limit) as Record<string, unknown>[])
    );
    return rows.map((r) => {
      const a = rowApproval(r, true);
      return toPublicApproval(a, {
        ruleName: r.rule_name == null ? null : String(r.rule_name),
      });
    });
  }

  countPendingApprovals(workspaceId: string): number {
    this.expireOverdueApprovals(workspaceId);
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS n FROM approvals WHERE workspace_id = ? AND status = 'pending'`,
      )
      .get(workspaceId) as { n: number | bigint };
    return Number(row.n);
  }

  decideApproval(
    workspaceId: string,
    id: string,
    input: {
      status: Extract<ApprovalStatus, "approved" | "denied">;
      decidedByKeyId?: string | null;
      mfaSatisfied?: boolean;
    },
  ): Approval | null {
    const now = nowIso();
    const res = this.db
      .prepare(
        `UPDATE approvals SET
           status = ?, decided_by_key_id = ?, decided_at = ?,
           mfa_satisfied_at = CASE WHEN ? = 1 THEN ? ELSE mfa_satisfied_at END
         WHERE id = ? AND workspace_id = ? AND status = 'pending'`,
      )
      .run(
        input.status,
        input.decidedByKeyId ?? null,
        now,
        input.mfaSatisfied ? 1 : 0,
        input.mfaSatisfied ? now : null,
        id,
        workspaceId,
      );
    if (Number(res.changes) === 0) return null;
    return this.getApproval(workspaceId, id, { redact: false });
  }

  expireApproval(workspaceId: string, id: string): Approval | null {
    const now = nowIso();
    const res = this.db
      .prepare(
        `UPDATE approvals SET status = 'expired', decided_at = ?
         WHERE id = ? AND workspace_id = ? AND status = 'pending'`,
      )
      .run(now, id, workspaceId);
    if (Number(res.changes) === 0) return null;
    return this.getApproval(workspaceId, id, { redact: false });
  }

  expireOverdueApprovals(workspaceId: string): number {
    const res = this.db
      .prepare(
        `UPDATE approvals SET status = 'expired', decided_at = ?
         WHERE workspace_id = ? AND status = 'pending' AND expires_at < ?`,
      )
      .run(nowIso(), workspaceId, nowIso());
    return Number(res.changes);
  }

  getOperatorMfa(
    workspaceId: string,
    operatorKeyId: string,
  ): { enrolled: boolean; pending: boolean } {
    const row = this.db
      .prepare(
        `SELECT enrolled_at FROM operator_mfa WHERE workspace_id = ? AND operator_key_id = ?`,
      )
      .get(workspaceId, operatorKeyId) as
      | { enrolled_at: string | null }
      | undefined;
    if (!row) return { enrolled: false, pending: false };
    return {
      enrolled: Boolean(row.enrolled_at),
      pending: !row.enrolled_at,
    };
  }

  upsertOperatorMfaPending(
    workspaceId: string,
    operatorKeyId: string,
    secretEnc: string,
  ): void {
    const now = nowIso();
    const existing = this.db
      .prepare(
        `SELECT id FROM operator_mfa WHERE workspace_id = ? AND operator_key_id = ?`,
      )
      .get(workspaceId, operatorKeyId) as { id: string } | undefined;
    if (existing) {
      this.db
        .prepare(
          `UPDATE operator_mfa SET secret_enc = ?, enrolled_at = NULL, updated_at = ?
           WHERE id = ?`,
        )
        .run(secretEnc, now, existing.id);
      return;
    }
    this.db
      .prepare(
        `INSERT INTO operator_mfa (
          id, workspace_id, operator_key_id, kind, secret_enc, enrolled_at, created_at, updated_at
        ) VALUES (?, ?, ?, 'totp', ?, NULL, ?, ?)`,
      )
      .run(newId("mfa"), workspaceId, operatorKeyId, secretEnc, now, now);
  }

  markOperatorMfaEnrolled(
    workspaceId: string,
    operatorKeyId: string,
  ): boolean {
    const now = nowIso();
    const res = this.db
      .prepare(
        `UPDATE operator_mfa SET enrolled_at = ?, updated_at = ?
         WHERE workspace_id = ? AND operator_key_id = ?`,
      )
      .run(now, now, workspaceId, operatorKeyId);
    return Number(res.changes) > 0;
  }

  getOperatorMfaSecretEnc(
    workspaceId: string,
    operatorKeyId: string,
  ): { secretEnc: string; enrolled: boolean } | null {
    const row = this.db
      .prepare(
        `SELECT secret_enc, enrolled_at FROM operator_mfa
         WHERE workspace_id = ? AND operator_key_id = ?`,
      )
      .get(workspaceId, operatorKeyId) as
      | { secret_enc: string; enrolled_at: string | null }
      | undefined;
    if (!row) return null;
    return { secretEnc: String(row.secret_enc), enrolled: Boolean(row.enrolled_at) };
  }

  deleteOperatorMfa(workspaceId: string, operatorKeyId: string): boolean {
    const res = this.db
      .prepare(
        `DELETE FROM operator_mfa WHERE workspace_id = ? AND operator_key_id = ?`,
      )
      .run(workspaceId, operatorKeyId);
    return Number(res.changes) > 0;
  }
}
