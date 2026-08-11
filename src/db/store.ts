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
  BackendPublic,
  BackendRecord,
  CreateBackendInput,
  Placement,
  UpdateBackendInput,
  Workspace,
} from "../types.js";
import { DEFAULT_PLACEMENT } from "../types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
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
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(workspace_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(token_hash);
CREATE INDEX IF NOT EXISTS idx_backends_ws ON backends(workspace_id);
`;

function nowIso(): string {
  return new Date().toISOString();
}

function rowKey(r: Record<string, unknown>): ApiKeyRecord {
  return {
    id: String(r.id),
    workspaceId: String(r.workspace_id),
    name: String(r.name),
    tokenHash: String(r.token_hash),
    prefix: String(r.prefix),
    createdAt: String(r.created_at),
    revokedAt: r.revoked_at == null ? null : String(r.revoked_at),
  };
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
    createdAt: String(r.created_at),
    updatedAt: String(r.updated_at),
  };
}

function toPublicKey(k: ApiKeyRecord): ApiKeyPublic {
  return {
    id: k.id,
    workspaceId: k.workspaceId,
    name: k.name,
    prefix: k.prefix,
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
  }

  close(): void {
    this.db.close();
  }

  ensureWorkspace(name: string): Workspace {
    const existing = this.db
      .prepare("SELECT id, name, created_at FROM workspaces WHERE name = ?")
      .get(name) as Record<string, unknown> | undefined;
    if (existing) {
      return {
        id: String(existing.id),
        name: String(existing.name),
        createdAt: String(existing.created_at),
      };
    }
    const ws: Workspace = {
      id: newId("ws"),
      name,
      createdAt: nowIso(),
    };
    this.db
      .prepare(
        "INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)",
      )
      .run(ws.id, ws.name, ws.createdAt);
    return ws;
  }

  getWorkspace(id: string): Workspace | null {
    const row = this.db
      .prepare("SELECT id, name, created_at FROM workspaces WHERE id = ?")
      .get(id) as Record<string, unknown> | undefined;
    if (!row) return null;
    return {
      id: String(row.id),
      name: String(row.name),
      createdAt: String(row.created_at),
    };
  }

  createApiKey(workspaceId: string, name: string): ApiKeyCreated {
    const { token, prefix, hash } = mintApiToken();
    const rec: ApiKeyRecord = {
      id: newId("key"),
      workspaceId,
      name,
      tokenHash: hash,
      prefix,
      createdAt: nowIso(),
      revokedAt: null,
    };
    this.db
      .prepare(
        `INSERT INTO api_keys (id, workspace_id, name, token_hash, prefix, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL)`,
      )
      .run(
        rec.id,
        rec.workspaceId,
        rec.name,
        rec.tokenHash,
        rec.prefix,
        rec.createdAt,
      );
    return { ...toPublicKey(rec), token };
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

  authenticateApiKey(
    token: string,
  ): { workspaceId: string; keyId: string; keyName: string } | null {
    const hash = hashToken(token);
    const row = this.db
      .prepare(
        `SELECT id, workspace_id, name, revoked_at FROM api_keys WHERE token_hash = ?`,
      )
      .get(hash) as Record<string, unknown> | undefined;
    if (!row || row.revoked_at != null) return null;
    return {
      workspaceId: String(row.workspace_id),
      keyId: String(row.id),
      keyName: String(row.name),
    };
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
      createdAt: ts,
      updatedAt: ts,
    };
    this.db
      .prepare(
        `INSERT INTO backends (
          id, workspace_id, slug, title, transport, url, image, command_json,
          headers_enc, env_enc, enabled, tool_allowlist_json, placement_json,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
    const updatedAt = nowIso();

    this.db
      .prepare(
        `UPDATE backends SET
          title = ?, transport = ?, url = ?, image = ?, command_json = ?,
          headers_enc = ?, env_enc = ?, enabled = ?, tool_allowlist_json = ?,
          placement_json = ?, updated_at = ?
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
}
