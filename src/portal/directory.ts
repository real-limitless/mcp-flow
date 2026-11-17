import { randomBytes } from "node:crypto";
import { hashToken, newId, seal, unseal } from "../crypto.js";
import type { Store } from "../db/store.js";
import type { ResolvedAgent } from "../identity/agents.js";

const ABSOLUTE_MS = 8 * 60 * 60 * 1000;
const IDLE_MS = 30 * 60 * 1000;
const PRE_MFA_MS = 10 * 60 * 1000;
const STATE_MS = 10 * 60 * 1000;

export class PortalError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "PortalError";
  }
}

export interface PortalGooglePublic {
  clientId: string;
  hostedDomain: string | null;
  secretSet: boolean;
  updatedAt: string;
}

export interface PortalUserPublic {
  id: string;
  email: string;
  status: "active" | "suspended";
  platformAdmin: boolean;
  googleLinked: boolean;
  mfaEnrolled: boolean;
  mfaCompletedAt: string | null;
  workspaceIds: string[];
}

export interface PortalWorkspacePublic {
  id: string;
  name: string;
  disabledAt: string | null;
}

export interface PortalSession {
  id: string;
  kind: "bootstrap" | "user";
  workspaceId: string | null;
  userId: string | null;
  agentId: string | null;
  mfaOk: boolean;
  email: string | null;
  platformAdmin: boolean;
  expiresAt: string;
}

export interface PortalOAuthState {
  nonceHash: string;
  verifier: string;
}

function nowIso(): string {
  return new Date().toISOString();
}

function emailOf(raw: string): string {
  return raw.trim().toLowerCase();
}

function validEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function agentName(email: string, n: number): string {
  const local = email.split("@")[0]!.replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 48) || "admin";
  const suffix = n === 0 ? "" : `-${n + 1}`;
  return `${local}${suffix}`.slice(0, 128);
}

export class PortalDirectory {
  constructor(private readonly store: Store) {}

  private get db() {
    return this.store.db;
  }

  platformEnabled(): boolean {
    const row = this.db
      .prepare(`SELECT enabled_at FROM portal_platform WHERE id = 'platform'`)
      .get() as { enabled_at: string | null } | undefined;
    return Boolean(row?.enabled_at);
  }

  /** Env values fill an empty install once. A later portal save is left alone. */
  seed(input: {
    clientId: string;
    clientSecret: string;
    hostedDomain: string;
    emails: string[];
    workspaceId: string;
  }): void {
    const existing = this.db.prepare(`SELECT id FROM portal_google WHERE id = 'google'`).get();
    if (!existing && input.clientId.trim() && input.clientSecret.trim()) {
      this.saveGoogle({
        clientId: input.clientId.trim(),
        clientSecret: input.clientSecret.trim(),
        hostedDomain: input.hostedDomain.trim() || null,
      });
    }
    const count = this.db.prepare(`SELECT count(*) AS n FROM portal_user`).get() as { n: number };
    if (Number(count.n) > 0) return;
    for (const raw of input.emails) {
      const email = emailOf(raw);
      if (!validEmail(email)) continue;
      this.upsertUser({
        email,
        platformAdmin: true,
        workspaceIds: [input.workspaceId],
        status: "active",
      });
    }
  }

  getGoogle(): PortalGooglePublic | null {
    const row = this.db
      .prepare(
        `SELECT client_id, hosted_domain, client_secret_enc, updated_at FROM portal_google WHERE id = 'google'`,
      )
      .get() as
      | { client_id: string; hosted_domain: string | null; client_secret_enc: string; updated_at: string }
      | undefined;
    if (!row) return null;
    return {
      clientId: row.client_id,
      hostedDomain: row.hosted_domain,
      secretSet: Boolean(row.client_secret_enc),
      updatedAt: row.updated_at,
    };
  }

  googleSecret(): string | null {
    const row = this.db
      .prepare(`SELECT client_secret_enc FROM portal_google WHERE id = 'google'`)
      .get() as { client_secret_enc: string } | undefined;
    if (!row) return null;
    const payload = unseal<{ secret?: string }>(this.store.masterKey, row.client_secret_enc);
    const secret = String(payload.secret ?? "");
    return secret || null;
  }

  saveGoogle(input: { clientId: string; clientSecret?: string | null; hostedDomain?: string | null }): void {
    const clientId = input.clientId.trim();
    if (!clientId || clientId.length > 256) throw new PortalError("client id is required", 400);
    const hosted = input.hostedDomain?.trim() || null;
    if (hosted && (hosted.length > 253 || /[\s/]/.test(hosted))) {
      throw new PortalError("hosted domain is invalid", 400);
    }
    const current = this.db
      .prepare(`SELECT client_secret_enc FROM portal_google WHERE id = 'google'`)
      .get() as { client_secret_enc: string } | undefined;
    let secretEnc = current?.client_secret_enc ?? "";
    const incoming = input.clientSecret?.trim() ?? "";
    if (incoming) {
      if (incoming.length > 512) throw new PortalError("client secret is invalid", 400);
      secretEnc = seal(this.store.masterKey, { secret: incoming });
    }
    if (!secretEnc) throw new PortalError("client secret is required", 400);
    const ts = nowIso();
    this.db
      .prepare(
        `INSERT INTO portal_google (id, client_id, client_secret_enc, hosted_domain, updated_at)
         VALUES ('google', ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           client_id = excluded.client_id,
           client_secret_enc = excluded.client_secret_enc,
           hosted_domain = excluded.hosted_domain,
           updated_at = excluded.updated_at`,
      )
      .run(clientId, secretEnc, hosted, ts);
  }

  listUsers(): PortalUserPublic[] {
    const rows = this.db
      .prepare(
        `SELECT u.id, u.email, u.status, u.platform_admin, u.google_sub, u.mfa_completed_at,
                m.enrolled_at
           FROM portal_user u
           LEFT JOIN portal_login_mfa m ON m.user_id = u.id
          ORDER BY u.email ASC`,
      )
      .all() as Array<Record<string, unknown>>;
    return rows.map((row) => this.publishUser(row));
  }

  upsertUser(input: {
    email: string;
    platformAdmin: boolean;
    workspaceIds: string[];
    status?: "active" | "suspended";
    id?: string;
  }): PortalUserPublic {
    const email = emailOf(input.email);
    if (!validEmail(email)) throw new PortalError("email is invalid", 400);
    const workspaceIds = [...new Set(input.workspaceIds.map((id) => id.trim()).filter(Boolean))];
    for (const id of workspaceIds) {
      if (!this.workspace(id)) throw new PortalError("workspace not found", 400);
    }
    const status = input.status ?? "active";
    const ts = nowIso();
    const existing = input.id
      ? (this.db.prepare(`SELECT id FROM portal_user WHERE id = ?`).get(input.id) as { id: string } | undefined)
      : (this.db.prepare(`SELECT id FROM portal_user WHERE email = ?`).get(email) as { id: string } | undefined);
    const id = existing?.id ?? newId("pu");
    this.db.exec("BEGIN");
    try {
      if (existing) {
        this.db
          .prepare(
            `UPDATE portal_user SET email = ?, status = ?, platform_admin = ?, updated_at = ? WHERE id = ?`,
          )
          .run(email, status, input.platformAdmin ? 1 : 0, ts, id);
      } else {
        this.db
          .prepare(
            `INSERT INTO portal_user (
              id, email, google_sub, status, platform_admin, mfa_completed_at, created_at, updated_at
            ) VALUES (?, ?, NULL, ?, ?, NULL, ?, ?)`,
          )
          .run(id, email, status, input.platformAdmin ? 1 : 0, ts, ts);
      }
      this.db.prepare(`DELETE FROM portal_membership WHERE user_id = ?`).run(id);
      const ins = this.db.prepare(
        `INSERT INTO portal_membership (user_id, workspace_id, role) VALUES (?, ?, 'admin')`,
      );
      for (const workspaceId of workspaceIds) ins.run(id, workspaceId);
      if (status === "suspended" || workspaceIds.length === 0) {
        this.db
          .prepare(`UPDATE portal_session SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`)
          .run(ts, id);
      }
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
    return this.userById(id)!;
  }

  userById(id: string): PortalUserPublic | null {
    const row = this.db
      .prepare(
        `SELECT u.id, u.email, u.status, u.platform_admin, u.google_sub, u.mfa_completed_at,
                m.enrolled_at
           FROM portal_user u
           LEFT JOIN portal_login_mfa m ON m.user_id = u.id
          WHERE u.id = ?`,
      )
      .get(id) as Record<string, unknown> | undefined;
    return row ? this.publishUser(row) : null;
  }

  listWorkspaces(): PortalWorkspacePublic[] {
    const rows = this.db
      .prepare(`SELECT id, name, disabled_at FROM workspaces ORDER BY name ASC`)
      .all() as Array<{ id: string; name: string; disabled_at: string | null }>;
    return rows.map((row) => ({
      id: row.id,
      name: row.name,
      disabledAt: row.disabled_at,
    }));
  }

  workspace(id: string): PortalWorkspacePublic | null {
    const row = this.db
      .prepare(`SELECT id, name, disabled_at FROM workspaces WHERE id = ?`)
      .get(id) as { id: string; name: string; disabled_at: string | null } | undefined;
    if (!row) return null;
    return { id: row.id, name: row.name, disabledAt: row.disabled_at };
  }

  createWorkspace(name: string): PortalWorkspacePublic {
    const trimmed = name.trim();
    if (!trimmed || trimmed.length > 64) throw new PortalError("workspace name is invalid", 400);
    if (this.db.prepare(`SELECT id FROM workspaces WHERE name = ?`).get(trimmed)) {
      throw new PortalError("workspace already exists", 400);
    }
    const created = this.store.ensureWorkspace(trimmed);
    return { id: created.id, name: created.name, disabledAt: null };
  }

  updateWorkspace(id: string, input: { name?: string; disabled?: boolean }): PortalWorkspacePublic {
    const current = this.workspace(id);
    if (!current) throw new PortalError("workspace not found", 404);
    if (input.name !== undefined) {
      const trimmed = input.name.trim();
      if (!trimmed || trimmed.length > 64) throw new PortalError("workspace name is invalid", 400);
      const taken = this.db.prepare(`SELECT id FROM workspaces WHERE name = ?`).get(trimmed) as
        | { id: string }
        | undefined;
      if (taken && taken.id !== id) throw new PortalError("workspace already exists", 400);
      this.db.prepare(`UPDATE workspaces SET name = ? WHERE id = ?`).run(trimmed, id);
    }
    if (input.disabled !== undefined) {
      this.db
        .prepare(`UPDATE workspaces SET disabled_at = ? WHERE id = ?`)
        .run(input.disabled ? nowIso() : null, id);
      if (input.disabled) {
        this.db
          .prepare(
            `UPDATE portal_session SET revoked_at = ?
              WHERE workspace_id = ? AND kind = 'user' AND revoked_at IS NULL
                AND user_id NOT IN (SELECT id FROM portal_user WHERE platform_admin = 1)`,
          )
          .run(nowIso(), id);
      }
    }
    return this.workspace(id)!;
  }

  workspaceDisabled(id: string): boolean {
    return Boolean(this.workspace(id)?.disabledAt);
  }

  saveOAuthState(input: { state: string; nonce: string; verifier: string }): void {
    const ts = nowIso();
    this.db.prepare(`DELETE FROM portal_oauth_state WHERE expires_at <= ?`).run(ts);
    this.db
      .prepare(
        `INSERT INTO portal_oauth_state (state_hash, nonce_hash, pkce_verifier_enc, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .run(
        hashToken(input.state),
        hashToken(input.nonce),
        seal(this.store.masterKey, { verifier: input.verifier }),
        new Date(Date.now() + STATE_MS).toISOString(),
        ts,
      );
  }

  /** Single use. Returns null when the state is missing, expired, or already consumed. */
  takeOAuthState(state: string): PortalOAuthState | null {
    const hash = hashToken(state);
    const row = this.db
      .prepare(
        `SELECT nonce_hash, pkce_verifier_enc, expires_at FROM portal_oauth_state WHERE state_hash = ?`,
      )
      .get(hash) as
      | { nonce_hash: string; pkce_verifier_enc: string; expires_at: string }
      | undefined;
    this.db.prepare(`DELETE FROM portal_oauth_state WHERE state_hash = ?`).run(hash);
    if (!row || Date.parse(row.expires_at) <= Date.now()) return null;
    const payload = unseal<{ verifier?: string }>(this.store.masterKey, row.pkce_verifier_enc);
    const verifier = String(payload.verifier ?? "");
    if (!verifier) return null;
    return { nonceHash: row.nonce_hash, verifier };
  }

  nonceMatches(nonce: string, nonceHash: string): boolean {
    return hashToken(nonce) === nonceHash;
  }

  /**
   * Bind a verified Google identity to a portal user.
   * Unknown emails and accounts with no workspace are refused.
   */
  acceptGoogleIdentity(input: {
    sub: string;
    email: string;
    hostedDomain: string | null;
  }): { user: PortalUserPublic } {
    const email = emailOf(input.email);
    const bySub = this.db
      .prepare(`SELECT id, email FROM portal_user WHERE google_sub = ?`)
      .get(input.sub) as { id: string; email: string } | undefined;
    const byEmail = this.db
      .prepare(`SELECT id, google_sub, status FROM portal_user WHERE email = ?`)
      .get(email) as { id: string; google_sub: string | null; status: string } | undefined;
    if (bySub && byEmail && bySub.id !== byEmail.id) {
      throw new PortalError("sign-in was not accepted", 401);
    }
    const id = bySub?.id ?? byEmail?.id;
    if (!id) throw new PortalError("sign-in was not accepted", 401);
    if (byEmail?.google_sub && byEmail.google_sub !== input.sub && !bySub) {
      throw new PortalError("sign-in was not accepted", 401);
    }
    const google = this.getGoogle();
    if (google?.hostedDomain && input.hostedDomain?.toLowerCase() !== google.hostedDomain.toLowerCase()) {
      throw new PortalError("sign-in was not accepted", 401);
    }
    this.db
      .prepare(`UPDATE portal_user SET google_sub = ?, email = ?, updated_at = ? WHERE id = ?`)
      .run(input.sub, email, nowIso(), id);
    const user = this.userById(id);
    if (!user || user.status !== "active" || user.workspaceIds.length === 0) {
      throw new PortalError("sign-in was not accepted", 401);
    }
    return { user };
  }

  openUserSession(user: PortalUserPublic, mfaOk: boolean): { token: string; session: PortalSession } {
    const workspaceId = user.workspaceIds[0] ?? null;
    if (!workspaceId) throw new PortalError("sign-in was not accepted", 401);
    const agentId = mfaOk ? this.ensureAgent(user.email, workspaceId) : null;
    return this.insertSession({
      kind: "user",
      workspaceId,
      userId: user.id,
      agentId,
      mfaOk,
      ttlMs: mfaOk ? ABSOLUTE_MS : PRE_MFA_MS,
    });
  }

  openBootstrapSession(workspaceId: string): { token: string; session: PortalSession } {
    if (this.platformEnabled()) throw new PortalError("unauthorized", 401);
    return this.insertSession({
      kind: "bootstrap",
      workspaceId,
      userId: null,
      agentId: null,
      mfaOk: true,
      ttlMs: ABSOLUTE_MS,
    });
  }

  resolveSession(token: string): PortalSession | null {
    const row = this.db
      .prepare(
        `SELECT s.id, s.kind, s.workspace_id, s.user_id, s.agent_id, s.mfa_ok,
                s.expires_at, s.last_seen_at, s.revoked_at,
                u.email, u.status AS user_status, u.platform_admin
           FROM portal_session s
           LEFT JOIN portal_user u ON u.id = s.user_id
          WHERE s.token_hash = ?`,
      )
      .get(hashToken(token)) as Record<string, unknown> | undefined;
    if (!row || row.revoked_at != null) return null;
    const now = Date.now();
    if (Date.parse(String(row.expires_at)) <= now) return null;
    if (now - Date.parse(String(row.last_seen_at)) > IDLE_MS) {
      this.revokeSessionId(String(row.id));
      return null;
    }
    if (String(row.kind) === "bootstrap" && this.platformEnabled()) {
      this.revokeSessionId(String(row.id));
      return null;
    }
    if (String(row.kind) === "user") {
      if (row.user_status !== "active") {
        this.revokeSessionId(String(row.id));
        return null;
      }
      const workspaceId = row.workspace_id == null ? null : String(row.workspace_id);
      const member = workspaceId
        ? this.db
            .prepare(`SELECT 1 AS n FROM portal_membership WHERE user_id = ? AND workspace_id = ?`)
            .get(String(row.user_id), workspaceId)
        : undefined;
      if (!member) {
        this.revokeSessionId(String(row.id));
        return null;
      }
      const platformAdmin = Number(row.platform_admin) === 1;
      if (workspaceId && this.workspaceDisabled(workspaceId) && !platformAdmin) {
        this.revokeSessionId(String(row.id));
        return null;
      }
    }
    this.db
      .prepare(`UPDATE portal_session SET last_seen_at = ? WHERE id = ?`)
      .run(nowIso(), String(row.id));
    return this.sessionFromRow(row);
  }

  revokeToken(token: string): void {
    this.db
      .prepare(`UPDATE portal_session SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`)
      .run(nowIso(), hashToken(token));
  }

  switchWorkspace(token: string, workspaceId: string): PortalSession {
    const session = this.resolveSession(token);
    if (!session || !session.mfaOk) throw new PortalError("unauthorized", 401);
    const workspace = this.workspace(workspaceId);
    if (!workspace) throw new PortalError("workspace not found", 404);
    if (session.kind === "user") {
      const user = session.userId ? this.userById(session.userId) : null;
      if (!user || !user.workspaceIds.includes(workspaceId)) {
        throw new PortalError("forbidden", 403);
      }
      if (workspace.disabledAt && !user.platformAdmin) throw new PortalError("workspace disabled", 403);
      const agentId = this.ensureAgent(user.email, workspaceId);
      this.db
        .prepare(`UPDATE portal_session SET workspace_id = ?, agent_id = ? WHERE id = ?`)
        .run(workspaceId, agentId, session.id);
    } else {
      this.db.prepare(`UPDATE portal_session SET workspace_id = ? WHERE id = ?`).run(workspaceId, session.id);
    }
    return this.resolveSession(token)!;
  }

  mfaEnrolled(userId: string): boolean {
    const row = this.db
      .prepare(`SELECT enrolled_at FROM portal_login_mfa WHERE user_id = ?`)
      .get(userId) as { enrolled_at: string | null } | undefined;
    return Boolean(row?.enrolled_at);
  }

  beginEnroll(userId: string, base32: string): void {
    if (this.mfaEnrolled(userId)) throw new PortalError("totp already enrolled", 409);
    const ts = nowIso();
    const secretEnc = seal(this.store.masterKey, { base32 });
    const existing = this.db.prepare(`SELECT user_id FROM portal_login_mfa WHERE user_id = ?`).get(userId);
    if (existing) {
      this.db
        .prepare(
          `UPDATE portal_login_mfa SET secret_enc = ?, enrolled_at = NULL, updated_at = ? WHERE user_id = ?`,
        )
        .run(secretEnc, ts, userId);
    } else {
      this.db
        .prepare(
          `INSERT INTO portal_login_mfa (user_id, secret_enc, enrolled_at, updated_at) VALUES (?, ?, NULL, ?)`,
        )
        .run(userId, secretEnc, ts);
    }
  }

  mfaSecret(userId: string): { base32: string; enrolled: boolean } | null {
    const row = this.db
      .prepare(`SELECT secret_enc, enrolled_at FROM portal_login_mfa WHERE user_id = ?`)
      .get(userId) as { secret_enc: string; enrolled_at: string | null } | undefined;
    if (!row) return null;
    const payload = unseal<{ base32?: string }>(this.store.masterKey, row.secret_enc);
    const base32 = String(payload.base32 ?? "");
    if (!base32) return null;
    return { base32, enrolled: Boolean(row.enrolled_at) };
  }

  markMfaEnrolled(userId: string): void {
    const ts = nowIso();
    this.db
      .prepare(`UPDATE portal_login_mfa SET enrolled_at = COALESCE(enrolled_at, ?), updated_at = ? WHERE user_id = ?`)
      .run(ts, ts, userId);
  }

  /** Replace a pre-MFA cookie with a full session after the code checks out. */
  promoteMfa(token: string): { token: string; session: PortalSession } {
    const session = this.resolveSession(token);
    if (!session || session.kind !== "user" || !session.userId) throw new PortalError("unauthorized", 401);
    const user = this.userById(session.userId);
    if (!user) throw new PortalError("unauthorized", 401);
    this.markMfaEnrolled(user.id);
    this.db
      .prepare(`UPDATE portal_user SET mfa_completed_at = COALESCE(mfa_completed_at, ?) WHERE id = ?`)
      .run(nowIso(), user.id);
    this.revokeToken(token);
    const fresh = this.userById(user.id)!;
    return this.openUserSession(fresh, true);
  }

  canEnable(): { ok: true; userId: string } | { ok: false; error: string } {
    const google = this.getGoogle();
    if (!google?.clientId || !google.secretSet) return { ok: false, error: "google client is incomplete" };
    const row = this.db
      .prepare(
        `SELECT u.id
           FROM portal_user u
           JOIN portal_membership m ON m.user_id = u.id
          WHERE u.platform_admin = 1 AND u.status = 'active'
            AND u.google_sub IS NOT NULL AND u.mfa_completed_at IS NOT NULL
          LIMIT 1`,
      )
      .get() as { id: string } | undefined;
    if (!row) return { ok: false, error: "a platform admin must finish Google and TOTP first" };
    return { ok: true, userId: row.id };
  }

  enablePlatform(): { userId: string } {
    if (this.platformEnabled()) throw new PortalError("platform logins are already enabled", 409);
    const ready = this.canEnable();
    if (!ready.ok) throw new PortalError(ready.error, 400);
    const ts = nowIso();
    this.db.exec("BEGIN");
    try {
      this.db
        .prepare(
          `INSERT INTO portal_platform (id, enabled_at) VALUES ('platform', ?)
           ON CONFLICT(id) DO UPDATE SET enabled_at = excluded.enabled_at`,
        )
        .run(ts);
      this.db
        .prepare(`UPDATE portal_session SET revoked_at = ? WHERE kind = 'bootstrap' AND revoked_at IS NULL`)
        .run(ts);
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
    return { userId: ready.userId };
  }

  resetPlatform(): void {
    this.db.prepare(`UPDATE portal_platform SET enabled_at = NULL WHERE id = 'platform'`).run();
  }

  /** Human admin agent for this email in this workspace. */
  ensureAgent(email: string, workspaceId: string): string {
    this.store.ensureDefaultProject(workspaceId);
    const owner = emailOf(email);
    const found = this.db
      .prepare(
        `SELECT id, is_admin, status FROM mcpflow_agent
          WHERE workspace_id = ? AND owner = ? AND kind = 'human'
          ORDER BY created_at ASC LIMIT 1`,
      )
      .get(workspaceId, owner) as { id: string; is_admin: number; status: string } | undefined;
    if (found) {
      if (found.status !== "active" || found.is_admin !== 1) {
        throw new PortalError("sign-in was not accepted", 401);
      }
      return found.id;
    }
    const createdBy = this.store.identity.ensureBootstrapAdmin(workspaceId, {
      name: "operator",
      owner: "operator",
    });
    for (let n = 0; n < 5; n++) {
      try {
        return this.store.identity.createAgent({
          workspaceId,
          name: agentName(owner, n),
          owner,
          kind: "human",
          isAdmin: true,
          projects: ["default"],
          createdBy,
        });
      } catch (err) {
        if (!/UNIQUE constraint failed/.test(String((err as Error).message))) throw err;
      }
    }
    throw new PortalError("could not create the admin agent", 500);
  }

  resolvedAgent(session: PortalSession): ResolvedAgent | null {
    if (session.kind !== "user" || !session.agentId || !session.workspaceId || !session.mfaOk) return null;
    const row = this.db
      .prepare(
        `SELECT id, name, owner, kind, is_admin, status FROM mcpflow_agent WHERE id = ? AND workspace_id = ?`,
      )
      .get(session.agentId, session.workspaceId) as
      | { id: string; name: string; owner: string; kind: string; is_admin: number; status: string }
      | undefined;
    if (!row || row.status !== "active" || row.kind !== "human" || row.is_admin !== 1) return null;
    const projects = (
      this.db.prepare(`SELECT project_id FROM mcpflow_agent_project WHERE agent_id = ?`).all(row.id) as Array<{
        project_id: string;
      }>
    ).map((p) => p.project_id);
    return {
      agentId: row.id,
      agentName: row.name,
      owner: row.owner,
      kind: "human",
      isAdmin: true,
      workspaceId: session.workspaceId,
      keyId: "",
      keyPrefix: "",
      keyExpiresAt: session.expiresAt,
      effectiveProjects: projects,
      toolPrefixAllowlist: [],
    };
  }

  workspacesFor(session: PortalSession): PortalWorkspacePublic[] {
    if (session.kind === "bootstrap") return this.listWorkspaces();
    const user = session.userId ? this.userById(session.userId) : null;
    if (!user) return [];
    return this.listWorkspaces().filter((ws) => user.workspaceIds.includes(ws.id));
  }

  private publishUser(row: Record<string, unknown>): PortalUserPublic {
    const id = String(row.id);
    const memberships = this.db
      .prepare(`SELECT workspace_id FROM portal_membership WHERE user_id = ? ORDER BY workspace_id ASC`)
      .all(id) as Array<{ workspace_id: string }>;
    return {
      id,
      email: String(row.email),
      status: row.status === "suspended" ? "suspended" : "active",
      platformAdmin: Number(row.platform_admin) === 1,
      googleLinked: row.google_sub != null && String(row.google_sub) !== "",
      mfaEnrolled: row.enrolled_at != null && String(row.enrolled_at) !== "",
      mfaCompletedAt: row.mfa_completed_at == null ? null : String(row.mfa_completed_at),
      workspaceIds: memberships.map((m) => m.workspace_id),
    };
  }

  private insertSession(input: {
    kind: "bootstrap" | "user";
    workspaceId: string | null;
    userId: string | null;
    agentId: string | null;
    mfaOk: boolean;
    ttlMs: number;
  }): { token: string; session: PortalSession } {
    const token = randomBytes(32).toString("base64url");
    const ts = nowIso();
    const id = newId("ps");
    const expires = new Date(Date.now() + input.ttlMs).toISOString();
    this.db
      .prepare(
        `INSERT INTO portal_session (
          id, token_hash, kind, workspace_id, user_id, agent_id, mfa_ok,
          expires_at, last_seen_at, revoked_at, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
      )
      .run(
        id,
        hashToken(token),
        input.kind,
        input.workspaceId,
        input.userId,
        input.agentId,
        input.mfaOk ? 1 : 0,
        expires,
        ts,
        ts,
      );
    const session = this.resolveSession(token);
    if (!session) throw new PortalError("could not open a session", 500);
    return { token, session };
  }

  private revokeSessionId(id: string): void {
    this.db
      .prepare(`UPDATE portal_session SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`)
      .run(nowIso(), id);
  }

  private sessionFromRow(row: Record<string, unknown>): PortalSession {
    return {
      id: String(row.id),
      kind: row.kind === "bootstrap" ? "bootstrap" : "user",
      workspaceId: row.workspace_id == null ? null : String(row.workspace_id),
      userId: row.user_id == null ? null : String(row.user_id),
      agentId: row.agent_id == null ? null : String(row.agent_id),
      mfaOk: Number(row.mfa_ok) === 1,
      email: row.email == null ? null : String(row.email),
      platformAdmin: Number(row.platform_admin) === 1,
      expiresAt: String(row.expires_at),
    };
  }
}
