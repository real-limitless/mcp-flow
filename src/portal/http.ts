import type { Context, Hono } from "hono";
import { generateTotpSecret, otpauthUrl } from "../authz/totp.js";
import { fromBase32, verifyTotp } from "../authz/totp.js";
import { mfaIsLocked, mfaRecordFailure, mfaRecordSuccess, mfaSubjectKey } from "../authz/mfa-lockout.js";
import type { Config } from "../config.js";
import { safeEqualStr } from "../crypto.js";
import type { Store } from "../db/store.js";
import { agentAuthContext } from "../identity/auth-context.js";
import type { AuthContext } from "../types.js";
import {
  clearPortalCookie,
  clearStateCookie,
  cookieMutationError,
  portalCookieIsSecure,
  publicOrigin,
  readPortalCookie,
  readStateCookie,
  writePortalCookie,
  writeStateCookie,
} from "./cookies.js";
import { PortalDirectory, PortalError, type PortalSession } from "./directory.js";
import {
  beginGoogleAuth,
  exchangeGoogleCode,
  GoogleSignInError,
  googleRedirectUri,
  verifyGoogleIdToken,
  type GoogleIdentity,
} from "./google.js";
import { isPortalSignInCode, safeProviderCode, type PortalSignInCode } from "./signin-codes.js";
import type { JWTVerifyGetKey } from "jose";

export interface PortalHooks {
  fetch?: typeof fetch;
  jwks?: JWTVerifyGetKey;
}

type PortalVars = {
  auth: AuthContext;
  humanAdmin?: string;
  bootstrap?: boolean;
  platformAdmin?: boolean;
};

export interface PortalAuth {
  auth: AuthContext;
  humanAdmin?: string;
  bootstrap: boolean;
  platformAdmin: boolean;
  /** Set when the browser presented a portal cookie, including a rejected one. */
  fromCookie: boolean;
  /** Pre-MFA Google session. /v1 stays closed. */
  mfaPending: boolean;
}

function mfaKey(userId: string): string {
  return mfaSubjectKey("portal", userId);
}

export function createPortal(store: Store, cfg: Config): PortalDirectory {
  const portal = new PortalDirectory(store);
  const ws = store.ensureWorkspace(cfg.workspaceName);
  portal.seed({
    clientId: cfg.googleClientId,
    clientSecret: cfg.googleClientSecret,
    hostedDomain: cfg.googleHostedDomain,
    emails: cfg.googleAdminEmails,
    workspaceId: ws.id,
  });
  return portal;
}

export function sessionAuth(portal: PortalDirectory, session: PortalSession): PortalAuth | null {
  if (session.kind === "bootstrap") {
    if (!session.workspaceId || !session.mfaOk) return null;
    return {
      auth: { kind: "admin", workspaceId: session.workspaceId },
      bootstrap: true,
      platformAdmin: false,
      fromCookie: true,
      mfaPending: false,
    };
  }
  if (!session.mfaOk) {
    return {
      auth: { kind: "admin", workspaceId: session.workspaceId ?? "" },
      bootstrap: false,
      platformAdmin: false,
      fromCookie: true,
      mfaPending: true,
    };
  }
  const agent = portal.resolvedAgent(session);
  if (!agent) return null;
  return {
    auth: agentAuthContext(agent, { mcpSessionId: null }),
    humanAdmin: agent.agentId,
    bootstrap: false,
    platformAdmin: session.platformAdmin,
    fromCookie: true,
    mfaPending: false,
  };
}

/** Bearer equal to the admin token. After cutover this is never a credential. */
export function adminTokenAccepted(portal: PortalDirectory, cfg: Config, token: string): boolean {
  if (!cfg.adminToken || !safeEqualStr(token, cfg.adminToken)) return false;
  return !portal.platformEnabled();
}

export function registerPortalRoutes(
  app: Hono<{ Variables: PortalVars }>,
  deps: {
    store: Store;
    cfg: Config;
    portal: PortalDirectory;
    requestOrigin: (c: Context) => string;
    hooks?: PortalHooks;
  },
): void {
  const { cfg, portal } = deps;

  const secure = (c: Context) =>
    portalCookieIsSecure({
      origin: c.req.header("origin"),
      requestOrigin: deps.requestOrigin(c),
      publicUrl: cfg.publicUrl,
      forwardedProto: c.req.header("x-forwarded-proto"),
      forwardedHost: c.req.header("x-forwarded-host"),
      host: c.req.header("host"),
    });

  const noteRejection = (kind: "google" | "bootstrap", code: string, provider?: string): PortalSignInCode => {
    const reason: PortalSignInCode = isPortalSignInCode(code) ? code : "token_rejected";
    const safeProvider = safeProviderCode(provider);
    console.error(
      `[mcp-flow] portal sign-in rejected kind=${kind} code=${reason}${safeProvider ? ` provider=${safeProvider}` : ""}`,
    );
    try {
      const ws = deps.store.ensureWorkspace(cfg.workspaceName);
      deps.store.writeAudit({
        workspaceId: ws.id,
        action: "portal.login_rejected",
        detail: { kind, reason, ...(safeProvider ? { provider: safeProvider } : {}) },
      });
    } catch {
      console.error(`[mcp-flow] portal sign-in audit failed code=${reason}`);
    }
    return reason;
  };

  const mutationGuard = (c: Context): Response | null => {
    const err = cookieMutationError(c, deps.requestOrigin(c), [publicOrigin(cfg.publicUrl)]);
    if (!err) return null;
    return c.json({ error: err === "origin" ? "origin not allowed" : "csrf" }, 403);
  };

  const sessionView = (c: Context, session: PortalSession | null) => {
    const google = portal.getGoogle();
    let redirectUri: string | null = null;
    try {
      redirectUri = googleRedirectUri(cfg.publicUrl);
    } catch {
      redirectUri = null;
    }
    const base = {
      googleConfigured: Boolean(google?.clientId && google.secretSet),
      platformLoginsEnabled: portal.platformEnabled(),
      redirectUri,
      hostedDomain: google?.hostedDomain ?? null,
    };
    if (!session) return c.json({ ...base, state: "anonymous" });
    const workspace = session.workspaceId ? portal.workspace(session.workspaceId) : null;
    return c.json({
      ...base,
      state: session.kind === "bootstrap" ? "bootstrap" : session.mfaOk ? "user" : "mfa",
      email: session.email,
      platformAdmin: session.kind === "bootstrap" || session.platformAdmin,
      mfaEnrolled: session.userId ? portal.mfaEnrolled(session.userId) : false,
      workspace,
      workspaces: portal.workspacesFor(session),
    });
  };

  app.get("/admin/session", (c) => {
    const token = readPortalCookie(c);
    const session = token ? portal.resolveSession(token) : null;
    return sessionView(c, session);
  });

  app.post("/admin/bootstrap-login", async (c) => {
    const guard = cookieMutationError(c, deps.requestOrigin(c), [publicOrigin(cfg.publicUrl)]);
    if (guard) {
      const reason = noteRejection("bootstrap", guard === "origin" ? "origin" : "csrf");
      return c.json({ error: guard === "origin" ? "origin not allowed" : "csrf", reason }, 403);
    }
    if (portal.platformEnabled()) {
      const reason = noteRejection("bootstrap", "bootstrap_retired");
      return c.json({ error: "unauthorized", reason }, 401);
    }
    const body = (await c.req.json().catch(() => ({}))) as { token?: unknown };
    const token = typeof body.token === "string" ? body.token.trim() : "";
    if (!cfg.adminToken || !token || !safeEqualStr(token, cfg.adminToken)) {
      const reason = noteRejection("bootstrap", token ? "bootstrap_rejected" : "bootstrap_missing");
      return c.json({ error: "unauthorized", reason }, 401);
    }
    const ws = deps.store.ensureWorkspace(cfg.workspaceName);
    const opened = portal.openBootstrapSession(ws.id);
    writePortalCookie(c, opened.token, secure(c));
    deps.store.writeAudit({
      workspaceId: ws.id,
      action: "portal.login",
      detail: { kind: "bootstrap" },
    });
    return sessionView(c, opened.session);
  });

  app.post("/admin/session/logout", (c) => {
    const blocked = mutationGuard(c);
    if (blocked) return blocked;
    const token = readPortalCookie(c);
    if (token) {
      const session = portal.resolveSession(token);
      portal.revokeToken(token);
      if (session?.workspaceId) {
        deps.store.writeAudit({
          workspaceId: session.workspaceId,
          action: "portal.logout",
          detail: { kind: session.kind },
        });
      }
    }
    clearPortalCookie(c, secure(c));
    return c.json({ ok: true });
  });

  app.post("/admin/session/workspace", async (c) => {
    const blocked = mutationGuard(c);
    if (blocked) return blocked;
    const token = readPortalCookie(c);
    if (!token) return c.json({ error: "unauthorized" }, 401);
    const body = (await c.req.json().catch(() => ({}))) as { id?: unknown };
    const id = typeof body.id === "string" ? body.id.trim() : "";
    if (!id) return c.json({ error: "workspace id required" }, 400);
    try {
      const session = portal.switchWorkspace(token, id);
      return sessionView(c, session);
    } catch (err) {
      if (err instanceof PortalError) return c.json({ error: err.message }, err.status as 400);
      throw err;
    }
  });

  app.post("/admin/session/mfa/enroll", (c) => {
    const blocked = mutationGuard(c);
    if (blocked) return blocked;
    const token = readPortalCookie(c);
    const session = token ? portal.resolveSession(token) : null;
    if (!session || session.kind !== "user" || session.mfaOk || !session.userId || !session.email) {
      return c.json({ error: "unauthorized" }, 401);
    }
    if (portal.mfaEnrolled(session.userId)) return c.json({ error: "totp already enrolled" }, 409);
    const secret = generateTotpSecret();
    portal.beginEnroll(session.userId, secret.base32);
    return c.json({
      otpauth: otpauthUrl({ issuer: "mcp-flow", account: session.email, base32: secret.base32 }),
      secret: secret.base32,
    });
  });

  app.post("/admin/session/mfa/confirm", async (c) => {
    const blocked = mutationGuard(c);
    if (blocked) return blocked;
    const token = readPortalCookie(c);
    const session = token ? portal.resolveSession(token) : null;
    if (!session || session.kind !== "user" || !session.userId) {
      return c.json({ error: "unauthorized" }, 401);
    }
    const body = (await c.req.json().catch(() => ({}))) as { totp?: unknown };
    const code = typeof body.totp === "string" ? body.totp.trim() : "";
    const subject = mfaKey(session.userId);
    if (mfaIsLocked(subject)) return c.json({ error: "totp locked" }, 429);
    const row = portal.mfaSecret(session.userId);
    if (!row) return c.json({ error: "totp required" }, 400);
    if (!verifyTotp(fromBase32(row.base32), code)) {
      mfaRecordFailure(subject);
      if (session.workspaceId) {
        deps.store.writeAudit({
          workspaceId: session.workspaceId,
          action: "portal.mfa_fail",
          detail: { userId: session.userId },
        });
      }
      return c.json({ error: mfaIsLocked(subject) ? "totp locked" : "invalid totp" }, mfaIsLocked(subject) ? 429 : 401);
    }
    mfaRecordSuccess(subject);
    try {
      const opened = portal.promoteMfa(token!);
      writePortalCookie(c, opened.token, secure(c));
      deps.store.writeAudit({
        workspaceId: opened.session.workspaceId ?? "",
        action: "portal.enroll",
        detail: { userId: session.userId },
      });
      return sessionView(c, opened.session);
    } catch (err) {
      if (err instanceof PortalError) {
        if (err.code) noteRejection("google", err.code);
        return c.json({ error: err.message, ...(err.code ? { reason: err.code } : {}) }, err.status as 400);
      }
      throw err;
    }
  });

  app.get("/admin/oauth/start", (c) => {
    const fail = (code: PortalSignInCode) => {
      noteRejection("google", code);
      return c.redirect(`/admin/?portal_error=${code}`);
    };
    const google = portal.getGoogle();
    const secret = portal.googleSecret();
    if (!google?.clientId || !secret) return fail("google_unconfigured");
    let redirectUri: string;
    try {
      redirectUri = googleRedirectUri(cfg.publicUrl);
    } catch {
      return fail("public_url");
    }
    const started = beginGoogleAuth({
      clientId: google.clientId,
      redirectUri,
      hostedDomain: google.hostedDomain,
    });
    portal.saveOAuthState(started);
    writeStateCookie(c, started.state, secure(c));
    return c.redirect(started.url);
  });

  app.get("/admin/oauth/callback", async (c) => {
    const fail = (code: string, provider?: string) => {
      const reason = noteRejection("google", code, provider);
      clearStateCookie(c, secure(c));
      return c.redirect(`/admin/?portal_error=${encodeURIComponent(reason)}`);
    };
    const state = c.req.query("state") ?? "";
    const code = c.req.query("code") ?? "";
    const providerError = c.req.query("error") ?? "";
    if (providerError && !code) return fail("provider_denied", safeProviderCode(providerError));
    if (!state) return fail("state_missing");
    if (!code) return fail("code_missing");
    const cookie = readStateCookie(c);
    if (!cookie) return fail("state_cookie");
    if (!safeEqualStr(cookie, state)) return fail("state_mismatch");
    let saved: ReturnType<PortalDirectory["takeOAuthState"]>;
    try {
      saved = portal.takeOAuthState(state);
    } catch {
      return fail("state_unreadable");
    }
    clearStateCookie(c, secure(c));
    if (!saved) return fail("state_expired");
    const google = portal.getGoogle();
    const secret = portal.googleSecret();
    if (!google || !secret) return fail("google_unconfigured");
    let redirectUri: string;
    try {
      redirectUri = googleRedirectUri(cfg.publicUrl);
    } catch {
      return fail("public_url");
    }
    let identity: GoogleIdentity;
    try {
      const idToken = await exchangeGoogleCode(
        {
          clientId: google.clientId,
          clientSecret: secret,
          redirectUri,
          code,
          verifier: saved.verifier,
        },
        deps.hooks?.fetch,
      );
      identity = await verifyGoogleIdToken(idToken, {
        audience: google.clientId,
        jwks: deps.hooks?.jwks,
      });
    } catch (err) {
      if (err instanceof GoogleSignInError) return fail(err.code, err.provider);
      return fail("token_rejected");
    }
    if (!portal.nonceMatches(identity.nonce, saved.nonceHash)) return fail("nonce");
    try {
      const accepted = portal.acceptGoogleIdentity({
        sub: identity.sub,
        email: identity.email,
        hostedDomain: identity.hostedDomain,
      });
      const opened = portal.openUserSession(accepted.user, false);
      writePortalCookie(c, opened.token, secure(c), 10 * 60);
      const ws = opened.session.workspaceId ?? accepted.user.workspaceIds[0] ?? "";
      deps.store.writeAudit({
        workspaceId: ws,
        action: "portal.login",
        detail: { kind: "user", mfa: false },
      });
      return c.redirect("/admin/?mfa=1");
    } catch (err) {
      if (err instanceof PortalError && err.code) return fail(err.code);
      return fail("session_rejected");
    }
  });
}

export function registerPortalSetup(
  admin: Hono<{ Variables: PortalVars }>,
  deps: { store: Store; cfg: Config; portal: PortalDirectory },
): void {
  const { portal, store, cfg } = deps;

  admin.use("/portal/*", async (c, next) => {
    if (c.get("bootstrap") || c.get("platformAdmin")) {
      await next();
      return;
    }
    return c.json({ error: "forbidden" }, 403);
  });

  admin.get("/portal/google", (c) => {
    const google = portal.getGoogle();
    let redirectUri: string | null = null;
    try {
      redirectUri = googleRedirectUri(cfg.publicUrl);
    } catch {
      redirectUri = null;
    }
    return c.json({
      clientId: google?.clientId ?? "",
      hostedDomain: google?.hostedDomain ?? "",
      secretSet: Boolean(google?.secretSet),
      redirectUri,
      platformLoginsEnabled: portal.platformEnabled(),
      canEnable: portal.canEnable().ok,
    });
  });

  admin.put("/portal/google", async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      clientId?: unknown;
      clientSecret?: unknown;
      hostedDomain?: unknown;
    };
    try {
      portal.saveGoogle({
        clientId: typeof body.clientId === "string" ? body.clientId : "",
        clientSecret: typeof body.clientSecret === "string" ? body.clientSecret : "",
        hostedDomain: typeof body.hostedDomain === "string" ? body.hostedDomain : "",
      });
    } catch (err) {
      if (err instanceof PortalError) return c.json({ error: err.message }, err.status as 400);
      throw err;
    }
    store.writeAudit({
      workspaceId: c.get("auth").workspaceId,
      action: "portal.google_update",
      detail: { secretChanged: typeof body.clientSecret === "string" && body.clientSecret.trim() !== "" },
    });
    const google = portal.getGoogle();
    return c.json({ clientId: google?.clientId ?? "", secretSet: Boolean(google?.secretSet), hostedDomain: google?.hostedDomain ?? "" });
  });

  admin.get("/portal/users", (c) => c.json({ users: portal.listUsers() }));

  admin.post("/portal/users", async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as {
      email?: unknown;
      platformAdmin?: unknown;
      workspaceIds?: unknown;
      status?: unknown;
    };
    try {
      const user = portal.upsertUser({
        email: typeof body.email === "string" ? body.email : "",
        platformAdmin: body.platformAdmin === true,
        workspaceIds: Array.isArray(body.workspaceIds) ? body.workspaceIds.map(String) : [],
        status: body.status === "suspended" ? "suspended" : "active",
      });
      store.writeAudit({
        workspaceId: c.get("auth").workspaceId,
        action: "portal.user_update",
        detail: { userId: user.id, email: user.email, platformAdmin: user.platformAdmin },
      });
      return c.json({ user }, 201);
    } catch (err) {
      if (err instanceof PortalError) return c.json({ error: err.message }, err.status as 400);
      throw err;
    }
  });

  admin.patch("/portal/users/:id", async (c) => {
    const current = portal.userById(c.req.param("id"));
    if (!current) return c.json({ error: "not found" }, 404);
    const body = (await c.req.json().catch(() => ({}))) as {
      email?: unknown;
      platformAdmin?: unknown;
      workspaceIds?: unknown;
      status?: unknown;
    };
    try {
      const user = portal.upsertUser({
        id: current.id,
        email: typeof body.email === "string" ? body.email : current.email,
        platformAdmin: body.platformAdmin === undefined ? current.platformAdmin : body.platformAdmin === true,
        workspaceIds: Array.isArray(body.workspaceIds) ? body.workspaceIds.map(String) : current.workspaceIds,
        status: body.status === "suspended" ? "suspended" : body.status === "active" ? "active" : current.status,
      });
      store.writeAudit({
        workspaceId: c.get("auth").workspaceId,
        action: "portal.user_update",
        detail: { userId: user.id, status: user.status, platformAdmin: user.platformAdmin },
      });
      return c.json({ user });
    } catch (err) {
      if (err instanceof PortalError) return c.json({ error: err.message }, err.status as 400);
      throw err;
    }
  });

  admin.get("/portal/workspaces", (c) => c.json({ workspaces: portal.listWorkspaces() }));

  admin.post("/portal/workspaces", async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { name?: unknown };
    try {
      const workspace = portal.createWorkspace(typeof body.name === "string" ? body.name : "");
      store.writeAudit({
        workspaceId: workspace.id,
        action: "portal.workspace_update",
        detail: { op: "create", name: workspace.name },
      });
      return c.json({ workspace }, 201);
    } catch (err) {
      if (err instanceof PortalError) return c.json({ error: err.message }, err.status as 400);
      throw err;
    }
  });

  admin.patch("/portal/workspaces/:id", async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as { name?: unknown; disabled?: unknown };
    try {
      const workspace = portal.updateWorkspace(c.req.param("id"), {
        name: typeof body.name === "string" ? body.name : undefined,
        disabled: typeof body.disabled === "boolean" ? body.disabled : undefined,
      });
      store.writeAudit({
        workspaceId: workspace.id,
        action: "portal.workspace_update",
        detail: { name: workspace.name, disabled: Boolean(workspace.disabledAt) },
      });
      return c.json({ workspace });
    } catch (err) {
      if (err instanceof PortalError) return c.json({ error: err.message }, err.status as 400);
      throw err;
    }
  });

  admin.post("/portal/enable", (c) => {
    try {
      const enabled = portal.enablePlatform();
      store.writeAudit({
        workspaceId: c.get("auth").workspaceId,
        action: "portal.platform_enabled",
        detail: { platformAdminId: enabled.userId },
      });
      return c.json({ platformLoginsEnabled: true });
    } catch (err) {
      if (err instanceof PortalError) return c.json({ error: err.message }, err.status as 400);
      throw err;
    }
  });
}
