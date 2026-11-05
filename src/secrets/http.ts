/**
 * Admin REST for the secrets store. Human admin agents only.
 * Break-glass, legacy api_key, and OAuth grants are refused (do not widen M53-1).
 * Responses are refs and metadata. There is no import or reveal route.
 */

import type { Context, Hono } from "hono";
import type { AuthContext } from "../types.js";
import type { SecretDirectory } from "./directory.js";
import { SecretError } from "./directory.js";
import { ProtectedTargetError } from "./protected.js";

interface SecretHttpEnv {
  Variables: {
    auth: AuthContext;
    humanAdmin?: string;
  };
}

function fail(err: unknown): { status: 400 | 403 | 404 | 409; body: { error: string } } {
  if (err instanceof SecretError) return { status: err.status, body: { error: err.message } };
  if (err instanceof ProtectedTargetError) return { status: 403, body: { error: err.message } };
  return { status: 400, body: { error: "secret operation failed" } };
}

export function registerSecretRoutes(
  admin: Hono<SecretHttpEnv>,
  secrets: SecretDirectory,
): void {
  const actor = (c: Context<SecretHttpEnv>) => {
    const human = c.get("humanAdmin");
    const auth = c.get("auth");
    if (typeof human !== "string" || !auth?.workspaceId || !auth.keyId) return null;
    return {
      workspaceId: auth.workspaceId,
      keyId: auth.keyId,
      agentId: human,
      allowedProjects: null,
      humanAdmin: true,
    };
  };

  admin.post("/secrets", async (c) => {
    const who = actor(c);
    if (!who) return c.json({ error: "secret routes require a human admin agent" }, 403);
    const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body) return c.json({ error: "invalid body" }, 400);
    try {
      const out = secrets.create({
        ...who,
        project: String(body.project ?? ""),
        name: String(body.name ?? ""),
        type: String(body.type ?? ""),
        params: body.params,
        description: typeof body.description === "string" ? body.description : null,
      });
      return c.json(out, 201);
    } catch (err) {
      const failed = fail(err);
      return c.json(failed.body, failed.status);
    }
  });

  admin.get("/secrets", (c) => {
    const who = actor(c);
    if (!who) return c.json({ error: "secret routes require a human admin agent" }, 403);
    try {
      const out = secrets.list({
        ...who,
        project: c.req.query("project") ?? null,
        q: c.req.query("q") ?? null,
      });
      return c.json(out);
    } catch (err) {
      const failed = fail(err);
      return c.json(failed.body, failed.status);
    }
  });

  admin.post("/secrets/rotate", async (c) => {
    const who = actor(c);
    if (!who) return c.json({ error: "secret routes require a human admin agent" }, 403);
    const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body) return c.json({ error: "invalid body" }, 400);
    try {
      const out = secrets.rotate({
        ...who,
        ref: String(body.ref ?? ""),
        graceSeconds: typeof body.grace_seconds === "number" ? body.grace_seconds : null,
        resync: body.resync === true,
      });
      return c.json(out);
    } catch (err) {
      const failed = fail(err);
      return c.json(failed.body, failed.status);
    }
  });

  admin.post("/secrets/delete", async (c) => {
    const who = actor(c);
    if (!who) return c.json({ error: "secret routes require a human admin agent" }, 403);
    const body = (await c.req.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body) return c.json({ error: "invalid body" }, 400);
    try {
      const out = secrets.delete({ ...who, ref: String(body.ref ?? ""), purge: body.purge === true });
      return c.json(out);
    } catch (err) {
      const failed = fail(err);
      return c.json(failed.body, failed.status);
    }
  });
}
