/**
 * Single-use secret upload. No admin credential.
 * The token in the link authorizes one write. The response never echoes the value.
 */

import type { Env, Hono } from "hono";
import type { ProjectSecretDirectory } from "./project-scope.js";
import { SecretError } from "./directory.js";
import { ProtectedTargetError } from "./protected.js";

const MAX_BODY = 70_000;

function page(title: string, body: string): string {
  return `<!doctype html>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<title>${title}</title>
${body}
`;
}

function formPage(id: string, project: string, name: string): string {
  return page(
    "Supply a secret",
    `<p>Store one value for <strong>${name}</strong> in project <strong>${project}</strong>. It is not shown again.</p>
<form method="post" action="/secret-uploads/${id}">
  <input type="hidden" name="token" id="token">
  <label>Value <input name="value" type="password" autocomplete="off" required></label>
  <button type="submit">Store</button>
</form>
<script>
  var hash = location.hash.charAt(0) === "#" ? location.hash.slice(1) : "";
  document.getElementById("token").value = decodeURIComponent(hash);
</script>`,
  );
}

export function registerSecretUploadRoutes<E extends Env>(app: Hono<E>, projectSecrets: ProjectSecretDirectory): void {
  app.use("/secret-uploads/*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    c.header("Referrer-Policy", "no-referrer");
    c.header("X-Content-Type-Options", "nosniff");
    await next();
  });

  app.get("/secret-uploads/:id", (c) => {
    const found = projectSecrets.uploadPage(c.req.param("id"));
    if (!found) return c.html(page("Upload link", "<p>This upload link is unavailable.</p>"), 404);
    return c.html(formPage(c.req.param("id"), found.project, found.name));
  });

  app.post("/secret-uploads/:id", async (c) => {
    const len = Number(c.req.header("content-length") ?? "0");
    if (Number.isFinite(len) && len > MAX_BODY) return c.json({ error: "body too large" }, 413);
    const type = (c.req.header("content-type") ?? "").toLowerCase();
    let token = "";
    let value = "";
    try {
      if (type.includes("application/json")) {
        const body = (await c.req.json()) as Record<string, unknown>;
        token = typeof body.token === "string" ? body.token : "";
        value = typeof body.value === "string" ? body.value : "";
      } else {
        const body = await c.req.parseBody();
        const rawToken = body.token;
        const rawValue = body.value;
        token = typeof rawToken === "string" ? rawToken : "";
        value = typeof rawValue === "string" ? rawValue : "";
      }
    } catch {
      return c.json({ error: "invalid body" }, 400);
    }
    const wantsHtml = !type.includes("application/json");
    try {
      const stored = projectSecrets.consumeUpload(c.req.param("id"), token, value);
      value = "";
      token = "";
      if (wantsHtml) {
        return c.html(
          page(
            "Secret stored",
            `<p>Stored ${stored.ref} version ${stored.version}. The value was not displayed.</p>`,
          ),
        );
      }
      return c.json({ ok: true, ref: stored.ref, version: stored.version, name: stored.name, project: stored.project });
    } catch (err) {
      value = "";
      token = "";
      const status = err instanceof SecretError ? err.status : err instanceof ProtectedTargetError ? 403 : 400;
      const message = err instanceof SecretError || err instanceof ProtectedTargetError ? err.message : "secret operation failed";
      if (wantsHtml) return c.html(page("Upload failed", `<p>${message}</p>`), status);
      return c.json({ error: message }, status);
    }
  });
}
