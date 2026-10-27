import { createHash, randomBytes } from "node:crypto";
import { hashToken, safeEqualStr } from "../crypto.js";
import type { ApiKeyScopes } from "../types.js";

export const OAUTH_SCOPES = ["mcp", "mcp:admin"] as const;

export function issuerOrigin(publicUrl: string, requestOrigin: string): string {
  const raw = (publicUrl.trim() || requestOrigin.trim()).replace(/\/$/, "");
  return new URL(raw).origin;
}

export function resourceMetadata(origin: string) {
  return {
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
    scopes_supported: [...OAUTH_SCOPES],
    bearer_methods_supported: ["header"],
    resource_name: "mcp-flow",
  };
}

export function authorizationServerMetadata(origin: string) {
  return {
    issuer: origin,
    authorization_endpoint: `${origin}/oauth/authorize`,
    token_endpoint: `${origin}/oauth/token`,
    registration_endpoint: `${origin}/oauth/register`,
    scopes_supported: [...OAUTH_SCOPES],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: [
      "none",
      "client_secret_post",
      "client_secret_basic",
    ],
  };
}

export function wwwAuthenticate(origin: string): string {
  const metadata = `${origin}/.well-known/oauth-protected-resource/mcp`;
  return `Bearer realm="mcp-flow", resource_metadata="${metadata}"`;
}

export function normalizeOauthScope(scope: string | null | undefined): {
  scope: string;
  scopes: ApiKeyScopes | null;
} {
  const requested = new Set(
    (scope ?? "")
      .split(/\s+/)
      .map((s) => s.trim())
      .filter(Boolean),
  );
  const admin = requested.has("mcp:admin");
  const out = admin ? ["mcp", "mcp:admin"] : ["mcp"];
  return { scope: out.join(" "), scopes: admin ? { admin: true } : null };
}

export function pkceS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

export function validCodeVerifier(verifier: string): boolean {
  return /^[A-Za-z0-9\-._~]{43,128}$/.test(verifier);
}

export function mintAuthCode(): { code: string; hash: string } {
  const code = randomBytes(32).toString("base64url");
  return { code, hash: hashToken(code) };
}

export function redirectAllowed(registered: string[], uri: string): boolean {
  if (registered.includes(uri)) return true;
  if (!registered.includes("*")) return false;
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (url.username || url.password) return false;
  if (url.protocol === "https:") return true;
  if (url.protocol !== "http:") return false;
  const host = url.hostname.toLowerCase();
  return host === "127.0.0.1" || host === "localhost" || host === "::1";
}

export function clientSecretOk(
  secretHash: string | null,
  presented: string | null,
): boolean {
  if (!secretHash) return true;
  if (!presented) return false;
  return safeEqualStr(hashToken(presented), secretHash);
}

export function registrationRedirectsOk(uris: string[]): boolean {
  if (!uris.length || uris.length > 8) return false;
  return uris.every((uri) => redirectAllowed(["*"], uri) && !uri.includes("*"));
}

export function escHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

export function consentPage(input: {
  clientName: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  resource: string;
  error?: string;
}): string {
  const hidden = (name: string, value: string) =>
    `<input type="hidden" name="${escHtml(name)}" value="${escHtml(value)}" />`;
  return `<!doctype html><html><head><meta charset="utf-8"><title>mcp-flow login</title>
<style>
  body{font-family:ui-sans-serif,system-ui,sans-serif;background:#080b12;color:#e8eefc;margin:0;padding:48px 16px}
  main{max-width:32rem;margin:0 auto}
  h1{font-size:1.4rem}
  .box{border:1px solid #243049;border-radius:12px;padding:16px;margin:16px 0}
  label{display:block;margin:12px 0 6px;font-size:12px;letter-spacing:.04em;text-transform:uppercase;color:#93a0bd}
  input[type=password]{width:100%;box-sizing:border-box;background:#0d1320;color:#e8eefc;border:1px solid #31415f;border-radius:8px;padding:10px}
  .row{display:flex;gap:8px;margin-top:16px}
  button{border:0;border-radius:999px;padding:8px 14px;cursor:pointer}
  .allow{background:#5b8def;color:#fff}
  .deny{background:transparent;color:#e8eefc;border:1px solid #31415f}
  .err{color:#ff8d8d}
  code{font-size:12px}
</style></head><body><main>
  <h1>Allow connector</h1>
  <p>${escHtml(input.clientName)} is asking to call this gateway.</p>
  <div class="box">
    <div>Client <code>${escHtml(input.clientId)}</code></div>
    <div>Redirect <code>${escHtml(input.redirectUri)}</code></div>
    <div>Scope <code>${escHtml(input.scope)}</code></div>
  </div>
  ${input.error ? `<p class="err">${escHtml(input.error)}</p>` : ""}
  <form method="post" action="/oauth/authorize">
    ${hidden("client_id", input.clientId)}
    ${hidden("redirect_uri", input.redirectUri)}
    ${hidden("scope", input.scope)}
    ${hidden("state", input.state)}
    ${hidden("code_challenge", input.codeChallenge)}
    ${hidden("resource", input.resource)}
    <label for="admin_token">Agent key or admin token</label>
    <input id="admin_token" name="admin_token" type="password" autocomplete="off" required />
    <p>The connector gets this key's scopes. Paste an <code>mf_…</code> key from Keys, or the admin token.</p>
    <div class="row">
      <button class="allow" name="decision" value="allow" type="submit">Allow</button>
      <button class="deny" name="decision" value="deny" type="submit">Deny</button>
    </div>
  </form>
</main></body></html>`;
}
