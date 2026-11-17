import { randomBytes } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { pkceS256 } from "../oauth/downstream.js";

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

const ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

let remoteJwks: JWTVerifyGetKey | null = null;

function defaultJwks(): JWTVerifyGetKey {
  if (!remoteJwks) remoteJwks = createRemoteJWKSet(new URL(GOOGLE_JWKS_URL));
  return remoteJwks;
}

export interface GoogleIdentity {
  sub: string;
  email: string;
  emailVerified: boolean;
  hostedDomain: string | null;
  nonce: string;
}

export interface GoogleClientConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export function googleRedirectUri(publicUrl: string): string {
  const raw = publicUrl.trim();
  if (!raw) throw new Error("MCP_FLOW_PUBLIC_URL is required to start Google sign-in");
  const url = new URL(raw);
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("MCP_FLOW_PUBLIC_URL must be http or https");
  }
  return `${url.origin}/admin/oauth/callback`;
}

export function beginGoogleAuth(input: { clientId: string; redirectUri: string }): {
  url: string;
  state: string;
  nonce: string;
  verifier: string;
} {
  const state = randomBytes(32).toString("base64url");
  const nonce = randomBytes(32).toString("base64url");
  const verifier = randomBytes(32).toString("base64url");
  const url = new URL(GOOGLE_AUTH_URL);
  url.searchParams.set("client_id", input.clientId);
  url.searchParams.set("redirect_uri", input.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email");
  url.searchParams.set("state", state);
  url.searchParams.set("nonce", nonce);
  url.searchParams.set("code_challenge", pkceS256(verifier));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("prompt", "select_account");
  return { url: url.toString(), state, nonce, verifier };
}

export async function exchangeGoogleCode(
  input: GoogleClientConfig & { code: string; verifier: string },
  fetchImpl: typeof fetch = fetch,
): Promise<string> {
  const body = new URLSearchParams({
    code: input.code,
    client_id: input.clientId,
    client_secret: input.clientSecret,
    redirect_uri: input.redirectUri,
    grant_type: "authorization_code",
    code_verifier: input.verifier,
  });
  const res = await fetchImpl(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!res.ok) throw new Error("google token exchange failed");
  const json = (await res.json()) as { id_token?: unknown };
  if (typeof json.id_token !== "string" || !json.id_token) {
    throw new Error("google token exchange failed");
  }
  return json.id_token;
}

export async function verifyGoogleIdToken(
  idToken: string,
  input: { audience: string; jwks?: JWTVerifyGetKey },
): Promise<GoogleIdentity> {
  const { payload } = await jwtVerify(idToken, input.jwks ?? defaultJwks(), {
    issuer: ISSUERS,
    audience: input.audience,
  });
  const email = typeof payload.email === "string" ? payload.email : "";
  const verified = payload.email_verified === true || payload.email_verified === "true";
  const sub = typeof payload.sub === "string" ? payload.sub : "";
  const nonce = typeof payload.nonce === "string" ? payload.nonce : "";
  const hd = typeof payload.hd === "string" ? payload.hd : null;
  if (!sub || !email || !verified || !nonce) {
    throw new Error("google id token was not accepted");
  }
  return { sub, email, emailVerified: verified, hostedDomain: hd, nonce };
}
