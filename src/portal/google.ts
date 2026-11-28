import { randomBytes } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { pkceS256 } from "../oauth/downstream.js";
import { safeProviderCode, type PortalSignInCode } from "./signin-codes.js";

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";

const ISSUERS = ["https://accounts.google.com", "accounts.google.com"];

/** Seconds of clock skew accepted on the Google ID token exp/nbf checks. */
export const GOOGLE_CLOCK_TOLERANCE_SEC = 60;

export class GoogleSignInError extends Error {
  readonly provider: string | undefined;
  constructor(
    readonly code: PortalSignInCode,
    provider?: string,
  ) {
    super(code);
    this.name = "GoogleSignInError";
    this.provider = provider;
  }
}

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

export function beginGoogleAuth(input: {
  clientId: string;
  redirectUri: string;
  hostedDomain?: string | null;
}): {
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
  // Google includes the hd claim only when the authorization request sends hd.
  const hd = input.hostedDomain?.trim().toLowerCase() ?? "";
  if (hd) url.searchParams.set("hd", hd);
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
  if (!res.ok) {
    let provider: string | undefined;
    try {
      const json = (await res.json()) as { error?: unknown };
      provider = typeof json.error === "string" ? safeProviderCode(json.error) : undefined;
    } catch {
      provider = undefined;
    }
    throw new GoogleSignInError("token_exchange", provider);
  }
  const json = (await res.json()) as { id_token?: unknown };
  if (typeof json.id_token !== "string" || !json.id_token) {
    throw new GoogleSignInError("token_exchange");
  }
  return json.id_token;
}

export async function verifyGoogleIdToken(
  idToken: string,
  input: { audience: string; jwks?: JWTVerifyGetKey },
): Promise<GoogleIdentity> {
  let payload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
  try {
    ({ payload } = await jwtVerify(idToken, input.jwks ?? defaultJwks(), {
      issuer: ISSUERS,
      audience: input.audience,
      clockTolerance: GOOGLE_CLOCK_TOLERANCE_SEC,
    }));
  } catch (err) {
    throw new GoogleSignInError(googleTokenCode(err));
  }
  const email = typeof payload.email === "string" ? payload.email : "";
  const verified = payload.email_verified === true || payload.email_verified === "true";
  const sub = typeof payload.sub === "string" ? payload.sub : "";
  const nonce = typeof payload.nonce === "string" ? payload.nonce : "";
  const hd = typeof payload.hd === "string" ? payload.hd : null;
  if (!sub || !email) throw new GoogleSignInError("token_rejected");
  if (!verified) throw new GoogleSignInError("email_unverified");
  if (!nonce) throw new GoogleSignInError("nonce");
  return { sub, email, emailVerified: verified, hostedDomain: hd, nonce };
}

/** Map a jose verification failure to a reason code. The error text is not kept. */
export function googleTokenCode(err: unknown): PortalSignInCode {
  if (!err || typeof err !== "object") return "token_rejected";
  const code = "code" in err ? String((err as { code?: unknown }).code) : "";
  const claim = "claim" in err ? String((err as { claim?: unknown }).claim) : "";
  if (code === "ERR_JWT_EXPIRED") return "token_expired";
  if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
    if (claim === "aud") return "token_audience";
    if (claim === "iss") return "token_issuer";
    if (claim === "exp" || claim === "nbf" || claim === "iat") return "token_expired";
  }
  return "token_rejected";
}

/**
 * Gaps that stop Google sign-in. Empty when the client is not being configured.
 * Messages name env vars only. They do not include secret values or account addresses.
 */
export function googleSignInWarnings(input: {
  publicUrl: string;
  clientId: string;
  clientSecretConfigured: boolean;
}): string[] {
  const warnings: string[] = [];
  const id = input.clientId.trim();
  if (!id && !input.clientSecretConfigured) return warnings;
  if (!id) warnings.push("Google client secret is set without MCP_FLOW_GOOGLE_CLIENT_ID.");
  if (id && !input.clientSecretConfigured) {
    warnings.push(
      "Google client id is set without a client secret. Set MCP_FLOW_GOOGLE_CLIENT_SECRET or save one in Setup.",
    );
  }
  if (!input.publicUrl.trim()) {
    warnings.push(
      "MCP_FLOW_PUBLIC_URL is required for Google sign-in. Set it to the https origin browsers use, and register that origin plus /admin/oauth/callback on the Google client.",
    );
  }
  return warnings;
}
