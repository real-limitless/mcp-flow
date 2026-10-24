import type { BackendOauthInput } from "../types.js";

export function hasAuthorizationHeader(
  headers: Record<string, string | null> | null | undefined,
): boolean {
  if (!headers) return false;
  return Object.entries(headers).some(
    ([name, value]) => name.toLowerCase() === "authorization" && value != null,
  );
}

export function scopeString(scopes: string[] | undefined): string | null {
  if (!scopes?.length) return null;
  const joined = scopes.map((s) => s.trim()).filter(Boolean).join(" ");
  return joined || null;
}

/**
 * OAuth is only for remote HTTP/SSE, and it owns the Authorization header.
 * Static apiKey / Authorization and an OAuth grant cannot be set together.
 */
export function assertOauthBackendConfig(input: {
  transport: string;
  placementMode: string;
  auth?: BackendOauthInput | { type: "static" } | null;
  apiKey?: string | null;
  headers?: Record<string, string | null> | null;
}): void {
  if (!input.auth || input.auth.type !== "oauth") return;
  if (input.transport !== "streamable-http" && input.transport !== "sse") {
    throw new Error(
      "OAuth auth is only supported for remote streamable-http and sse backends",
    );
  }
  if (input.placementMode !== "remote") {
    throw new Error("OAuth auth is only supported for remote placement");
  }
  if (input.apiKey) {
    throw new Error("OAuth backends cannot also set an API key");
  }
  if (hasAuthorizationHeader(input.headers)) {
    throw new Error(
      "OAuth backends cannot also set an Authorization header",
    );
  }
  const auth = input.auth;
  if (auth.clientId != null && typeof auth.clientId !== "string") {
    throw new Error("auth.clientId must be a string");
  }
  if (auth.clientSecret != null && typeof auth.clientSecret !== "string") {
    throw new Error("auth.clientSecret must be a string");
  }
  if (
    auth.scopes != null &&
    (!Array.isArray(auth.scopes) ||
      auth.scopes.some((s) => typeof s !== "string"))
  ) {
    throw new Error("auth.scopes must be an array of strings");
  }
}
