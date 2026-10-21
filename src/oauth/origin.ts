/**
 * Redirect URI registered with the authorization server.
 * A configured public URL wins. Otherwise the admin request origin is used.
 */
export function resolveRedirectUri(opts: {
  publicUrl?: string;
  requestOrigin?: string;
  fallbackOrigin?: string;
}): { redirectUri: string; derived: boolean } {
  const configured = opts.publicUrl?.trim() ?? "";
  const raw = configured || opts.requestOrigin?.trim() || opts.fallbackOrigin?.trim() || "";
  if (!raw) {
    throw new Error(
      "MCP_FLOW_PUBLIC_URL is required to start OAuth",
    );
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new Error("OAuth redirect origin is not a valid URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("OAuth redirect origin must be http or https");
  }
  return {
    redirectUri: `${url.origin}/oauth/callback`,
    derived: !configured,
  };
}
