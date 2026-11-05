/**
 * Origin of an upstream URL: scheme, host, and port.
 * Userinfo, path, and query are left out. Default ports are normalized
 * (`https://host` and `https://host:443` are the same origin).
 * Returns null when the value is empty or has no URL origin.
 */
export function urlOrigin(url: string | null | undefined): string | null {
  if (url == null) return null;
  const trimmed = url.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (!parsed.host || parsed.origin === "null") return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

/**
 * True when a URL edit changes scheme, host, or port.
 * Path-only and query-only edits are false.
 * Two different values that both lack an origin count as a change so sealed
 * credentials are not kept for an unparseable URL.
 */
export function urlOriginChanged(
  previousUrl: string | null | undefined,
  nextUrl: string | null | undefined,
): boolean {
  const previous = previousUrl?.trim() || null;
  const next = nextUrl?.trim() || null;
  if (previous === next) return false;
  const previousOrigin = urlOrigin(previous);
  const nextOrigin = urlOrigin(next);
  if (previousOrigin !== nextOrigin) return true;
  return previousOrigin == null && nextOrigin == null;
}
