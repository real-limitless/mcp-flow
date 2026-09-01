import type { Context } from "hono";

/** Best-effort client IP (no trusted proxy by default). */
export function clientIp(c: Context): string | null {
  const xff = c.req.header("x-forwarded-for");
  if (process.env.MCP_FLOW_TRUST_PROXY === "true" && xff) {
    const first = xff.split(",")[0]?.trim();
    if (first) return first;
  }
  // Hono/node may expose via raw request
  const raw = c.req.raw as unknown as {
    socket?: { remoteAddress?: string };
  };
  return raw.socket?.remoteAddress ?? null;
}
