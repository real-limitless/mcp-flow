import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type {
  GalleryToolPreview,
  GalleryTransport,
  ToolsPreviewStatus,
} from "../types.js";

export interface ToolsProbeResult {
  status: ToolsPreviewStatus;
  tools?: GalleryToolPreview[];
  error?: string;
  at: string;
}

export interface ToolsProbeOptions {
  timeoutMs?: number;
  /** Optional request headers (e.g. from sealed backend — never persist) */
  headers?: Record<string, string>;
}

function isAuthError(msg: string): boolean {
  return /401|403|unauthorized|forbidden|auth|api.?key|bearer/i.test(msg);
}

/**
 * Probe a remote MCP endpoint for tools/list.
 * Does not store secrets. Soft-fails auth as auth_required.
 */
export async function probeToolsList(
  endpointUrl: string | undefined,
  transport: GalleryTransport,
  opts: ToolsProbeOptions = {},
): Promise<ToolsProbeResult> {
  const at = new Date().toISOString();
  const timeoutMs = opts.timeoutMs ?? 15_000;

  if (!endpointUrl) {
    return { status: "unsupported", error: "no endpointUrl", at };
  }
  if (transport !== "streamable-http" && transport !== "sse") {
    return {
      status: "unsupported",
      error: `transport ${transport} not probeable`,
      at,
    };
  }

  let url: URL;
  try {
    url = new URL(endpointUrl);
  } catch {
    return { status: "unreachable", error: "invalid endpointUrl", at };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { status: "unreachable", error: "only http(s)", at };
  }

  const client = new Client(
    { name: "mcp-flow-enrich", version: "0.1.0" },
    { capabilities: {} },
  );

  let transportImpl: Transport;
  const requestInit: RequestInit = {
    headers: { ...(opts.headers ?? {}) },
  };

  try {
    if (transport === "sse") {
      transportImpl = new SSEClientTransport(url, { requestInit });
    } else {
      transportImpl = new StreamableHTTPClientTransport(url, { requestInit });
    }

    const connectOrTimeout = Promise.race([
      client.connect(transportImpl).then(() => "ok" as const),
      new Promise<"timeout">((resolve) =>
        setTimeout(() => resolve("timeout"), timeoutMs),
      ),
    ]);

    const c = await connectOrTimeout;
    if (c === "timeout") {
      try {
        await client.close();
      } catch {
        /* ignore */
      }
      return { status: "unreachable", error: `timeout ${timeoutMs}ms`, at };
    }

    const listed = await Promise.race([
      client.listTools(),
      new Promise<null>((resolve) =>
        setTimeout(() => resolve(null), timeoutMs),
      ),
    ]);

    try {
      await client.close();
    } catch {
      /* ignore */
    }

    if (!listed) {
      return { status: "unreachable", error: "tools/list timeout", at };
    }

    const tools: GalleryToolPreview[] = (listed.tools ?? []).map((t) => ({
      name: t.name,
      description: t.description,
    }));

    return { status: "ok", tools, at };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    try {
      await client.close();
    } catch {
      /* ignore */
    }
    if (isAuthError(msg)) {
      return { status: "auth_required", error: msg, at };
    }
    return { status: "unreachable", error: msg, at };
  }
}
