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

function closeQuiet(client: Client, ms = 1500): void {
  void Promise.race([
    client.close().catch(() => undefined),
    new Promise<void>((r) => setTimeout(r, ms)),
  ]);
}

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  return new Promise<T>((resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timeout ${ms}ms`)), ms);
    p.then(
      (v) => {
        if (timer) clearTimeout(timer);
        resolve(v);
      },
      (err) => {
        if (timer) clearTimeout(timer);
        reject(err);
      },
    );
  });
}

/**
 * Probe a remote MCP endpoint for tools/list.
 * Does not store secrets. Soft-fails auth as auth_required.
 * Hard-timeouts connect + listTools so factory jobs cannot hang forever.
 */
export async function probeToolsList(
  endpointUrl: string | undefined,
  transport: GalleryTransport,
  opts: ToolsProbeOptions = {},
): Promise<ToolsProbeResult> {
  const at = new Date().toISOString();
  const timeoutMs = opts.timeoutMs ?? 15_000;
  // overall budget slightly above connect+list so outer wrapper always wins
  const overallMs = timeoutMs + 3_000;

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

  const run = async (): Promise<ToolsProbeResult> => {
    const client = new Client(
      { name: "mcp-flow-enrich", version: "0.1.0" },
      { capabilities: {} },
    );

    let transportImpl: Transport;
    const requestInit: RequestInit = {
      headers: { ...(opts.headers ?? {}) },
      signal: AbortSignal.timeout(timeoutMs),
    };

    try {
      if (transport === "sse") {
        transportImpl = new SSEClientTransport(url, { requestInit });
      } else {
        transportImpl = new StreamableHTTPClientTransport(url, { requestInit });
      }

      await withTimeout(client.connect(transportImpl), timeoutMs, "connect");

      const listed = await withTimeout(
        client.listTools(),
        timeoutMs,
        "tools/list",
      );

      closeQuiet(client);

      const tools: GalleryToolPreview[] = (listed.tools ?? []).map((t) => ({
        name: t.name,
        description: t.description,
      }));

      return { status: "ok", tools, at };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      closeQuiet(client);
      if (isAuthError(msg)) {
        return { status: "auth_required", error: msg, at };
      }
      return { status: "unreachable", error: msg, at };
    }
  };

  try {
    return await withTimeout(run(), overallMs, "tools-probe");
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { status: "unreachable", error: msg, at };
  }
}
