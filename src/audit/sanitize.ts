import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";

const SECRET_KEY_RE =
  /secret|token|password|passwd|authorization|api[_-]?key|apikey|cookie|set-cookie|private[_-]?key|access[_-]?key|refresh[_-]?token|bearer|credential|session/i;

const SECRET_VALUE_RE =
  /^(?:Bearer\s+\S+|sk-[A-Za-z0-9_-]{16,}|mf_[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})/i;

const DEFAULT_MAX_BYTES = 65_536;
const DEFAULT_MAX_STRING = 16_384;
const DEFAULT_MAX_DEPTH = 12;

export function auditMaxDetailBytes(): number {
  const n = Number(process.env.MCP_FLOW_AUDIT_MAX_DETAIL_BYTES ?? "");
  if (Number.isFinite(n) && n >= 1024 && n <= 1_000_000) return Math.floor(n);
  return DEFAULT_MAX_BYTES;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function redactString(s: string, maxString: number): string {
  if (SECRET_VALUE_RE.test(s.trim())) return "[redacted]";
  if (s.length <= maxString) return s;
  return `${s.slice(0, maxString)}…[truncated ${s.length} chars]`;
}

/**
 * Deep-sanitize a value for audit storage: redact secrets, cap depth/size.
 */
export function sanitizeForAudit(
  value: unknown,
  opts: {
    maxBytes?: number;
    maxString?: number;
    maxDepth?: number;
  } = {},
): unknown {
  const maxBytes = opts.maxBytes ?? auditMaxDetailBytes();
  const maxString = opts.maxString ?? DEFAULT_MAX_STRING;
  const maxDepth = opts.maxDepth ?? DEFAULT_MAX_DEPTH;

  try {
    const walked = walk(value, 0, maxDepth, maxString);
    const json = JSON.stringify(walked);
    if (json === undefined) return null;
    const bytes = Buffer.byteLength(json, "utf8");
    if (bytes <= maxBytes) {
      return walked === undefined ? null : walked;
    }
    const preview = json.slice(0, Math.min(maxString, 2000));
    return {
      _truncated: true,
      byteLength: bytes,
      maxBytes,
      preview: `${preview}…`,
    };
  } catch {
    return { _error: "sanitize_failed" };
  }
}

function walk(
  value: unknown,
  depth: number,
  maxDepth: number,
  maxString: number,
): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return redactString(value, maxString);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function" || typeof value === "symbol") {
    return `[${typeof value}]`;
  }
  if (depth >= maxDepth) return "[max_depth]";

  if (Array.isArray(value)) {
    const out: unknown[] = [];
    const limit = Math.min(value.length, 200);
    for (let i = 0; i < limit; i++) {
      out.push(walk(value[i], depth + 1, maxDepth, maxString));
    }
    if (value.length > limit) {
      out.push(`…[${value.length - limit} more items]`);
    }
    return out;
  }

  if (isPlainObject(value)) {
    const out: Record<string, unknown> = {};
    const keys = Object.keys(value);
    const limit = Math.min(keys.length, 100);
    for (let i = 0; i < limit; i++) {
      const k = keys[i]!;
      if (SECRET_KEY_RE.test(k)) {
        out[k] = "[redacted]";
        continue;
      }
      out[k] = walk(value[k], depth + 1, maxDepth, maxString);
    }
    if (keys.length > limit) {
      out._omittedKeys = keys.length - limit;
    }
    return out;
  }

  return String(value);
}

/**
 * Normalize CallToolResult for audit (drop huge binary blobs).
 */
export function summarizeCallToolResult(result: CallToolResult): unknown {
  const content = Array.isArray(result.content) ? result.content : [];
  const summarized = content.map((block) => {
    if (!block || typeof block !== "object") return block;
    const b = block as Record<string, unknown>;
    const type = String(b.type ?? "unknown");
    if (type === "text") {
      return { type: "text", text: b.text };
    }
    if (type === "image" || type === "audio" || type === "resource") {
      const data = b.data;
      const len =
        typeof data === "string"
          ? data.length
          : Buffer.isBuffer(data)
            ? data.length
            : undefined;
      return {
        type,
        mimeType: b.mimeType,
        _omitted: "binary",
        byteLength: len,
      };
    }
    return walk(b, 0, 6, DEFAULT_MAX_STRING);
  });

  const out: Record<string, unknown> = {
    isError: Boolean(result.isError),
    content: summarized,
  };
  if ("structuredContent" in result && result.structuredContent !== undefined) {
    out.structuredContent = result.structuredContent;
  }
  return out;
}

/** Build standard tools/call audit detail blob (pre-store sanitize). */
export function toolCallAuditDetail(input: {
  arguments?: unknown;
  result?: CallToolResult | unknown;
  denied?: boolean;
  reason?: string;
  meta?: boolean;
  durationMs?: number;
  extra?: Record<string, unknown>;
}): Record<string, unknown> {
  const detail: Record<string, unknown> = {};
  if (input.meta) detail.meta = true;
  if (input.denied) {
    detail.denied = true;
    if (input.reason) detail.reason = input.reason;
  }
  if (input.arguments !== undefined) {
    detail.arguments = input.arguments;
  }
  if (input.result !== undefined) {
    const r = input.result as CallToolResult;
    if (r && typeof r === "object" && Array.isArray((r as CallToolResult).content)) {
      detail.result = summarizeCallToolResult(r);
      detail.isError = Boolean(r.isError);
    } else {
      detail.result = input.result;
      if (
        input.result &&
        typeof input.result === "object" &&
        "isError" in (input.result as object)
      ) {
        detail.isError = Boolean(
          (input.result as { isError?: boolean }).isError,
        );
      }
    }
  }
  if (input.durationMs !== undefined) {
    detail.durationMs = input.durationMs;
  }
  if (input.extra) {
    Object.assign(detail, input.extra);
  }
  return detail;
}
