import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { containsPlaceholder } from "../audit/placeholder-guard.js";
import { EnvSinkError, type SinkCallTool } from "./env-sink.js";
import { envDigest } from "./env-text.js";
import { assertSecretTargetAllowed, ProtectedTargetError, type ProtectedTargets } from "./protected.js";

export { EnvSinkError };
export class FileChangedError extends EnvSinkError {}

const PATH_RE = /^\/[A-Za-z0-9._+\-/]{1,255}$/;

export function assertMountPath(path: string): void {
  if (typeof path !== "string" || path.length < 2 || path.length > 256) {
    throw new EnvSinkError("invalid file path");
  }
  if (path.includes("\u0000") || path.includes("\r") || path.includes("\n")) {
    throw new EnvSinkError("invalid file path");
  }
  if (containsPlaceholder(path)) throw new EnvSinkError("file path contains a redaction placeholder");
  if (!PATH_RE.test(path)) throw new EnvSinkError("invalid file path");
  const parts = path.split("/").slice(1);
  if (parts.some((part) => part === "" || part === "." || part === "..")) {
    throw new EnvSinkError("invalid file path");
  }
}

/** Host-side file name Dokploy stores beside the compose. The container path is mountPath. */
export function filePathForMount(mountPath: string): string {
  return mountPath.replace(/^\/+/, "");
}

export function assertFileContentSafe(value: string): void {
  if (typeof value !== "string") throw new EnvSinkError("invalid file content");
  if (value.includes("\u0000")) throw new EnvSinkError("file content contains a control character");
  if (containsPlaceholder(value)) throw new EnvSinkError("file content contains a redaction placeholder");
  if (value.length > 64 * 1024) throw new EnvSinkError("file content is too large");
}

export interface ListedMount {
  mountId: string;
  path: string;
  type: string;
}

interface Snapshot {
  mountId: string | null;
  digest: string;
}

/**
 * Writes one Dokploy compose file mount through the projects backend.
 * Tool names follow Dokploy MCP `<router>-<procedure>`:
 * mounts-listByServiceId, mounts-one, mounts-create, mounts-update, mounts-remove.
 * Content stays in this process. Callers return the mount id, never the body.
 */
export class DokployFileSink {
  constructor(
    private readonly callTool: SinkCallTool,
    private readonly protectedTargets: ProtectedTargets,
  ) {}

  async list(backendSlug: string, composeId: string): Promise<ListedMount[]> {
    this.guard(composeId);
    const parsed = await this.invoke(`${backendSlug}__mounts-listByServiceId`, {
      serviceType: "compose",
      serviceId: composeId,
    }, "could not read compose file mounts");
    return mountRows(parsed).flatMap((row) => {
      const mountId = mountIdOf(row);
      const path = mountPathOf(row);
      if (!mountId || !path) return [];
      const type = typeof row.type === "string" ? row.type : "file";
      if (type !== "file") return [];
      return [{ mountId, path, type }];
    });
  }

  async apply(backendSlug: string, composeId: string, path: string, content: string): Promise<{ mountId: string }> {
    this.guard(composeId);
    assertMountPath(path);
    assertFileContentSafe(content);
    const first = await this.snapshot(backendSlug, composeId, path);
    const second = await this.snapshot(backendSlug, composeId, path);
    if (first.mountId !== second.mountId || first.digest !== second.digest) {
      throw new FileChangedError("compose file mount changed during update; retry");
    }
    const filePath = filePathForMount(path);
    if (second.mountId) {
      await this.invoke(`${backendSlug}__mounts-update`, {
        mountId: second.mountId,
        type: "file",
        content,
        mountPath: path,
        filePath,
        serviceType: "compose",
        composeId,
      }, "could not write compose file mount");
      return { mountId: second.mountId };
    }
    const created = await this.invoke(`${backendSlug}__mounts-create`, {
      type: "file",
      content,
      mountPath: path,
      filePath,
      serviceType: "compose",
      serviceId: composeId,
    }, "could not write compose file mount");
    const mountId = mountIdOf(asRecord(created) ?? {}) ?? (await this.findNewMountId(backendSlug, composeId, path));
    if (!mountId || mountId.length > 128) throw new EnvSinkError("could not write compose file mount");
    return { mountId };
  }

  async remove(backendSlug: string, composeId: string, path: string, mountId: string | null): Promise<void> {
    this.guard(composeId);
    assertMountPath(path);
    const id = mountId ?? (await this.snapshot(backendSlug, composeId, path)).mountId;
    if (!id) return;
    await this.invoke(`${backendSlug}__mounts-remove`, { mountId: id }, "could not remove compose file mount");
  }

  private guard(composeId: string): void {
    try {
      assertSecretTargetAllowed(this.protectedTargets, composeId);
    } catch (err) {
      if (err instanceof ProtectedTargetError) throw err;
      throw new ProtectedTargetError();
    }
  }

  private async snapshot(backendSlug: string, composeId: string, path: string): Promise<Snapshot> {
    const rows = mountRows(await this.invoke(`${backendSlug}__mounts-listByServiceId`, {
      serviceType: "compose",
      serviceId: composeId,
    }, "could not read compose file mounts"));
    const matches = rows.filter((row) => mountPathOf(row) === path);
    if (matches.length > 1) throw new EnvSinkError("compose file mount is ambiguous");
    const match = matches[0];
    if (!match) return { mountId: null, digest: envDigest("") };
    const type = typeof match.type === "string" ? match.type : "file";
    if (type !== "file") throw new EnvSinkError("path is not a file mount");
    const mountId = mountIdOf(match);
    if (!mountId) throw new EnvSinkError("could not read compose file mount");
    const one = asRecord(await this.invoke(`${backendSlug}__mounts-one`, { mountId }, "could not read compose file mount"));
    const content = one && typeof one.content === "string" ? one.content : null;
    if (content == null) throw new EnvSinkError("could not read compose file mount");
    if (containsPlaceholder(content)) {
      throw new EnvSinkError("file mount already contains a redaction placeholder; fix it by hand");
    }
    return { mountId, digest: envDigest(content) };
  }

  private async findNewMountId(backendSlug: string, composeId: string, path: string): Promise<string | null> {
    const rows = mountRows(await this.invoke(`${backendSlug}__mounts-listByServiceId`, {
      serviceType: "compose",
      serviceId: composeId,
    }, "could not write compose file mount"));
    const match = rows.find((row) => mountPathOf(row) === path);
    return match ? mountIdOf(match) : null;
  }

  private async invoke(name: string, args: Record<string, unknown>, failure: string): Promise<unknown> {
    let result: CallToolResult;
    try {
      result = await this.callTool(name, args);
    } catch {
      throw new EnvSinkError(failure);
    }
    if (!result || result.isError) throw new EnvSinkError(failure);
    const text = resultText(result);
    if (text == null) return null;
    try {
      return JSON.parse(text);
    } catch {
      return null;
    }
  }
}

function resultText(result: CallToolResult): string | null {
  if (!result || !Array.isArray(result.content)) return null;
  const textPart = result.content.find((part) => part && typeof part === "object" && (part as { type?: string }).type === "text");
  if (!textPart) return null;
  const text = (textPart as { text?: unknown }).text;
  return typeof text === "string" ? text : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function mountRows(parsed: unknown): Record<string, unknown>[] {
  if (Array.isArray(parsed)) return parsed.filter((row) => asRecord(row) !== null) as Record<string, unknown>[];
  const record = asRecord(parsed);
  if (!record) return [];
  for (const key of ["mounts", "data", "items", "rows"]) {
    if (Array.isArray(record[key])) {
      return (record[key] as unknown[]).filter((row) => asRecord(row) !== null) as Record<string, unknown>[];
    }
  }
  if (typeof record.mountId === "string" || typeof record.mountPath === "string") return [record];
  return [];
}

function mountIdOf(row: Record<string, unknown>): string | null {
  const id = row.mountId ?? row.mount_id ?? row.id;
  return typeof id === "string" && id.length > 0 ? id : null;
}

function mountPathOf(row: Record<string, unknown>): string | null {
  const path = row.mountPath ?? row.mount_path ?? row.path;
  return typeof path === "string" ? path : null;
}
