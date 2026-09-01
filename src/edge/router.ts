import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Store } from "../db/store.js";
import { toPublicBackend } from "../db/store.js";
import type { BackendRecord, Placement } from "../types.js";
import type { EdgeHub } from "./hub.js";
import type {
  EdgeToolsCallResult,
  EdgeToolsListResult,
} from "./protocol.js";

/**
 * Session sticky overrides from mf_use_device (keyId → deviceId).
 */
export class DeviceSticky {
  private map = new Map<string, { deviceId: string; expires: number }>();
  private ttlMs: number;

  constructor(ttlMs = 30 * 60_000) {
    this.ttlMs = ttlMs;
  }

  set(keyId: string, deviceId: string): void {
    this.map.set(keyId, { deviceId, expires: Date.now() + this.ttlMs });
  }

  get(keyId: string | undefined): string | null {
    if (!keyId) return null;
    const e = this.map.get(keyId);
    if (!e) return null;
    if (Date.now() > e.expires) {
      this.map.delete(keyId);
      return null;
    }
    return e.deviceId;
  }

  clear(keyId: string): void {
    this.map.delete(keyId);
  }
}

export class EdgeRouter {
  readonly sticky = new DeviceSticky();

  constructor(
    private store: Store,
    private hub: EdgeHub,
  ) {}

  resolveDeviceId(
    backend: BackendRecord,
    opts?: { keyId?: string },
  ): string {
    const placement = this.placement(backend);
    const sticky = this.sticky.get(opts?.keyId);
    if (sticky && this.hub.isOnline(sticky)) {
      return sticky;
    }

    const affinity = placement.affinity ?? "pinned";

    if (affinity === "pinned" || !placement.deviceTags?.length) {
      if (!placement.deviceId) {
        throw new Error("edge backend missing placement.deviceId");
      }
      if (!this.hub.isOnline(placement.deviceId)) {
        // failover for any-online
        if (affinity === "any-online") {
          const alt = this.pickOnline(backend.workspaceId, placement);
          if (alt) return alt;
        }
        throw new Error(`device_offline: ${placement.deviceId}`);
      }
      return placement.deviceId;
    }

    if (affinity === "any-online" || affinity === "harness-local") {
      const picked = this.pickOnline(backend.workspaceId, placement);
      if (picked) return picked;
      if (placement.deviceId && this.hub.isOnline(placement.deviceId)) {
        return placement.deviceId;
      }
      throw new Error("no online edge device matching tags");
    }

    if (!placement.deviceId) {
      throw new Error("edge backend missing placement.deviceId");
    }
    if (!this.hub.isOnline(placement.deviceId)) {
      throw new Error(`device_offline: ${placement.deviceId}`);
    }
    return placement.deviceId;
  }

  private pickOnline(
    workspaceId: string,
    placement: Placement,
  ): string | null {
    const online = this.hub.onlineDeviceIds(workspaceId);
    const tags = placement.deviceTags ?? [];
    for (const id of online) {
      const d = this.store.getDevice(workspaceId, id);
      if (!d) continue;
      if (tags.length && !tags.every((t) => d.tags.includes(t))) continue;
      if (placement.mode === "edge-bare" && !d.capabilities.bare) continue;
      if (
        placement.mode === "edge-sandbox" &&
        d.capabilities.sandbox === "none"
      ) {
        continue;
      }
      return id;
    }
    return null;
  }

  private placement(backend: BackendRecord): Placement {
    try {
      return JSON.parse(backend.placementJson) as Placement;
    } catch {
      return { mode: "remote" };
    }
  }

  private runtimePayload(backend: BackendRecord): Record<string, unknown> {
    const pub = toPublicBackend(backend);
    const placement = this.placement(backend);
    const env = this.store.decryptEnv(backend);
    return {
      backendId: backend.id,
      slug: backend.slug,
      transport: backend.transport,
      mode: placement.mode,
      image: backend.image,
      command: pub.command,
      env,
      sandbox: pub.sandbox,
    };
  }

  async listTools(backend: BackendRecord): Promise<Tool[]> {
    const deviceId = this.resolveDeviceId(backend);
    const resp = await this.hub.rpc(
      deviceId,
      "tools.list",
      this.runtimePayload(backend),
    );
    const payload = (resp.payload ?? {}) as unknown as EdgeToolsListResult;
    return payload.tools ?? [];
  }

  async callTool(
    backend: BackendRecord,
    tool: string,
    args: Record<string, unknown>,
  ): Promise<CallToolResult> {
    const deviceId = this.resolveDeviceId(backend);
    const placement = this.placement(backend);
    if (placement.mode === "edge-bare") {
      this.store.writeAudit({
        workspaceId: backend.workspaceId,
        action: "bare_exec",
        backendSlug: backend.slug,
        deviceId,
        placement: "edge-bare",
        detail: { tool },
      });
    }
    const resp = await this.hub.rpc(deviceId, "tools.call", {
      ...this.runtimePayload(backend),
      tool,
      arguments: args,
    });
    const payload = (resp.payload ?? {}) as unknown as EdgeToolsCallResult;
    if (!payload.result) {
      throw new Error("edge tools.call missing result");
    }
    return payload.result;
  }
}
