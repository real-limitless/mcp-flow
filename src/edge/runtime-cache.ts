import { createHash } from "node:crypto";
import type { EdgeToolsListPayload } from "./protocol.js";

export interface CachedRuntime {
  close(): Promise<void>;
}

export function edgeRuntimeFingerprint(payload: EdgeToolsListPayload): string {
  const env = payload.env ?? {};
  const lines = Object.keys(env)
    .sort()
    .map((name) => `${name}=${env[name] ?? ""}`);
  return createHash("sha256")
    .update(
      JSON.stringify({
        transport: payload.transport,
        mode: payload.mode,
        image: payload.image ?? null,
        command: payload.command ?? null,
        sandbox: payload.sandbox ?? null,
        env: lines,
      }),
    )
    .digest("hex");
}

/**
 * One live child per backend. A changed env, command, image, or sandbox
 * closes that child before the next list or call.
 */
export class EdgeRuntimeCache<T extends CachedRuntime> {
  private readonly entries = new Map<string, { fingerprint: string; runtime: T }>();

  async resolve(
    payload: EdgeToolsListPayload,
    factory: () => Promise<T>,
  ): Promise<T> {
    const fingerprint = edgeRuntimeFingerprint(payload);
    const existing = this.entries.get(payload.backendId);
    if (existing && existing.fingerprint === fingerprint) return existing.runtime;
    if (existing) {
      this.entries.delete(payload.backendId);
      await existing.runtime.close();
    }
    const runtime = await factory();
    this.entries.set(payload.backendId, { fingerprint, runtime });
    return runtime;
  }

  async stop(backendId: string): Promise<void> {
    const existing = this.entries.get(backendId);
    if (!existing) return;
    this.entries.delete(backendId);
    await existing.runtime.close();
  }
}
