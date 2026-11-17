import { createHash } from "node:crypto";
import type { BackendRecord } from "../types.js";

/** Hash of the env map, command, image, and sandbox a process was started with. */
export function spawnFingerprint(backend: BackendRecord, env: Record<string, string>): string {
  const names = Object.keys(env).sort();
  const lines = names.map((name) => `${name}=${env[name] ?? ""}`);
  const envHash = createHash("sha256").update(lines.join("\n")).digest("hex");
  return [
    backend.updatedAt,
    backend.commandJson ?? "",
    backend.image ?? "",
    backend.sandboxJson ?? "",
    envHash,
  ].join("\n");
}
