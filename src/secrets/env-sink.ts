import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { assertSecretTargetAllowed, ProtectedTargetError } from "./protected.js";
import { containsPlaceholder } from "../audit/placeholder-guard.js";
import { EnvSinkError, assertEnvValueSafe, envDigest, envKeyNames, mergeEnvText } from "./env-text.js";
import type { ProtectedTargets } from "./protected.js";

export { EnvSinkError };
export class EnvChangedError extends EnvSinkError {}

export interface SinkCallTool {
  (name: string, args: Record<string, unknown>): Promise<CallToolResult>;
}

export class DokployEnvSink {
  constructor(
    private readonly callTool: SinkCallTool,
    private readonly protectedTargets: ProtectedTargets,
  ) {}

  private resultText(result: CallToolResult): string | null {
    if (!result || !Array.isArray(result.content)) return null;
    const textPart = result.content.find((c) => c && typeof c === "object" && (c as { type?: string }).type === "text");
    if (!textPart) return null;
    const t = (textPart as { text?: unknown }).text;
    return typeof t === "string" ? t : null;
  }

  async readEnv(backendSlug: string, composeId: string): Promise<{ env: string; digest: string }> {
    let result: CallToolResult;
    try {
      result = await this.callTool(`${backendSlug}__compose-one`, { composeId });
    } catch {
      throw new EnvSinkError("could not read compose env");
    }
    if (!result || result.isError) throw new EnvSinkError("could not read compose env");
    const text = this.resultText(result);
    if (text == null) throw new EnvSinkError("could not read compose env");
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new EnvSinkError("could not read compose env");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new EnvSinkError("could not read compose env");
    }
    const envRaw = (parsed as Record<string, unknown>).env;
    const env = envRaw == null ? "" : envRaw;
    if (typeof env !== "string") throw new EnvSinkError("could not read compose env");
    if (containsPlaceholder(env)) {
      throw new EnvSinkError("env already contains a redaction placeholder; fix it by hand");
    }
    return { env, digest: envDigest(env) };
  }

  async apply(
    backendSlug: string,
    composeId: string,
    set: Record<string, string>,
    unset: string[],
  ): Promise<{ set: string[]; unset: string[]; keys: string[] }> {
    try {
      assertSecretTargetAllowed(this.protectedTargets, composeId);
    } catch (err) {
      if (err instanceof ProtectedTargetError) throw err;
      throw new ProtectedTargetError();
    }
    // Validate keys and values.
    for (const key of Object.keys(set)) {
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) throw new EnvSinkError("invalid env key");
      assertEnvValueSafe(set[key]);
    }
    for (const key of unset) {
      if (typeof key !== "string" || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
        throw new EnvSinkError("invalid env key");
      }
    }

    const first = await this.readEnv(backendSlug, composeId);
    const merged = mergeEnvText(first.env, set, unset);
    if (containsPlaceholder(merged)) {
      throw new EnvSinkError("merged env contains a redaction placeholder");
    }
    const second = await this.readEnv(backendSlug, composeId);
    if (second.digest !== first.digest) {
      throw new EnvChangedError("compose env changed during update; retry");
    }

    let saveResult: CallToolResult;
    try {
      saveResult = await this.callTool(`${backendSlug}__compose-saveEnvironment`, {
        composeId,
        env: merged,
      });
    } catch {
      throw new EnvSinkError("could not save compose env");
    }
    if (!saveResult || saveResult.isError) {
      throw new EnvSinkError("could not save compose env");
    }
    return {
      set: Object.keys(set),
      unset: [...unset],
      keys: envKeyNames(merged),
    };
  }
}
