import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
  DEFAULT_SETTINGS,
  SETTINGS_PATH,
  ensureJobsDirs,
  type FactorySettings,
} from "./paths.js";

export function loadSettings(): FactorySettings {
  ensureJobsDirs();
  if (!existsSync(SETTINGS_PATH)) {
    return { ...DEFAULT_SETTINGS };
  }
  try {
    const raw = JSON.parse(readFileSync(SETTINGS_PATH, "utf8")) as Partial<FactorySettings>;
    return { ...DEFAULT_SETTINGS, ...raw };
  } catch {
    return { ...DEFAULT_SETTINGS };
  }
}

export function saveSettings(s: FactorySettings): void {
  ensureJobsDirs();
  writeFileSync(SETTINGS_PATH, `${JSON.stringify(s, null, 2)}\n`, "utf8");
}

/** Resolve active proxy URL from settings + env. */
export function resolveProxyUrl(s: FactorySettings): string | undefined {
  if (s.proxy?.trim()) return s.proxy.trim();
  const env =
    process.env.ALL_PROXY ||
    process.env.all_proxy ||
    process.env.HTTPS_PROXY ||
    process.env.https_proxy ||
    process.env.HTTP_PROXY ||
    process.env.http_proxy;
  return env?.trim() || undefined;
}
