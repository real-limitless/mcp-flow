import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const FILLED = ["MCP_FLOW_MASTER_KEY", "MCP_FLOW_ADMIN_TOKEN"] as const;

/**
 * The gateway entrypoint writes these into $MCP_FLOW_DATA_DIR/secrets.env when
 * Compose left them empty. A shell inside the container does not reload that
 * file, so CLI commands fill only the keys that are still empty.
 */
export function applyVolumeSecrets(env: NodeJS.ProcessEnv = process.env): void {
  const data = env.MCP_FLOW_DATA_DIR?.trim();
  if (!data) return;
  const path = join(data, "secrets.env");
  if (!existsSync(path)) return;
  const parsed = parseEnvFile(readFileSync(path, "utf8"));
  for (const key of FILLED) {
    if (env[key]?.trim()) continue;
    const value = parsed[key]?.trim();
    if (value) env[key] = value;
  }
}

function parseEnvFile(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    let value = trimmed.slice(eq + 1);
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    out[trimmed.slice(0, eq)] = value;
  }
  return out;
}
