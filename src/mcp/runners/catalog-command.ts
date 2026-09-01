import type { McpGalleryEntry } from "../../catalog/types.js";
import type { TransportKind } from "../../types.js";

export interface SynthesizedInstall {
  transport: TransportKind;
  command?: string[];
  image?: string;
  placementMode: "central-sandbox";
  warnings: string[];
}

/**
 * Map gallery install/packages metadata → backend stdio/oci shape.
 */
export function synthesizeFromGallery(
  entry: McpGalleryEntry,
): SynthesizedInstall | null {
  const warnings: string[] = [];
  const install =
    entry.install ??
    entry.packages?.find((p) => p.kind === "npm") ??
    entry.packages?.find((p) => p.kind === "pypi") ??
    entry.packages?.find((p) => p.kind === "oci") ??
    entry.packages?.[0];

  if (!install) return null;

  if (install.environmentVariables?.length) {
    const required = install.environmentVariables
      .filter((e) => e.required)
      .map((e) => e.name);
    if (required.length) {
      warnings.push(
        `entry may require env (not provided): ${required.join(", ")}`,
      );
    }
  }

  if (install.kind === "oci" || (install.package && /^[\w./-]+[:@]/.test(install.package) && install.kind === "unknown" && !install.command)) {
    // prefer explicit oci
  }

  if (install.kind === "oci") {
    const image = install.package?.trim();
    if (!image) return null;
    return {
      transport: "oci",
      image,
      command: install.command?.length ? install.command : undefined,
      placementMode: "central-sandbox",
      warnings,
    };
  }

  if (install.command?.length) {
    return {
      transport: "stdio",
      command: install.command,
      placementMode: "central-sandbox",
      warnings,
    };
  }

  if (install.kind === "npm" && install.package) {
    const pkg = install.version
      ? `${install.package}@${install.version}`
      : install.package;
    return {
      transport: "stdio",
      command: ["npx", "-y", pkg],
      placementMode: "central-sandbox",
      warnings,
    };
  }

  if (install.kind === "pypi" && install.package) {
    const pkg = install.version
      ? `${install.package}==${install.version}`
      : install.package;
    return {
      transport: "stdio",
      command: ["uvx", pkg],
      placementMode: "central-sandbox",
      warnings,
    };
  }

  return null;
}
