import type {
  Placement,
  PlacementMode,
  TransportKind,
  WorkspacePolicy,
} from "./types.js";
import { DEFAULT_WORKSPACE_POLICY } from "./types.js";

/** Modes the control plane can run without an edge device */
export const CONTROL_PLANE_MODES: PlacementMode[] = [
  "remote",
  "central-sandbox",
];

/** All modes once edge is enabled */
export const ALL_PLACEMENT_MODES: PlacementMode[] = [
  "remote",
  "central-sandbox",
  "edge-sandbox",
  "edge-bare",
];

export class PlacementError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PlacementError";
  }
}

export function supportedPlacementModes(opts: {
  edgeEnabled?: boolean;
}): PlacementMode[] {
  if (opts.edgeEnabled) return [...ALL_PLACEMENT_MODES];
  return [...CONTROL_PLANE_MODES];
}

/**
 * Validate placement + transport combination for create/update.
 * `edgeEnabled` / device presence gate edge modes (P4+).
 */
export function assertPlacementAllowed(
  placement: Placement,
  opts: {
    transport: TransportKind;
    policy?: WorkspacePolicy | null;
    /** Device exists in registry (P4+) */
    deviceExists?: boolean;
    /** Device reports bare capability */
    deviceBare?: boolean;
    /** Device reports container sandbox */
    deviceSandbox?: boolean;
    /** Edge control plane wired */
    edgeEnabled?: boolean;
  },
): void {
  const mode = placement.mode;
  const policy = opts.policy ?? DEFAULT_WORKSPACE_POLICY;

  if (mode === "remote") {
    if (opts.transport !== "streamable-http" && opts.transport !== "sse") {
      throw new PlacementError(
        `placement remote requires streamable-http or sse transport (got ${opts.transport})`,
      );
    }
    return;
  }

  if (mode === "central-sandbox") {
    if (opts.transport !== "stdio" && opts.transport !== "oci") {
      throw new PlacementError(
        `placement central-sandbox requires stdio or oci transport (got ${opts.transport})`,
      );
    }
    return;
  }

  if (mode === "edge-sandbox" || mode === "edge-bare") {
    if (!opts.edgeEnabled) {
      throw new PlacementError(
        `placement.mode=${mode} not available (edge agent not enabled)`,
      );
    }
    if (!placement.deviceId) {
      throw new PlacementError(
        `placement.mode=${mode} requires placement.deviceId`,
      );
    }
    if (!opts.deviceExists) {
      throw new PlacementError(
        `device not found: ${placement.deviceId}`,
      );
    }
    if (mode === "edge-bare") {
      if (!policy.allowEdgeBare) {
        throw new PlacementError(
          "edge-bare denied by workspace policy (set allowEdgeBare)",
        );
      }
      if (!opts.deviceBare) {
        throw new PlacementError(
          "device does not allow bare execution",
        );
      }
      if (opts.transport !== "stdio") {
        throw new PlacementError(
          "edge-bare requires stdio transport",
        );
      }
    } else {
      if (!opts.deviceSandbox) {
        throw new PlacementError(
          "device has no container sandbox capability",
        );
      }
      if (opts.transport !== "stdio" && opts.transport !== "oci") {
        throw new PlacementError(
          `edge-sandbox requires stdio or oci (got ${opts.transport})`,
        );
      }
    }
    return;
  }

  throw new PlacementError(`unknown placement.mode=${String(mode)}`);
}

export function assertBackendShape(input: {
  transport: TransportKind;
  url?: string | null;
  image?: string | null;
  command?: string[] | null;
}): void {
  const { transport } = input;
  if (transport === "streamable-http" || transport === "sse") {
    if (!input.url?.trim()) {
      throw new PlacementError(`${transport} backend requires url`);
    }
    return;
  }
  if (transport === "stdio") {
    if (!input.command?.length) {
      throw new PlacementError("stdio backend requires command[]");
    }
    return;
  }
  if (transport === "oci") {
    if (!input.image?.trim()) {
      throw new PlacementError("oci backend requires image");
    }
    return;
  }
}
