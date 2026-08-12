/**
 * Operator MCP tools (mf_admin_*) — only for keys with scopes.admin.
 */
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { installFromGallery } from "../catalog/install.js";
import { readEntryFile } from "../catalog/shard.js";
import {
  defaultCatalogDir,
  loadLocalGallery,
  searchRegistryLive,
} from "../catalog/sync.js";
import type { Config } from "../config.js";
import type { Store } from "../db/store.js";
import type { EdgeHub } from "../edge/hub.js";
import type { McpGalleryEntry } from "../catalog/types.js";
import {
  assertBackendShape,
  assertPlacementAllowed,
  PlacementError,
  supportedPlacementModes,
} from "../placement.js";
import { assertSafeUrl, SsrfError } from "../ssrf.js";
import type {
  ApiKeyScopes,
  AuthContext,
  CreateBackendInput,
  DeviceCapabilities,
  TransportKind,
  UpdateBackendInput,
  WorkspacePolicy,
} from "../types.js";
import { DEFAULT_PLACEMENT, isAdminScopes } from "../types.js";
import type { UpstreamPool } from "./upstream.js";

export const ADMIN_META_TOOLS: Tool[] = [
  {
    name: "mf_admin_status",
    description:
      "Operator status: workspace, policy, placement modes, backend/device counts. Requires admin key.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "mf_admin_list_backends",
    description: "List backends (secrets redacted). Requires admin key.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "mf_admin_get_backend",
    description: "Get one backend by id or slug. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: { idOrSlug: { type: "string" } },
      required: ["idOrSlug"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_create_backend",
    description:
      "Create a backend (remote URL, stdio command, oci image, edge placement). Headers/env sealed. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: {
        slug: { type: "string" },
        title: { type: "string" },
        transport: {
          type: "string",
          enum: ["streamable-http", "sse", "stdio", "oci"],
        },
        url: { type: "string" },
        image: { type: "string" },
        command: { type: "array", items: { type: "string" } },
        headers: { type: "object", additionalProperties: { type: "string" } },
        env: { type: "object", additionalProperties: { type: "string" } },
        enabled: { type: "boolean" },
        placement: {
          type: "object",
          properties: {
            mode: {
              type: "string",
              enum: ["remote", "central-sandbox", "edge-sandbox", "edge-bare"],
            },
            deviceId: { type: "string" },
          },
          additionalProperties: false,
        },
      },
      required: ["slug"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_update_backend",
    description: "Patch backend by id or slug. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: {
        idOrSlug: { type: "string" },
        enabled: { type: "boolean" },
        title: { type: "string" },
        transport: { type: "string" },
        url: { type: ["string", "null"] },
        image: { type: ["string", "null"] },
        command: { type: ["array", "null"], items: { type: "string" } },
        headers: {
          type: ["object", "null"],
          additionalProperties: { type: "string" },
        },
        env: {
          type: ["object", "null"],
          additionalProperties: { type: "string" },
        },
        placement: { type: "object" },
      },
      required: ["idOrSlug"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_delete_backend",
    description: "Delete backend by id or slug. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: { idOrSlug: { type: "string" } },
      required: ["idOrSlug"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_test_backend",
    description: "Probe backend tools/list. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: { idOrSlug: { type: "string" } },
      required: ["idOrSlug"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_list_keys",
    description: "List agent API keys (no secrets). Requires admin key.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "mf_admin_create_key",
    description:
      "Mint agent API key. Token shown once. Set admin:true only as operator. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        admin: { type: "boolean", description: "Operator key (mf_admin_*)" },
        toolPrefixAllowlist: {
          type: "array",
          items: { type: "string" },
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_update_key_scopes",
    description: "Set scopes on a key (null/empty clears). Requires admin key.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string" },
        admin: { type: "boolean" },
        toolPrefixAllowlist: {
          type: "array",
          items: { type: "string" },
        },
        clear: { type: "boolean", description: "Clear all scopes (full tool access, non-admin)" },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_revoke_key",
    description: "Revoke an agent API key. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_list_devices",
    description: "List edge devices. Requires admin key.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
  {
    name: "mf_admin_enroll_device",
    description:
      "Enroll edge device; returns one-time device token. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string" },
        tags: { type: "array", items: { type: "string" } },
        bare: { type: "boolean" },
        sandbox: { type: "string", enum: ["docker", "podman", "none"] },
      },
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_revoke_device",
    description: "Revoke edge device. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_set_policy",
    description: "Update workspace policy (e.g. allowEdgeBare). Requires admin key.",
    inputSchema: {
      type: "object",
      properties: { allowEdgeBare: { type: "boolean" } },
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_list_audit",
    description: "Recent audit events (redacted detail). Requires admin key.",
    inputSchema: {
      type: "object",
      properties: {
        limit: { type: "number" },
        before: { type: "string" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_catalog_search",
    description: "Search local catalog / live registry. Requires admin key.",
    inputSchema: {
      type: "object",
      properties: {
        q: { type: "string" },
        limit: { type: "number" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_catalog_install",
    description:
      "Install gallery entry as backend (remote or central-sandbox). Requires admin key.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Gallery entry id" },
        slug: { type: "string" },
        enable: { type: "boolean" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        env: { type: "object", additionalProperties: { type: "string" } },
      },
      required: ["id"],
      additionalProperties: false,
    },
  },
];

function textResult(data: unknown, isError = false): CallToolResult {
  return {
    isError,
    content: [
      {
        type: "text",
        text: typeof data === "string" ? data : JSON.stringify(data, null, 2),
      },
    ],
  };
}

function findEntryById(
  catalogDir: string,
  id: string,
): import("../catalog/types.js").McpGalleryEntry | undefined {
  const fromFile = readEntryFile(catalogDir, id);
  if (fromFile) return fromFile;
  return loadLocalGallery(catalogDir).find((e) => e.id === id);
}

export function buildScopesFromArgs(args: {
  admin?: boolean;
  toolPrefixAllowlist?: string[];
  clear?: boolean;
}): ApiKeyScopes | null {
  if (args.clear) return null;
  const scopes: ApiKeyScopes = {};
  if (args.admin === true) scopes.admin = true;
  if (args.toolPrefixAllowlist?.length) {
    scopes.toolPrefixAllowlist = args.toolPrefixAllowlist.map(String);
  }
  if (!scopes.admin && !scopes.toolPrefixAllowlist?.length) return null;
  return scopes;
}

export interface AdminToolDeps {
  store: Store;
  pool: UpstreamPool;
  cfg: Config;
  auth: AuthContext;
  edgeHub?: EdgeHub | null;
  ip?: string | null;
  edgeEnabled: boolean;
}

function validateBackendWrite(
  deps: AdminToolDeps,
  transport: TransportKind,
  body: CreateBackendInput | UpdateBackendInput,
  placement = body.placement ?? { ...DEFAULT_PLACEMENT },
): string | null {
  try {
    const command = "command" in body ? body.command : undefined;
    const image = "image" in body ? body.image : undefined;
    const url = "url" in body ? body.url : undefined;
    assertBackendShape({
      transport,
      url: url as string | null | undefined,
      image: image as string | null | undefined,
      command: command as string[] | null | undefined,
    });
    const ws = deps.store.getWorkspace(deps.auth.workspaceId);
    const deviceId = placement.deviceId;
    const device = deviceId
      ? deps.store.getDevice(deps.auth.workspaceId, deviceId)
      : null;
    assertPlacementAllowed(placement, {
      transport,
      policy: ws?.policy,
      edgeEnabled: deps.edgeEnabled,
      deviceExists: Boolean(device),
      deviceBare: Boolean(device?.capabilities.bare),
      deviceSandbox: Boolean(device && device.capabilities.sandbox !== "none"),
    });
    return null;
  } catch (err) {
    return err instanceof PlacementError || err instanceof Error
      ? err.message
      : String(err);
  }
}

export async function handleAdminTool(
  name: string,
  args: Record<string, unknown>,
  deps: AdminToolDeps,
): Promise<CallToolResult> {
  if (!isAdminScopes(deps.auth.scopes) && deps.auth.kind !== "admin") {
    return textResult("admin key required for " + name, true);
  }

  const { store, pool, cfg, auth } = deps;
  const wsId = auth.workspaceId;
  const ip = deps.ip ?? null;
  const edgeHub = deps.edgeHub ?? null;
  const catalogDir = defaultCatalogDir(process.cwd());

  const audit = (
    action: string,
    detail?: Record<string, unknown>,
    extra?: { backendSlug?: string; deviceId?: string | null },
  ) => {
    store.writeAudit({
      workspaceId: wsId,
      keyId: auth.keyId,
      action: action as never,
      backendSlug: extra?.backendSlug,
      deviceId: extra?.deviceId ?? null,
      detail: detail ?? {},
      ip,
    });
  };

  try {
    switch (name) {
      case "mf_admin_status": {
        const ws = store.getWorkspace(wsId);
        const backends = store.listBackends(wsId);
        const devices = store.listDevices(wsId);
        return textResult({
          ok: true,
          workspace: ws,
          placementModes: supportedPlacementModes({
            edgeEnabled: deps.edgeEnabled,
          }),
          backends: {
            total: backends.length,
            enabled: backends.filter((b) => b.enabled).length,
          },
          devices: {
            total: devices.length,
            online: edgeHub
              ? devices.filter((d) => edgeHub.isOnline(d.id)).length
              : 0,
          },
          keyId: auth.keyId ?? null,
          admin: true,
        });
      }

      case "mf_admin_list_backends":
        return textResult({ backends: store.listBackends(wsId) });

      case "mf_admin_get_backend": {
        const id = String(args.idOrSlug ?? "");
        const b = store.getBackendPublic(wsId, id);
        if (!b) return textResult("not found", true);
        return textResult({ backend: b });
      }

      case "mf_admin_create_backend": {
        const body = args as unknown as CreateBackendInput;
        if (!body.slug) return textResult("slug required", true);
        const transport = (body.transport ?? "streamable-http") as TransportKind;
        if (
          (transport === "streamable-http" || transport === "sse") &&
          body.url
        ) {
          try {
            await assertSafeUrl(body.url, cfg.allowPrivateUrls);
          } catch (err) {
            return textResult(
              err instanceof SsrfError ? err.message : "invalid url",
              true,
            );
          }
        }
        const placement = body.placement ?? { ...DEFAULT_PLACEMENT };
        const verr = validateBackendWrite(deps, transport, body, placement);
        if (verr) return textResult(verr, true);
        const backend = store.createBackend(wsId, {
          ...body,
          transport,
          placement,
        });
        audit(
          "backend.create",
          { via: "mf_admin" },
          {
            backendSlug: backend.slug,
            deviceId: backend.placement.deviceId ?? null,
          },
        );
        return textResult({ backend });
      }

      case "mf_admin_update_backend": {
        const idOrSlug = String(args.idOrSlug ?? "");
        const existing = store.getBackend(wsId, idOrSlug);
        if (!existing) return textResult("not found", true);
        const body = { ...args } as UpdateBackendInput & { idOrSlug?: string };
        delete (body as { idOrSlug?: string }).idOrSlug;
        if (body.url) {
          try {
            await assertSafeUrl(body.url, cfg.allowPrivateUrls);
          } catch (err) {
            return textResult(
              err instanceof SsrfError ? err.message : "invalid url",
              true,
            );
          }
        }
        const transport = (body.transport ??
          existing.transport) as TransportKind;
        const placement =
          body.placement ??
          (JSON.parse(existing.placementJson) as typeof DEFAULT_PLACEMENT);
        const merged: UpdateBackendInput = {
          ...body,
          url: body.url !== undefined ? body.url : existing.url,
          image: body.image !== undefined ? body.image : existing.image,
          command:
            body.command !== undefined
              ? body.command
              : existing.commandJson
                ? (JSON.parse(existing.commandJson) as string[])
                : null,
        };
        const verr = validateBackendWrite(deps, transport, merged, placement);
        if (verr) return textResult(verr, true);
        const backend = store.updateBackend(wsId, existing.id, body);
        if (!backend) return textResult("not found", true);
        pool.invalidate(existing.id);
        audit(
          "backend.update",
          { via: "mf_admin" },
          { backendSlug: backend.slug },
        );
        return textResult({ backend });
      }

      case "mf_admin_delete_backend": {
        const idOrSlug = String(args.idOrSlug ?? "");
        const existing = store.getBackend(wsId, idOrSlug);
        const ok = store.deleteBackend(wsId, idOrSlug);
        if (!ok) return textResult("not found", true);
        if (existing) pool.invalidate(existing.id);
        audit(
          "backend.delete",
          { via: "mf_admin" },
          { backendSlug: existing?.slug },
        );
        return textResult({ ok: true });
      }

      case "mf_admin_test_backend": {
        const idOrSlug = String(args.idOrSlug ?? "");
        const backend = store.getBackend(wsId, idOrSlug);
        if (!backend) return textResult("not found", true);
        const result = await pool.testBackend(backend);
        audit(
          "backend.test",
          { via: "mf_admin", ok: result.ok, toolCount: result.toolCount },
          { backendSlug: backend.slug },
        );
        return textResult(result, !result.ok);
      }

      case "mf_admin_list_keys":
        return textResult({ keys: store.listApiKeys(wsId) });

      case "mf_admin_create_key": {
        const name = String(args.name ?? "default").trim() || "default";
        const scopes = buildScopesFromArgs({
          admin: args.admin === true,
          toolPrefixAllowlist: Array.isArray(args.toolPrefixAllowlist)
            ? (args.toolPrefixAllowlist as string[])
            : undefined,
        });
        const created = store.createApiKey(wsId, name, scopes);
        audit("key.create", {
          via: "mf_admin",
          keyId: created.id,
          name: created.name,
          scopes,
        });
        return textResult({
          key: created,
          note: "token shown once — store it securely",
        });
      }

      case "mf_admin_update_key_scopes": {
        const id = String(args.id ?? "");
        let scopes: ApiKeyScopes | null;
        if (args.clear === true) scopes = null;
        else {
          scopes = buildScopesFromArgs({
            admin: args.admin === true,
            toolPrefixAllowlist: Array.isArray(args.toolPrefixAllowlist)
              ? (args.toolPrefixAllowlist as string[])
              : undefined,
          });
          if (
            args.admin === false &&
            scopes &&
            !Array.isArray(args.toolPrefixAllowlist)
          ) {
            // explicit admin:false with no prefixes
            scopes = null;
          }
          if (args.admin === false && scopes?.admin) {
            delete scopes.admin;
            if (!scopes.toolPrefixAllowlist?.length) scopes = null;
          }
        }
        // allow setting admin:false by passing admin:false and prefixes
        if (args.admin === false && Array.isArray(args.toolPrefixAllowlist)) {
          scopes = args.toolPrefixAllowlist.length
            ? { toolPrefixAllowlist: args.toolPrefixAllowlist as string[] }
            : null;
        }
        const key = store.updateApiKeyScopes(wsId, id, scopes);
        if (!key) return textResult("not found", true);
        audit("key.update", { via: "mf_admin", keyId: id, scopes });
        return textResult({ key });
      }

      case "mf_admin_revoke_key": {
        const id = String(args.id ?? "");
        if (auth.keyId && id === auth.keyId) {
          return textResult("refusing to revoke the calling key", true);
        }
        const ok = store.revokeApiKey(wsId, id);
        if (!ok) return textResult("not found", true);
        audit("key.revoke", { via: "mf_admin", keyId: id });
        return textResult({ ok: true });
      }

      case "mf_admin_list_devices": {
        const devices = store.listDevices(wsId).map((d) => ({
          ...d,
          status: edgeHub?.isOnline(d.id) ? "online" : d.status,
        }));
        return textResult({ devices });
      }

      case "mf_admin_enroll_device": {
        const caps: DeviceCapabilities = {
          sandbox: (args.sandbox as DeviceCapabilities["sandbox"]) || "docker",
          bare: Boolean(args.bare),
        };
        const enrolled = store.enrollDevice(wsId, {
          name: String(args.name ?? "edge").trim() || "edge",
          tags: Array.isArray(args.tags) ? (args.tags as string[]) : [],
          capabilities: caps,
        });
        audit("device.enroll", {
          via: "mf_admin",
          deviceId: enrolled.id,
        });
        return textResult({
          device: enrolled,
          note: "device token shown once on device.token",
        });
      }

      case "mf_admin_revoke_device": {
        const id = String(args.id ?? "");
        const ok = store.revokeDevice(wsId, id);
        if (!ok) return textResult("not found", true);
        audit("device.revoke", { via: "mf_admin", deviceId: id });
        return textResult({ ok: true });
      }

      case "mf_admin_set_policy": {
        const policy: WorkspacePolicy = {
          allowEdgeBare: Boolean(args.allowEdgeBare),
        };
        const ws = store.updateWorkspacePolicy(wsId, policy);
        if (!ws) return textResult("not found", true);
        audit("workspace.policy", { via: "mf_admin", policy: ws.policy });
        return textResult({ workspace: ws });
      }

      case "mf_admin_list_audit": {
        const limit = Number(args.limit ?? 40);
        const before =
          typeof args.before === "string" ? args.before : undefined;
        const events = store.listAudit(wsId, { limit, before });
        return textResult({ events });
      }

      case "mf_admin_catalog_search": {
        const q = String(args.q ?? "").trim();
        const limit = Math.min(Number(args.limit ?? 20), 50);
        let entries: McpGalleryEntry[] = [];
        try {
          entries = await searchRegistryLive(q || "mcp", { limit });
        } catch {
          const local = loadLocalGallery(catalogDir);
          const ql = q.toLowerCase();
          entries = local
            .filter(
              (e) =>
                !ql ||
                e.id.toLowerCase().includes(ql) ||
                (e.title ?? "").toLowerCase().includes(ql) ||
                (e.summary ?? "").toLowerCase().includes(ql),
            )
            .slice(0, limit);
        }
        return textResult({
          entries: entries.map((e) => ({
            id: e.id,
            title: e.title,
            transport: e.transport,
            endpointUrl: e.endpointUrl,
            summary: e.summary,
          })),
        });
      }

      case "mf_admin_catalog_install": {
        const id = String(args.id ?? "");
        let entry = findEntryById(catalogDir, id);
        if (!entry) {
          try {
            const live = await searchRegistryLive(id, { limit: 15 });
            entry =
              live.find((e) => e.id === id) ??
              (live.length === 1 ? live[0] : undefined);
          } catch {
            /* ignore */
          }
        }
        if (!entry) return textResult("gallery entry not found", true);
        const result = await installFromGallery(store, wsId, {
          entry,
          slug: typeof args.slug === "string" ? args.slug : undefined,
          enable: args.enable !== false,
          headers: (args.headers as Record<string, string>) ?? undefined,
          env: (args.env as Record<string, string>) ?? undefined,
          allowPrivateUrls: cfg.allowPrivateUrls,
        });
        audit(
          "catalog.install",
          {
            via: "mf_admin",
            galleryId: entry.id,
            warnings: result.warnings,
          },
          { backendSlug: result.backend.slug },
        );
        return textResult(result);
      }

      default:
        return textResult(`Unknown admin tool: ${name}`, true);
    }
  } catch (err) {
    return textResult(err instanceof Error ? err.message : String(err), true);
  }
}
