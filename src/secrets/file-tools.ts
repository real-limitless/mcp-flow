import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Store } from "../db/store.js";
import { SecretError, parseSecretRef, type SecretActor, type SecretDirectory } from "./directory.js";
import { DokployEnvSink } from "./env-sink.js";
import { assertEnvValueSafe } from "./env-text.js";
import { DokployFileSink, assertMountPath } from "./file-sink.js";
import type { FileTemplateDirectory } from "./file-templates.js";
import { ProtectedTargetError, type ProtectedTargets } from "./protected.js";

export const FILE_META_TOOLS: Tool[] = [
  {
    name: "mf_secret_file_list",
    description:
      "List compose file mounts. Tracked mounts show the phase B ref. Others are masked. Never returns file content.",
    inputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        compose_id: { type: "string" },
        project: { type: "string" },
      },
      required: ["backend", "compose_id", "project"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_secret_file_set",
    description:
      "Write a phase B secret ref, or an admin-generated secret, into a Dokploy compose file mount. Returns the ref, path, version, and mount id. Never the value. Optional env_key sets a *_FILE env key to that path through the env sink.",
    inputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        compose_id: { type: "string" },
        project: { type: "string" },
        path: { type: "string" },
        ref: { type: "string" },
        generate: { type: "string", enum: ["token", "password", "uuid"] },
        name: { type: "string" },
        env_key: { type: "string" },
      },
      required: ["backend", "compose_id", "project", "path"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_secret_file_unset",
    description:
      "Remove a compose file mount written by mf_secret_file_set, and the *_FILE env key when one was set with it.",
    inputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        compose_id: { type: "string" },
        project: { type: "string" },
        path: { type: "string" },
      },
      required: ["backend", "compose_id", "project", "path"],
      additionalProperties: false,
    },
  },
];

const FILE_TOOL_NAMES = new Set(FILE_META_TOOLS.map((tool) => tool.name));

export function isFileTool(name: string): boolean {
  return FILE_TOOL_NAMES.has(name);
}

export interface FileToolCaller {
  workspaceId: string;
  keyId: string;
  agentId: string;
  allowedProjects: readonly string[] | null;
}

export interface FileAuth {
  via: "admin" | "grant" | "project";
  tier: "DEVELOPMENT" | "PRODUCTION" | null;
}

export interface FileToolDeps {
  store: Store;
  secrets: SecretDirectory;
  fileTemplates: FileTemplateDirectory;
  protectedTargets: ProtectedTargets;
  callTool: (name: string, args: Record<string, unknown>) => Promise<import("@modelcontextprotocol/sdk/types.js").CallToolResult>;
}

export interface FileAuthz {
  humanAdmin: boolean;
  authorize: (project: string, backend: string, composeId: string) => FileAuth;
  needsProductionApproval: (auth: FileAuth) => boolean;
  actor: () => SecretActor;
}

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const MASK = "***";

function requireString(args: Record<string, unknown>, key: string): string {
  const value = args[key];
  if (typeof value !== "string" || value.trim() === "") throw new SecretError(`${key} is required`);
  return value;
}

function refBase(ref: string): string {
  let base = ref.trim();
  const hashIndex = base.indexOf("#");
  if (hashIndex >= 0) base = base.slice(0, hashIndex);
  const atIndex = base.indexOf("@");
  if (atIndex >= 0) base = base.slice(0, atIndex);
  return base;
}

function auditWrite(store: Store, caller: FileToolCaller, action: string, detail: Record<string, unknown>): void {
  store.writeAudit({
    workspaceId: caller.workspaceId,
    keyId: caller.keyId,
    action,
    detail,
  });
}

function assertEnvKey(envKey: string): void {
  if (!KEY_RE.test(envKey) || !envKey.endsWith("_FILE")) {
    throw new SecretError("env_key must be a *_FILE name");
  }
}

function secretNameFrom(path: string, explicit: unknown): string {
  if (typeof explicit === "string" && explicit !== "") {
    if (!/^[a-z0-9_-]{1,128}$/.test(explicit)) throw new SecretError("invalid secret name");
    return explicit;
  }
  const base = path.split("/").filter(Boolean).pop() ?? "file";
  const name = base.toLowerCase().replace(/[^a-z0-9_-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 128);
  if (!/^[a-z0-9_-]{1,128}$/.test(name)) throw new SecretError("invalid secret name");
  return name;
}

function refuseProduction(authz: FileAuthz, auth: FileAuth): void {
  if (authz.needsProductionApproval(auth)) {
    throw new SecretError("file sink on a PRODUCTION target needs a human admin", 403);
  }
}

async function resolveRef(
  deps: FileToolDeps,
  caller: FileToolCaller,
  project: string,
  ref: string,
): Promise<{ value: string; version: number; base: string }> {
  if (!ref.startsWith("secret://")) throw new SecretError("invalid ref");
  const base = refBase(ref);
  const parsed = parseSecretRef(base);
  if (parsed.project !== project) throw new SecretError("ref project must equal project");
  const resolved = deps.secrets.resolveForSink({ workspaceId: caller.workspaceId, ref });
  return { value: resolved.value, version: resolved.version, base };
}

export async function callFileTool(
  deps: FileToolDeps,
  name: string,
  args: Record<string, unknown>,
  caller: FileToolCaller,
  authz: FileAuthz,
): Promise<unknown> {
  if (name === "mf_secret_file_list") {
    const backend = requireString(args, "backend");
    const composeId = requireString(args, "compose_id");
    const project = requireString(args, "project");
    authz.authorize(project, backend, composeId);
    const sink = new DokployFileSink(deps.callTool, deps.protectedTargets);
    const mounts = await sink.list(backend, composeId);
    const files = mounts.map((mount) => {
      const template = deps.fileTemplates.get(caller.workspaceId, backend, composeId, mount.path);
      if (template) {
        return {
          path: mount.path,
          mount_id: mount.mountId,
          ref: template.ref,
          version: template.version,
          env_key: template.envKey,
        };
      }
      return { path: mount.path, mount_id: mount.mountId, value: MASK };
    });
    return { files };
  }

  if (name === "mf_secret_file_set") {
    const backend = requireString(args, "backend");
    const composeId = requireString(args, "compose_id");
    const project = requireString(args, "project");
    const path = requireString(args, "path");
    assertMountPath(path);
    const auth = authz.authorize(project, backend, composeId);
    if (caller.allowedProjects && !caller.allowedProjects.includes(project)) {
      throw new SecretError("project is not permitted", 403);
    }
    refuseProduction(authz, auth);
    const refArg = typeof args.ref === "string" ? args.ref : undefined;
    const generate = args.generate;
    if (refArg && generate !== undefined) throw new SecretError("pass a ref or generate, not both");
    if (!refArg && generate === undefined) throw new SecretError("ref or generate is required");
    let value: string;
    let version: number;
    let base: string;
    if (refArg) {
      if (auth.via === "project" && !refArg.startsWith("secret://")) {
        throw new SecretError("project secret bind accepts only secret refs");
      }
      const resolved = await resolveRef(deps, caller, project, refArg);
      value = resolved.value;
      version = resolved.version;
      base = resolved.base;
    } else {
      if (generate !== "token" && generate !== "password" && generate !== "uuid") {
        throw new SecretError("invalid generate type");
      }
      if (!authz.humanAdmin) throw new SecretError("human admin required", 403);
      const secretName = secretNameFrom(path, args.name);
      const created = deps.secrets.create({
        ...authz.actor(),
        project,
        name: secretName,
        type: generate,
        params: {},
      });
      const resolved = await resolveRef(deps, caller, project, created.ref);
      value = resolved.value;
      version = resolved.version;
      base = created.ref;
    }
    const previous = deps.fileTemplates.get(caller.workspaceId, backend, composeId, path);
    let envKey: string | undefined;
    if (typeof args.env_key === "string") envKey = args.env_key;
    else if (previous?.envKey) envKey = previous.envKey;
    if (envKey !== undefined) {
      assertEnvKey(envKey);
      assertEnvValueSafe(path);
    }
    const sink = new DokployFileSink(deps.callTool, deps.protectedTargets);
    const written = await sink.apply(backend, composeId, path, value);
    deps.fileTemplates.upsert({
      workspaceId: caller.workspaceId,
      backendSlug: backend,
      composeId,
      mountPath: path,
      mountId: written.mountId,
      ref: base,
      version,
      envKey: null,
    });
    if (envKey) {
      const envSink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
      await envSink.apply(backend, composeId, { [envKey]: path }, []);
      deps.fileTemplates.upsert({
        workspaceId: caller.workspaceId,
        backendSlug: backend,
        composeId,
        mountPath: path,
        mountId: written.mountId,
        ref: base,
        version,
        envKey,
      });
    }
    auditWrite(deps.store, caller, "file.set", {
      backend,
      compose_id: composeId,
      project,
      path,
      mount_id: written.mountId,
      ref: base,
      version,
      env_key: envKey ?? null,
      via: auth.via,
    });
    return {
      ref: base,
      path,
      version,
      mount_id: written.mountId,
      ...(envKey ? { env_key: envKey } : {}),
    };
  }

  if (name === "mf_secret_file_unset") {
    const backend = requireString(args, "backend");
    const composeId = requireString(args, "compose_id");
    const project = requireString(args, "project");
    const path = requireString(args, "path");
    assertMountPath(path);
    const auth = authz.authorize(project, backend, composeId);
    refuseProduction(authz, auth);
    const template = deps.fileTemplates.get(caller.workspaceId, backend, composeId, path);
    if (template?.envKey) {
      const envSink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
      await envSink.apply(backend, composeId, {}, [template.envKey]);
    }
    const sink = new DokployFileSink(deps.callTool, deps.protectedTargets);
    await sink.remove(backend, composeId, path, template?.mountId ?? null);
    deps.fileTemplates.delete(caller.workspaceId, backend, composeId, path);
    auditWrite(deps.store, caller, "file.unset", {
      backend,
      compose_id: composeId,
      project,
      path,
      mount_id: template?.mountId ?? null,
      ref: template?.ref ?? null,
      env_key: template?.envKey ?? null,
    });
    return {
      path,
      mount_id: template?.mountId ?? null,
      ref: template?.ref ?? null,
      unset: true,
    };
  }

  throw new SecretError("unknown file tool", 404);
}

export interface FileResyncRow {
  backend: string;
  compose_id: string;
  path: string;
  ref: string;
  mount_id?: string;
  reason?: string;
}

export async function resyncFileSinks(
  deps: FileToolDeps,
  caller: FileToolCaller,
  authz: FileAuthz,
  filter: { workspaceId: string; backendSlug?: string; composeId?: string; ref?: string },
): Promise<{ resynced: FileResyncRow[]; skipped: FileResyncRow[] }> {
  const rows = deps.fileTemplates.list(filter);
  const resynced: FileResyncRow[] = [];
  const skipped: FileResyncRow[] = [];
  for (const row of rows) {
    let project = "";
    try {
      project = parseSecretRef(row.ref).project;
    } catch {
      skipped.push({ backend: row.backendSlug, compose_id: row.composeId, path: row.mountPath, ref: row.ref, reason: "ref" });
      continue;
    }
    let auth: FileAuth;
    try {
      auth = authz.authorize(project, row.backendSlug, row.composeId);
    } catch (err) {
      if (err instanceof ProtectedTargetError) throw err;
      throw err;
    }
    if (authz.needsProductionApproval(auth)) {
      skipped.push({
        backend: row.backendSlug,
        compose_id: row.composeId,
        path: row.mountPath,
        ref: row.ref,
        reason: "production_approval",
      });
      continue;
    }
    let value: string;
    let version = row.version;
    try {
      const resolved = deps.secrets.resolveForSink({ workspaceId: caller.workspaceId, ref: row.ref });
      value = resolved.value;
      version = resolved.version;
    } catch {
      skipped.push({ backend: row.backendSlug, compose_id: row.composeId, path: row.mountPath, ref: row.ref, reason: "resolve" });
      continue;
    }
    if (version <= row.version) {
      skipped.push({ backend: row.backendSlug, compose_id: row.composeId, path: row.mountPath, ref: row.ref });
      continue;
    }
    const sink = new DokployFileSink(deps.callTool, deps.protectedTargets);
    const written = await sink.apply(row.backendSlug, row.composeId, row.mountPath, value);
    if (row.envKey) {
      const envSink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
      await envSink.apply(row.backendSlug, row.composeId, { [row.envKey]: row.mountPath }, []);
    }
    deps.fileTemplates.upsert({
      workspaceId: caller.workspaceId,
      backendSlug: row.backendSlug,
      composeId: row.composeId,
      mountPath: row.mountPath,
      mountId: written.mountId,
      ref: row.ref,
      version,
      envKey: row.envKey,
    });
    resynced.push({
      backend: row.backendSlug,
      compose_id: row.composeId,
      path: row.mountPath,
      ref: row.ref,
      mount_id: written.mountId,
    });
  }
  if (resynced.length > 0) {
    auditWrite(deps.store, caller, "file.resync", {
      resynced: resynced.map((row) => ({
        backend: row.backend,
        compose_id: row.compose_id,
        path: row.path,
        ref: row.ref,
        mount_id: row.mount_id,
      })),
    });
  }
  return { resynced, skipped };
}
