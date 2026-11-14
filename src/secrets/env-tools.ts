import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Store } from "../db/store.js";
import type { SecretActor, SecretDirectory } from "./directory.js";
import { SecretError, parseSecretRef } from "./directory.js";
import { ProtectedTargetError, type ProtectedTargets } from "./protected.js";
import { EnvSinkError, DokployEnvSink } from "./env-sink.js";
import { EnvGrantDirectory } from "./env-grants.js";
import { EnvGrantError } from "./env-grants.js";
import { EnvTemplateDirectory } from "./env-templates.js";
import { assertEnvValueSafe, MASK, envKeyNames } from "./env-text.js";
import { callProjectSecretTool, isProjectSecretTool, PROJECT_SECRET_ADMIN_TOOLS } from "./project-tools.js";
import type { ProjectSecretDirectory } from "./project-scope.js";


export const ENV_META_TOOLS: Tool[] = [
  {
    name: "mf_env_keys_list",
    description: "List env keys for a compose deployment. Values are masked; refs shown when a template row exists.",
    inputSchema: {
      type: "object",
      properties: { backend: { type: "string" }, compose_id: { type: "string" }, project: { type: "string" } },
      required: ["backend", "compose_id", "project"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_env_keys_set",
    description: "Set env keys for a compose deployment. Values may be plain strings or phase B refs.",
    inputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        compose_id: { type: "string" },
        project: { type: "string" },
        values: { type: "object", additionalProperties: { type: "string" } },
      },
      required: ["backend", "compose_id", "project", "values"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_env_keys_unset",
    description: "Unset env keys for a compose deployment.",
    inputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        compose_id: { type: "string" },
        project: { type: "string" },
        keys: { type: "array", items: { type: "string" } },
      },
      required: ["backend", "compose_id", "project", "keys"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_env_provision",
    description: "Provision env keys for a DEVELOPMENT compose deployment from refs or generated secrets.",
    inputSchema: {
      type: "object",
      properties: {
        backend: { type: "string" },
        compose_id: { type: "string" },
        project: { type: "string" },
        keys: { type: "object", additionalProperties: true },
      },
      required: ["backend", "compose_id", "project", "keys"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_secret_resync",
    description: "Re-apply template-tracked env refs whose active secret version advanced.",
    inputSchema: {
      type: "object",
      properties: {
        ref: { type: "string" },
        backend: { type: "string" },
        compose_id: { type: "string" },
      },
      additionalProperties: false,
    },
  },
];

export const ENV_ADMIN_TOOLS: Tool[] = [
  ...PROJECT_SECRET_ADMIN_TOOLS,
  {
    name: "mf_admin_env_grant_create",
    description: "Create an env sink grant. Human admin only.",
    inputSchema: {
      type: "object",
      properties: {
        project: { type: "string" },
        backend: { type: "string" },
        compose_ids: { type: "array", items: { type: "string" } },
        key_id: { type: "string" },
        agent_id: { type: "string" },
      },
      required: ["project", "backend", "compose_ids"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_env_grant_list",
    description: "List env sink grants. Human admin only.",
    inputSchema: {
      type: "object",
      properties: { project: { type: "string" } },
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_env_grant_revoke",
    description: "Revoke an env sink grant. Human admin only.",
    inputSchema: {
      type: "object",
      properties: { grant_id: { type: "string" } },
      required: ["grant_id"],
      additionalProperties: false,
    },
  },
];

const ALL_ENV_TOOL_NAMES = new Set([
  ...ENV_META_TOOLS.map((t) => t.name),
  ...ENV_ADMIN_TOOLS.map((t) => t.name),
]);

export function isEnvTool(name: string): boolean {
  return ALL_ENV_TOOL_NAMES.has(name);
}

export interface EnvToolCaller {
  workspaceId: string;
  keyId: string;
  agentId: string;
  agentKind: string | null;
  admin: boolean;
  allowedProjects: readonly string[] | null;
  activeProject: string | null;
}

export interface EnvToolDeps {
  store: Store;
  secrets: SecretDirectory;
  projectSecrets: ProjectSecretDirectory;
  envGrants: EnvGrantDirectory;
  envTemplates: EnvTemplateDirectory;
  protectedTargets: ProtectedTargets;
  provisionTargets: ProtectedTargets;
  callTool: (name: string, args: Record<string, unknown>) => Promise<CallToolResult>;
}

type EnvAuth = { via: "admin" | "grant" | "project"; tier: "DEVELOPMENT" | "PRODUCTION" | null };

function actor(caller: EnvToolCaller): SecretActor {
  return {
    workspaceId: caller.workspaceId,
    keyId: caller.keyId,
    agentId: caller.agentId,
    allowedProjects: caller.allowedProjects,
    humanAdmin: false,
  };
}

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function isHumanAdmin(store: Store, caller: EnvToolCaller): boolean {
  const row = store.db
    .prepare(
      `SELECT a.kind, a.is_admin, k.status, a.status AS agent_status
         FROM mcpflow_api_key k JOIN mcpflow_agent a ON a.id = k.agent_id
        WHERE k.id = ? AND k.agent_id = ? AND a.workspace_id = ?`,
    )
    .get(caller.keyId, caller.agentId, caller.workspaceId) as
    | { kind: string; is_admin: number; status: string; agent_status: string }
    | undefined;
  if (!row) return false;
  if (row.agent_status !== "active") return false;
  if (row.status !== "active" && row.status !== "rotating") return false;
  return row.kind === "human" && row.is_admin === 1;
}

function requireString(args: Record<string, unknown>, key: string): string {
  const v = args[key];
  if (typeof v !== "string" || v.trim() === "") throw new SecretError(`${key} is required`);
  return v;
}

function authorizeEnv(
  deps: EnvToolDeps,
  caller: EnvToolCaller,
  humanAdmin: boolean,
  project: string,
  backend: string,
  composeId: string,
): EnvAuth {
  if (deps.protectedTargets.invalid || deps.protectedTargets.ids.has(composeId)) {
    throw new ProtectedTargetError();
  }
  if (caller.allowedProjects && !caller.allowedProjects.includes(project)) {
    throw new SecretError("project is not permitted", 403);
  }
  if (humanAdmin) return { via: "admin", tier: null };
  const ok = deps.envGrants.check({
    workspaceId: caller.workspaceId,
    keyId: caller.keyId,
    agentId: caller.agentId,
    project,
    backend,
    composeId,
  });
  if (ok) return { via: "grant", tier: null };
  const registered = deps.projectSecrets.registeredTarget({
    workspaceId: caller.workspaceId,
    keyId: caller.keyId,
    project,
    backend,
    composeId,
  });
  if (registered) return { via: "project", tier: registered.tier };
  throw new SecretError("env operation requires a grant", 403);
}

function needsProductionApproval(deps: EnvToolDeps, auth: EnvAuth): boolean {
  return auth.via === "project" && auth.tier === "PRODUCTION" && deps.projectSecrets.productionApproval();
}

function refBase(ref: string): string {
  let base = ref.trim();
  const hashIndex = base.indexOf("#");
  if (hashIndex >= 0) base = base.slice(0, hashIndex);
  const atIndex = base.indexOf("@");
  if (atIndex >= 0) base = base.slice(0, atIndex);
  return base;
}

function projectFromRef(ref: string): string {
  try {
    const parsed = parseSecretRef(refBase(ref));
    return parsed.project;
  } catch {
    return "";
  }
}

function auditWrite(store: Store, caller: EnvToolCaller, action: string, detail: Record<string, unknown>): void {
  store.writeAudit({
    workspaceId: caller.workspaceId,
    keyId: caller.keyId,
    action,
    detail,
  });
}

export async function callEnvTool(
  deps: EnvToolDeps,
  name: string,
  args: Record<string, unknown>,
  caller: EnvToolCaller,
): Promise<unknown> {
  const humanAdmin = isHumanAdmin(deps.store, caller);
  const who = actor(caller);
  const secretActor: SecretActor = { ...who, humanAdmin };

  if (isProjectSecretTool(name)) {
    return callProjectSecretTool(deps, name, args, caller);
  }

  if (name === "mf_env_keys_list") {
    const backend = requireString(args, "backend");
    const composeId = requireString(args, "compose_id");
    const project = requireString(args, "project");
    authorizeEnv(deps, caller, humanAdmin, project, backend, composeId);
    const sink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
    const read = await sink.readEnv(backend, composeId);
    const keys = read.env ? envKeyNames(read.env) : [];
    const outKeys = [];
    for (const k of keys) {
      const tmpl = deps.envTemplates.get(caller.workspaceId, backend, composeId, k);
      if (tmpl) outKeys.push({ name: k, ref: tmpl.ref });
      else outKeys.push({ name: k, value: MASK });
    }
    return { keys: outKeys };
  }

  if (name === "mf_env_keys_set") {
    const backend = requireString(args, "backend");
    const composeId = requireString(args, "compose_id");
    const project = requireString(args, "project");
    const values = args.values;
    if (!values || typeof values !== "object" || Array.isArray(values)) {
      throw new SecretError("values is required");
    }
    const vmap = values as Record<string, unknown>;
    const auth = authorizeEnv(deps, caller, humanAdmin, project, backend, composeId);
    const setMap: Record<string, string> = {};
    const refVersions: Record<string, string> = {};
    const refKeys: string[] = [];
    const plainKeys: string[] = [];
    for (const [key, raw] of Object.entries(vmap)) {
      if (!KEY_RE.test(key)) throw new SecretError("invalid env key");
      if (typeof raw !== "string") throw new SecretError("invalid env value");
      if (auth.via === "project" && !raw.startsWith("secret://")) {
        throw new SecretError("project secret bind accepts only secret refs");
      }
      if (raw.startsWith("secret://")) {
        const base = refBase(raw);
        const parsed = parseSecretRef(base);
        if (parsed.project !== project) throw new SecretError("ref project must equal project");
        const resolved = deps.secrets.resolveForSink({ workspaceId: caller.workspaceId, ref: raw });
        assertEnvValueSafe(resolved.value);
        setMap[key] = resolved.value;
        refKeys.push(key);
        refVersions[key] = `${base}@${resolved.version}`;
      } else {
        assertEnvValueSafe(raw);
        setMap[key] = raw;
        plainKeys.push(key);
      }
    }
    if (needsProductionApproval(deps, auth)) {
      const approvals = [];
      for (const key of refKeys) {
        const base = refVersions[key]!.split("@")[0]!;
        const version = Number(refVersions[key]!.split("@").pop());
        const queued = deps.projectSecrets.queueApproval({
          caller,
          project,
          backend,
          composeId,
          envKey: key,
          action: "set",
          ref: base,
          version,
          privateRef: String(vmap[key] ?? "").includes("#private"),
        });
        approvals.push({ approval_id: queued.approval_id, env_key: key, ref: base, version, expires_at: queued.expires_at });
      }
      auditWrite(deps.store, caller, "project_secret.bind", {
        backend,
        compose_id: composeId,
        project,
        pending: true,
        refs: refVersions,
      });
      return { pending: true, compose_id: composeId, approvals };
    }
    const sink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
    await sink.apply(backend, composeId, setMap, []);
    for (const key of refKeys) {
      const version = Number(refVersions[key].split("@").pop());
      deps.envTemplates.upsert({
        workspaceId: caller.workspaceId,
        backendSlug: backend,
        composeId,
        envKey: key,
        ref: refVersions[key].split("@")[0],
        version,
      });
    }
    for (const key of plainKeys) {
      deps.envTemplates.delete(caller.workspaceId, backend, composeId, key);
    }
    auditWrite(deps.store, caller, "env.keys_set", {
      backend,
      compose_id: composeId,
      project,
      keys: Object.keys(vmap),
      refs: refVersions,
      via: auth.via,
    });
    if (auth.via === "project") {
      auditWrite(deps.store, caller, "project_secret.bind", {
        backend,
        compose_id: composeId,
        project,
        pending: false,
        refs: refVersions,
      });
    }
    return { compose_id: composeId, set: Object.keys(vmap), refs: refVersions };
  }

  if (name === "mf_env_keys_unset") {
    const backend = requireString(args, "backend");
    const composeId = requireString(args, "compose_id");
    const project = requireString(args, "project");
    const keys = args.keys;
    if (!Array.isArray(keys) || keys.some((k) => typeof k !== "string")) {
      throw new SecretError("keys is required");
    }
    const keyList = keys as string[];
    for (const k of keyList) if (!KEY_RE.test(k)) throw new SecretError("invalid env key");
    const unsetAuth = authorizeEnv(deps, caller, humanAdmin, project, backend, composeId);
    if (needsProductionApproval(deps, unsetAuth)) {
      const approvals = [];
      for (const key of keyList) {
        const queued = deps.projectSecrets.queueApproval({
          caller,
          project,
          backend,
          composeId,
          envKey: key,
          action: "unset",
          ref: "",
          version: 0,
          privateRef: false,
        });
        approvals.push({ approval_id: queued.approval_id, env_key: key, expires_at: queued.expires_at });
      }
      auditWrite(deps.store, caller, "project_secret.bind", {
        backend,
        compose_id: composeId,
        project,
        pending: true,
        unset: keyList,
      });
      return { pending: true, compose_id: composeId, approvals };
    }
    const sink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
    await sink.apply(backend, composeId, {}, keyList);
    deps.envTemplates.deleteForKeys(caller.workspaceId, backend, composeId, keyList);
    auditWrite(deps.store, caller, "env.keys_unset", {
      backend,
      compose_id: composeId,
      project,
      keys: keyList,
    });
    return { compose_id: composeId, unset: keyList };
  }

  if (name === "mf_env_provision") {
    const backend = requireString(args, "backend");
    const composeId = requireString(args, "compose_id");
    const project = requireString(args, "project");
    const keys = args.keys;
    if (!keys || typeof keys !== "object" || Array.isArray(keys)) {
      throw new SecretError("keys is required");
    }
    if (deps.provisionTargets.invalid || deps.provisionTargets.ids.size === 0 || !deps.provisionTargets.ids.has(composeId)) {
      throw new EnvSinkError("mf_env_provision is off: set MCP_FLOW_ENV_PROVISION_TARGETS to the DEVELOPMENT compose ids");
    }
    const provisionAuth = authorizeEnv(deps, caller, humanAdmin, project, backend, composeId);
    if (provisionAuth.via === "project") {
      throw new SecretError("mf_env_provision requires an env grant or a human admin", 403);
    }
    const kmap = keys as Record<string, unknown>;
    const setMap: Record<string, string> = {};
    const refVersions: Record<string, string> = {};
    const keyNames = Object.keys(kmap);
    for (const [key, spec] of Object.entries(kmap)) {
      if (!KEY_RE.test(key)) throw new SecretError("invalid env key");
      if (typeof spec === "string") {
        if (!spec.startsWith("secret://")) throw new SecretError("invalid ref");
        const base = refBase(spec);
        const parsed = parseSecretRef(base);
        if (parsed.project !== project) throw new SecretError("ref project must equal project");
        const resolved = deps.secrets.resolveForSink({ workspaceId: caller.workspaceId, ref: spec });
        assertEnvValueSafe(resolved.value);
        setMap[key] = resolved.value;
        refVersions[key] = `${base}@${resolved.version}`;
      } else if (spec && typeof spec === "object" && !Array.isArray(spec)) {
        const g = (spec as Record<string, unknown>).generate;
        if (g !== "token" && g !== "password" && g !== "uuid") throw new SecretError("invalid generate type");
        if (!humanAdmin) throw new SecretError("human admin required", 403);
        const secretName = key.toLowerCase();
        const created = deps.secrets.create({
          ...secretActor,
          project,
          name: secretName,
          type: g,
          params: {},
        });
        const resolved = deps.secrets.resolveForSink({
          workspaceId: caller.workspaceId,
          ref: `secret://${project}/${secretName}`,
        });
        assertEnvValueSafe(resolved.value);
        setMap[key] = resolved.value;
        refVersions[key] = `${created.ref}@${created.version}`;
      } else {
        throw new SecretError("invalid provision spec");
      }
    }
    const sink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
    await sink.apply(backend, composeId, setMap, []);
    for (const key of keyNames) {
      const baseRef = refVersions[key].split("@")[0];
      const version = Number(refVersions[key].split("@").pop());
      deps.envTemplates.upsert({
        workspaceId: caller.workspaceId,
        backendSlug: backend,
        composeId,
        envKey: key,
        ref: baseRef,
        version,
      });
    }
    auditWrite(deps.store, caller, "env.keys_provision", {
      backend,
      compose_id: composeId,
      project,
      keys: keyNames,
      refs: refVersions,
    });
    return { compose_id: composeId, set: keyNames, refs: refVersions };
  }

  if (name === "mf_secret_resync") {
    const filter: { workspaceId: string; backendSlug?: string; composeId?: string; ref?: string } = {
      workspaceId: caller.workspaceId,
    };
    const refFilter = typeof args.ref === "string" ? args.ref : undefined;
    const backendFilter = typeof args.backend === "string" ? args.backend : undefined;
    const composeFilter = typeof args.compose_id === "string" ? args.compose_id : undefined;
    if (backendFilter) filter.backendSlug = backendFilter;
    if (composeFilter) filter.composeId = composeFilter;
    if (refFilter) filter.ref = refFilter;
    const rows = deps.envTemplates.list(filter);
    const groups = new Map<string, typeof rows>();
    for (const r of rows) {
      const project = projectFromRef(r.ref);
      const key = `${r.backendSlug}|${r.composeId}|${project}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(r);
    }
    const resynced: Array<{ backend: string; compose_id: string; keys: string[]; ref: string }> = [];
    const skipped: Array<{ backend: string; compose_id: string; keys: string[]; ref: string }> = [];
    const pending: Array<{ approval_id: string; env_key: string; ref: string; version: number }> = [];
    for (const [gkey, grows] of groups) {
      const parts = gkey.split("|");
      const backend = parts[0];
      const composeId = parts[1];
      const project = parts[2];
      const resyncAuth = authorizeEnv(deps, caller, humanAdmin, project, backend, composeId);
      const sink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
      const changedKeys: string[] = [];
      const changedValues: Record<string, string> = {};
      const rowVersions = new Map<string, number>();
      for (const r of grows) {
        let value: string;
        let resolvedVersion = r.version;
        try {
          const res = deps.secrets.resolveForSink({ workspaceId: caller.workspaceId, ref: r.ref });
          value = res.value;
          resolvedVersion = res.version;
        } catch {
          continue;
        }
        if (resolvedVersion > r.version) {
          changedKeys.push(r.envKey);
          changedValues[r.envKey] = value;
          rowVersions.set(r.envKey, resolvedVersion);
        }
      }
      if (changedKeys.length > 0 && needsProductionApproval(deps, resyncAuth)) {
        for (const key of changedKeys) {
          const r = grows.find((x) => x.envKey === key)!;
          const queued = deps.projectSecrets.queueApproval({
            caller,
            project,
            backend,
            composeId,
            envKey: key,
            action: "resync",
            ref: r.ref,
            version: rowVersions.get(key)!,
            privateRef: false,
          });
          pending.push({ approval_id: queued.approval_id, env_key: key, ref: r.ref, version: rowVersions.get(key)! });
        }
      } else if (changedKeys.length > 0) {
        await sink.apply(backend, composeId, changedValues, []);
        for (const key of changedKeys) {
          const r = grows.find((x) => x.envKey === key)!;
          deps.envTemplates.upsert({
            workspaceId: caller.workspaceId,
            backendSlug: backend,
            composeId,
            envKey: key,
            ref: r.ref,
            version: rowVersions.get(key)!,
          });
        }
        resynced.push({ backend, compose_id: composeId, keys: changedKeys, ref: grows[0].ref });
      } else {
        skipped.push({ backend, compose_id: composeId, keys: grows.map((r) => r.envKey), ref: grows[0].ref });
      }
    }
    auditWrite(deps.store, caller, "env.keys_resync", {
      backend: backendFilter ?? null,
      compose_id: composeFilter ?? null,
      ref: refFilter ?? null,
      resynced: resynced.map((r) => ({ backend: r.backend, compose_id: r.compose_id, keys: r.keys, ref: r.ref })),
    });
    if (pending.length) {
      auditWrite(deps.store, caller, "project_secret.bind", {
        backend: backendFilter ?? null,
        compose_id: composeFilter ?? null,
        ref: refFilter ?? null,
        pending: true,
        approvals: pending.map((item) => item.approval_id),
      });
    }
    return pending.length ? { resynced, skipped, pending } : { resynced, skipped };
  }

  if (name === "mf_admin_env_grant_create") {
    if (!humanAdmin) throw new SecretError("human admin required", 403);
    const project = requireString(args, "project");
    const backend = requireString(args, "backend");
    const composeIds = args.compose_ids;
    if (!Array.isArray(composeIds) || composeIds.length === 0 || composeIds.some((x) => typeof x !== "string")) {
      throw new SecretError("compose_ids is required");
    }
    const ids = composeIds as string[];
    const keyId = typeof args.key_id === "string" ? args.key_id : null;
    const agentId = typeof args.agent_id === "string" ? args.agent_id : null;
    const { sinkId, grantId } = deps.envGrants.create({
      actor: secretActor,
      keyId,
      agentId,
      project,
      backend,
      composeIds: ids,
    });
    auditWrite(deps.store, caller, "env.grant_create", {
      project,
      backend,
      compose_ids: ids,
      grant_id: grantId,
    });
    return { sink_id: sinkId, grant_id: grantId };
  }

  if (name === "mf_admin_env_grant_list") {
    if (!humanAdmin) throw new SecretError("human admin required", 403);
    const project = typeof args.project === "string" ? args.project : null;
    const grants = deps.envGrants.list({ actor: secretActor, project });
    return { grants };
  }

  if (name === "mf_admin_env_grant_revoke") {
    if (!humanAdmin) throw new SecretError("human admin required", 403);
    const grantId = requireString(args, "grant_id");
    deps.envGrants.revoke({ actor: secretActor, grantId });
    auditWrite(deps.store, caller, "env.grant_revoke", { grant_id: grantId });
    return { revoked: true };
  }

  throw new SecretError("unknown env tool", 404);
}

export function envToolError(err: unknown): { message: string; isError: true } {
  if (
    err instanceof EnvSinkError ||
    err instanceof ProtectedTargetError ||
    err instanceof SecretError ||
    err instanceof EnvGrantError
  ) {
    return { message: err.message, isError: true };
  }
  return { message: "env operation failed", isError: true };
}

export function envToolResult(body: unknown, isError = false): CallToolResult {
  return {
    isError,
    content: [{ type: "text", text: typeof body === "string" ? body : JSON.stringify(body) }],
  };
}