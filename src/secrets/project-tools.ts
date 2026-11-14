/**
 * Agent tools for secrets:project:write, plus the human-admin grant,
 * target registration, and PRODUCTION approval decision.
 * Responses are refs and metadata. A secret value is never returned.
 */

import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Store } from "../db/store.js";
import type { SecretActor, SecretDirectory } from "./directory.js";
import { SecretError } from "./directory.js";
import { DokployEnvSink } from "./env-sink.js";
import type { EnvTemplateDirectory } from "./env-templates.js";
import type { ProjectCaller, ProjectSecretDirectory } from "./project-scope.js";
import { ProtectedTargetError, type ProtectedTargets } from "./protected.js";

export const PROJECT_SECRET_TOOLS: Tool[] = [
  {
    name: "mf_project_secret_create",
    description:
      "Generate a secret for this key's own project. Requires secrets:project:write, which is off until a human admin grants it. Returns a ref and version, never the value.",
    inputSchema: {
      type: "object",
      properties: {
        project: { type: "string" },
        name: { type: "string" },
        type: { type: "string", enum: ["token", "password", "uuid", "keypair"] },
        params: { type: "object", additionalProperties: true },
        description: { type: "string" },
      },
      required: ["name", "type"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_project_secret_rotate",
    description:
      "Rotate a secret in this key's own project. Requires secrets:project:write. Returns the new ref and version, never the value. Imported secrets cannot be rotated.",
    inputSchema: {
      type: "object",
      properties: { ref: { type: "string" } },
      required: ["ref"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_project_secret_list",
    description:
      "List secret metadata for this key's own projects. Requires secrets:project:write. Never returns a value.",
    inputSchema: {
      type: "object",
      properties: { project: { type: "string" }, q: { type: "string" } },
      additionalProperties: false,
    },
  },
  {
    name: "mf_project_secret_upload_link",
    description:
      "Issue a short-lived single-use upload link so a human can supply a value that cannot be generated. Requires secrets:project:write. The link is not the secret. The value is never accepted or returned on this tool.",
    inputSchema: {
      type: "object",
      properties: {
        project: { type: "string" },
        name: { type: "string" },
        description: { type: "string" },
      },
      required: ["name"],
      additionalProperties: false,
    },
  },
];

export const PROJECT_SECRET_ADMIN_TOOLS: Tool[] = [
  {
    name: "mf_admin_secret_scope_set",
    description:
      "Grant or revoke secrets:project:write on one agent key. Human admin only. Off by default. The key can then create and bind secrets only for its own projects.",
    inputSchema: {
      type: "object",
      properties: {
        key_id: { type: "string" },
        enabled: { type: "boolean" },
      },
      required: ["key_id", "enabled"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_env_target_register",
    description:
      "Register a compose deployment as an env target for one project. Human admin only. Protected targets are refused. Tier is DEVELOPMENT or PRODUCTION.",
    inputSchema: {
      type: "object",
      properties: {
        project: { type: "string" },
        backend: { type: "string" },
        compose_id: { type: "string" },
        tier: { type: "string", enum: ["DEVELOPMENT", "PRODUCTION"] },
      },
      required: ["project", "backend", "compose_id", "tier"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_env_target_list",
    description: "List registered env targets. Human admin only.",
    inputSchema: {
      type: "object",
      properties: { project: { type: "string" } },
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_env_target_revoke",
    description: "Revoke a registered env target. Human admin only.",
    inputSchema: {
      type: "object",
      properties: { target_id: { type: "string" } },
      required: ["target_id"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_admin_project_secret_approval_decide",
    description:
      "Approve or deny a pending PRODUCTION secret bind. Human admin only. The stored row is a ref, and the decision response never includes a secret value.",
    inputSchema: {
      type: "object",
      properties: {
        approval_id: { type: "string" },
        decision: { type: "string", enum: ["approve", "deny"] },
      },
      required: ["approval_id", "decision"],
      additionalProperties: false,
    },
  },
];

const PROJECT_SECRET_NAMES = new Set([
  ...PROJECT_SECRET_TOOLS.map((tool) => tool.name),
  ...PROJECT_SECRET_ADMIN_TOOLS.map((tool) => tool.name),
]);

export function isProjectSecretTool(name: string): boolean {
  return PROJECT_SECRET_NAMES.has(name);
}

export interface ProjectToolDeps {
  store: Store;
  secrets: SecretDirectory;
  projectSecrets: ProjectSecretDirectory;
  envTemplates: EnvTemplateDirectory;
  protectedTargets: ProtectedTargets;
  callTool: (name: string, args: Record<string, unknown>) => Promise<CallToolResult>;
}

export interface ProjectToolCaller {
  workspaceId: string;
  keyId: string;
  agentId: string;
  agentKind: string | null;
  admin: boolean;
  allowedProjects: readonly string[] | null;
}

function callerOf(caller: ProjectToolCaller): ProjectCaller {
  return {
    workspaceId: caller.workspaceId,
    keyId: caller.keyId,
    agentId: caller.agentId,
    allowedProjects: caller.allowedProjects,
  };
}

function actorOf(caller: ProjectToolCaller): SecretActor {
  return {
    workspaceId: caller.workspaceId,
    keyId: caller.keyId,
    agentId: caller.agentId,
    allowedProjects: caller.allowedProjects,
    humanAdmin: false,
  };
}

function requireString(args: Record<string, unknown>, key: string): string {
  const value = args[key];
  if (typeof value !== "string" || value.trim() === "") throw new SecretError(`${key} is required`);
  return value;
}

export async function callProjectSecretTool(
  deps: ProjectToolDeps,
  name: string,
  args: Record<string, unknown>,
  caller: ProjectToolCaller,
): Promise<unknown> {
  const who = callerOf(caller);
  if (name === "mf_project_secret_create") {
    return deps.projectSecrets.create(who, {
      project: typeof args.project === "string" ? args.project : null,
      name: String(args.name ?? ""),
      type: String(args.type ?? ""),
      params: args.params,
      description: typeof args.description === "string" ? args.description : null,
    });
  }
  if (name === "mf_project_secret_rotate") {
    return deps.projectSecrets.rotate(who, requireString(args, "ref"));
  }
  if (name === "mf_project_secret_list") {
    return deps.projectSecrets.list(
      who,
      typeof args.project === "string" ? args.project : null,
      typeof args.q === "string" ? args.q : null,
    );
  }
  if (name === "mf_project_secret_upload_link") {
    return deps.projectSecrets.issueUpload(who, {
      project: typeof args.project === "string" ? args.project : null,
      name: String(args.name ?? ""),
      description: typeof args.description === "string" ? args.description : null,
    });
  }
  if (name === "mf_admin_secret_scope_set") {
    return deps.projectSecrets.setScope(actorOf(caller), requireString(args, "key_id"), args.enabled === true);
  }
  if (name === "mf_admin_env_target_register") {
    return deps.projectSecrets.registerTarget(actorOf(caller), {
      project: requireString(args, "project"),
      backend: requireString(args, "backend"),
      composeId: requireString(args, "compose_id"),
      tier: requireString(args, "tier"),
    });
  }
  if (name === "mf_admin_env_target_list") {
    return deps.projectSecrets.listTargets(actorOf(caller), typeof args.project === "string" ? args.project : null);
  }
  if (name === "mf_admin_env_target_revoke") {
    return deps.projectSecrets.revokeTarget(actorOf(caller), requireString(args, "target_id"));
  }
  if (name === "mf_admin_project_secret_approval_decide") {
    return decideApproval(deps, caller, requireString(args, "approval_id"), requireString(args, "decision"));
  }
  throw new SecretError("unknown secret tool", 404);
}

async function decideApproval(
  deps: ProjectToolDeps,
  caller: ProjectToolCaller,
  approvalId: string,
  decision: string,
): Promise<unknown> {
  const actor = actorOf(caller);
  const row = deps.projectSecrets.loadApproval(caller.workspaceId, approvalId);
  if (row.state !== "pending") throw new SecretError("approval is not pending", 409);
  if (row.expires_at <= new Date().toISOString()) {
    deps.projectSecrets.markApproval(actor, approvalId, "expired");
    throw new SecretError("approval expired", 400);
  }
  if (decision === "deny") {
    deps.projectSecrets.markApproval(actor, approvalId, "denied");
    return { approval_id: approvalId, state: "denied", ref: row.ref || null };
  }
  if (decision !== "approve") throw new SecretError("decision must be approve or deny");
  if (deps.protectedTargets.invalid || deps.protectedTargets.ids.has(row.compose_id)) {
    throw new ProtectedTargetError();
  }
  const target = deps.projectSecrets.activeTarget({
    workspaceId: caller.workspaceId,
    project: row.project,
    backend: row.backend,
    composeId: row.compose_id,
  });
  if (!target) throw new SecretError("env target is not registered", 403);
  const sink = new DokployEnvSink(deps.callTool, deps.protectedTargets);
  if (row.action === "unset") {
    await sink.apply(row.backend, row.compose_id, {}, [row.env_key]);
    deps.envTemplates.delete(caller.workspaceId, row.backend, row.compose_id, row.env_key);
  } else {
    const pinned = `${row.ref}@${row.version}${row.private ? "#private" : ""}`;
    const resolved = deps.secrets.resolveForSink({ workspaceId: caller.workspaceId, ref: pinned });
    await sink.apply(row.backend, row.compose_id, { [row.env_key]: resolved.value }, []);
    deps.envTemplates.upsert({
      workspaceId: caller.workspaceId,
      backendSlug: row.backend,
      composeId: row.compose_id,
      envKey: row.env_key,
      ref: row.ref,
      version: resolved.version,
    });
  }
  deps.projectSecrets.markApproval(actor, approvalId, "approved");
  return {
    approval_id: approvalId,
    state: "approved",
    project: row.project,
    compose_id: row.compose_id,
    env_key: row.env_key,
    ref: row.action === "unset" ? null : row.ref,
    version: row.version,
  };
}
