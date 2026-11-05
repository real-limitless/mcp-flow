/**
 * mf_secret_create / list / rotate / delete.
 * Results are refs and metadata. Import, reveal, and resync are not registered.
 */

import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { SecretActor, SecretDirectory } from "./directory.js";
import { SecretError } from "./directory.js";
import { ProtectedTargetError } from "./protected.js";

export const SECRET_META_TOOLS: Tool[] = [
  {
    name: "mf_secret_create",
    description:
      "Generate and store a secret. Returns a ref and version, and the public key for a keypair. Never returns the secret value.",
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
    name: "mf_secret_list",
    description: "List secret metadata for projects this key may use. Never returns a secret value.",
    inputSchema: {
      type: "object",
      properties: {
        project: { type: "string" },
        q: { type: "string" },
      },
      additionalProperties: false,
    },
  },
  {
    name: "mf_secret_rotate",
    description: "Create a new secret version from the stored generator. Returns the new ref and version, never the value.",
    inputSchema: {
      type: "object",
      properties: {
        ref: { type: "string" },
        grace_seconds: { type: "number" },
        resync: { type: "boolean" },
      },
      required: ["ref"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_secret_delete",
    description: "Soft-delete a secret so its ref fails closed. purge destroys ciphertext and is human-admin only.",
    inputSchema: {
      type: "object",
      properties: {
        ref: { type: "string" },
        purge: { type: "boolean" },
      },
      required: ["ref"],
      additionalProperties: false,
    },
  },
];

const SECRET_TOOL_NAMES = new Set(SECRET_META_TOOLS.map((tool) => tool.name));

export function isSecretTool(name: string): boolean {
  return SECRET_TOOL_NAMES.has(name);
}

export interface SecretToolCaller {
  workspaceId: string;
  keyId: string;
  agentId: string;
  agentKind: string | null;
  admin: boolean;
  allowedProjects: readonly string[] | null;
  activeProject: string | null;
}

function actor(caller: SecretToolCaller): SecretActor {
  return {
    workspaceId: caller.workspaceId,
    keyId: caller.keyId,
    agentId: caller.agentId,
    allowedProjects: caller.allowedProjects,
    humanAdmin: caller.admin && caller.agentKind === "human",
  };
}

function projectOf(args: Record<string, unknown>, caller: SecretToolCaller): string {
  const requested = typeof args.project === "string" ? args.project : caller.activeProject;
  if (!requested) throw new SecretError("project is required");
  return requested;
}

export function callSecretTool(
  secrets: SecretDirectory,
  name: string,
  args: Record<string, unknown>,
  caller: SecretToolCaller,
): unknown {
  const who = actor(caller);
  if (name === "mf_secret_create") {
    return secrets.create({
      ...who,
      project: projectOf(args, caller),
      name: String(args.name ?? ""),
      type: String(args.type ?? ""),
      params: args.params,
      description: typeof args.description === "string" ? args.description : null,
    });
  }
  if (name === "mf_secret_list") {
    return secrets.list({
      ...who,
      project: typeof args.project === "string" ? args.project : null,
      q: typeof args.q === "string" ? args.q : null,
    });
  }
  if (name === "mf_secret_rotate") {
    return secrets.rotate({
      ...who,
      ref: String(args.ref ?? ""),
      graceSeconds: typeof args.grace_seconds === "number" ? args.grace_seconds : null,
      resync: args.resync === true,
    });
  }
  if (name === "mf_secret_delete") {
    return secrets.delete({ ...who, ref: String(args.ref ?? ""), purge: args.purge === true });
  }
  throw new SecretError("unknown secret tool", 404);
}

export function secretToolError(err: unknown): { message: string; isError: true } {
  if (err instanceof SecretError || err instanceof ProtectedTargetError) {
    return { message: err.message, isError: true };
  }
  return { message: "secret operation failed", isError: true };
}

export function secretToolResult(body: unknown, isError = false): CallToolResult {
  return {
    isError,
    content: [{ type: "text", text: typeof body === "string" ? body : JSON.stringify(body) }],
  };
}
