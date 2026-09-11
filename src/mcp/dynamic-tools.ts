import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import {
  DYNAMIC_LIST_DEFAULT_LIMIT,
  DYNAMIC_LIST_MAX_LIMIT,
  DYNAMIC_TOOLS_LIST_CAP,
} from "../types.js";

export const DYNAMIC_INSTRUCTIONS = [
  "This mcp-flow key has dynamic tool discovery enabled.",
  "tools/list does not include the full upstream catalog (harness tool-count caps).",
  "Workflow:",
  "1. mf_list_tools({ q, backend, limit }) to search namespaced tools (slug__tool).",
  "2. mf_enable_tools({ names and/or backends, prefixes }) to add matches to this session working set.",
  `3. mf_get_tool_schema then mf_call_tool({ name, arguments }), or native tools/call of an enabled name. Cap ${DYNAMIC_TOOLS_LIST_CAP} enabled tools.`,
  "4. mf_disable_tools to drop tools. scopes.dynamicToolsHot prefixes stay enabled.",
].join(" ");

export const DYNAMIC_META_TOOLS: Tool[] = [
  {
    name: "mf_get_tool_schema",
    description:
      "Return the full inputSchema for one namespaced tool (slug__tool). Scope and project gated.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Namespaced tool name (slug__tool)",
        },
      },
      required: ["name"],
      additionalProperties: false,
    },
  },
  {
    name: "mf_enable_tools",
    description:
      "Add namespaced tools to this session's working set so they can be called (and listed, under cap). Does not grant access outside key scopes/project.",
    inputSchema: {
      type: "object",
      properties: {
        names: {
          type: "array",
          items: { type: "string" },
          description: "Fully namespaced tool names (slug__tool)",
        },
        backends: {
          type: "array",
          items: { type: "string" },
          description: "Enable every in-scope tool from these backend slugs",
        },
        prefixes: {
          type: "array",
          items: { type: "string" },
          description: "Enable tools whose names start with these prefixes",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "mf_disable_tools",
    description:
      "Remove tools from this session working set. all:true clears. Hot prefixes on the key stay enabled.",
    inputSchema: {
      type: "object",
      properties: {
        names: {
          type: "array",
          items: { type: "string" },
        },
        backends: {
          type: "array",
          items: { type: "string" },
        },
        prefixes: {
          type: "array",
          items: { type: "string" },
        },
        all: {
          type: "boolean",
          description: "Clear the entire working set",
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: "mf_call_tool",
    description:
      "Invoke a namespaced tool by name with arguments. Required when the harness never re-lists tools after mf_enable_tools.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Namespaced tool name (slug__tool)",
        },
        arguments: {
          type: "object",
          description: "Arguments for the upstream tool",
        },
      },
      required: ["name"],
      additionalProperties: false,
    },
  },
];

export interface CatalogToolHit {
  name: string;
  description?: string;
  backend: string;
}

export function searchCatalogTools(
  tools: CatalogToolHit[],
  opts: { q?: string; backend?: string; limit?: number },
): CatalogToolHit[] {
  const limit = Math.min(
    Math.max(opts.limit ?? DYNAMIC_LIST_DEFAULT_LIMIT, 1),
    DYNAMIC_LIST_MAX_LIMIT,
  );
  let rows = tools;
  const backend = opts.backend?.trim().toLowerCase();
  if (backend) {
    rows = rows.filter((t) => t.backend.toLowerCase() === backend);
  }
  const q = opts.q?.trim().toLowerCase();
  if (!q) {
    return [...rows]
      .sort((a, b) => a.name.localeCompare(b.name))
      .slice(0, limit);
  }
  const scored = rows
    .map((t) => {
      const name = t.name.toLowerCase();
      const desc = (t.description ?? "").toLowerCase();
      const be = t.backend.toLowerCase();
      let score = 0;
      if (name === q) score = 100;
      else if (name.startsWith(q) || name.includes(`__${q}`)) score = 80;
      else if (name.includes(q)) score = 60;
      else if (desc.includes(q)) score = 40;
      else if (be.includes(q)) score = 20;
      return { t, score };
    })
    .filter((x) => x.score > 0);
  scored.sort(
    (a, b) => b.score - a.score || a.t.name.localeCompare(b.t.name),
  );
  return scored.slice(0, limit).map((x) => x.t);
}

export function stringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((v) => String(v).trim()).filter(Boolean);
  }
  if (typeof value === "string" && value.trim()) return [value.trim()];
  return [];
}
