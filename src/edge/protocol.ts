import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

export type EdgeMsgType =
  | "hello"
  | "hello_ok"
  | "heartbeat"
  | "heartbeat_ok"
  | "rpc"
  | "rpc_result"
  | "rpc_error"
  | "error";

export type EdgeRpcMethod =
  | "tools.list"
  | "tools.call"
  | "runtime.start"
  | "runtime.stop";

export interface EdgeEnvelope {
  v: 1;
  id: string;
  type: EdgeMsgType;
  /** device id (server → device may omit) */
  deviceId?: string;
  method?: EdgeRpcMethod;
  payload?: Record<string, unknown>;
  error?: string;
}

export interface EdgeToolsListPayload {
  backendId: string;
  slug: string;
  transport: string;
  mode: "edge-sandbox" | "edge-bare";
  image?: string | null;
  command?: string[] | null;
  env?: Record<string, string>;
  sandbox?: Record<string, unknown> | null;
}

export interface EdgeToolsCallPayload extends EdgeToolsListPayload {
  tool: string;
  arguments?: Record<string, unknown>;
}

export interface EdgeToolsListResult {
  tools: Tool[];
}

export interface EdgeToolsCallResult {
  result: CallToolResult;
}

export function encodeMsg(msg: EdgeEnvelope): string {
  return JSON.stringify(msg);
}

export function decodeMsg(raw: string): EdgeEnvelope {
  const m = JSON.parse(raw) as EdgeEnvelope;
  if (m.v !== 1 || !m.id || !m.type) {
    throw new Error("invalid edge message");
  }
  return m;
}

export function newMsgId(): string {
  return `m_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}
