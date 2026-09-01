import WebSocket from "ws";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import { connectOci } from "../mcp/runners/oci.js";
import { connectStdioCommand } from "../mcp/runners/stdio.js";
import {
  decodeMsg,
  encodeMsg,
  newMsgId,
  type EdgeEnvelope,
  type EdgeToolsCallPayload,
  type EdgeToolsListPayload,
} from "./protocol.js";

interface LocalRuntime {
  listTools: () => Promise<Tool[]>;
  callTool: (
    name: string,
    args: Record<string, unknown>,
  ) => Promise<CallToolResult>;
  close: () => Promise<void>;
}

/**
 * Edge device daemon: outbound WS to control plane, run local stdio/oci MCP.
 */
export async function runEdgeAgent(opts: {
  url: string;
  token: string;
  name?: string;
}): Promise<void> {
  const wsUrl = opts.url.replace(/\/$/, "").replace(/^http/, "ws") + "/v1/edge/connect";
  const runtimes = new Map<string, LocalRuntime>();

  const connect = () => {
    const ws = new WebSocket(wsUrl, {
      headers: { Authorization: `Bearer ${opts.token}` },
    });

    ws.on("open", () => {
      ws.send(
        encodeMsg({
          v: 1,
          id: newMsgId(),
          type: "hello",
          payload: { name: opts.name },
        }),
      );
      console.error(`[edge] connected to ${wsUrl}`);
    });

    const heartbeat = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(
          encodeMsg({
            v: 1,
            id: newMsgId(),
            type: "heartbeat",
          }),
        );
      }
    }, 15_000);

    ws.on("message", (data) => {
      void (async () => {
        let msg: EdgeEnvelope;
        try {
          msg = decodeMsg(String(data));
        } catch {
          return;
        }
        if (msg.type !== "rpc" || !msg.method) return;
        try {
          const result = await handleRpc(msg.method, msg.payload ?? {}, runtimes);
          ws.send(
            encodeMsg({
              v: 1,
              id: msg.id,
              type: "rpc_result",
              payload: result,
            }),
          );
        } catch (err) {
          ws.send(
            encodeMsg({
              v: 1,
              id: msg.id,
              type: "rpc_error",
              error: err instanceof Error ? err.message : String(err),
            }),
          );
        }
      })();
    });

    ws.on("close", () => {
      clearInterval(heartbeat);
      console.error("[edge] disconnected; reconnecting in 3s");
      setTimeout(connect, 3000);
    });

    ws.on("error", (err) => {
      console.error("[edge] ws error:", err.message);
    });
  };

  connect();
  // keep process alive
  await new Promise(() => undefined);
}

async function ensureRuntime(
  payload: EdgeToolsListPayload,
  runtimes: Map<string, LocalRuntime>,
): Promise<LocalRuntime> {
  const key = payload.backendId;
  const existing = runtimes.get(key);
  if (existing) return existing;

  const env = payload.env ?? {};
  const mode = payload.mode;

  if (mode === "edge-bare" || payload.transport === "stdio") {
    if (!payload.command?.length) {
      throw new Error("stdio/bare requires command");
    }
    const run = await connectStdioCommand({
      command: payload.command,
      env,
    });
    const rt: LocalRuntime = {
      listTools: async () => run.tools,
      callTool: async (name, args) =>
        (await run.client.callTool({
          name,
          arguments: args,
        })) as CallToolResult,
      close: async () => {
        await run.client.close().catch(() => undefined);
        if (run.dispose) await run.dispose();
      },
    };
    runtimes.set(key, rt);
    return rt;
  }

  if (payload.transport === "oci" || mode === "edge-sandbox") {
    if (payload.image) {
      const run = await connectOci({
        image: payload.image,
        command: payload.command,
        env,
        sandbox: payload.sandbox as never,
      });
      const rt: LocalRuntime = {
        listTools: async () => run.tools,
        callTool: async (name, args) =>
          (await run.client.callTool({
            name,
            arguments: args,
          })) as CallToolResult,
        close: async () => {
          await run.client.close().catch(() => undefined);
          if (run.dispose) await run.dispose();
        },
      };
      runtimes.set(key, rt);
      return rt;
    }
    if (payload.command?.length) {
      // sandbox stdio via local docker optional — run bare command in sandbox mode as process for MVP
      const run = await connectStdioCommand({
        command: payload.command,
        env,
      });
      const rt: LocalRuntime = {
        listTools: async () => run.tools,
        callTool: async (name, args) =>
          (await run.client.callTool({
            name,
            arguments: args,
          })) as CallToolResult,
        close: async () => {
          await run.client.close().catch(() => undefined);
        },
      };
      runtimes.set(key, rt);
      return rt;
    }
  }

  throw new Error(
    `unsupported edge runtime transport=${payload.transport} mode=${mode}`,
  );
}

async function handleRpc(
  method: string,
  payload: Record<string, unknown>,
  runtimes: Map<string, LocalRuntime>,
): Promise<Record<string, unknown>> {
  if (method === "tools.list") {
    const p = payload as unknown as EdgeToolsListPayload;
    const rt = await ensureRuntime(p, runtimes);
    const tools = await rt.listTools();
    return { tools };
  }
  if (method === "tools.call") {
    const p = payload as unknown as EdgeToolsCallPayload;
    const rt = await ensureRuntime(p, runtimes);
    const result = await rt.callTool(p.tool, p.arguments ?? {});
    return { result };
  }
  if (method === "runtime.stop") {
    const backendId = String(payload.backendId ?? "");
    const rt = runtimes.get(backendId);
    if (rt) {
      await rt.close();
      runtimes.delete(backendId);
    }
    return { ok: true };
  }
  if (method === "runtime.start") {
    const p = payload as unknown as EdgeToolsListPayload;
    await ensureRuntime(p, runtimes);
    return { ok: true };
  }
  throw new Error(`unknown method ${method}`);
}
