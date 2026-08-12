import type { Store } from "../db/store.js";
import {
  decodeMsg,
  encodeMsg,
  newMsgId,
  type EdgeEnvelope,
  type EdgeRpcMethod,
} from "./protocol.js";

export interface EdgeSocket {
  send(data: string): void;
  close(): void;
}

interface Pending {
  resolve: (msg: EdgeEnvelope) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface Session {
  deviceId: string;
  workspaceId: string;
  socket: EdgeSocket;
  pending: Map<string, Pending>;
}

const DEFAULT_RPC_TIMEOUT_MS = 30_000;

/**
 * In-memory device session hub (one process).
 * Device connections register here; control plane RPCs go out over WS.
 */
export class EdgeHub {
  private sessions = new Map<string, Session>();

  constructor(private store: Store) {}

  isOnline(deviceId: string): boolean {
    return this.sessions.has(deviceId);
  }

  onlineDeviceIds(workspaceId: string): string[] {
    const out: string[] = [];
    for (const s of this.sessions.values()) {
      if (s.workspaceId === workspaceId) out.push(s.deviceId);
    }
    return out;
  }

  attach(
    deviceId: string,
    workspaceId: string,
    socket: EdgeSocket,
  ): void {
    const prev = this.sessions.get(deviceId);
    if (prev) {
      try {
        prev.socket.close();
      } catch {
        /* ignore */
      }
      this.failPending(prev, new Error("device reconnected"));
    }
    this.sessions.set(deviceId, {
      deviceId,
      workspaceId,
      socket,
      pending: new Map(),
    });
    this.store.touchDeviceOnline(deviceId);
    this.store.writeAudit({
      workspaceId,
      action: "device.connect",
      deviceId,
      detail: { online: true },
    });
  }

  detach(deviceId: string): void {
    const s = this.sessions.get(deviceId);
    if (!s) return;
    this.sessions.delete(deviceId);
    this.failPending(s, new Error("device_offline"));
    this.store.markDeviceOffline(deviceId);
  }

  handleMessage(deviceId: string, raw: string): void {
    const s = this.sessions.get(deviceId);
    if (!s) return;
    let msg: EdgeEnvelope;
    try {
      msg = decodeMsg(raw);
    } catch {
      return;
    }
    this.store.touchDeviceOnline(deviceId);

    if (msg.type === "heartbeat") {
      s.socket.send(
        encodeMsg({
          v: 1,
          id: msg.id,
          type: "heartbeat_ok",
          deviceId,
        }),
      );
      return;
    }

    if (msg.type === "rpc_result" || msg.type === "rpc_error") {
      const p = s.pending.get(msg.id);
      if (p) {
        clearTimeout(p.timer);
        s.pending.delete(msg.id);
        if (msg.type === "rpc_error") {
          p.reject(new Error(msg.error || "edge rpc error"));
        } else {
          p.resolve(msg);
        }
      }
    }
  }

  async rpc(
    deviceId: string,
    method: EdgeRpcMethod,
    payload: Record<string, unknown>,
    timeoutMs = DEFAULT_RPC_TIMEOUT_MS,
  ): Promise<EdgeEnvelope> {
    const s = this.sessions.get(deviceId);
    if (!s) {
      throw new Error(`device_offline: ${deviceId}`);
    }
    const id = newMsgId();
    const msg: EdgeEnvelope = {
      v: 1,
      id,
      type: "rpc",
      deviceId,
      method,
      payload,
    };
    return new Promise<EdgeEnvelope>((resolve, reject) => {
      const timer = setTimeout(() => {
        s.pending.delete(id);
        reject(new Error(`device_timeout: ${deviceId}`));
      }, timeoutMs);
      s.pending.set(id, { resolve, reject, timer });
      try {
        s.socket.send(encodeMsg(msg));
      } catch (err) {
        clearTimeout(timer);
        s.pending.delete(id);
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
  }

  private failPending(s: Session, err: Error): void {
    for (const [, p] of s.pending) {
      clearTimeout(p.timer);
      p.reject(err);
    }
    s.pending.clear();
  }

  closeAll(): void {
    for (const id of [...this.sessions.keys()]) {
      const s = this.sessions.get(id);
      this.detach(id);
      try {
        s?.socket.close();
      } catch {
        /* ignore */
      }
    }
  }
}
