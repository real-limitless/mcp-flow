import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { Store } from "../src/db/store.js";
import { EdgeHub } from "../src/edge/hub.js";
import { EdgeRouter } from "../src/edge/router.js";
import { encodeMsg, type EdgeEnvelope } from "../src/edge/protocol.js";

const master = Buffer.alloc(32, 11).toString("base64");
const dirs: string[] = [];

afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe("edge hub + router", () => {
  it("rpc succeeds when device online; offline is fast", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-edge-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const ws = store.ensureWorkspace("default");
    const enrolled = store.enrollDevice(ws.id, {
      name: "laptop",
      capabilities: { sandbox: "docker", bare: false },
    });
    const hub = new EdgeHub(store);
    const router = new EdgeRouter(store, hub);

    const backend = store.createBackend(ws.id, {
      slug: "local",
      transport: "stdio",
      command: ["echo"],
      enabled: true,
      placement: {
        mode: "edge-sandbox",
        deviceId: enrolled.id,
        affinity: "pinned",
      },
    });

    await expect(router.listTools(store.getBackend(ws.id, backend.id)!)).rejects.toThrow(
      /device_offline/,
    );

    const replies: string[] = [];
    hub.attach(enrolled.id, ws.id, {
      send: (data) => {
        replies.push(data);
        const msg = JSON.parse(data) as EdgeEnvelope;
        if (msg.type === "rpc" && msg.method === "tools.list") {
          hub.handleMessage(
            enrolled.id,
            encodeMsg({
              v: 1,
              id: msg.id,
              type: "rpc_result",
              payload: {
                tools: [
                  {
                    name: "hello",
                    description: "hi",
                    inputSchema: { type: "object" },
                  },
                ],
              },
            }),
          );
        }
      },
      close: () => undefined,
    });

    expect(hub.isOnline(enrolled.id)).toBe(true);
    const tools = await router.listTools(store.getBackend(ws.id, backend.id)!);
    expect(tools.map((t) => t.name)).toEqual(["hello"]);
    expect(replies.length).toBeGreaterThan(0);

    hub.detach(enrolled.id);
    expect(hub.isOnline(enrolled.id)).toBe(false);
    store.close();
  });

  it("sticky device override", () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-flow-sticky-"));
    dirs.push(dir);
    const store = new Store(join(dir, "t.db"), master);
    const hub = new EdgeHub(store);
    const router = new EdgeRouter(store, hub);
    router.sticky.set("key1", "devA");
    expect(router.sticky.get("key1")).toBe("devA");
    router.sticky.clear("key1");
    expect(router.sticky.get("key1")).toBeNull();
    store.close();
  });
});
