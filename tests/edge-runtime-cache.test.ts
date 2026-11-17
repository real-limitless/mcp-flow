import { describe, expect, it } from "vitest";
import { EdgeRuntimeCache } from "../src/edge/runtime-cache.js";
import type { EdgeToolsListPayload } from "../src/edge/protocol.js";

function payload(env: Record<string, string>): EdgeToolsListPayload {
  return {
    backendId: "be_1",
    slug: "echo",
    transport: "stdio",
    mode: "edge-sandbox",
    command: ["echo"],
    env,
  };
}

describe("edge runtime cache", () => {
  it("reuses a child until the env changes, then closes it", async () => {
    const cache = new EdgeRuntimeCache<{ id: number; close(): Promise<void> }>();
    const closed: number[] = [];
    let n = 0;
    const factory = async () => {
      const id = ++n;
      return { id, close: async () => { closed.push(id); } };
    };
    const first = await cache.resolve(payload({ DEMO_VALUE: "one" }), factory);
    const again = await cache.resolve(payload({ DEMO_VALUE: "one" }), async () => {
      throw new Error("reused child should not be replaced");
    });
    expect(again).toBe(first);
    const next = await cache.resolve(payload({ DEMO_VALUE: "two" }), factory);
    expect(next.id).toBe(2);
    expect(closed).toEqual([1]);
    expect(first).not.toBe(next);
  });
});
