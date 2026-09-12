import { describe, expect, it } from "vitest";
import { ApprovalWaiterMap } from "../src/authz/waiters.js";

describe("approval waiters", () => {
  it("resolves approve before timeout", async () => {
    const w = new ApprovalWaiterMap();
    const p = w.wait("a1", { workspaceId: "ws", timeoutMs: 5_000 });
    expect(w.atCap("ws")).toBe(false);
    expect(w.resolve("a1", "approved")).toBe(true);
    expect(await p).toEqual({ status: "approved" });
    expect(w.resolve("a1", "approved")).toBe(false);
  });

  it("times out and expires", async () => {
    const w = new ApprovalWaiterMap();
    let timed = false;
    const p = w.wait("a2", {
      workspaceId: "ws",
      timeoutMs: 30,
      onTimeout: () => {
        timed = true;
      },
    });
    expect(await p).toEqual({ status: "expired" });
    expect(timed).toBe(true);
  });

  it("aborts without running timeout callback as success", async () => {
    const w = new ApprovalWaiterMap();
    const ac = new AbortController();
    let aborted = false;
    const p = w.wait("a3", {
      workspaceId: "ws",
      timeoutMs: 5_000,
      signal: ac.signal,
      onAbort: () => {
        aborted = true;
      },
    });
    ac.abort();
    expect(await p).toEqual({ status: "expired" });
    expect(aborted).toBe(true);
  });

  it("caps concurrent waits per workspace at 32", () => {
    const w = new ApprovalWaiterMap();
    for (let i = 0; i < 32; i++) {
      void w.wait(`c${i}`, { workspaceId: "ws", timeoutMs: 60_000 });
    }
    expect(w.atCap("ws")).toBe(true);
    expect(w.atCap("other")).toBe(false);
    expect(w.resolve("c0", "denied")).toBe(true);
    expect(w.atCap("ws")).toBe(false);
    for (let i = 1; i < 32; i++) expect(w.resolve(`c${i}`, "denied")).toBe(true);
  });
});
