import { describe, expect, it } from "vitest";
import { parseProtectedTargets } from "../src/secrets/protected.js";
import {
  assertFileContentSafe,
  assertMountPath,
  DokployFileSink,
  FileChangedError,
} from "../src/secrets/file-sink.js";
import { EnvSinkError } from "../src/secrets/env-sink.js";

describe("file sink", () => {
  function make(initial: { mountId: string; mountPath: string; content: string } | null = null) {
    const mounts = initial ? [{ ...initial, type: "file" }] : [];
    let writes = 0;
    const callTool = async (name: string, args: any) => {
      if (name.endsWith("__mounts-listByServiceId")) {
        return { content: [{ type: "text", text: JSON.stringify(mounts) }], isError: false };
      }
      if (name.endsWith("__mounts-one")) {
        const row = mounts.find((mount) => mount.mountId === args.mountId);
        if (!row) return { content: [{ type: "text", text: "missing" }], isError: true };
        return { content: [{ type: "text", text: JSON.stringify(row) }], isError: false };
      }
      if (name.endsWith("__mounts-create")) {
        writes++;
        const row = { mountId: "mnt_new", type: "file", mountPath: args.mountPath, content: args.content };
        mounts.push(row);
        return { content: [{ type: "text", text: JSON.stringify({ mountId: row.mountId }) }], isError: false };
      }
      if (name.endsWith("__mounts-update")) {
        writes++;
        const row = mounts.find((mount) => mount.mountId === args.mountId);
        if (row) row.content = args.content;
        return { content: [{ type: "text", text: JSON.stringify({ mountId: args.mountId }) }], isError: false };
      }
      return { content: [{ type: "text", text: "nope" }], isError: true };
    };
    const sink = new DokployFileSink(callTool as any, parseProtectedTargets(""));
    return { sink, mounts, writes: () => writes };
  }

  it("creates a file mount and returns only the mount id", async () => {
    const { sink, mounts } = make();
    const written = await sink.apply("cmp", "cmp_test_1", "/run/secrets/api.key", "value-stays-here");
    expect(written).toEqual({ mountId: "mnt_new" });
    expect(mounts[0].content).toBe("value-stays-here");
    expect(mounts[0].mountPath).toBe("/run/secrets/api.key");
  });

  it("updates the mount at the same path", async () => {
    const { sink, mounts, writes } = make({ mountId: "mnt_1", mountPath: "/run/secrets/api.key", content: "old" });
    const written = await sink.apply("cmp", "cmp_test_1", "/run/secrets/api.key", "next");
    expect(written.mountId).toBe("mnt_1");
    expect(mounts[0].content).toBe("next");
    expect(writes()).toBe(1);
  });

  it("refuses a placeholder in the new content and in an existing mount", async () => {
    const ph = "[" + "REDACTED" + "]";
    const created = make();
    await expect(created.sink.apply("cmp", "cmp_test_1", "/run/secrets/api.key", ph)).rejects.toBeInstanceOf(EnvSinkError);
    expect(created.writes()).toBe(0);
    const existing = make({ mountId: "mnt_1", mountPath: "/run/secrets/api.key", content: ph });
    await expect(existing.sink.apply("cmp", "cmp_test_1", "/run/secrets/api.key", "next")).rejects.toBeInstanceOf(EnvSinkError);
    expect(existing.writes()).toBe(0);
    expect(existing.mounts[0].content).toBe(ph);
  });

  it("refuses when the mount changes between reads and does not write", async () => {
    const mounts = [{ mountId: "mnt_1", type: "file", mountPath: "/run/secrets/api.key", content: "one" }];
    let reads = 0;
    let writes = 0;
    const callTool = async (name: string, args: any) => {
      if (name.endsWith("__mounts-listByServiceId")) {
        return { content: [{ type: "text", text: JSON.stringify(mounts) }], isError: false };
      }
      if (name.endsWith("__mounts-one")) {
        reads++;
        if (reads === 2) mounts[0].content = "tampered";
        return { content: [{ type: "text", text: JSON.stringify(mounts[0]) }], isError: false };
      }
      if (name.endsWith("__mounts-update") || name.endsWith("__mounts-create")) {
        writes++;
        return { content: [{ type: "text", text: JSON.stringify({ mountId: "mnt_1" }) }], isError: false };
      }
      return { content: [], isError: true };
    };
    const sink = new DokployFileSink(callTool as any, parseProtectedTargets(""));
    await expect(sink.apply("cmp", "cmp_test_1", "/run/secrets/api.key", "next")).rejects.toBeInstanceOf(FileChangedError);
    expect(writes).toBe(0);
  });

  it("refuses a protected compose id before any mount call", async () => {
    let calls = 0;
    const sink = new DokployFileSink((async () => {
      calls++;
      return { content: [], isError: true };
    }) as any, parseProtectedTargets("cmp_protected"));
    await expect(sink.apply("cmp", "cmp_protected", "/run/secrets/api.key", "x")).rejects.toThrow(/protected target/);
    expect(calls).toBe(0);
  });

  it("rejects unsafe paths and control characters", () => {
    expect(() => assertMountPath("/run/secrets/api.key")).not.toThrow();
    expect(() => assertMountPath("relative.key")).toThrow(EnvSinkError);
    expect(() => assertMountPath("/run/../secrets/api.key")).toThrow(EnvSinkError);
    const ph = "[" + "REDACTED" + "]";
    expect(() => assertMountPath(`/run/${ph}`)).toThrow(EnvSinkError);
    expect(() => assertFileContentSafe("line\nline")).not.toThrow();
    expect(() => assertFileContentSafe("has\u0000nul")).toThrow(EnvSinkError);
    expect(() => assertFileContentSafe(ph)).toThrow(EnvSinkError);
  });
});
