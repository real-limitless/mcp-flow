import { describe, expect, it } from "vitest";
import { DokployEnvSink, EnvChangedError, EnvSinkError } from "../src/secrets/env-sink.js";
import { parseProtectedTargets } from "../src/secrets/protected.js";

describe("env sink", () => {
  function make(initial = "") {
    let env = initial;
    let writes = 0;
    const callTool = async (name: string, args: any) => {
      if (name.endsWith("__compose-one")) {
        return { content: [{ type: "text", text: JSON.stringify({ env }) }], isError: false };
      }
      if (name.endsWith("__compose-saveEnvironment")) {
        env = args.env;
        writes++;
        return { content: [{ type: "text", text: "ok" }], isError: false };
      }
      return { content: [{ type: "text", text: "nope" }], isError: true };
    };
    const sink = new DokployEnvSink(callTool as any, parseProtectedTargets(""));
    return { sink, getEnv: () => env, writes: () => writes };
  }

  it("merge preserves other lines", async () => {
    const { sink, getEnv } = make("A=1\nB=2\n");
    await sink.apply("cmp", "c1", { C: "3" }, []);
    expect(getEnv()).toBe("A=1\nB=2\nC=3\n");
  });

  it("replaces in place and unsets", async () => {
    const { sink, getEnv } = make("A=1\nB=2\n");
    await sink.apply("cmp", "c1", { A: "9" }, ["B"]);
    expect(getEnv()).toBe("A=9\n");
  });

  it("placeholder refusal on value", async () => {
    const { sink } = make("A=1\n");
    const ph = "[" + "REDACTED" + "]";
    await expect(sink.apply("cmp", "c1", { X: ph }, [])).rejects.toBeInstanceOf(EnvSinkError);
  });

  it("placeholder refusal when value contains placeholder", async () => {
    const { sink } = make("A=1\n");
    const ph = "[" + "REDACTED" + "]";
    await expect(sink.apply("cmp", "c1", { X: `y${ph}z` }, [])).rejects.toBeInstanceOf(EnvSinkError);
  });

  it("read env already contains placeholder", async () => {
    const ph = "[" + "REDACTED" + "]";
    const { sink } = make(`A=${ph}\n`);
    await expect(sink.readEnv("cmp", "c1")).rejects.toBeInstanceOf(EnvSinkError);
  });

  it("fail closed on changed env", async () => {
    let env = "A=1\n";
    let reads = 0;
    const callTool = async (name: string, args: any) => {
      if (name.endsWith("__compose-one")) {
        reads++;
        if (reads === 2) env = "A=2\n";
        return { content: [{ type: "text", text: JSON.stringify({ env }) }], isError: false };
      }
      if (name.endsWith("__compose-saveEnvironment")) {
        return { content: [{ type: "text", text: "ok" }], isError: false };
      }
      return { content: [], isError: true };
    };
    const sink = new DokployEnvSink(callTool as any, parseProtectedTargets(""));
    await expect(sink.apply("cmp", "c1", { X: "3" }, [])).rejects.toBeInstanceOf(EnvChangedError);
  });

  it("protected target refusal", async () => {
    const { sink } = make("A=1\n");
    const sink2 = new DokployEnvSink((async (n: string, a: any) => ({ content: [{ type: "text", text: JSON.stringify({ env: "A=1\n" }) }], isError: false })) as any, parseProtectedTargets("c1"));
    await expect(sink2.apply("cmp", "c1", { X: "3" }, [])).rejects.toBeInstanceOf(Error);
    void sink;
  });

  it("no write on changed env", async () => {
    let writes = 0;
    let env = "A=1\n";
    let reads = 0;
    const callTool = async (name: string, args: any) => {
      if (name.endsWith("__compose-one")) {
        reads++;
        if (reads === 2) env = "A=2\n";
        return { content: [{ type: "text", text: JSON.stringify({ env }) }], isError: false };
      }
      if (name.endsWith("__compose-saveEnvironment")) {
        writes++;
        env = args.env;
        return { content: [{ type: "text", text: "ok" }], isError: false };
      }
      return { content: [], isError: true };
    };
    const sink = new DokployEnvSink(callTool as any, parseProtectedTargets(""));
    try { await sink.apply("cmp", "c1", { X: "3" }, []); } catch {}
    expect(writes).toBe(0);
  });
});