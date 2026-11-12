import { describe, expect, it } from "vitest";
import {
  parseEnvText,
  mergeEnvText,
  envKeyNames,
  envDigest,
  assertEnvValueSafe,
  MASK,
  EnvSinkError,
} from "../src/secrets/env-text.js";

describe("env text", () => {
  it("parses and preserves comments/blanks", () => {
    const text = "# c\n\nA=1\nexport B=2\n";
    const lines = parseEnvText(text);
    expect(lines.map((l) => l.kind)).toEqual(["comment", "blank", "entry", "entry", "blank"]);
    expect(envKeyNames(text)).toEqual(["A", "B"]);
  });

  it("merges in place and appends", () => {
    const text = "# c\nA=1\nB=2\n";
    const out = mergeEnvText(text, { A: "9", C: "3" }, ["B"]);
    expect(out).toBe("# c\nA=9\nC=3\n");
  });

  it("preserves bytes for untouched lines", () => {
    const text = "A=1\n  # indented? \nB=2";
    const out = mergeEnvText(text, { Z: "z" }, []);
    expect(out).toBe("A=1\n  # indented? \nB=2\nZ=z");
  });

  it("digest is sha256 hex", () => {
    expect(envDigest("abc")).toMatch(/^[0-9a-f]{64}$/);
  });

  it("assertEnvValueSafe rejects control chars and placeholders", () => {
    const ph = "[" + "REDACTED" + "]";
    expect(() => assertEnvValueSafe("a\nb")).toThrow(EnvSinkError);
    expect(() => assertEnvValueSafe("a\rb")).toThrow(EnvSinkError);
    expect(() => assertEnvValueSafe("a\0b")).toThrow(EnvSinkError);
    expect(() => assertEnvValueSafe(`x${ph}y`)).toThrow(EnvSinkError);
    expect(() => assertEnvValueSafe("ok")).not.toThrow();
  });

  it("MASK is ***", () => {
    expect(MASK).toBe("***");
  });
});