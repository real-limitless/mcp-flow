import { describe, expect, it } from "vitest";
import {
  parseHeaderFlag,
  parseHeaderFlags,
  parseHeadersBlob,
  compactSecretRecord,
  normalizeAuthorizationValue,
  normalizeUpstreamHeaders,
  withAuthorizationToken,
} from "../src/headers.js";

describe("headers", () => {
  it("parses Name=value", () => {
    expect(parseHeaderFlag("Authorization=Bearer x=y")).toEqual({
      name: "Authorization",
      value: "Bearer x=y",
    });
  });

  it("parses Name: value (mcp-remote style)", () => {
    expect(
      parseHeaderFlag("x-api-host: yahoo-finance15.p.rapidapi.com"),
    ).toEqual({
      name: "x-api-host",
      value: "yahoo-finance15.p.rapidapi.com",
    });
  });

  it("parses multiple flags", () => {
    const h = parseHeaderFlags([
      "x-api-host: example.com",
      "x-api-key=secret",
    ]);
    expect(h).toEqual({
      "x-api-host": "example.com",
      "x-api-key": "secret",
    });
  });

  it("parses blob with ; separators", () => {
    const h = parseHeadersBlob(
      "x-api-host: h.example; x-api-key=sekrit| X-Extra=1",
    );
    expect(h).toEqual({
      "x-api-host": "h.example",
      "x-api-key": "sekrit",
      "X-Extra": "1",
    });
  });

  it("compacts blank secret records", () => {
    expect(compactSecretRecord(undefined)).toBeUndefined();
    expect(compactSecretRecord(null)).toBeUndefined();
    expect(compactSecretRecord({ Authorization: "" })).toBeUndefined();
    expect(compactSecretRecord({ "": "x" })).toBeUndefined();
    expect(
      compactSecretRecord({
        Authorization: "  ",
        "X-Api-Key": " secret ",
      }),
    ).toEqual({ "X-Api-Key": "secret" });
  });

  it("prefixes Bearer on raw Authorization tokens", () => {
    expect(normalizeAuthorizationValue("of_abc")).toBe("Bearer of_abc");
    expect(normalizeAuthorizationValue("Bearer of_abc")).toBe("Bearer of_abc");
    expect(normalizeAuthorizationValue("bearer of_abc")).toBe("Bearer of_abc");
    expect(normalizeAuthorizationValue("Basic Zm9v")).toBe("Basic Zm9v");
    expect(normalizeUpstreamHeaders({ authorization: "of_abc" })).toEqual({
      Authorization: "Bearer of_abc",
    });
    expect(
      normalizeUpstreamHeaders({
        Authorization: "of_abc",
        "X-Api-Key": "of_abc",
      }),
    ).toEqual({
      Authorization: "Bearer of_abc",
      "X-Api-Key": "of_abc",
    });
    expect(withAuthorizationToken(undefined, "of_abc")).toEqual({
      Authorization: "Bearer of_abc",
    });
    expect(
      withAuthorizationToken({ "X-Extra": "1" }, "of_abc"),
    ).toEqual({
      Authorization: "Bearer of_abc",
      "X-Extra": "1",
    });
  });
});
