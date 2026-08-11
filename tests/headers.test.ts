import { describe, expect, it } from "vitest";
import {
  parseHeaderFlag,
  parseHeaderFlags,
  parseHeadersBlob,
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
});
