import { describe, expect, it } from "vitest";
import { assertSafeUrl, isPrivateIp } from "../src/ssrf.js";

describe("ssrf", () => {
  it("detects private ips", () => {
    expect(isPrivateIp("127.0.0.1")).toBe(true);
    expect(isPrivateIp("10.0.0.1")).toBe(true);
    expect(isPrivateIp("192.168.1.1")).toBe(true);
    expect(isPrivateIp("8.8.8.8")).toBe(false);
  });

  it("blocks localhost when private disallowed", async () => {
    await expect(
      assertSafeUrl("http://localhost:3000/mcp", false),
    ).rejects.toThrow(/blocked|private/i);
  });

  it("allows localhost when private allowed", async () => {
    const u = await assertSafeUrl("http://127.0.0.1:3000/mcp", true);
    expect(u.hostname).toBe("127.0.0.1");
  });

  it("rejects non-http schemes", async () => {
    await expect(assertSafeUrl("file:///etc/passwd", true)).rejects.toThrow(
      /http/i,
    );
  });
});
