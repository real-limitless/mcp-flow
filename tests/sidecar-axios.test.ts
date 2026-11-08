import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";
import { applySidecarEnv } from "../src/egress/sidecar.js";
import type { EgressProxy } from "../src/egress/sidecar.js";

function proxyServer(): Promise<{ port: number; seen: string[]; close: () => Promise<void> }> {
  const seen: string[] = [];
  const server = createServer((req, res) => {
    seen.push(`REQ ${req.url ?? ""}`);
    res.end("ok");
  });
  server.on("connect", (req, socket) => {
    seen.push(`CONNECT ${String(req.url ?? "")}`);
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    socket.destroy();
  });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("proxy listen timed out")), 2_000);
    server.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    server.listen(0, "127.0.0.1", () => {
      clearTimeout(timer);
      const address = server.address();
      if (!address || typeof address === "string") {
        reject(new Error("no port"));
        return;
      }
      resolve({
        port: address.port,
        seen,
        close: () => {
          server.closeAllConnections();
          server.unref();
          server.close();
          return Promise.resolve();
        },
      });
    });
  });
}

function runAxios(env: NodeJS.ProcessEnv): Promise<{ code: number | null; out: string }> {
  const child = spawn(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `import axios from "axios";
try {
  const res = await axios.get(process.env.TARGET, { timeout: 4000, validateStatus: () => true });
  console.log("STATUS", res.status);
} catch (err) {
  const error = err instanceof Error ? err : new Error(String(err));
  console.log("ERR", "code" in error ? String(error.code) : "", error.message);
}`,
    ],
    {
      cwd: process.cwd(),
      env,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let out = "";
  child.stdout.on("data", (chunk: Buffer) => {
    out += chunk.toString("utf8");
  });
  child.stderr.on("data", () => undefined);
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 8_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, out });
    });
  });
}

describe("axios honors a selected sidecar", () => {
  it("sends the MagicDNS hostname to the HTTP proxy", async () => {
    const proxy = await proxyServer();
    const egress: EgressProxy = {
      connectionId: "sc_office",
      slug: "office",
      displayName: "Office",
      kind: "tailscale",
      httpProxyUrl: `http://127.0.0.1:${proxy.port}`,
      socksProxyUrl: `socks5://127.0.0.1:${proxy.port}`,
      scope: "gateway",
      deviceId: null,
    };
    const injected = applySidecarEnv({}, egress);
    try {
      const via = await runAxios({
        PATH: process.env.PATH,
        TARGET: "https://magicdns.invalid/mcp",
        ...injected,
      });
      expect(via.out).toMatch(/ERR|STATUS/);
      expect(proxy.seen.some((line) => line.startsWith("CONNECT magicdns.invalid:"))).toBe(true);

      const seenBefore = proxy.seen.length;
      const direct = await runAxios({
        PATH: process.env.PATH,
        TARGET: "http://127.0.0.1:1/",
      });
      expect(direct.out).toMatch(/ERR/);
      expect(proxy.seen.length).toBe(seenBefore);
    } finally {
      await proxy.close();
    }
  });
});
