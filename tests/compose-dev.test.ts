import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function read(rel: string): string {
  return readFileSync(resolve(root, rel), "utf8");
}

function stripComments(src: string): string {
  return src
    .split("\n")
    .map((line) => {
      const hash = line.indexOf("#");
      if (hash === -1) return line;
      const before = line.slice(0, hash);
      const quotes = before.match(/"/g);
      if (quotes && quotes.length % 2 === 1) return line;
      return before.replace(/\s+$/, "");
    })
    .join("\n");
}

describe("DEV compose template", () => {
  const compose = read("docker-compose.dev.yml");
  const stripped = stripComments(compose);
  const env = read(".env.dev.example");
  const traefik = stripComments(read("docker/dev/traefik.yml"));
  const dynamic = stripComments(read("docker/dev/dynamic.yml"));
  const serve = JSON.parse(read("docker/dev/ts-serve.json")) as {
    TCP: Record<string, { TCPForward?: string }>;
  };
  const prod = read("docker-compose.yml");
  const ignore = read(".gitignore");

  it("keeps the prod compose file on its own names", () => {
    expect(prod).toMatch(/^name: mcp-flow$/m);
    expect(prod).toMatch(/container_name: mcp-flow$/m);
    expect(prod).not.toMatch(/mcp-flow-dev/);
    expect(prod).not.toMatch(/docker-compose\.dev\.yml/);
  });

  it("is additive and does not publish host ports or join another network", () => {
    expect(stripped).toMatch(/^name: mcp-flow-dev$/m);
    expect(stripped).not.toMatch(/^\s*ports\s*:/m);
    expect(stripped).not.toMatch(/dokploy-network/);
    expect(stripped).not.toMatch(/external:\s*true/);
    expect(stripped).not.toMatch(/docker\.sock/);
    expect(stripped).not.toMatch(/^\s*edge\s*:/m);
    expect(stripped).not.toMatch(/mem_limit:/);
    expect(ignore).toMatch(/^!\.env\.dev\.example$/m);
  });

  it("uses distinct container, network, and volume names", () => {
    for (const name of [
      "mcp-flow-dev",
      "mcp-flow-dev-bootstrap",
      "mcp-flow-dev-traefik",
      "mcp-flow-dev-tailscale",
    ]) {
      expect(stripped).toMatch(new RegExp(`container_name: ${name}$`, "m"));
    }
    expect(stripped).toMatch(/^ {2}mcp-flow-dev:\n {4}name: mcp-flow-dev$/m);
    expect(stripped).toMatch(/name: mcp-flow-dev-data$/m);
    expect(stripped).toMatch(/name: mcp-flow-dev-tailscale-state$/m);
    expect(stripped).toMatch(/name: mcp-flow-dev-traefik-logs$/m);
    expect(stripped).not.toMatch(/name: mcp-flow$/m);
    expect(stripped).not.toMatch(/name: mcp-flow-data$/m);
  });

  it("builds the gateway from the repo context and pins Traefik", () => {
    expect(stripped).toMatch(/target: gateway/);
    expect(stripped).toMatch(/image: mcp-flow-dev:local/);
    expect(stripped).toMatch(/image: traefik:v3\.7\.16/);
    expect(stripped).not.toMatch(/:\s*latest\s*$/m);
    expect(stripped).not.toMatch(/ghcr\.io/);
    expect(stripped).toMatch(/image: tailscale\/tailscale:stable/);
  });

  it("sets the locked gateway environment explicitly", () => {
    expect(stripped).toMatch(/ENVIRONMENT: staging/);
    expect(stripped).toMatch(/MCP_FLOW_ALLOW_PRIVATE_URLS: "false"/);
    expect(stripped).toMatch(/MCP_FLOW_REFUSE_LEGACY_MCP_KEYS: "true"/);
    expect(stripped).toMatch(/MCP_FLOW_DB_PATH: \/data\/mcp-flow\.db/);
    expect(stripped).toMatch(/MCP_FLOW_LOCK_PATH: \/data\/mcp-flow\.lock/);
    expect(stripped).toMatch(/MCP_FLOW_TRUST_PROXY: "true"/);
    expect(stripped).toMatch(
      /MCP_FLOW_PUBLIC_URL: "\$\{MCP_FLOW_DEV_PUBLIC_URL:-https:\/\/mcp-flow-dev\.example\.com\}"/,
    );
    expect(stripped).toMatch(
      /MCP_FLOW_CORS_ORIGINS: "\$\{MCP_FLOW_DEV_CORS_ORIGINS:-\}"/,
    );
    expect(stripped).not.toMatch(/MCP_FLOW_ALLOW_PRIVATE_URLS:.*true/);
    expect(stripped).not.toMatch(/\$\{MCP_FLOW_MASTER_KEY/);
    expect(stripped).not.toMatch(/\$\{MCP_FLOW_PUBLIC_URL/);
    expect(stripped).not.toMatch(/\$\{TS_AUTHKEY/);
    expect(stripped).not.toMatch(/\$\{TS_HOSTNAME/);
    expect(stripped).not.toMatch(/\$\{TS_LOGIN_SERVER/);
  });

  it("points Tailscale at the DEV Traefik service and logs JSON there", () => {
    expect(serve.TCP["443"]?.TCPForward).toBe("mcp-flow-dev-traefik:8443");
    expect(Object.keys(serve.TCP)).toEqual(["443"]);
    expect(traefik).toMatch(/format:\s*json/);
    expect(traefik).toMatch(/filePath:\s*\/var\/log\/traefik\/access\.json/);
    expect(traefik).toMatch(/defaultMode:\s*drop/);
    expect(traefik).toMatch(/address:\s*":8443"/);
    expect(traefik).toMatch(/address:\s*"127\.0\.0\.1:8082"/);
    expect(traefik).not.toMatch(/^\s*api\s*:/m);
    expect(traefik).not.toMatch(/insecure:\s*true/);
    expect(traefik).not.toMatch(/dashboard:\s*true/);
    expect(traefik).not.toMatch(/docker/);
    expect(dynamic).toMatch(/url:\s*"http:\/\/mcp-flow-dev:8787"/);
    expect(dynamic).not.toMatch(/Host\(/);
    expect(dynamic).not.toMatch(/api@internal/);
  });

  it("keeps placeholders out of real hostnames and wildcard CORS", () => {
    const blob = [compose, env, traefik, dynamic, JSON.stringify(serve)].join("\n");
    expect(blob).not.toMatch(/z\.srl/i);
    const ips = blob.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [];
    expect(ips.every((ip) => ip === "127.0.0.1" || ip === "0.0.0.0")).toBe(true);
    expect(ips.length).toBeGreaterThan(0);
    expect(env).toMatch(
      /^MCP_FLOW_DEV_PUBLIC_URL=https:\/\/mcp-flow-dev\.example\.com$/m,
    );
    expect(env).toMatch(/^TS_DEV_HOSTNAME=mcp-flow-dev$/m);
    expect(env).toMatch(/^TS_DEV_LOGIN_SERVER=https:\/\/headscale\.example\.com$/m);
    expect(env).toMatch(/mcp_flow_dev/);
    expect(env).not.toMatch(/CORS.*=\s*\*/);
    expect(stripComments(env)).not.toMatch(/\*/);
  });
});
