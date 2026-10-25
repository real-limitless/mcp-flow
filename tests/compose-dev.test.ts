import { execFileSync } from "node:child_process";
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

function composeBin(): string | undefined {
  try {
    execFileSync("docker-compose", ["version"], { stdio: "ignore" });
    return "docker-compose";
  } catch {
    return undefined;
  }
}

describe("DEV compose template", () => {
  const compose = read("docker-compose.dev.yml");
  const gateway = read("docker/dev/gateway.yml");
  const gatewayPublic = read("docker/dev/gateway-public.yml");
  const stripped = stripComments(compose);
  const gatewayStripped = stripComments(gateway);
  const publicStripped = stripComments(gatewayPublic);
  const stack = `${stripped}\n${gatewayStripped}`;
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

  it("is additive and does not publish host ports on the default path", () => {
    expect(stripped).toMatch(/^name: mcp-flow-dev$/m);
    expect(stack).not.toMatch(/^\s*ports\s*:/m);
    expect(stack).not.toMatch(/dokploy-network/);
    expect(stack).not.toMatch(/external:\s*true/);
    expect(stack).not.toMatch(/traefik\.enable/);
    expect(stack).not.toMatch(/traefik\.http/);
    expect(stack).not.toMatch(/traefik\.docker/);
    expect(stack).not.toMatch(/docker\.sock/);
    expect(stack).not.toMatch(/^\s*edge\s*:/m);
    expect(stack).not.toMatch(/mem_limit:/);
    expect(stripped).toMatch(
      /path: \.\/docker\/dev\/gateway\$\{MCP_FLOW_DEV_PUBLIC_HOST:\+-public\}\.yml/,
    );
    expect(ignore).toMatch(/^!\.env\.dev\.example$/m);
  });

  it("uses distinct container, network, and volume names", () => {
    expect(gatewayStripped).toMatch(/container_name: mcp-flow-dev$/m);
    for (const name of [
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
    expect(gatewayStripped).toMatch(/context: \.\.\/\.\./);
    expect(gatewayStripped).toMatch(/path: \.\.\/\.\.\/\.env\.dev/);
    expect(gatewayStripped).toMatch(/target: gateway/);
    expect(gatewayStripped).toMatch(/image: mcp-flow-dev:local/);
    expect(stripped).toMatch(/image: traefik:v3\.7\.16/);
    expect(stripped).not.toMatch(/:\s*latest\s*$/m);
    expect(stripped).not.toMatch(/ghcr\.io/);
    expect(stripped).toMatch(/image: tailscale\/tailscale:stable/);
  });

  it("sets the locked gateway environment explicitly", () => {
    expect(gatewayStripped).toMatch(/ENVIRONMENT: staging/);
    expect(gatewayStripped).toMatch(/MCP_FLOW_ALLOW_PRIVATE_URLS: "false"/);
    expect(gatewayStripped).toMatch(/MCP_FLOW_REFUSE_LEGACY_MCP_KEYS: "true"/);
    expect(gatewayStripped).toMatch(/MCP_FLOW_DB_PATH: \/data\/mcp-flow\.db/);
    expect(gatewayStripped).toMatch(/MCP_FLOW_LOCK_PATH: \/data\/mcp-flow\.lock/);
    expect(gatewayStripped).toMatch(/MCP_FLOW_TRUST_PROXY: "true"/);
    expect(gatewayStripped).toMatch(
      /MCP_FLOW_PUBLIC_URL: "\$\{MCP_FLOW_DEV_PUBLIC_URL:-https:\/\/mcp-flow-dev\.example\.com\}"/,
    );
    expect(gatewayStripped).toMatch(
      /MCP_FLOW_CORS_ORIGINS: "\$\{MCP_FLOW_DEV_CORS_ORIGINS:-\}"/,
    );
    expect(stack).not.toMatch(/MCP_FLOW_ALLOW_PRIVATE_URLS:.*true/);
    expect(stack).not.toMatch(/\$\{MCP_FLOW_MASTER_KEY/);
    expect(stack).not.toMatch(/\$\{MCP_FLOW_PUBLIC_URL/);
    expect(stack).not.toMatch(/\$\{TS_AUTHKEY/);
    expect(stripped).not.toMatch(/\$\{TS_HOSTNAME/);
    expect(stripped).not.toMatch(/\$\{TS_LOGIN_SERVER/);
  });

  it("adds host Traefik labels only on the public overlay", () => {
    expect(publicStripped).toMatch(/extends:/);
    expect(publicStripped).toMatch(/file: gateway\.yml/);
    expect(publicStripped).toMatch(/service: mcp-flow-dev/);
    expect(publicStripped).toMatch(/traefik\.enable: "true"/);
    expect(publicStripped).toMatch(
      /traefik\.docker\.network: \$\{MCP_FLOW_DEV_DOKPLOY_NETWORK:-dokploy-network\}/,
    );
    expect(publicStripped).toMatch(
      /traefik\.http\.routers\.mcp-flow-dev\.rule: "Host\(`\$\{MCP_FLOW_DEV_PUBLIC_HOST:\?/,
    );
    expect(publicStripped).toMatch(
      /traefik\.http\.routers\.mcp-flow-dev\.entrypoints: \$\{MCP_FLOW_DEV_TRAEFIK_ENTRYPOINT:-websecure\}/,
    );
    expect(publicStripped).toMatch(
      /traefik\.http\.routers\.mcp-flow-dev\.tls\.certresolver: \$\{MCP_FLOW_DEV_TRAEFIK_CERTRESOLVER:-letsencrypt\}/,
    );
    expect(publicStripped).toMatch(
      /traefik\.http\.services\.mcp-flow-dev\.loadbalancer\.server\.port: "8787"/,
    );
    expect(publicStripped).toMatch(
      /name: \$\{MCP_FLOW_DEV_DOKPLOY_NETWORK:-dokploy-network\}/,
    );
    expect(publicStripped).toMatch(/external: true/);
    expect(publicStripped).not.toMatch(/^\s*ports\s*:/m);
    expect(publicStripped).not.toMatch(/mcp-flow-dev-traefik/);
    expect(publicStripped).not.toMatch(/mcp-flow-dev-tailscale/);
    expect(env).toMatch(/^# MCP_FLOW_DEV_PUBLIC_HOST=$/m);
    expect(env).toMatch(/^# MCP_FLOW_DEV_DOKPLOY_NETWORK=dokploy-network$/m);
    expect(env).toMatch(/^# MCP_FLOW_DEV_TRAEFIK_ENTRYPOINT=websecure$/m);
    expect(env).toMatch(/^# MCP_FLOW_DEV_TRAEFIK_CERTRESOLVER=letsencrypt$/m);
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
    const blob = [
      compose,
      gateway,
      gatewayPublic,
      env,
      traefik,
      dynamic,
      JSON.stringify(serve),
    ].join("\n");
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
    expect(stripComments(gatewayPublic)).not.toMatch(/example\.com/);
  });

  const bin = composeBin();
  it.skipIf(!bin)("renders tailnet-only or Dokploy labels from the public host", () => {
    const render = (host: string | undefined) => {
      const envVars = { ...process.env };
      if (host === undefined) delete envVars.MCP_FLOW_DEV_PUBLIC_HOST;
      else envVars.MCP_FLOW_DEV_PUBLIC_HOST = host;
      return execFileSync(bin!, ["-f", "docker-compose.dev.yml", "config"], {
        cwd: root,
        env: envVars,
        encoding: "utf8",
      });
    };

    const off = render(undefined);
    expect(off).not.toMatch(/dokploy/);
    expect(off).not.toMatch(/traefik\.enable/);
    expect(off).not.toMatch(/traefik\.http/);
    expect(off).not.toMatch(/^\s*ports\s*:/m);
    expect(off).toMatch(/container_name: mcp-flow-dev$/m);
    expect(off).toMatch(/container_name: mcp-flow-dev-traefik$/m);
    expect(off).toMatch(/container_name: mcp-flow-dev-tailscale$/m);
    expect(off).toContain(`context: ${root}`);

    const on = render("mcp-flow-dev.example.com");
    expect(on).toMatch(/traefik\.enable: "true"/);
    expect(on).toMatch(/traefik\.docker\.network: dokploy-network/);
    expect(on).toMatch(/rule: Host\(`mcp-flow-dev\.example\.com`\)/);
    expect(on).toMatch(/entrypoints: websecure/);
    expect(on).toMatch(/certresolver: letsencrypt/);
    expect(on).toMatch(/server\.port: "8787"/);
    expect(on).toMatch(/dokploy:\n\s+name: dokploy-network\n\s+external: true/);
    expect(on).toMatch(/container_name: mcp-flow-dev-traefik$/m);
    expect(on).toMatch(/container_name: mcp-flow-dev-tailscale$/m);
    expect(on).not.toMatch(/^\s*ports\s*:/m);
    expect(on).toContain(`context: ${root}`);

    const custom = execFileSync(bin!, ["-f", "docker-compose.dev.yml", "config"], {
      cwd: root,
      env: {
        ...process.env,
        MCP_FLOW_DEV_PUBLIC_HOST: "gateway.example.com",
        MCP_FLOW_DEV_DOKPLOY_NETWORK: "proxy-net",
        MCP_FLOW_DEV_TRAEFIK_ENTRYPOINT: "https",
        MCP_FLOW_DEV_TRAEFIK_CERTRESOLVER: "acme",
      },
      encoding: "utf8",
    });
    expect(custom).toMatch(/traefik\.docker\.network: proxy-net/);
    expect(custom).toMatch(/rule: Host\(`gateway\.example\.com`\)/);
    expect(custom).toMatch(/entrypoints: https/);
    expect(custom).toMatch(/certresolver: acme/);
    expect(custom).toMatch(/name: proxy-net\n\s+external: true/);
  });
});
