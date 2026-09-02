import { existsSync, readFileSync, writeFileSync } from "node:fs";

const DATA = process.env.MCP_FLOW_DATA_DIR || "/data";
const INTERNAL = (
  process.env.MCP_FLOW_INTERNAL_URL || "http://mcp-flow:8787"
).replace(/\/$/, "");
const PUBLIC = (
  process.env.MCP_FLOW_PUBLIC_URL || "http://127.0.0.1:8787"
).replace(/\/$/, "");

function parseEnvFile(text) {
  const out = {};
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const i = t.indexOf("=");
    if (i === -1) continue;
    out[t.slice(0, i)] = t.slice(i + 1);
  }
  return out;
}

function adminToken() {
  if (process.env.MCP_FLOW_ADMIN_TOKEN?.trim()) {
    return process.env.MCP_FLOW_ADMIN_TOKEN.trim();
  }
  const p = `${DATA}/secrets.env`;
  if (existsSync(p)) {
    return parseEnvFile(readFileSync(p, "utf8")).MCP_FLOW_ADMIN_TOKEN?.trim() || "";
  }
  return "";
}

async function waitHealthy(tries = 40) {
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(`${INTERNAL}/health`);
      if (r.ok) return;
    } catch {
      /* retry */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`gateway not healthy at ${INTERNAL}/health`);
}

async function adminJson(method, path, body) {
  const token = adminToken();
  if (!token) throw new Error("MCP_FLOW_ADMIN_TOKEN missing");
  const r = await fetch(`${INTERNAL}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let json = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { error: text };
  }
  if (!r.ok) {
    throw new Error(`${method} ${path} ${r.status}: ${json.error || text}`);
  }
  return json;
}

export async function runBootstrap() {
  await waitHealthy();

  const clientPath = `${DATA}/mcp-client.json`;
  if (!existsSync(clientPath)) {
    const created = await adminJson("POST", "/v1/keys", {
      name: "compose-agent",
    });
    const token = created.key?.token;
    if (!token) throw new Error("key create returned no token");
    writeFileSync(`${DATA}/agent.key`, `${token}\n`, { mode: 0o600 });
    writeFileSync(
      clientPath,
      JSON.stringify(
        {
          url: `${PUBLIC}/mcp`,
          admin: `${PUBLIC}/admin/`,
          mcpServers: {
            "mcp-flow": {
              url: `${PUBLIC}/mcp`,
              headers: { Authorization: `Bearer ${token}` },
            },
          },
        },
        null,
        2,
      ) + "\n",
      { mode: 0o600 },
    );
    console.error("mcp-flow bootstrap: wrote /data/mcp-client.json");
  } else {
    console.error("mcp-flow bootstrap: /data/mcp-client.json exists — skip key");
  }

  const devicePath = `${DATA}/device-token.txt`;
  if (!existsSync(devicePath)) {
    const enrolled = await adminJson("POST", "/v1/devices", {
      name: "compose-edge",
      tags: ["compose"],
      capabilities: { sandbox: "docker", bare: false },
    });
    const token = enrolled.device?.token;
    if (!token) throw new Error("device enroll returned no token");
    writeFileSync(devicePath, `${token}\n`, { mode: 0o600 });
    if (enrolled.device?.id) {
      writeFileSync(`${DATA}/device-id.txt`, `${enrolled.device.id}\n`, {
        mode: 0o600,
      });
    }
    console.error("mcp-flow bootstrap: wrote /data/device-token.txt");
  } else {
    console.error("mcp-flow bootstrap: /data/device-token.txt exists — skip enroll");
  }
}
