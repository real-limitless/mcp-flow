/**
 * Decide how the edge process is started.
 *
 * A token already on the command line or in MCP_FLOW_DEVICE_TOKEN connects to
 * an existing server and does not wait for the full-stack bootstrap file.
 * The env token is left in the environment. It is not copied onto argv.
 * With neither an env token nor a token file, the full stack still waits
 * for /data/device-token.txt, then passes that file token as --token.
 */

function nonempty(v) {
  return typeof v === "string" && v.trim() !== "";
}

export function planEdgeCliArgs({ args, env, tokenFromFile }) {
  const rest = Array.isArray(args) && args[0] === "edge" ? args.slice(1) : [];
  const hasTokenFlag = rest.includes("--token");
  const envToken = nonempty(env?.MCP_FLOW_DEVICE_TOKEN)
    ? env.MCP_FLOW_DEVICE_TOKEN.trim()
    : "";
  const fileToken = nonempty(tokenFromFile) ? tokenFromFile.trim() : "";

  if (!hasTokenFlag && !envToken && !fileToken) {
    return { waitForTokenFile: true, cliArgs: null };
  }

  if (!hasTokenFlag && !envToken && fileToken) {
    rest.push("--token", fileToken);
  }

  if (!rest.includes("--url")) {
    const envUrl = nonempty(env?.MCP_FLOW_URL) ? env.MCP_FLOW_URL.trim() : "";
    rest.push("--url", envUrl || "http://mcp-flow:8787");
  }

  return { waitForTokenFile: false, cliArgs: ["edge", ...rest] };
}
