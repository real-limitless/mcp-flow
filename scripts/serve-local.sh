#!/usr/bin/env bash
# Start mcp-flow gateway for local OpenCode.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f "$ROOT/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT/.env"
  set +a
fi

: "${MCP_FLOW_MASTER_KEY:?Set MCP_FLOW_MASTER_KEY (same key used with tui)}"
: "${MCP_FLOW_ADMIN_TOKEN:?Set MCP_FLOW_ADMIN_TOKEN (openssl rand -hex 32)}"

export MCP_FLOW_HOST="${MCP_FLOW_HOST:-127.0.0.1}"
export MCP_FLOW_PORT="${MCP_FLOW_PORT:-8787}"
export MCP_FLOW_DB_PATH="${MCP_FLOW_DB_PATH:-$ROOT/data/mcp-flow.db}"
export MCP_FLOW_ALLOW_PRIVATE_URLS="${MCP_FLOW_ALLOW_PRIVATE_URLS:-true}"

if [[ ! -f "$ROOT/dist/cli.js" ]]; then
  npm run build
fi

exec node "$ROOT/dist/cli.js" serve --host "$MCP_FLOW_HOST" --port "$MCP_FLOW_PORT" --db "$MCP_FLOW_DB_PATH"
