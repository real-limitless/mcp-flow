#!/usr/bin/env bash
set -euo pipefail
PORT="${MCP_FLOW_PORT:-8787}"
if command -v npx >/dev/null 2>&1 && [ -f package.json ]; then
  npx mcp-flow doctor || curl -fsS "http://127.0.0.1:${PORT}/health"
else
  curl -fsS "http://127.0.0.1:${PORT}/health"
fi
echo
