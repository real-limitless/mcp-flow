#!/bin/sh
set -e
TOKEN=$(gh auth token 2>/dev/null) || {
  echo "github-mcp: gh is not logged in. From a shell MCP run: gh auth login" >&2
  exit 1
}
export GITHUB_PERSONAL_ACCESS_TOKEN="$TOKEN"
exec docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN ghcr.io/github/github-mcp-server
