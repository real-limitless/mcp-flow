# Installation

Source: private kit TheFLOW. Family ritual: clone DEVELOPMENT, then Compose.

This CORE branch is documentation only.

```sh
git clone -b DEVELOPMENT https://github.com/real-limitless/mcp-flow.git
cd mcp-flow
cp .env.example .env
docker compose up -d --build
```

Gateway: http://127.0.0.1:8787/

Host Node (`npx mcp-flow serve`) is for contributors. It is not the supported run path.

`npx mcp-flow doctor` after the container is up.
