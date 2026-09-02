FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim AS gateway
WORKDIR /app
ENV NODE_ENV=production \
    MCP_FLOW_HOST=0.0.0.0 \
    MCP_FLOW_PORT=8787 \
    MCP_FLOW_DB_PATH=/data/mcp-flow.db \
    MCP_FLOW_DATA_DIR=/data
RUN mkdir -p /data /app/catalog && chown node:node /data /app/catalog
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=build /app/package.json /app/package-lock.json* ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY docker ./docker
COPY catalog/schema.json catalog/blocklist.txt ./catalog/
USER node
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=10 \
  CMD node -e "fetch('http://127.0.0.1:8787/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
ENTRYPOINT ["node", "docker/entrypoint.mjs"]
CMD ["serve"]

FROM gateway AS edge
USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends git ca-certificates curl gnupg \
  && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | tee /usr/share/keyrings/githubcli-archive-keyring.gpg >/dev/null \
  && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    > /etc/apt/sources.list.d/github-cli.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends gh \
  && mkdir -p /repos /root/.config/gh \
  && chmod 755 /app/docker/github-mcp.sh \
  && ln -sf /app/docker/github-mcp.sh /usr/local/bin/github-mcp \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /repos
