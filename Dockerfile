FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
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
