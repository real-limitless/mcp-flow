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
    MCP_FLOW_DB_PATH=/data/mcp-flow.db
RUN mkdir -p /data && chown node:node /data
COPY --from=build /app/package.json /app/package-lock.json* ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
USER node
EXPOSE 8787
VOLUME ["/data"]
CMD ["node", "dist/cli.js", "serve"]
