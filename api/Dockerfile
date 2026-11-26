# syntax=docker/dockerfile:1
# ---------------------------------------------------------------------------
# Chainmark AI - Managed Cloud Hono API (Bun)
# ---------------------------------------------------------------------------
FROM oven/bun:1-alpine

WORKDIR /app

# Install dependencies first for layer caching.
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile || bun install

# Runtime sources: cloud API, database schema/ORM layer, and Drizzle config.
COPY api ./api
COPY db ./db
COPY drizzle.config.ts ./
COPY tsconfig.json* ./

ENV NODE_ENV=development \
    API_PORT=3001 \
    DEPLOYMENT_MODE=cloud

EXPOSE 3001

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
    CMD wget -qO- http://127.0.0.1:3001/api/cloud/health >/dev/null || exit 1

CMD ["bun", "run", "api"]
