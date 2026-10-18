# syntax=docker/dockerfile:1
# Small production image for the Whatscraft relay (Bun + Postgres client).
FROM oven/bun:1.4-slim AS base
WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json bun.lock* ./
RUN bun install --production --frozen-lockfile 2>/dev/null || bun install --production

COPY tsconfig.json schema.sql ./
COPY src ./src

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

# Fly.io and most PaaS need the process to bind 0.0.0.0 (Bun does by default).
CMD ["bun", "run", "src/index.ts"]
