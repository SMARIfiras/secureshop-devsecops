# syntax=docker/dockerfile:1
# ── Stage 1: Build (with native compilation tools for better-sqlite3) ─────────
FROM node:20-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev && npm cache clean --force

# ── Stage 2: Runtime (minimal image) ──────────────────────────────────────────
FROM node:20-slim AS runtime

RUN groupadd -r appuser && useradd -r -g appuser --create-home appuser

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY index.js .

RUN mkdir -p /data && chown appuser:appuser /data

USER appuser

EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8002/health', r => process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

CMD ["node", "index.js"]
